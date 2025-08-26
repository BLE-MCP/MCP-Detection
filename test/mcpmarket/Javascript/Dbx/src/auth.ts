import * as fs from 'fs';
import * as path from 'path';
import axios, { AxiosError } from 'axios';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { randomBytes, createHash } from 'crypto';
import dotenv from 'dotenv';
import {
    encryptData,
    decryptData,
    TokenRefreshError,
    TOKEN_REFRESH_CONFIG,
    EncryptedTokenData
} from './security-utils.js';
import { config, log } from './config.js';

dotenv.config();

const TOKEN_STORE_PATH = process.env.TOKEN_STORE_PATH || path.join(process.cwd(), '.tokens.json');

export const REQUIRED_SCOPES = [
    'files.metadata.read',
    'files.metadata.write',
    'files.content.read',
    'files.content.write',
    'sharing.read',
    'sharing.write'
];

interface TokenData {
    accessToken: string;
    refreshToken: string;
    expiresAt: number;
    scope: string[];
    accountId?: string;
    teamId?: string;
    uid?: string;
    codeVerifier: string;
}

// Use config values which handle encrypted secrets
const validatedAppKey: string = config.dropbox.appKey as string;
const validatedAppSecret: string = config.dropbox.appSecret as string;
const validatedRedirectUri: string = config.dropbox.redirectUri as string;

// Initialize token data from environment or stored tokens
let tokenData: TokenData | null = null;

export async function initializeTokenData(): Promise<void> {
    try {
        tokenData = process.env.DROPBOX_ACCESS_TOKEN ? {
            accessToken: process.env.DROPBOX_ACCESS_TOKEN,
            refreshToken: process.env.DROPBOX_REFRESH_TOKEN || '',
            expiresAt: Date.now() + (4 * 60 * 60 * 1000), // 4 hours from now
            scope: REQUIRED_SCOPES,
            codeVerifier: ''
        } : loadTokenData();

        if (!tokenData) {
            log.info('No token data found, authentication will be required');
            return;
        }

        // If we loaded from env vars but don't have a refresh token, force re-auth
        if (process.env.DROPBOX_ACCESS_TOKEN && !process.env.DROPBOX_REFRESH_TOKEN) {
            log.warn('Access token provided without refresh token, re-authentication required');
            await handleInvalidToken('Missing refresh token in environment');
            return;
        }

        // Validate token format before attempting refresh
        if (!isValidTokenFormat(tokenData)) {
            log.error('Invalid token format detected during initialization', {
                hasAccessToken: !!tokenData.accessToken,
                hasRefreshToken: !!tokenData.refreshToken,
                accessTokenLength: tokenData.accessToken?.length,
                refreshTokenLength: tokenData.refreshToken?.length
            });
            await handleInvalidToken('Invalid token format detected');
            return;
        }

        try {
            // Try to refresh the token immediately to ensure it's valid
            await refreshAccessToken();
            log.info('Token successfully refreshed during initialization');
        } catch (error) {
            if (error instanceof TokenRefreshError) {
                log.warn('Token refresh failed during initialization', {
                    error: error.message,
                    code: error.code,
                    retryable: error.retryable
                });
                if (!error.retryable) {
                    await handleInvalidToken('Non-retryable token refresh error');
                }
            } else {
                log.warn('Unexpected error during token refresh:', error);
            }
        }
    } catch (error) {
        log.error('Failed to initialize token data:', error);
        tokenData = null;
    }
}

function isValidTokenFormat(token: TokenData): boolean {
    return (
        typeof token.accessToken === 'string' &&
        token.accessToken.length > 0 &&
        typeof token.refreshToken === 'string' &&
        token.refreshToken.length > 0 &&
        typeof token.expiresAt === 'number' &&
        token.expiresAt > 0 &&
        Array.isArray(token.scope) &&
        token.scope.length > 0
    );
}

async function handleInvalidToken(reason: string): Promise<void> {
    log.info(`Clearing invalid token data: ${reason}`);
    if (tokenData && fs.existsSync(TOKEN_STORE_PATH)) {
        const backupPath = `${TOKEN_STORE_PATH}.invalid.${Date.now()}`;
        fs.copyFileSync(TOKEN_STORE_PATH, backupPath);
        fs.unlinkSync(TOKEN_STORE_PATH);
        log.info(`Backed up invalid token data to ${backupPath}`);
    }
    tokenData = null;
}

export function generatePKCE() {
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');
    return { codeVerifier, codeChallenge };
}

export function generateAuthUrl(): { url: string, codeVerifier: string } {
    const { codeVerifier, codeChallenge } = generatePKCE();
    const authUrl = new URL('https://www.dropbox.com/oauth2/authorize');
    
    authUrl.searchParams.append('client_id', validatedAppKey);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('redirect_uri', validatedRedirectUri);
    authUrl.searchParams.append('token_access_type', 'offline');
    authUrl.searchParams.append('code_challenge', codeChallenge);
    authUrl.searchParams.append('code_challenge_method', 'S256');
    authUrl.searchParams.append('scope', REQUIRED_SCOPES.join(' '));
    
    return {
        url: authUrl.toString(),
        codeVerifier
    };
}

export async function exchangeCodeForTokens(code: string, codeVerifier: string): Promise<TokenData> {
    try {
        const params = new URLSearchParams({
            code,
            grant_type: 'authorization_code',
            client_id: validatedAppKey,
            client_secret: validatedAppSecret,
            redirect_uri: validatedRedirectUri,
            code_verifier: codeVerifier,
            token_access_type: 'offline'  // Ensure we get a refresh token
        });

        log.debug('Exchanging code for tokens...', { 
            clientId: validatedAppKey,
            hasCode: !!code,
            hasCodeVerifier: !!codeVerifier
        });

        const response = await axios.post(
            'https://api.dropboxapi.com/oauth2/token',
            params.toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
            }
        );

        log.debug('Raw token response data:', {
            responseData: response.data,
            responseKeys: Object.keys(response.data)
        });

        log.debug('Received token response:', {
            hasAccessToken: !!response.data.access_token,
            hasRefreshToken: !!response.data.refresh_token,
            expiresIn: response.data.expires_in,
            scope: response.data.scope
        });

        if (!response.data.access_token || !response.data.refresh_token) {
            log.error('Token exchange response missing required tokens', {
                hasAccessToken: !!response.data.access_token,
                hasRefreshToken: !!response.data.refresh_token,
                responseData: response.data
            });
            throw new McpError(
                ErrorCode.InvalidRequest,
                'Token exchange response did not include required tokens'
            );
        }

        // Validate the refresh token format
        if (typeof response.data.refresh_token !== 'string' || response.data.refresh_token.trim() === '') {
            log.error('Invalid refresh token format received', {
                refreshTokenType: typeof response.data.refresh_token,
                refreshTokenLength: response.data.refresh_token?.length
            });
            throw new McpError(
                ErrorCode.InvalidRequest,
                'Invalid refresh token format received from Dropbox'
            );
        }

        const newTokenData: TokenData = {
            accessToken: response.data.access_token,
            refreshToken: response.data.refresh_token,
            expiresAt: Date.now() + (response.data.expires_in * 1000),
            scope: response.data.scope ? response.data.scope.split(' ') : REQUIRED_SCOPES,
            accountId: response.data.account_id,
            teamId: response.data.team_id,
            uid: response.data.uid,
            codeVerifier
        };

        // Validate the new token data
        if (!isValidTokenFormat(newTokenData)) {
            log.error('Generated token data is invalid', {
                hasAccessToken: !!newTokenData.accessToken,
                hasRefreshToken: !!newTokenData.refreshToken,
                accessTokenLength: newTokenData.accessToken?.length,
                refreshTokenLength: newTokenData.refreshToken?.length,
                expiresAt: newTokenData.expiresAt,
                scope: newTokenData.scope
            });
            throw new McpError(
                ErrorCode.InvalidRequest,
                'Generated token data is invalid'
            );
        }

        // Save token data before updating in-memory reference
        try {
            saveTokenData(newTokenData);
            log.debug('Token data saved to file');
        } catch (saveError) {
            log.error('Failed to save token data:', saveError);
            throw new McpError(
                ErrorCode.InternalError,
                'Failed to save token data'
            );
        }

        // Update in-memory token data only after successful save
        tokenData = newTokenData;

        log.debug('Token exchange successful', {
            hasAccessToken: true,
            hasRefreshToken: true,
            expiresAt: newTokenData.expiresAt,
            scope: newTokenData.scope
        });

        return newTokenData;
    } catch (error) {
        log.error('Token exchange error:', {
            error: error instanceof Error ? error.message : 'Unknown error',
            type: error instanceof Error ? error.constructor.name : typeof error,
            status: axios.isAxiosError(error) ? error.response?.status : undefined,
            responseData: axios.isAxiosError(error) ? error.response?.data : undefined
        });
        throw error;
    }
}

export async function refreshAccessToken(): Promise<string> {
    if (!tokenData?.refreshToken) {
        throw new TokenRefreshError(
            'No refresh token available',
            'NO_REFRESH_TOKEN',
            false
        );
    }

    // Validate refresh token before attempting to use it
    if (typeof tokenData.refreshToken !== 'string' || tokenData.refreshToken.trim() === '') {
        log.error('Invalid refresh token format detected', {
            type: typeof tokenData.refreshToken,
            length: tokenData.refreshToken ? tokenData.refreshToken.length : 0,
            isEmpty: tokenData.refreshToken?.trim() === '',
            tokenDataExists: !!tokenData
        });
        
        await handleInvalidToken('Malformed refresh token');
        throw new TokenRefreshError(
            'Refresh token is malformed',
            'INVALID_FORMAT',
            false
        );
    }

    try {
        const params = new URLSearchParams({
            refresh_token: tokenData.refreshToken,
            grant_type: 'refresh_token',
            client_id: validatedAppKey,
            client_secret: validatedAppSecret
        });

        log.debug('Attempting token refresh', {
            clientId: validatedAppKey,
            currentExpiresAt: tokenData.expiresAt,
            timeUntilExpiry: tokenData.expiresAt - Date.now(),
            hasRefreshToken: true
        });

        const response = await axios.post(
            'https://api.dropboxapi.com/oauth2/token',
            params.toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                timeout: 15000
            }
        );

        if (!response.data.access_token) {
            throw new TokenRefreshError(
                'Token refresh response missing access token',
                'INVALID_RESPONSE',
                true
            );
        }

        const newTokenData: TokenData = {
            ...tokenData,
            accessToken: response.data.access_token,
            expiresAt: Date.now() + (response.data.expires_in * 1000),
            scope: response.data.scope ? response.data.scope.split(' ') : tokenData.scope,
            refreshToken: response.data.refresh_token || tokenData.refreshToken
        };

        if (!isValidTokenFormat(newTokenData)) {
            throw new TokenRefreshError(
                'Received invalid token format from Dropbox',
                'INVALID_RESPONSE_FORMAT',
                true
            );
        }

        log.debug('Token refresh successful', {
            hasAccessToken: true,
            hasRefreshToken: !!newTokenData.refreshToken,
            expiresAt: newTokenData.expiresAt,
            scope: newTokenData.scope
        });

        saveTokenData(newTokenData);
        tokenData = newTokenData;
        return newTokenData.accessToken;
    } catch (error) {
        log.error('Token refresh error:', {
            error: error instanceof Error ? error.message : 'Unknown error',
            type: error instanceof Error ? error.constructor.name : typeof error,
            status: axios.isAxiosError(error) ? error.response?.status : undefined,
            responseData: axios.isAxiosError(error) ? error.response?.data : undefined
        });

        if (axios.isAxiosError(error)) {
            const status = error.response?.status ?? 0;
            const errorData = error.response?.data as { error?: string; error_description?: string };

            if (status === 401 || (status === 400 && errorData?.error === 'invalid_grant')) {
                await handleInvalidToken('Authentication failed during refresh');
                throw new TokenRefreshError(
                    'Authentication failed - please re-authenticate',
                    'INVALID_GRANT',
                    false
                );
            } else if (status === 429) {
                throw new TokenRefreshError(
                    'Rate limit exceeded - please wait before retrying',
                    'RATE_LIMIT',
                    true
                );
            } else if (status >= 500) {
                throw new TokenRefreshError(
                    'Dropbox server error - please try again later',
                    'SERVER_ERROR',
                    true
                );
            }
        }
        
        throw new TokenRefreshError(
            'Unexpected error during token refresh',
            'UNKNOWN_ERROR',
            true
        );
    }
}

export async function getValidAccessToken(): Promise<string> {
    try {
        if (!tokenData) {
            // Initialize token data from storage if not already loaded
            await initializeTokenData();
        }

        // Check if we have a token
        if (!tokenData || !tokenData.accessToken) {
            log.error('No access token available');
            throw new McpError(
                ErrorCode.InvalidRequest,
                'No access token available. Please re-authenticate.'
            );
        }

        const now = Date.now();
        const timeUntilExpiry = tokenData.expiresAt - now;
        const refreshThreshold = TOKEN_REFRESH_CONFIG.thresholdMinutes * 60 * 1000;

        // Log token status
        log.debug('Token status check', {
            currentTime: now,
            expiresAt: tokenData.expiresAt,
            timeUntilExpiry,
            refreshThreshold,
            shouldRefresh: timeUntilExpiry < refreshThreshold
        });

        // If token is not close to expiring, return it
        if (timeUntilExpiry > refreshThreshold) {
            return tokenData.accessToken;
        }

        // Token is close to expiry or expired, attempt refresh
        log.info('Token requires refresh', {
            timeUntilExpiry,
            refreshThreshold
        });

        try {
            return await refreshAccessToken();
        } catch (refreshError) {
            log.error('Token refresh failed', {
                error: refreshError instanceof Error ? refreshError.message : 'Unknown error',
                timeUntilExpiry
            });

            // If token is already expired, we must throw
            if (timeUntilExpiry <= 0) {
                throw new McpError(
                    ErrorCode.InvalidRequest,
                    'Access token is expired and refresh failed. Please re-authenticate.'
                );
            }

            // If token is still valid but refresh failed, we can use the existing token
            log.warn('Using existing token despite refresh failure', {
                timeUntilExpiry
            });
            return tokenData.accessToken;
        }
    } catch (error) {
        log.error('Failed to get valid access token:', {
            error: error instanceof Error ? error.message : 'Unknown error',
            type: error instanceof Error ? error.constructor.name : typeof error
        });
        throw error;
    }
}

function handleTokenError(error: unknown): never {
    if (axios.isAxiosError(error)) {
        const axiosError = error as AxiosError;
        const statusCode = axiosError.response?.status;
        const errorData = axiosError.response?.data as { error?: string, error_description?: string };

        if (statusCode === 401 && errorData?.error === 'invalid_grant') {
            throw new McpError(
                ErrorCode.InvalidRequest,
                'Invalid or expired token. Please re-authenticate.'
            );
        } else if (statusCode === 429) {
            throw new McpError(
                ErrorCode.InvalidRequest,
                'Rate limit exceeded. Please try again later.'
            );
        } else if (statusCode && statusCode >= 500) {
            throw new McpError(
                ErrorCode.InternalError,
                'Dropbox API server error. Please try again later.'
            );
        }

        throw new McpError(
            ErrorCode.InvalidRequest,
            errorData?.error_description || 'Failed to authenticate with Dropbox'
        );
    }

    throw new McpError(
        ErrorCode.InternalError,
        'An unexpected error occurred during authentication'
    );
}

function saveTokenData(data: TokenData): void {
    try {
        // Validate data before saving
        if (!isValidTokenFormat(data)) {
            throw new McpError(
                ErrorCode.InvalidRequest,
                'Cannot save invalid token data'
            );
        }

        log.debug('Saving token data:', { 
            hasAccessToken: !!data?.accessToken,
            hasRefreshToken: !!data?.refreshToken,
            expiresAt: data?.expiresAt,
            scope: data?.scope,
            tokenLength: {
                access: data.accessToken.length,
                refresh: data.refreshToken.length
            }
        });

        // Create backup of existing file if it exists
        if (fs.existsSync(TOKEN_STORE_PATH)) {
            const backupPath = `${TOKEN_STORE_PATH}.bak.${Date.now()}`;
            fs.copyFileSync(TOKEN_STORE_PATH, backupPath);
            log.debug('Created backup of existing token file', { backupPath });
        }

        // Encrypt and save the data
        const encryptedData = encryptData(data);
        const jsonData = JSON.stringify(encryptedData, null, 2);
        
        // Ensure the directory exists
        const tokenDir = path.dirname(TOKEN_STORE_PATH);
        if (!fs.existsSync(tokenDir)) {
            fs.mkdirSync(tokenDir, { recursive: true });
        }
        
        // Write the new token file
        fs.writeFileSync(TOKEN_STORE_PATH, jsonData, 'utf8');
        
        // Verify the saved data can be read back
        const savedData = fs.readFileSync(TOKEN_STORE_PATH, 'utf8');
        const parsedData = JSON.parse(savedData) as EncryptedTokenData;
        const decryptedData = decryptData(parsedData) as TokenData;
        
        if (!isValidTokenFormat(decryptedData)) {
            throw new McpError(
                ErrorCode.InternalError,
                'Saved token data is invalid after write'
            );
        }

        log.debug('Token data saved and verified', {
            path: TOKEN_STORE_PATH,
            hasValidFormat: true
        });

        // Only update in-memory data after successful save and verify
        tokenData = data;
    } catch (error) {
        log.error('Error saving token data:', {
            error: error instanceof Error ? error.message : 'Unknown error',
            type: error instanceof Error ? error.constructor.name : typeof error
        });
        throw new McpError(
            ErrorCode.InternalError,
            'Failed to save token data'
        );
    }
}

function loadTokenData(): TokenData | null {
    try {
        if (!fs.existsSync(TOKEN_STORE_PATH)) {
            log.debug('No token file found at:', { path: TOKEN_STORE_PATH });
            return null;
        }

        const rawData = fs.readFileSync(TOKEN_STORE_PATH, 'utf-8');
        log.debug('Loading token data from file:', { 
            path: TOKEN_STORE_PATH,
            rawDataLength: rawData.length,
            hasData: !!rawData
        });
        
        const encryptedData = JSON.parse(rawData) as EncryptedTokenData;
        log.debug('Parsed encrypted data:', {
            hasIv: !!encryptedData.iv,
            hasEncryptedData: !!encryptedData.encryptedData,
            hasAuthTag: !!encryptedData.authTag,
            ivLength: encryptedData.iv?.length,
            encryptedDataLength: encryptedData.encryptedData?.length,
            authTagLength: encryptedData.authTag?.length
        });
        
        const decryptedData = decryptData(encryptedData) as TokenData;
        log.debug('Decrypted token data:', {
            hasAccessToken: !!decryptedData?.accessToken,
            hasRefreshToken: !!decryptedData?.refreshToken,
            accessTokenLength: decryptedData?.accessToken?.length,
            refreshTokenLength: decryptedData?.refreshToken?.length,
            expiresAt: decryptedData?.expiresAt,
            scope: decryptedData?.scope,
            hasCodeVerifier: !!decryptedData?.codeVerifier
        });
        
        if (!isValidTokenFormat(decryptedData)) {
            log.error('Loaded token data is invalid', {
                hasAccessToken: !!decryptedData?.accessToken,
                hasRefreshToken: !!decryptedData?.refreshToken,
                accessTokenLength: decryptedData?.accessToken?.length,
                refreshTokenLength: decryptedData?.refreshToken?.length,
                expiresAt: decryptedData?.expiresAt,
                scope: decryptedData?.scope,
                hasCodeVerifier: !!decryptedData?.codeVerifier,
                tokenDataType: typeof decryptedData
            });
            return null;
        }

        log.debug('Token data loaded successfully:', { 
            hasAccessToken: true,
            hasRefreshToken: true,
            expiresAt: decryptedData.expiresAt,
            scope: decryptedData.scope
        });
        
        return decryptedData;
    } catch (error) {
        log.error('Error loading token data:', {
            error: error instanceof Error ? error.message : 'Unknown error',
            type: error instanceof Error ? error.constructor.name : typeof error,
            stack: error instanceof Error ? error.stack : undefined
        });
        return null;
    }
}
