import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import * as dotenv from 'dotenv';

dotenv.config();

function getValidatedKey() {
    const key = process.env.TOKEN_ENCRYPTION_KEY || '';
    if (!key) {
        throw new McpError(
            ErrorCode.InvalidParams,
            'TOKEN_ENCRYPTION_KEY must be set in environment variables'
        );
    }

    try {
        // First try to decode the key from base64
        const decodedKey = Buffer.from(key, 'base64');
        
        // If the decoded key is too short, try using the original key
        if (decodedKey.length < 32) {
            // Try using the original key directly
            const directKey = Buffer.from(key);
            if (directKey.length >= 32) {
                return directKey.slice(0, 32);
            }
            throw new McpError(
                ErrorCode.InvalidParams,
                'TOKEN_ENCRYPTION_KEY must be at least 32 bytes when decoded'
            );
        }

        return decodedKey.slice(0, 32);
    } catch (error) {
        if (error instanceof McpError) {
            throw error;
        }
        throw new McpError(
            ErrorCode.InvalidParams,
            'TOKEN_ENCRYPTION_KEY must be a valid base64 encoded string or at least 32 bytes long'
        );
    }
}

export interface EncryptedTokenData {
    iv: string;
    encryptedData: string;
    authTag: string;
}

const ALGORITHM = 'aes-256-gcm';

export function encryptData(data: any): EncryptedTokenData {
    try {
        // Generate a random initialization vector
        const iv = randomBytes(16);
        
        // Create cipher with key and iv
        const cipher = createCipheriv(
            ALGORITHM, 
            getValidatedKey().slice(0, 32), 
            iv
        );
        
        // Convert data to JSON string
        const jsonStr = JSON.stringify(data);
        
        // Encrypt the data
        let encryptedData = cipher.update(jsonStr, 'utf8', 'base64');
        encryptedData += cipher.final('base64');
        
        // Get the auth tag
        const authTag = cipher.getAuthTag();
        
        return {
            iv: iv.toString('base64'),
            encryptedData: encryptedData,
            authTag: authTag.toString('base64')
        };
    } catch (error) {
        console.error('Encryption error:', error);
        throw new McpError(
            ErrorCode.InternalError,
            'Failed to encrypt token data'
        );
    }
}

export function decryptData(encryptedData: EncryptedTokenData): any {
    try {
        const iv = Buffer.from(encryptedData.iv, 'base64');
        const authTag = Buffer.from(encryptedData.authTag, 'base64');
        
        console.log('Decrypting data:', {
            ivLength: iv.length,
            authTagLength: authTag.length,
            encryptedDataLength: encryptedData.encryptedData.length
        });
        
        // Create decipher
        const decipher = createDecipheriv(
            ALGORITHM,
            getValidatedKey().slice(0, 32),
            iv
        );
        
        // Set auth tag
        decipher.setAuthTag(authTag);
        
        // Decrypt the data
        let decrypted = decipher.update(encryptedData.encryptedData, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        
        if (!decrypted) {
            throw new Error('Decryption produced empty result');
        }
        
        const parsedData = JSON.parse(decrypted);
        console.log('Decrypted data:', {
            hasAccessToken: !!parsedData?.accessToken,
            hasRefreshToken: !!parsedData?.refreshToken,
            accessTokenLength: parsedData?.accessToken?.length,
            refreshTokenLength: parsedData?.refreshToken?.length,
            expiresAt: parsedData?.expiresAt,
            scope: parsedData?.scope,
            hasCodeVerifier: !!parsedData?.codeVerifier,
            keys: Object.keys(parsedData)
        });
        
        return parsedData;
    } catch (error) {
        console.error('Decryption error:', {
            error: error instanceof Error ? error.message : 'Unknown error',
            type: error instanceof Error ? error.constructor.name : typeof error,
            stack: error instanceof Error ? error.stack : undefined
        });
        throw new McpError(
            ErrorCode.InternalError,
            'Failed to decrypt token data. The data may be corrupted or the encryption key may be invalid.'
        );
    }
}

export function validateCorsOrigin(origin: string): boolean {
    const allowedOrigins = process.env.CORS_ALLOWED_ORIGINS?.split(',') || [];
    return allowedOrigins.includes(origin);
}

export class TokenRefreshError extends Error {
    constructor(
        message: string,
        public readonly code: string,
        public readonly retryable: boolean = true
    ) {
        super(message);
        this.name = 'TokenRefreshError';
    }
}

export const TOKEN_REFRESH_CONFIG = {
    maxRetries: parseInt(process.env.MAX_TOKEN_REFRESH_RETRIES || '3', 10),
    retryDelay: parseInt(process.env.TOKEN_REFRESH_RETRY_DELAY_MS || '1000', 10),
    thresholdMinutes: parseInt(process.env.TOKEN_REFRESH_THRESHOLD_MINUTES || '5', 10)
};
