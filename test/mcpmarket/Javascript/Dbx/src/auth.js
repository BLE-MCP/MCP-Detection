"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var _a;
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateAuthUrl = generateAuthUrl;
exports.exchangeCodeForTokens = exchangeCodeForTokens;
exports.refreshAccessToken = refreshAccessToken;
exports.getValidAccessToken = getValidAccessToken;
exports.loadTokenData = loadTokenData;
exports.saveTokenData = saveTokenData;
var fs = require("fs");
var path = require("path");
var axios_1 = require("axios");
var types_js_1 = require("@modelcontextprotocol/sdk/types.js");
var crypto_1 = require("crypto");
var dotenv_1 = require("dotenv");
var security_utils_js_1 = require("./security-utils.js");
var config_js_1 = require("./config.js");
dotenv_1.default.config();
var TOKEN_STORE_PATH = process.env.TOKEN_STORE_PATH || path.join(process.cwd(), '.tokens.json');
// Use config values which handle encrypted secrets
var validatedAppKey = config_js_1.config.dropbox.appKey;
var validatedAppSecret = config_js_1.config.dropbox.appSecret;
var validatedRedirectUri = config_js_1.config.dropbox.redirectUri;
// Skip validation during setup
var isSetup = (_a = process.argv[1]) === null || _a === void 0 ? void 0 : _a.endsWith('setup.js');
if (!isSetup && (!validatedAppKey || !validatedAppSecret || !validatedRedirectUri)) {
    throw new types_js_1.McpError(types_js_1.ErrorCode.InvalidParams, 'Missing required configuration. Please ensure Dropbox configuration is properly set.');
}
var tokenData = process.env.DROPBOX_ACCESS_TOKEN ? {
    accessToken: process.env.DROPBOX_ACCESS_TOKEN,
    refreshToken: '',
    expiresAt: Date.now() + (4 * 60 * 60 * 1000), // 4 hours from now
    scope: ['files.content.read', 'files.content.write']
} : loadTokenData();
// Error messages map for better error handling
var ERROR_MESSAGES = {
    TOKEN_EXPIRED: 'Access token has expired. Attempting to refresh...',
    REFRESH_FAILED: 'Failed to refresh access token after multiple attempts.',
    INVALID_GRANT: 'The refresh token is invalid or has been revoked. Please re-authenticate.',
    NETWORK_ERROR: 'Network error occurred while refreshing token. Will retry...',
    RATE_LIMIT: 'Rate limit exceeded. Please try again later.',
    SERVER_ERROR: 'Dropbox server error occurred. Will retry...'
};
function generatePKCE() {
    var codeVerifier = (0, crypto_1.randomBytes)(32).toString('base64url');
    var codeChallenge = (0, crypto_1.createHash)('sha256')
        .update(codeVerifier)
        .digest('base64url');
    return { codeVerifier: codeVerifier, codeChallenge: codeChallenge };
}
function loadTokenData() {
    var _a;
    try {
        console.error('Loading tokens from:', TOKEN_STORE_PATH);
        if (fs.existsSync(TOKEN_STORE_PATH)) {
            console.error('Token file exists');
            var rawData = fs.readFileSync(TOKEN_STORE_PATH, 'utf-8');
            console.error('Raw token data:', rawData.substring(0, 50) + '...');
            var encryptedData = JSON.parse(rawData);
            console.error('Parsed encrypted data:', {
                hasIv: !!encryptedData.iv,
                encryptedDataLength: (_a = encryptedData.encryptedData) === null || _a === void 0 ? void 0 : _a.length
            });
            var decrypted = (0, security_utils_js_1.decryptData)(encryptedData);
            console.error('Token data decrypted successfully');
            return decrypted;
        }
        else {
            console.error('Token file not found');
        }
    }
    catch (error) {
        console.error('Error loading token data:', error);
        console.error('Current working directory:', process.cwd());
        throw new types_js_1.McpError(types_js_1.ErrorCode.InternalError, 'Failed to load token data. The token file may be corrupted or encryption key may be invalid.');
    }
    return null;
}
function saveTokenData(data) {
    try {
        var encryptedData = (0, security_utils_js_1.encryptData)(data);
        fs.writeFileSync(TOKEN_STORE_PATH, JSON.stringify(encryptedData, null, 2));
        tokenData = data;
    }
    catch (error) {
        console.error('Error saving token data:', error);
        throw new types_js_1.McpError(types_js_1.ErrorCode.InternalError, 'Failed to save token data. Please check if the encryption key is properly set.');
    }
}
function generateAuthUrl() {
    var _a;
    var _b = generatePKCE(), codeVerifier = _b.codeVerifier, codeChallenge = _b.codeChallenge;
    var authUrl = new URL('https://www.dropbox.com/oauth2/authorize');
    // During setup, use process.env directly
    var isSetup = (_a = process.argv[1]) === null || _a === void 0 ? void 0 : _a.endsWith('setup.js');
    var clientId = isSetup ? process.env.DROPBOX_APP_KEY : validatedAppKey;
    authUrl.searchParams.append('client_id', clientId);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('redirect_uri', 'http://localhost');
    authUrl.searchParams.append('code_challenge', codeChallenge);
    authUrl.searchParams.append('code_challenge_method', 'S256');
    authUrl.searchParams.append('token_access_type', 'offline');
    return {
        url: authUrl.toString(),
        codeVerifier: codeVerifier
    };
}
function exchangeCodeForTokens(code, codeVerifier) {
    return __awaiter(this, void 0, void 0, function () {
        var isSetup_1, clientId, clientSecret, params, response, tokenData_1, error_1, errorMessage;
        var _a, _b, _c, _d;
        return __generator(this, function (_e) {
            switch (_e.label) {
                case 0:
                    _e.trys.push([0, 2, , 3]);
                    isSetup_1 = (_a = process.argv[1]) === null || _a === void 0 ? void 0 : _a.endsWith('setup.js');
                    clientId = isSetup_1 ? process.env.DROPBOX_APP_KEY : validatedAppKey;
                    clientSecret = isSetup_1 ? process.env.DROPBOX_APP_SECRET : validatedAppSecret;
                    params = new URLSearchParams({
                        code: code,
                        grant_type: 'authorization_code',
                        client_id: clientId,
                        client_secret: clientSecret,
                        redirect_uri: 'http://localhost',
                        code_verifier: codeVerifier
                    });
                    return [4 /*yield*/, axios_1.default.post('https://api.dropboxapi.com/oauth2/token', params.toString(), {
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                            },
                        })];
                case 1:
                    response = _e.sent();
                    tokenData_1 = {
                        accessToken: response.data.access_token,
                        refreshToken: response.data.refresh_token,
                        expiresAt: Date.now() + (response.data.expires_in * 1000),
                        scope: response.data.scope.split(' '),
                        codeVerifier: codeVerifier // Store code verifier for token refresh
                    };
                    saveTokenData(tokenData_1);
                    return [2 /*return*/, tokenData_1];
                case 2:
                    error_1 = _e.sent();
                    if (axios_1.default.isAxiosError(error_1)) {
                        console.error('Error exchanging code for tokens:', (_b = error_1.response) === null || _b === void 0 ? void 0 : _b.data);
                        throw new types_js_1.McpError(types_js_1.ErrorCode.InternalError, "Failed to exchange authorization code for tokens: ".concat(((_d = (_c = error_1.response) === null || _c === void 0 ? void 0 : _c.data) === null || _d === void 0 ? void 0 : _d.error_description) || error_1.message));
                    }
                    errorMessage = error_1 instanceof Error ? error_1.message : 'Unknown error occurred';
                    console.error('Error exchanging code for tokens:', errorMessage);
                    throw new types_js_1.McpError(types_js_1.ErrorCode.InternalError, "Failed to exchange authorization code for tokens: ".concat(errorMessage));
                case 3: return [2 /*return*/];
            }
        });
    });
}
function refreshAccessToken() {
    return __awaiter(this, void 0, void 0, function () {
        var now, searchParams, response, newTokenData, error_2, axiosError, statusCode, errorData, errorMessage;
        var _a, _b, _c;
        return __generator(this, function (_d) {
            switch (_d.label) {
                case 0:
                    if (!(tokenData === null || tokenData === void 0 ? void 0 : tokenData.refreshToken)) {
                        throw new types_js_1.McpError(types_js_1.ErrorCode.InvalidRequest, 'No refresh token available. Please authenticate first by visiting the authorization URL.');
                    }
                    now = Date.now();
                    if (tokenData.lastRefreshAttempt &&
                        (now - tokenData.lastRefreshAttempt) < security_utils_js_1.TOKEN_REFRESH_CONFIG.retryDelay) {
                        throw new security_utils_js_1.TokenRefreshError('Too many refresh attempts. Please wait before trying again.', 'RATE_LIMIT', true);
                    }
                    // Update refresh attempt counters
                    tokenData.lastRefreshAttempt = now;
                    tokenData.refreshAttempts = (tokenData.refreshAttempts || 0) + 1;
                    if (tokenData.refreshAttempts > security_utils_js_1.TOKEN_REFRESH_CONFIG.maxRetries) {
                        throw new security_utils_js_1.TokenRefreshError(ERROR_MESSAGES.REFRESH_FAILED, 'MAX_RETRIES_EXCEEDED', false);
                    }
                    _d.label = 1;
                case 1:
                    _d.trys.push([1, 3, , 4]);
                    searchParams = new URLSearchParams({
                        refresh_token: tokenData.refreshToken,
                        grant_type: 'refresh_token',
                        client_id: validatedAppKey,
                        client_secret: validatedAppSecret
                    });
                    return [4 /*yield*/, axios_1.default.post('https://api.dropboxapi.com/oauth2/token', searchParams.toString(), {
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                            },
                            timeout: 10000 // 10 second timeout
                        })];
                case 2:
                    response = _d.sent();
                    newTokenData = __assign(__assign({}, tokenData), { accessToken: response.data.access_token, expiresAt: Date.now() + (response.data.expires_in * 1000), refreshAttempts: 0, lastRefreshAttempt: undefined });
                    saveTokenData(newTokenData);
                    return [2 /*return*/, newTokenData.accessToken];
                case 3:
                    error_2 = _d.sent();
                    if (axios_1.default.isAxiosError(error_2)) {
                        axiosError = error_2;
                        statusCode = (_b = (_a = axiosError.response) === null || _a === void 0 ? void 0 : _a.status) !== null && _b !== void 0 ? _b : 0;
                        errorData = (_c = axiosError.response) === null || _c === void 0 ? void 0 : _c.data;
                        // Handle specific error cases
                        if (statusCode === 401 && (errorData === null || errorData === void 0 ? void 0 : errorData.error) === 'invalid_grant') {
                            throw new security_utils_js_1.TokenRefreshError(ERROR_MESSAGES.INVALID_GRANT, 'INVALID_GRANT', false);
                        }
                        else if (statusCode === 429) {
                            throw new security_utils_js_1.TokenRefreshError(ERROR_MESSAGES.RATE_LIMIT, 'RATE_LIMIT', true);
                        }
                        else if (statusCode >= 500) {
                            throw new security_utils_js_1.TokenRefreshError(ERROR_MESSAGES.SERVER_ERROR, 'SERVER_ERROR', true);
                        }
                        else if (!axiosError.response) {
                            throw new security_utils_js_1.TokenRefreshError(ERROR_MESSAGES.NETWORK_ERROR, 'NETWORK_ERROR', true);
                        }
                    }
                    errorMessage = error_2 instanceof Error ? error_2.message : 'Unknown error occurred';
                    throw new security_utils_js_1.TokenRefreshError("Token refresh failed: ".concat(errorMessage), 'UNKNOWN_ERROR', true);
                case 4: return [2 /*return*/];
            }
        });
    });
}
function getValidAccessToken() {
    return __awaiter(this, void 0, void 0, function () {
        var refreshThreshold, retryCount, error_3, errorMessage;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    if (!tokenData) {
                        throw new types_js_1.McpError(types_js_1.ErrorCode.InvalidRequest, 'No token data available. Please authenticate first by visiting the authorization URL.');
                    }
                    refreshThreshold = security_utils_js_1.TOKEN_REFRESH_CONFIG.thresholdMinutes * 60 * 1000;
                    if (!(Date.now() >= (tokenData.expiresAt - refreshThreshold))) return [3 /*break*/, 9];
                    console.log(ERROR_MESSAGES.TOKEN_EXPIRED);
                    retryCount = 0;
                    _a.label = 1;
                case 1:
                    if (!(retryCount < security_utils_js_1.TOKEN_REFRESH_CONFIG.maxRetries)) return [3 /*break*/, 8];
                    _a.label = 2;
                case 2:
                    _a.trys.push([2, 4, , 7]);
                    return [4 /*yield*/, refreshAccessToken()];
                case 3: return [2 /*return*/, _a.sent()];
                case 4:
                    error_3 = _a.sent();
                    if (!(error_3 instanceof security_utils_js_1.TokenRefreshError)) return [3 /*break*/, 6];
                    if (!error_3.retryable) {
                        throw new types_js_1.McpError(types_js_1.ErrorCode.InvalidRequest, error_3.message);
                    }
                    retryCount++;
                    if (!(retryCount < security_utils_js_1.TOKEN_REFRESH_CONFIG.maxRetries)) return [3 /*break*/, 6];
                    return [4 /*yield*/, new Promise(function (resolve) {
                            return setTimeout(resolve, security_utils_js_1.TOKEN_REFRESH_CONFIG.retryDelay);
                        })];
                case 5:
                    _a.sent();
                    return [3 /*break*/, 1];
                case 6:
                    errorMessage = error_3 instanceof Error ? error_3.message : 'Unknown error occurred';
                    throw new types_js_1.McpError(types_js_1.ErrorCode.InvalidRequest, "Token refresh failed after ".concat(retryCount, " attempts: ").concat(errorMessage));
                case 7: return [3 /*break*/, 1];
                case 8: throw new types_js_1.McpError(types_js_1.ErrorCode.InvalidRequest, ERROR_MESSAGES.REFRESH_FAILED);
                case 9: return [2 /*return*/, tokenData.accessToken];
            }
        });
    });
}
