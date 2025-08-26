"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.TOKEN_REFRESH_CONFIG = exports.TokenRefreshError = void 0;
exports.encryptData = encryptData;
exports.decryptData = decryptData;
exports.validateCorsOrigin = validateCorsOrigin;
var crypto_1 = require("crypto");
var types_js_1 = require("@modelcontextprotocol/sdk/types.js");
var dotenv = require("dotenv");
dotenv.config();
function getValidatedKey() {
    var key = process.env.TOKEN_ENCRYPTION_KEY || '';
    if (!key) {
        throw new types_js_1.McpError(types_js_1.ErrorCode.InvalidParams, 'TOKEN_ENCRYPTION_KEY must be set in environment variables');
    }
    // Convert base64 key to buffer if it's base64 encoded
    var validatedKey = key.includes('+') || key.includes('/') || key.includes('=')
        ? Buffer.from(key, 'base64')
        : Buffer.from(key);
    // Ensure key is 32 bytes
    if (validatedKey.length < 32) {
        throw new types_js_1.McpError(types_js_1.ErrorCode.InvalidParams, 'TOKEN_ENCRYPTION_KEY must be at least 32 bytes when decoded');
    }
    return validatedKey;
}
var ALGORITHM = 'aes-256-gcm';
function encryptData(data) {
    try {
        // Generate a random initialization vector
        var iv = (0, crypto_1.randomBytes)(16);
        // Create cipher with key and iv
        var cipher = (0, crypto_1.createCipheriv)(ALGORITHM, getValidatedKey().slice(0, 32), iv);
        // Convert data to JSON string
        var jsonStr = JSON.stringify(data);
        // Encrypt the data
        var encryptedData = cipher.update(jsonStr, 'utf8', 'base64');
        encryptedData += cipher.final('base64');
        // Get the auth tag
        var authTag = cipher.getAuthTag();
        return {
            iv: iv.toString('base64'),
            encryptedData: encryptedData,
            authTag: authTag.toString('base64')
        };
    }
    catch (error) {
        console.error('Encryption error:', error);
        throw new types_js_1.McpError(types_js_1.ErrorCode.InternalError, 'Failed to encrypt token data');
    }
}
function decryptData(encryptedData) {
    try {
        const iv = Buffer.from(encryptedData.iv, 'base64');
        const authTag = Buffer.from(encryptedData.authTag, 'base64');
        // Create decipher
        var decipher = (0, crypto_1.createDecipheriv)(ALGORITHM, getValidatedKey().slice(0, 32), iv);
        decipher.setAuthTag(authTag);
        // Decrypt the data
        var decryptedData = decipher.update(encryptedData.encryptedData, 'base64', 'utf8');
        decryptedData += decipher.final('utf8');
        if (!decryptedData) {
            throw new Error('Decryption produced empty result');
        }
        return JSON.parse(decryptedData);
    }
    catch (error) {
        console.error('Decryption error:', error);
        throw new types_js_1.McpError(types_js_1.ErrorCode.InternalError, 'Failed to decrypt token data. The data may be corrupted or the encryption key may be invalid.');
    }
}
function validateCorsOrigin(origin) {
    var _a;
    var allowedOrigins = ((_a = process.env.CORS_ALLOWED_ORIGINS) === null || _a === void 0 ? void 0 : _a.split(',')) || [];
    return allowedOrigins.includes(origin) || allowedOrigins.includes('*');
}
var TokenRefreshError = /** @class */ (function (_super) {
    __extends(TokenRefreshError, _super);
    function TokenRefreshError(message, code, retryable) {
        if (retryable === void 0) { retryable = true; }
        var _this = _super.call(this, message) || this;
        _this.code = code;
        _this.retryable = retryable;
        _this.name = 'TokenRefreshError';
        return _this;
    }
    return TokenRefreshError;
}(Error));
exports.TokenRefreshError = TokenRefreshError;
exports.TOKEN_REFRESH_CONFIG = {
    maxRetries: parseInt(process.env.MAX_TOKEN_REFRESH_RETRIES || '3', 10),
    retryDelay: parseInt(process.env.TOKEN_REFRESH_RETRY_DELAY_MS || '1000', 10),
    thresholdMinutes: parseInt(process.env.TOKEN_REFRESH_THRESHOLD_MINUTES || '5', 10)
};
