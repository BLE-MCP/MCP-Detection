// Mock version of config.js that doesn't use import.meta.url
import dotenv from 'dotenv';
import winston from 'winston';
import path from 'path';
import fs from 'fs';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { decryptData } from './security-utils.js';

// Load environment variables
dotenv.config();

// Required environment variables
const requiredEnvVars = [
    'DROPBOX_APP_KEY',
    'DROPBOX_APP_SECRET',
    'DROPBOX_REDIRECT_URI',
    'TOKEN_ENCRYPTION_KEY'
];

// Function to validate environment variables
export function validateConfig() {
    for (const envVar of requiredEnvVars) {
        if (!process.env[envVar]) {
            throw new McpError(ErrorCode.InvalidParams, `Missing required environment variable: ${envVar}`);
        }
    }
}

// Skip validation during setup
const isSetup = process.argv[1]?.endsWith('setup.js');
if (!isSetup) {
    validateConfig();
}

// Create logs directory if it doesn't exist
// Use a fixed path for tests instead of import.meta.url
const logsDir = path.join(process.cwd(), 'logs');
try {
    fs.mkdirSync(logsDir, { recursive: true });
} catch (error) {
    const fsError = error;
    console.error('Failed to create logs directory:', fsError);
    throw new McpError(ErrorCode.InternalError, `Failed to create logs directory at ${logsDir}: ${fsError.message}`);
}

// Configure Winston logger
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    defaultMeta: { service: 'dropbox-mcp-server' },
    transports: [
        // Error logs
        new winston.transports.File({
            filename: path.join(logsDir, 'error.log'),
            level: 'error',
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        }),
        // Combined logs
        new winston.transports.File({
            filename: path.join(logsDir, 'combined.log'),
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        }),
    ],
});

// Add console transport in development, but only for stderr
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
        stderrLevels: ['error', 'warn', 'info', 'debug'], // Send all logs to stderr
    }));
}

// Configuration object
// Add required environment variables for safety features
const safetyEnvVars = [
    'DROPBOX_RECYCLE_BIN_PATH',
    'DROPBOX_MAX_DELETES_PER_DAY',
    'DROPBOX_RETENTION_DAYS',
    'DROPBOX_ALLOWED_PATHS',
    'DROPBOX_BLOCKED_PATHS'
];

// Validate safety environment variables with defaults
for (const envVar of safetyEnvVars) {
    if (!process.env[envVar]) {
        switch (envVar) {
            case 'DROPBOX_RECYCLE_BIN_PATH':
                process.env[envVar] = '/.recycle_bin';
                break;
            case 'DROPBOX_MAX_DELETES_PER_DAY':
                process.env[envVar] = '100';
                break;
            case 'DROPBOX_RETENTION_DAYS':
                process.env[envVar] = '30';
                break;
            case 'DROPBOX_ALLOWED_PATHS':
                process.env[envVar] = '/';
                break;
            case 'DROPBOX_BLOCKED_PATHS':
                process.env[envVar] = '/.recycle_bin,/.system';
                break;
        }
        logger.warn(`Using default value for ${envVar}: ${process.env[envVar]}`);
    }
}

// Configure audit logging
const auditLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    defaultMeta: { service: 'dropbox-mcp-server-audit' },
    transports: [
        new winston.transports.File({
            filename: path.join(logsDir, 'audit.log'),
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        })
    ],
});

// Parse and decrypt the app secret if it's encrypted
const parseAppSecret = () => {
    const secret = process.env.DROPBOX_APP_SECRET;
    try {
        // Check if the secret is in JSON format (encrypted)
        const parsed = JSON.parse(secret);
        if (parsed.iv && parsed.encryptedData) {
            try {
                return decryptData(parsed);
            } catch (decryptError) {
                console.error('Failed to decrypt app secret:', decryptError);
                throw new McpError(ErrorCode.InvalidParams, 'Failed to decrypt DROPBOX_APP_SECRET. You may need to run the setup script again.');
            }
        }
    } catch (e) {
        // If parsing fails, assume it's a plain secret
    }
    return secret;
};

export const config = {
    dropbox: {
        appKey: process.env.DROPBOX_APP_KEY,
        appSecret: parseAppSecret(),
        redirectUri: process.env.DROPBOX_REDIRECT_URI,
        accessToken: process.env.DROPBOX_ACCESS_TOKEN,
    },
    security: {
        tokenEncryptionKey: process.env.TOKEN_ENCRYPTION_KEY,
        corsAllowedOrigins: process.env.CORS_ALLOWED_ORIGINS?.split(',') || [],
    },
    tokens: {
        maxRetries: parseInt(process.env.MAX_TOKEN_REFRESH_RETRIES || '3', 10),
        retryDelay: parseInt(process.env.TOKEN_REFRESH_RETRY_DELAY_MS || '1000', 10),
        thresholdMinutes: parseInt(process.env.TOKEN_REFRESH_THRESHOLD_MINUTES || '5', 10),
    },
    paths: {
        tokenStore: path.join(process.cwd(), '.tokens.json'),
        logs: logsDir,
    },
    safety: {
        recycleBinPath: process.env.DROPBOX_RECYCLE_BIN_PATH,
        maxDeletesPerDay: parseInt(process.env.DROPBOX_MAX_DELETES_PER_DAY, 10),
        retentionDays: parseInt(process.env.DROPBOX_RETENTION_DAYS, 10),
        allowedPaths: process.env.DROPBOX_ALLOWED_PATHS.split(','),
        blockedPaths: process.env.DROPBOX_BLOCKED_PATHS.split(','),
    },
    logger: logger,
    auditLogger: auditLogger,
};

// Export logger separately for convenience
export const log = config.logger;
