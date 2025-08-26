// Mock config.js to avoid import.meta.url issues in tests
import path from 'path';
import winston from 'winston';

// Create a mock logger that doesn't actually write to files
const mockLogger = winston.createLogger({
    level: 'info',
    format: winston.format.simple(),
    transports: [
        new winston.transports.Console({
            format: winston.format.simple(),
            silent: true // Don't actually log anything in tests
        })
    ]
});

// Mock the full config object with all properties used in the codebase
export const config = {
    dropbox: {
        appKey: 'test-app-key',
        appSecret: 'test-app-secret',
        redirectUri: 'http://localhost:3000/auth/callback',
        accessToken: 'test-access-token'
    },
    security: {
        tokenEncryptionKey: 'test-encryption-key',
        corsAllowedOrigins: ['http://localhost:3000']
    },
    tokens: {
        maxRetries: 3,
        retryDelay: 1000,
        thresholdMinutes: 5
    },
    paths: {
        tokenStore: path.join(process.cwd(), '.test-tokens.json'),
        logs: path.join(process.cwd(), 'test-logs')
    },
    safety: {
        recycleBinPath: '/.recycle_bin',
        maxDeletesPerDay: 100,
        retentionDays: 30,
        allowedPaths: ['/'],
        blockedPaths: ['/.recycle_bin', '/.system']
    },
    logger: mockLogger,
    auditLogger: mockLogger
};

// Export logger separately for convenience
export const log = config.logger;
