#!/usr/bin/env node
import { encryptData } from './security-utils.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOKEN_STORE_PATH = path.join(process.cwd(), '.tokens.json');

const accessToken = process.env.DROPBOX_ACCESS_TOKEN;
if (!accessToken) {
    console.error('DROPBOX_ACCESS_TOKEN not found in environment variables');
    process.exit(1);
}

// Split the long-lived access token into two parts for demo purposes
// In a real OAuth flow, these would be separate tokens from the authorization server
const tokenData = {
    accessToken: accessToken,
    refreshToken: accessToken.slice(0, accessToken.length / 2), // Use first half as refresh token
    expiresAt: Date.now() + (4 * 60 * 60 * 1000), // 4 hours from now
    scope: ['files.metadata.read', 'files.content.read', 'files.content.write', 'sharing.write', 'account_info.read']
};

const encryptedData = encryptData(tokenData);
fs.writeFileSync(TOKEN_STORE_PATH, JSON.stringify(encryptedData, null, 2));
console.log('Created encrypted .tokens.json file at:', TOKEN_STORE_PATH);
