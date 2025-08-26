"use strict";
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { encryptData } from './security-utils.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// This script creates a fresh tokens file with minimal scope
// It's useful when you need to reset tokens after changing encryption keys
(async function() {
    console.log('Creating fresh tokens file with current encryption key...');
    
    const tokenStorePath = process.env.TOKEN_STORE_PATH || path.join(process.cwd(), '.tokens.json');
    
    // First, backup existing tokens file if it exists
    if (fs.existsSync(tokenStorePath)) {
        const backupPath = `${tokenStorePath}.bak.${Date.now()}`;
        fs.copyFileSync(tokenStorePath, backupPath);
        console.log(`Backed up existing tokens file to: ${backupPath}`);
    }

    const minimalTokenData = {
        accessToken: '', // Will be obtained during first use
        refreshToken: '', // Will be obtained during first use
        expiresAt: 0,
        scope: [],
        codeVerifier: ''
    };

    const encryptedData = encryptData(minimalTokenData);
    
    // Write the encrypted data to the tokens file
    fs.writeFileSync(tokenStorePath, JSON.stringify(encryptedData, null, 2));
    
    console.log(`✅ Created fresh tokens file at: ${tokenStorePath}`);
    console.log('The next time you run the server, it will prompt for re-authorization');
})().catch(error => {
    console.error('Failed to create tokens file:', error);
    process.exit(1);
});
