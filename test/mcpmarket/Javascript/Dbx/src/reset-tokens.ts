import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';
import { encryptData } from './security-utils.js';

// Load environment variables from .env file
dotenv.config();

// This script creates a fresh tokens file with minimal scope
// It's useful when you need to reset tokens after changing encryption keys

(async () => {
  console.log('Creating fresh tokens file with current encryption key...');
  
  // Get the token store path from environment or use default
  const tokenStorePath = process.env.TOKEN_STORE_PATH || path.join(process.cwd(), '.tokens.json');
  
  // First, backup existing tokens file if it exists
  if (fs.existsSync(tokenStorePath)) {
    const backupPath = `${tokenStorePath}.bak.${Date.now()}`;
    fs.copyFileSync(tokenStorePath, backupPath);
    console.log(`Backed up existing tokens file to: ${backupPath}`);
  }
  
  // Create minimal token data
  const minimalTokenData = {
    accessToken: '', // Will be obtained during first use
    refreshToken: '', // Will be obtained during first use
    expiresAt: 0,
    scope: [],
    codeVerifier: ''
  };
  
  // Encrypt the token data using the current encryption key
  const encryptedData = encryptData(minimalTokenData);
  
  // Write the encrypted data to the tokens file
  fs.writeFileSync(tokenStorePath, JSON.stringify(encryptedData, null, 2));
  
  console.log(`✅ Created fresh tokens file at: ${tokenStorePath}`);
  console.log('The next time you run the server, it will prompt for re-authorization');
})().catch(error => {
  console.error('Failed to create tokens file:', error);
  process.exit(1);
});
