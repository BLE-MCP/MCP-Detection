import { config } from 'dotenv';
import { fileURLToPath } from 'url';
import * as path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
config({ path: path.join(__dirname, '..', '.env') });

console.log('Environment variables:', {
  DROPBOX_APP_KEY: process.env.DROPBOX_APP_KEY,
  DROPBOX_APP_SECRET: process.env.DROPBOX_APP_SECRET,
  DROPBOX_REDIRECT_URI: process.env.DROPBOX_REDIRECT_URI
});

import * as auth from './auth.js';

export function generateAuthUrl(): string {
    const { url, codeVerifier } = auth.generateAuthUrl();
    console.log('\nAuthorization URL:', url);
    console.log('\nPlease visit this URL to authorize the application.');
    // Store code verifier for later use in token exchange
    process.env.TEMP_CODE_VERIFIER = codeVerifier;
    return url;
}
