import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import dotenv from 'dotenv';
import { config } from './config.js';
import { generateAuthUrl } from './auth.js';
import * as fs from 'fs';
import * as readline from 'readline';
import { exchangeCode } from './exchange-code.js';

dotenv.config();

async function setupDropboxCredentials(): Promise<void> {
    console.log('\nDropbox MCP Server Setup\n');
    
    // Load existing configuration if available
    if (fs.existsSync('.env')) {
        console.log('Found existing .env file. Loading configuration...\n');
        dotenv.config();
    }
    
    // Save configuration
    console.log('\nConfiguration saved to .env file.\n');
    
    console.log('Starting OAuth flow...\n');
    
    // Generate authorization URL with PKCE
    const { url, codeVerifier } = generateAuthUrl();
    
    console.log('\nPlease visit the following URL to authorize the application:');
    console.log(url);
    
    // Create readline interface
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    try {
        // Prompt for authorization code
        const code = await new Promise<string>((resolve) => {
            rl.question('\nEnter the authorization code from the redirect URL: ', (answer) => {
                resolve(answer.trim());
            });
        });
        
        // Exchange code for tokens
        await exchangeCode(code, codeVerifier);
        console.log('\nSetup completed successfully!');
        console.log('You can now start the server with: npm start\n');
    } catch (error) {
        console.error('\nSetup failed:', error);
        throw error;
    } finally {
        rl.close();
    }
}

// Run setup
setupDropboxCredentials().catch(error => {
    console.error('Setup failed:', error);
    process.exit(1);
});
