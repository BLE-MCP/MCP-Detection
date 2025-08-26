import * as auth from './auth.js';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';

export async function exchangeCode(code: string, codeVerifier: string): Promise<void> {
    if (!code) {
        throw new McpError(
            ErrorCode.InvalidParams,
            'Authorization code is required'
        );
    }

    if (!codeVerifier) {
        throw new McpError(
            ErrorCode.InvalidParams,
            'Code verifier is required'
        );
    }

    try {
        await auth.exchangeCodeForTokens(code.trim(), codeVerifier);
        console.log('Successfully authenticated with Dropbox');
    } catch (error) {
        console.error('Failed to exchange code:', error);
        throw error;
    }
}
