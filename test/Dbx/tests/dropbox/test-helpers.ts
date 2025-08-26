import path from 'node:path';
import { spawn } from 'node:child_process';

// Get root directory
const rootDir = process.cwd();

// Configuration
export const SERVER_COMMAND = 'node';
export const SERVER_ARGS = [path.join(rootDir, 'build', 'src', 'index.js')];
export const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
export const TEST_FOLDER_NAME = `mcp-test-${timestamp}`;
export const TEST_FILE_NAME = `test-file-${timestamp}.txt`;
export const TEST_FILE_CONTENT = 'Hello, this is a test file created by the Dropbox MCP test suite.';
export const TOKEN_STORE_PATH = path.join(rootDir, '.tokens.json');

// Helper functions
export function encodeBase64(text: string): string {
  return Buffer.from(text).toString('base64');
}

export function decodeBase64(base64: string): string {
  return Buffer.from(base64, 'base64').toString('utf-8');
}

export async function sendMcpRequest(request: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const serverProcess = spawn(SERVER_COMMAND, SERVER_ARGS, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env }
    });

    let responseData = '';
    let errorData = '';

    serverProcess.stdout.on('data', (data) => {
      responseData += data.toString();
    });

    serverProcess.stderr.on('data', (data) => {
      errorData += data.toString();
    });

    serverProcess.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Server process exited with code ${code}: ${errorData}`));
        return;
      }

      try {
        const lines = responseData.trim().split('\n');
        const lastLine = lines[lines.length - 1];
        const response = JSON.parse(lastLine);
        resolve(response);
      } catch (error) {
        reject(error);
      }
    });

    serverProcess.stdin.write(JSON.stringify(request) + '\n');
    serverProcess.stdin.end();
  });
}

export async function callMcpTool(toolName: string, args: any = {}): Promise<any> {
  const request = {
    jsonrpc: '2.0',
    id: Date.now().toString(),
    method: 'tools/call',
    params: {
      name: toolName,
      arguments: args
    }
  };

  const response = await sendMcpRequest(request);
  if (response.error) {
    throw new Error(`MCP error: ${JSON.stringify(response.error)}`);
  }
  return response.result;
}
