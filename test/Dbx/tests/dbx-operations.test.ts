import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { decryptData, encryptData } from '../src/security-utils.js';
import dotenv from 'dotenv';
import { setupTestLogger, restoreConsole } from './utils/test-logger.js';
import { testResultsTracker } from './utils/test-results-tracker.js';

// Load environment variables
dotenv.config();

// Get root directory
const rootDir = process.cwd();

// Configuration
const SERVER_COMMAND = 'node';
const SERVER_ARGS = [path.join(rootDir, 'build', 'src', 'index.js')];
const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
const TEST_FOLDER_NAME = `mcp-test-${timestamp}`;
const TEST_FILE_NAME = `test-file-${timestamp}.txt`;
const TEST_FILE_CONTENT = 'Hello, this is a test file created by the Dropbox MCP test suite.';
const TOKEN_STORE_PATH = path.join(rootDir, '.tokens.json');

// Helper functions
function encodeBase64(text: string): string {
  return Buffer.from(text).toString('base64');
}

function decodeBase64(base64: string): string {
  return Buffer.from(base64, 'base64').toString('utf-8');
}

async function sendMcpRequest(request: any): Promise<any> {
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

async function callMcpTool(toolName: string, args: any = {}): Promise<any> {
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

describe('Dropbox MCP Server', () => {
  const FILE_NAME = 'dbx-operations.test.ts';

  beforeAll(() => {
    // Set up the custom logger to suppress stack traces
    setupTestLogger();
    
    // Reset the test results tracker
    testResultsTracker.reset();
    
    // Verify token store exists
    if (!fs.existsSync(TOKEN_STORE_PATH)) {
      throw new Error('Token store not found. Please complete the authentication setup first.');
    }

    // Verify token data
    const tokenData = JSON.parse(fs.readFileSync(TOKEN_STORE_PATH, 'utf-8'));
    const decrypted = decryptData(tokenData);
    if (!decrypted.accessToken || !decrypted.refreshToken) {
      throw new Error('Invalid token data');
    }
  });

  afterAll(async () => {
    // Clean up test folder
    try {
      await callMcpTool('delete_item', {
        path: `/${TEST_FOLDER_NAME}`
      });
      console.log('Cleaned up test folder in Dropbox');
    } catch (error) {
      console.error('Failed to clean up test folder:', error);
    }
    
    // Print test summary
    testResultsTracker.printSummary(timestamp, TEST_FOLDER_NAME);
    
    // Restore original console methods
    restoreConsole();
  });

  beforeEach(() => {
    const testName = expect.getState().currentTestName;
    if (testName) {
      testResultsTracker.registerTest(testName, FILE_NAME);
    }
  });

  afterEach(() => {
    const testName = expect.getState().currentTestName;
    if (testName) {
      const isPassed = !expect.getState().currentTestName?.includes('failed');
      if (isPassed) {
        testResultsTracker.markTestPassed(testName, FILE_NAME);
      }
    }
  });

  it('should get account information', async () => {
    const response = await callMcpTool('get_account_info');
    const accountInfo = JSON.parse(response.content[0].text);
    expect(accountInfo.account_id).toBeDefined();
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      accountId: accountInfo.account_id,
      name: accountInfo.name?.display_name,
      email: accountInfo.email,
      accountType: accountInfo.account_type
    });
  });

  it('should create a folder', async () => {
    const response = await callMcpTool('create_folder', { path: `/${TEST_FOLDER_NAME}` });
    expect(response).toBeDefined();
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      folderName: TEST_FOLDER_NAME,
      path: `/${TEST_FOLDER_NAME}`
    });
  });

  it('should upload a file', async () => {
    const encodedContent = encodeBase64(TEST_FILE_CONTENT);
    const response = await callMcpTool('upload_file', {
      path: `/${TEST_FOLDER_NAME}/${TEST_FILE_NAME}`,
      content: encodedContent
    });
    expect(response).toBeDefined();
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      fileName: TEST_FILE_NAME,
      path: `/${TEST_FOLDER_NAME}/${TEST_FILE_NAME}`,
      contentSize: TEST_FILE_CONTENT.length
    });
  });

  it('should get file metadata', async () => {
    const response = await callMcpTool('get_file_metadata', {
      path: `/${TEST_FOLDER_NAME}/${TEST_FILE_NAME}`
    });
    const metadata = JSON.parse(response.content[0].text);
    expect(metadata.name).toBe(TEST_FILE_NAME);
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      name: metadata.name,
      path: metadata.path_display,
      size: metadata.size,
      modified: metadata.server_modified
    });
  });

  it('should download a file', async () => {
    const response = await callMcpTool('download_file', {
      path: `/${TEST_FOLDER_NAME}/${TEST_FILE_NAME}`
    });
    const reference = JSON.parse(response.content[0].text);
    const content = decodeBase64(reference.content.content);
    expect(content).toBe(TEST_FILE_CONTENT);
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      path: `/${TEST_FOLDER_NAME}/${TEST_FILE_NAME}`,
      contentSize: content.length,
      contentMatch: content === TEST_FILE_CONTENT
    });
  });

  it('should list files', async () => {
    const response = await callMcpTool('list_files', { path: `/${TEST_FOLDER_NAME}` });
    const files = JSON.parse(response.content[0].text);
    expect(files).toHaveLength(1);
    expect(files[0].name).toBe(TEST_FILE_NAME);
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      path: `/${TEST_FOLDER_NAME}`,
      fileCount: files.length,
      files: files.map((f: { name: string }) => f.name).join(', ')
    });
  });

  it('should search for files', async () => {
    const response = await callMcpTool('search_file_db', {
      query: TEST_FILE_NAME,
      path: '',
      max_results: 10
    });
    const results = JSON.parse(response.content[0].text);
    expect(results).toBeDefined();
    expect(results.matches || results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          metadata: expect.objectContaining({
            name: TEST_FILE_NAME
          })
        })
      ])
    );
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      query: TEST_FILE_NAME,
      totalResults: results.total_results,
      matchCount: results.matches?.length || 0
    });
  });

  it('should handle safe delete with confirmation', async () => {
    const response = await callMcpTool('safe_delete_item', {
      path: `/${TEST_FOLDER_NAME}/${TEST_FILE_NAME}`,
      userId: 'test_user'
    });
    const result = JSON.parse(response.content[0].text);
    expect(result.status).toBe('confirmation_required');
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      path: `/${TEST_FOLDER_NAME}/${TEST_FILE_NAME}`,
      status: result.status,
      message: result.message
    });
  });

  it('should perform safe delete with skip confirmation', async () => {
    const response = await callMcpTool('safe_delete_item', {
      path: `/${TEST_FOLDER_NAME}/${TEST_FILE_NAME}`,
      userId: 'test_user',
      skipConfirmation: true
    });
    const result = JSON.parse(response.content[0].text);
    expect(result.status).toBe('success');
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      path: `/${TEST_FOLDER_NAME}/${TEST_FILE_NAME}`,
      status: result.status,
      operation: result.operation
    });
  });
});
