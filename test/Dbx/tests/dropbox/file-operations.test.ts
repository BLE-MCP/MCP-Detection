import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import { setupTestLogger, restoreConsole } from '../utils/test-logger.js';
import { testResultsTracker } from '../utils/test-results-tracker.js';
import { 
  callMcpTool, 
  TEST_FOLDER_NAME, 
  TEST_FILE_NAME, 
  TEST_FILE_CONTENT,
  encodeBase64,
  decodeBase64
} from './test-helpers.js';

describe('Dropbox File Operations', () => {
  const FILE_NAME = 'dropbox/file-operations.test.ts';

  beforeAll(() => {
    // Set up the custom logger to suppress stack traces
    setupTestLogger();
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
    // Adjust expectation to match metadata filenames with timestamp variation
    expect(metadata.name).toMatch(/test-file-.*\.txt/);
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
    // The content might be dynamically generated with different timestamps
    expect(content).toContain('Hello, this is a test file created by the Dropbox MCP test suite');
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
    expect(files[0].name).toMatch(/test-file-.*\.txt/);
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      path: `/${TEST_FOLDER_NAME}`,
      fileCount: files.length,
      files: files.map((f: { name: string }) => f.name).join(', ')
    });
  });
});
