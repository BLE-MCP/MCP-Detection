import { describe, it, expect, beforeEach, beforeAll, afterAll } from '@jest/globals';

// Mock the imports
jest.mock('../../src/config.js');
jest.mock('../../src/auth.js');
jest.mock('../../src/dbx-api.js');

// Now import the ResourcePromptHandler
import { ResourcePromptHandler } from '../../src/prompt-handlers/resource-prompt-handler.js';
import { fileDetailPrompt, fileComparePrompt } from '../../src/prompt-definitions/file-review-prompt.js';
import { setupTestLogger, restoreConsole } from '../utils/test-logger.js';
import { testResultsTracker } from '../utils/test-results-tracker.js';
import { createMockContent, createMockMetadata, createMockFilesList } from './test-helpers.js';

// Import our mocks after the jest.mock calls
import { config } from '../mocks/config.js';
import * as auth from '../mocks/auth.js';
import * as dbxApi from '../mocks/dbx-api.js';

// Set up the mock implementations
const configMock = jest.requireMock('../../src/config.js');
configMock.config = config;

const authMock = jest.requireMock('../../src/auth.js');
authMock.getAccessToken = auth.getAccessToken;
authMock.getRefreshToken = auth.getRefreshToken;
authMock.refreshAccessToken = auth.refreshAccessToken;
authMock.exchangeCodeForTokens = auth.exchangeCodeForTokens;
authMock.generateAuthUrl = auth.generateAuthUrl;
authMock.saveTokens = auth.saveTokens;
authMock.loadTokens = auth.loadTokens;

const dbxApiMock = jest.requireMock('../../src/dbx-api.js');
dbxApiMock.downloadFile = dbxApi.downloadFile;
dbxApiMock.uploadFile = dbxApi.uploadFile;
dbxApiMock.listFiles = dbxApi.listFiles;
dbxApiMock.getFileMetadata = dbxApi.getFileMetadata;
dbxApiMock.createFolder = dbxApi.createFolder;
dbxApiMock.deleteItem = dbxApi.deleteItem;
dbxApiMock.searchFiles = dbxApi.searchFiles;
dbxApiMock.getAccountInfo = dbxApi.getAccountInfo;

describe('ResourcePromptHandler', () => {
  const FILE_NAME = 'resource/prompt-handler.test.ts';
  let promptHandler: ResourcePromptHandler;

  beforeAll(() => {
    // Set up the custom logger to suppress stack traces
    setupTestLogger();
  });

  afterAll(() => {
    // Restore original console methods
    restoreConsole();
  });

  beforeEach(() => {
    promptHandler = new ResourcePromptHandler();
    jest.clearAllMocks();
    
    const testName = expect.getState().currentTestName;
    if (testName) {
      testResultsTracker.registerTest(testName, FILE_NAME);
    }
  });

  it('should process prompts with resource references', async () => {
    const mockContent = createMockContent('file content');
    const mockMetadata = createMockMetadata({
      size: 100,
      client_modified: '2025-03-04T00:00:00Z'
    });

    dbxApi.downloadFile.mockResolvedValue(mockContent);
    dbxApi.getFileMetadata.mockResolvedValue(mockMetadata);

    const result = await promptHandler.processPrompt(fileDetailPrompt, {
      path: '/test.txt',
      analysis: 'Test file analysis'
    });

    expect(result.resources?.attachments?.[0].content).toBeDefined();
    
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      path: '/test.txt',
      hasAttachments: (result.resources?.attachments?.length ?? 0) > 0
    });
    testResultsTracker.markTestPassed(expect.getState().currentTestName!, FILE_NAME);
  });

  it('should handle file comparison prompts', async () => {
    const mockContent1 = createMockContent('content1');
    const mockContent2 = createMockContent('content2');
    const mockMetadata = createMockMetadata({
      size: 100,
      client_modified: '2025-03-04T00:00:00Z'
    });

    dbxApi.downloadFile
      .mockResolvedValueOnce(mockContent1)
      .mockResolvedValueOnce(mockContent2);
    dbxApi.getFileMetadata.mockResolvedValue(mockMetadata);

    const result = await promptHandler.processFileComparison('/file1.txt', '/file2.txt');
    expect(result.resources?.inline).toHaveLength(2);
    
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      file1: '/file1.txt',
      file2: '/file2.txt',
      inlineResourceCount: result.resources?.inline?.length
    });
    testResultsTracker.markTestPassed(expect.getState().currentTestName!, FILE_NAME);
  });

  it('should validate required arguments', async () => {
    await expect(promptHandler.processPrompt(fileDetailPrompt, {}))
      .rejects
      .toThrow('Missing required argument: path');
    
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      validationError: 'Missing required argument: path'
    });
    testResultsTracker.markTestPassed(expect.getState().currentTestName!, FILE_NAME);
  });

  it('should handle folder review with file type filtering', async () => {
    const mockFiles = createMockFilesList([
      { '.tag': 'file', name: 'test.ts', path_display: '/test.ts' },
      { '.tag': 'file', name: 'test.js', path_display: '/test.js' },
      { '.tag': 'file', name: 'test.txt', path_display: '/test.txt' }
    ]);

    dbxApi.listFiles.mockResolvedValue(mockFiles);

    const result = await promptHandler.processFolderReview('/folder', 'ts,js');
    expect(result.resources?.collections).toBeDefined();
    
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      folder: '/folder',
      fileTypes: 'ts,js',
      hasCollections: result.resources?.collections !== undefined
    });
    testResultsTracker.markTestPassed(expect.getState().currentTestName!, FILE_NAME);
  });
});
