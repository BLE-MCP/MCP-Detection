import { describe, it, expect, beforeEach, beforeAll, afterAll } from '@jest/globals';

// Mock the imports
jest.mock('../../src/config.js');
jest.mock('../../src/auth.js');
jest.mock('../../src/dbx-api.js');

// Now import the ResourceHandler
import { ResourceHandler } from '../../src/resource/resource-handler.js';
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

describe('ResourceHandler', () => {
  const FILE_NAME = 'resource/handler.test.ts';
  let resourceHandler: ResourceHandler;

  beforeAll(() => {
    // Set up the custom logger to suppress stack traces
    setupTestLogger();
  });

  afterAll(() => {
    // Restore original console methods
    restoreConsole();
  });

  beforeEach(() => {
    resourceHandler = new ResourceHandler();
    jest.clearAllMocks();
    
    const testName = expect.getState().currentTestName;
    if (testName) {
      testResultsTracker.registerTest(testName, FILE_NAME);
    }
  });

  it('should list resources with proper type', async () => {
    const mockFiles = createMockFilesList([
      { '.tag': 'file', name: 'test.txt', path_display: '/test.txt' }
    ]);

    dbxApi.listFiles.mockResolvedValue(mockFiles);
    const results = await resourceHandler.listResources('');
    expect(results[0].type).toBe('inline');
    
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      path: '',
      resultCount: results.length,
      resourceType: results[0].type
    });
    testResultsTracker.markTestPassed(expect.getState().currentTestName!, FILE_NAME);
  });

  it('should handle binary resources', async () => {
    const mockContent = createMockContent('base64data', 'base64');
    const mockMetadata = createMockMetadata({
      size: 100,
      client_modified: '2025-03-04T00:00:00Z'
    });

    dbxApi.downloadFile.mockResolvedValue(mockContent);
    dbxApi.getFileMetadata.mockResolvedValue(mockMetadata);

    const result = await resourceHandler.readBinaryResource('dbx://image.png');
    expect(result.encoding).toBe('base64');
    
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      uri: 'dbx://image.png',
      encoding: result.encoding
    });
    testResultsTracker.markTestPassed(expect.getState().currentTestName!, FILE_NAME);
  });

  it('should handle API errors gracefully', async () => {
    dbxApi.listFiles.mockRejectedValue(new Error('API error'));

    await expect(resourceHandler.listResources(''))
      .rejects
      .toThrow('Failed to list resources');
    
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      path: '',
      errorType: 'Failed to list resources'
    });
    testResultsTracker.markTestPassed(expect.getState().currentTestName!, FILE_NAME);
  });
});
