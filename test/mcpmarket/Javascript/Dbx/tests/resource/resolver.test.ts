import { describe, it, expect, beforeEach, beforeAll, afterAll } from '@jest/globals';

// Mock the imports
jest.mock('../../src/config.js');
jest.mock('../../src/auth.js');
jest.mock('../../src/dbx-api.js');

// Now import the ResourceResolver
import { ResourceResolver } from '../../src/resource/resource-resolver.js';
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

describe('ResourceResolver', () => {
  const FILE_NAME = 'resource/resolver.test.ts';
  let resourceResolver: ResourceResolver;

  beforeAll(() => {
    // Set up the custom logger to suppress stack traces
    setupTestLogger();
  });

  afterAll(() => {
    // Restore original console methods
    restoreConsole();
  });

  beforeEach(() => {
    resourceResolver = new ResourceResolver();
    jest.clearAllMocks();
    
    const testName = expect.getState().currentTestName;
    if (testName) {
      testResultsTracker.registerTest(testName, FILE_NAME);
    }
  });

  it('should resolve a single file resource', async () => {
    const mockContent = createMockContent('file content');
    const mockMetadata = createMockMetadata({
      size: 100,
      client_modified: '2025-03-04T00:00:00Z'
    });

    dbxApi.downloadFile.mockResolvedValue(mockContent);
    dbxApi.getFileMetadata.mockResolvedValue(mockMetadata);

    const result = await resourceResolver.resolveResource('dbx://test.txt');
    expect(result.content).toBe('file content');
    expect(result.mimeType).toBe('text/plain');
    
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      uri: 'dbx://test.txt',
      mimeType: result.mimeType
    });
    testResultsTracker.markTestPassed(expect.getState().currentTestName!, FILE_NAME);
  });

  it('should handle binary files with base64 encoding', async () => {
    const mockContent = createMockContent('base64data', 'base64');
    const mockMetadata = createMockMetadata({
      size: 100,
      client_modified: '2025-03-04T00:00:00Z'
    });

    dbxApi.downloadFile.mockResolvedValue(mockContent);
    dbxApi.getFileMetadata.mockResolvedValue(mockMetadata);

    const result = await resourceResolver.resolveResource('dbx://image.png', { encoding: 'base64' });
    expect(result.encoding).toBe('base64');
    expect(result.mimeType).toBe('image/png');
    
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      uri: 'dbx://image.png',
      encoding: result.encoding,
      mimeType: result.mimeType
    });
    testResultsTracker.markTestPassed(expect.getState().currentTestName!, FILE_NAME);
  });

  it('should resolve a collection of resources', async () => {
    const mockFiles = createMockFilesList([
      { '.tag': 'file', name: 'test1.txt', path_display: '/test1.txt' },
      { '.tag': 'file', name: 'test2.txt', path_display: '/test2.txt' }
    ]);

    dbxApi.listFiles.mockResolvedValue(mockFiles);
    const results = await resourceResolver.resolveCollection('dbx://folder');
    expect(results).toHaveLength(2);
    
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      uri: 'dbx://folder',
      resultCount: results.length
    });
    testResultsTracker.markTestPassed(expect.getState().currentTestName!, FILE_NAME);
  });

  it('should handle recursive folder resolution', async () => {
    const mockFiles = createMockFilesList([
      { '.tag': 'folder', name: 'subfolder', path_display: '/folder/subfolder' },
      { '.tag': 'file', name: 'test.txt', path_display: '/folder/test.txt' }
    ]);

    const mockSubfolderFiles = createMockFilesList([
      { '.tag': 'file', name: 'subtest.txt', path_display: '/folder/subfolder/subtest.txt' }
    ]);

    dbxApi.listFiles
      .mockResolvedValueOnce(mockFiles)
      .mockResolvedValueOnce(mockSubfolderFiles);

    const results = await resourceResolver.resolveCollection('dbx://folder', { recursive: true });
    expect(results.some(r => r.uri.includes('subfolder'))).toBe(true);
    
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      uri: 'dbx://folder',
      recursive: true,
      resultCount: results.length,
      hasSubfolderResults: results.some(r => r.uri.includes('subfolder'))
    });
    testResultsTracker.markTestPassed(expect.getState().currentTestName!, FILE_NAME);
  });

  it('should handle invalid URI format', async () => {
    await expect(resourceResolver.resolveResource('invalid://test.txt'))
      .rejects
      .toThrow('Invalid URI format');
    
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      invalidUri: 'invalid://test.txt',
      errorType: 'Invalid URI format'
    });
    testResultsTracker.markTestPassed(expect.getState().currentTestName!, FILE_NAME);
  });

  it('should handle missing resources', async () => {
    dbxApi.downloadFile.mockRejectedValue(new Error('path not found'));
    
    await expect(resourceResolver.resolveResource('dbx://missing.txt'))
      .rejects
      .toThrow('Failed to get file content');
    
    testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
      missingUri: 'dbx://missing.txt',
      errorType: 'Failed to get file content'
    });
    testResultsTracker.markTestPassed(expect.getState().currentTestName!, FILE_NAME);
  });
});
