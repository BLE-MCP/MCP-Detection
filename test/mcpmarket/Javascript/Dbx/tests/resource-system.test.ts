import { describe, it, expect, beforeEach, jest, beforeAll, afterAll } from '@jest/globals';
import { setupTestLogger, restoreConsole } from './utils/test-logger.js';
import { testResultsTracker } from './utils/test-results-tracker.js';
import { ResourceHandler } from '../src/resource/resource-handler.js';
import { ResourceResolver } from '../src/resource/resource-resolver.js';
import { ResourcePromptHandler } from '../src/prompt-handlers/resource-prompt-handler.js';
import { fileReviewPrompt, fileDetailPrompt, fileComparePrompt } from '../src/prompt-definitions/file-review-prompt.js';
import { McpError } from '@modelcontextprotocol/sdk/types.js';

// Mock the Dropbox API functions
jest.mock('../src/dbx-api.js', () => ({
  downloadFile: jest.fn(),
  listFiles: jest.fn(),
  getFileMetadata: jest.fn()
}));

describe('Resource System', () => {
  const FILE_NAME = 'resource-system.test.ts';
  let resourceHandler: ResourceHandler;
  let resourceResolver: ResourceResolver;
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
    resourceHandler = new ResourceHandler();
    resourceResolver = new ResourceResolver();
    promptHandler = new ResourcePromptHandler();
    jest.clearAllMocks();
    
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

  describe('ResourceResolver', () => {
    it('should resolve a single file resource', async () => {
      const mockContent = { content: [{ text: 'file content' }] };
      const mockMetadata = { content: [{ text: JSON.stringify({
        size: 100,
        client_modified: '2025-03-04T00:00:00Z'
      })}]};

      require('../src/dbx-api.js').downloadFile.mockResolvedValue(mockContent);
      require('../src/dbx-api.js').getFileMetadata.mockResolvedValue(mockMetadata);

      const result = await resourceResolver.resolveResource('dbx://test.txt');
      expect(result.content).toBe('file content');
      expect(result.mimeType).toBe('text/plain');
      
      testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
        uri: 'dbx://test.txt',
        mimeType: result.mimeType
      });
    });

    it('should handle binary files with base64 encoding', async () => {
      const mockContent = { content: [{ text: 'base64data', encoding: 'base64' }] };
      const mockMetadata = { content: [{ text: JSON.stringify({
        size: 100,
        client_modified: '2025-03-04T00:00:00Z'
      })}]};

      require('../src/dbx-api.js').downloadFile.mockResolvedValue(mockContent);
      require('../src/dbx-api.js').getFileMetadata.mockResolvedValue(mockMetadata);

      const result = await resourceResolver.resolveResource('dbx://image.png', { encoding: 'base64' });
      expect(result.encoding).toBe('base64');
      expect(result.mimeType).toBe('image/png');
      
      testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
        uri: 'dbx://image.png',
        encoding: result.encoding,
        mimeType: result.mimeType
      });
    });

    it('should resolve a collection of resources', async () => {
      const mockFiles = { content: [{ text: JSON.stringify([
        { '.tag': 'file', name: 'test1.txt', path_display: '/test1.txt' },
        { '.tag': 'file', name: 'test2.txt', path_display: '/test2.txt' }
      ])}]};

      require('../src/dbx-api.js').listFiles.mockResolvedValue(mockFiles);
      const results = await resourceResolver.resolveCollection('dbx://folder');
      expect(results).toHaveLength(2);
      
      testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
        uri: 'dbx://folder',
        resultCount: results.length
      });
    });

    it('should handle recursive folder resolution', async () => {
      const mockFiles = { content: [{ text: JSON.stringify([
        { '.tag': 'folder', name: 'subfolder', path_display: '/folder/subfolder' },
        { '.tag': 'file', name: 'test.txt', path_display: '/folder/test.txt' }
      ])}]};

      const mockSubfolderFiles = { content: [{ text: JSON.stringify([
        { '.tag': 'file', name: 'subtest.txt', path_display: '/folder/subfolder/subtest.txt' }
      ])}]};

      require('../src/dbx-api.js').listFiles
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
    });
  });

  describe('ResourceHandler', () => {
    it('should list resources with proper type', async () => {
      const mockFiles = { content: [{ text: JSON.stringify([
        { '.tag': 'file', name: 'test.txt', path_display: '/test.txt' }
      ])}]};

      require('../src/dbx-api.js').listFiles.mockResolvedValue(mockFiles);
      const results = await resourceHandler.listResources('');
      expect(results[0].type).toBe('inline');
      
      testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
        path: '',
        resultCount: results.length,
        resourceType: results[0].type
      });
    });

    it('should handle binary resources', async () => {
      const mockContent = { content: [{ text: 'base64data', encoding: 'base64' }] };
      const mockMetadata = { content: [{ text: JSON.stringify({
        size: 100,
        client_modified: '2025-03-04T00:00:00Z'
      })}]};

      require('../src/dbx-api.js').downloadFile.mockResolvedValue(mockContent);
      require('../src/dbx-api.js').getFileMetadata.mockResolvedValue(mockMetadata);

      const result = await resourceHandler.readBinaryResource('dbx://image.png');
      expect(result.encoding).toBe('base64');
      
      testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
        uri: 'dbx://image.png',
        encoding: result.encoding
      });
    });
  });

  describe('ResourcePromptHandler', () => {
    it('should process prompts with resource references', async () => {
      const mockContent = { content: [{ text: 'file content' }] };
      const mockMetadata = { content: [{ text: JSON.stringify({
        size: 100,
        client_modified: '2025-03-04T00:00:00Z'
      })}]};

      require('../src/dbx-api.js').downloadFile.mockResolvedValue(mockContent);
      require('../src/dbx-api.js').getFileMetadata.mockResolvedValue(mockMetadata);

      const result = await promptHandler.processPrompt(fileDetailPrompt, {
        path: '/test.txt',
        analysis: 'Test file analysis'
      });

      expect(result.resources?.attachments?.[0].content).toBeDefined();
      
      testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
        path: '/test.txt',
        hasAttachments: (result.resources?.attachments?.length ?? 0) > 0
      });
    });

    it('should handle file comparison prompts', async () => {
      const mockContent1 = { content: [{ text: 'content1' }] };
      const mockContent2 = { content: [{ text: 'content2' }] };
      const mockMetadata = { content: [{ text: JSON.stringify({
        size: 100,
        client_modified: '2025-03-04T00:00:00Z'
      })}]};

      require('../src/dbx-api.js').downloadFile
        .mockResolvedValueOnce(mockContent1)
        .mockResolvedValueOnce(mockContent2);
      require('../src/dbx-api.js').getFileMetadata.mockResolvedValue(mockMetadata);

      const result = await promptHandler.processFileComparison('/file1.txt', '/file2.txt');
      expect(result.resources?.inline).toHaveLength(2);
      
      testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
        file1: '/file1.txt',
        file2: '/file2.txt',
        inlineResourceCount: result.resources?.inline?.length
      });
    });

    it('should validate required arguments', async () => {
      await expect(promptHandler.processPrompt(fileDetailPrompt, {}))
        .rejects
        .toThrow('Missing required argument: path');
      
      testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
        validationError: 'Missing required argument: path'
      });
    });

    it('should handle folder review with file type filtering', async () => {
      const mockFiles = { content: [{ text: JSON.stringify([
        { '.tag': 'file', name: 'test.ts', path_display: '/test.ts' },
        { '.tag': 'file', name: 'test.js', path_display: '/test.js' },
        { '.tag': 'file', name: 'test.txt', path_display: '/test.txt' }
      ])}]};

      require('../src/dbx-api.js').listFiles.mockResolvedValue(mockFiles);

      const result = await promptHandler.processFolderReview('/folder', 'ts,js');
      expect(result.resources?.collections).toBeDefined();
      
      testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
        folder: '/folder',
        fileTypes: 'ts,js',
        hasCollections: result.resources?.collections !== undefined
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid URI format', async () => {
      await expect(resourceResolver.resolveResource('invalid://test.txt'))
        .rejects
        .toThrow('Invalid URI format');
      
      testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
        invalidUri: 'invalid://test.txt',
        errorType: 'Invalid URI format'
      });
    });

    it('should handle missing resources', async () => {
      require('../src/dbx-api.js').downloadFile.mockRejectedValue(new Error('path not found'));
      
      await expect(resourceResolver.resolveResource('dbx://missing.txt'))
        .rejects
        .toThrow('Failed to get file content');
      
      testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
        missingUri: 'dbx://missing.txt',
        errorType: 'Failed to get file content'
      });
    });

    it('should handle API errors gracefully', async () => {
      require('../src/dbx-api.js').listFiles.mockRejectedValue(new Error('API error'));

      await expect(resourceHandler.listResources(''))
        .rejects
        .toThrow('Failed to list resources');
      
      testResultsTracker.addTestDetails(expect.getState().currentTestName!, FILE_NAME, {
        path: '',
        errorType: 'Failed to list resources'
      });
    });
  });
});
