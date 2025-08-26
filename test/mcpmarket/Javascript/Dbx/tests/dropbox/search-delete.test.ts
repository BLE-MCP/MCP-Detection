import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import { setupTestLogger, restoreConsole } from '../utils/test-logger.js';
import { testResultsTracker } from '../utils/test-results-tracker.js';
import { 
  callMcpTool, 
  TEST_FOLDER_NAME, 
  TEST_FILE_NAME
} from './test-helpers.js';

describe('Dropbox Search and Delete Operations', () => {
  const FILE_NAME = 'dropbox/search-delete.test.ts';

  beforeAll(() => {
    // Set up the custom logger to suppress stack traces
    setupTestLogger();
  });

  afterAll(() => {
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
