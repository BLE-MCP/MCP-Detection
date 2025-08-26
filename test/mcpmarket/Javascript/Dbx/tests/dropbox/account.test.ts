import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import fs from 'node:fs';
import path from 'node:path';
import { decryptData } from '../../src/security-utils.js';
import { setupTestLogger, restoreConsole } from '../utils/test-logger.js';
import { testResultsTracker } from '../utils/test-results-tracker.js';
import { callMcpTool, TOKEN_STORE_PATH } from '../dropbox/test-helpers.js';

describe('Dropbox Account Operations', () => {
  const FILE_NAME = 'dropbox/account.test.ts';

  beforeAll(() => {
    // Set up the custom logger to suppress stack traces
    setupTestLogger();
    
    // In test environment, we'll skip token verification as it's mocked
    // This check only runs in real environments
    if (process.env.NODE_ENV !== 'test' && !process.env.JEST_WORKER_ID) {
      if (!fs.existsSync(TOKEN_STORE_PATH)) {
        throw new Error('Token store not found. Please complete the authentication setup first.');
      }

      // Verify token data
      const tokenData = JSON.parse(fs.readFileSync(TOKEN_STORE_PATH, 'utf-8'));
      const decrypted = decryptData(tokenData);
      if (!decrypted.accessToken || !decrypted.refreshToken) {
        throw new Error('Invalid token data');
      }
    }
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
});
