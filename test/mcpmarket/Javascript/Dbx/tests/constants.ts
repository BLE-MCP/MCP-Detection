/**
 * Global test constants
 */

// Generate the timestamp parts individually to avoid reference issues
const now = new Date();
export const TEST_TIMESTAMP = now.toISOString().replace(/[:.]/g, '-');
export const TEST_FOLDER_NAME = `mcp-test-${TEST_TIMESTAMP}`;
export const TEST_FILE_NAME = `test-file-${TEST_TIMESTAMP}.txt`;
export const TEST_FILE_CONTENT = 'Hello, this is a test file created by the Dropbox MCP test suite.';

// Set globals for easy access in all tests
(global as any).TEST_FOLDER_NAME = TEST_FOLDER_NAME;
(global as any).TEST_FILE_NAME = TEST_FILE_NAME;
