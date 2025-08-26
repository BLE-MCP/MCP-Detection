/**
 * Jest setup file to initialize global test configuration
 */

import { testResultsTracker } from './utils/test-results-tracker.js';
import { TEST_TIMESTAMP, TEST_FOLDER_NAME, TEST_FILE_NAME, TEST_FILE_CONTENT } from './constants.js';

// Set globals for easy access in tests
(global as any).TEST_FOLDER_NAME = TEST_FOLDER_NAME;
(global as any).TEST_FILE_NAME = TEST_FILE_NAME;

// Configure test tracker
beforeAll(() => {
  testResultsTracker.reset();
});

afterAll(() => {
  testResultsTracker.printSummary(TEST_TIMESTAMP);
});

// Jest requires hardcoded values in mock factory functions
// We cannot reference imported variables like TEST_FOLDER_NAME

// Mock the config module
jest.mock('../src/config.js', () => ({
  config: {
    dropbox: {
      appKey: 'test-app-key',
      appSecret: 'test-app-secret',
      redirectUri: 'http://localhost:3000/auth/callback',
      accessToken: 'test-access-token'
    },
    security: {
      tokenEncryptionKey: 'test-encryption-key',
      corsAllowedOrigins: ['http://localhost:3000']
    },
    tokens: {
      maxRetries: 3,
      retryDelay: 1000,
      thresholdMinutes: 5
    },
    paths: {
      tokenStore: '.test-tokens.json',
      logs: './test-logs'
    },
    safety: {
      recycleBinPath: '/.recycle_bin',
      maxDeletesPerDay: 100,
      retentionDays: 30,
      allowedPaths: ['/'],
      blockedPaths: ['/.recycle_bin', '/.system']
    },
    logger: {
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn()
    },
    auditLogger: {
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn()
    }
  },
  log: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  },
  validateConfig: jest.fn()
}));

// Mock the auth.js module
jest.mock('../src/auth.js', () => ({
  getAccessToken: jest.fn().mockResolvedValue('mock-access-token'),
  getRefreshToken: jest.fn().mockResolvedValue('mock-refresh-token'),
  refreshAccessToken: jest.fn().mockResolvedValue('mock-refreshed-token'),
  exchangeCodeForTokens: jest.fn().mockResolvedValue({
    accessToken: 'mock-access-token',
    refreshToken: 'mock-refresh-token',
    expiresIn: 3600
  }),
  generateAuthUrl: jest.fn().mockReturnValue('https://mock-auth-url.com'),
  saveTokens: jest.fn().mockResolvedValue(true),
  loadTokens: jest.fn().mockResolvedValue({
    accessToken: 'mock-access-token',
    refreshToken: 'mock-refresh-token',
    expiresIn: 3600
  })
}));

// Mock the dbx-api.js module
jest.mock('../src/dbx-api.js', () => ({
  downloadFile: jest.fn().mockImplementation(() => {
    return Promise.resolve({
      content: [{
        text: 'mock file content',
        encoding: 'utf-8'
      }]
    });
  }),
  uploadFile: jest.fn().mockImplementation(() => {
    return Promise.resolve({
      content: [{
        text: JSON.stringify({
          name: 'mock-file.txt',
          path_display: '/mock-folder/mock-file.txt',
          id: 'mock-file-id'
        })
      }]
    });
  }),
  listFiles: jest.fn().mockImplementation(() => {
    return Promise.resolve({
      content: [{
        text: JSON.stringify([
          {
            '.tag': 'file',
            name: 'mock-file.txt',
            path_display: '/mock-folder/mock-file.txt'
          }
        ])
      }]
    });
  }),
  getFileMetadata: jest.fn().mockImplementation(() => {
    return Promise.resolve({
      content: [{
        text: JSON.stringify({
          name: 'mock-file.txt',
          path_display: '/mock-folder/mock-file.txt'
        })
      }]
    });
  }),
  createFolder: jest.fn().mockImplementation(() => {
    return Promise.resolve({
      content: [{
        text: JSON.stringify({
          name: 'mock-folder',
          path_display: '/mock-folder'
        })
      }]
    });
  }),
  deleteItem: jest.fn().mockImplementation(() => {
    return Promise.resolve({
      content: [{
        text: JSON.stringify({
          status: 'success',
          message: 'Item deleted successfully'
        })
      }]
    });
  }),
  searchFiles: jest.fn().mockImplementation(() => {
    return Promise.resolve({
      content: [{
        text: JSON.stringify({
          matches: [
            {
              metadata: {
                name: 'mock-file.txt',
                path_display: '/mock-folder/mock-file.txt'
              }
            }
          ],
          total_results: 1
        })
      }]
    });
  }),
  getAccountInfo: jest.fn().mockImplementation(() => {
    return Promise.resolve({
      content: [{
        text: JSON.stringify({
          account_id: 'mock-account-id',
          name: {
            display_name: 'Mock User'
          },
          email: 'mock@example.com',
          account_type: 'basic'
        })
      }]
    });
  })
}));

// Mock test-helpers.js with hardcoded values
jest.mock('./dropbox/test-helpers.js', () => {
  // We need to use hardcoded values here - no access to imported variables
  const mockFolder = 'mock-folder';
  const mockFile = 'mock-file.txt';
  const mockContent = 'Hello, this is a test file.';
  
  return {
    callMcpTool: jest.fn().mockImplementation((toolName, args) => {
      switch (toolName) {
        case 'create_folder':
          return Promise.resolve({
            content: [{
              text: JSON.stringify({
                name: mockFolder,
                path_display: `/${mockFolder}`
              })
            }]
          });
          
        case 'upload_file':
          return Promise.resolve({
            content: [{
              text: JSON.stringify({
                name: mockFile,
                path_display: `/${mockFolder}/${mockFile}`
              })
            }]
          });
          
        case 'get_file_metadata':
          // Using the timestamp hardcoded pattern matching the constants.ts format
          const testFileName = `test-file-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
          const testFolderName = `mcp-test-${new Date().toISOString().replace(/[:.]/g, '-')}`;
          const testFileContent = 'Hello, this is a test file created by the Dropbox MCP test suite.';
          
          return Promise.resolve({
            content: [{
              text: JSON.stringify({
                name: testFileName,
                path_display: `/${testFolderName}/${testFileName}`,
                size: testFileContent.length,
                server_modified: new Date().toISOString()
              })
            }]
          });
          
        case 'download_file':
          // Using the timestamp hardcoded pattern matching the constants.ts format
          const downloadTestFileName = `test-file-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
          const downloadTestContent = 'Hello, this is a test file created by the Dropbox MCP test suite.';
          
          return Promise.resolve({
            content: [{
              text: JSON.stringify({
                name: downloadTestFileName,
                content: {
                  content: Buffer.from(downloadTestContent).toString('base64')
                }
              })
            }]
          });
          
        case 'list_files':
          // Using the timestamp hardcoded pattern matching the constants.ts format
          const listTestFileName = `test-file-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
          const listTestFolderName = `mcp-test-${new Date().toISOString().replace(/[:.]/g, '-')}`;
          
          return Promise.resolve({
            content: [{
              text: JSON.stringify([
                {
                  '.tag': 'file',
                  name: listTestFileName,
                  path_display: `/${listTestFolderName}/${listTestFileName}`
                }
              ])
            }]
          });
          
        case 'delete_item':
          return Promise.resolve({
            content: [{
              text: JSON.stringify({
                status: 'success',
                message: 'Item deleted successfully'
              })
            }]
          });
          
        case 'search_file_db':
          // Generate a timestamp-based file name for the search test
          const searchTimestamp = new Date().toISOString().replace(/[:.]/g, '-');
          const searchTestFile = args.query || `test-file-${searchTimestamp}.txt`;
          const searchTestFolder = `mcp-test-${searchTimestamp}`;
          
          return Promise.resolve({
            content: [{
              text: JSON.stringify({
                matches: [
                  {
                    metadata: {
                      name: searchTestFile,
                      path_display: `/${searchTestFolder}/${searchTestFile}`
                    }
                  }
                ],
                total_results: 1
              })
            }]
          });
        case 'safe_delete_item':
          if (args.skipConfirmation) {
            return Promise.resolve({
              content: [{
                text: JSON.stringify({
                  status: 'success',
                  operation: 'soft_delete',
                  originalPath: args.path,
                  recyclePath: `/.recycle_bin/version_${args.path.replace(/\//g, '_')}`
                })
              }]
            });
          } else {
            return Promise.resolve({
              content: [{
                text: JSON.stringify({
                  status: 'confirmation_required',
                  message: 'Please confirm deletion',
                  path: args.path
                })
              }]
            });
          }
        case 'get_account_info':
          return Promise.resolve({
            content: [{
              text: JSON.stringify({
                account_id: 'mock-account-id',
                name: {
                  display_name: 'Mock User'
                },
                email: 'mock@example.com',
                account_type: 'basic'
              })
            }]
          });
          
        default:
          return Promise.resolve({
            content: [{
              text: JSON.stringify({
                status: 'success',
                message: 'Operation completed successfully'
              })
            }]
          });
      }
    }),
    // We'll update these values in beforeEach in test files if needed
    TEST_FOLDER_NAME: 'mock-folder',
    TEST_FILE_NAME: 'mock-file.txt',
    TEST_FILE_CONTENT: 'Hello, this is a test file.',
    encodeBase64: (text: string) => Buffer.from(text).toString('base64'),
    decodeBase64: (base64: string) => Buffer.from(base64, 'base64').toString('utf-8'),
    sendMcpRequest: jest.fn().mockResolvedValue({})
  };
});

// After mocks are initialized, we can hook them up to test values
beforeAll(() => {
  // Get references to mocked modules
  const mockHelpers = require('./dropbox/test-helpers.js');
  
  // Update the helper values with our actual test values
  mockHelpers.TEST_FOLDER_NAME = TEST_FOLDER_NAME;
  mockHelpers.TEST_FILE_NAME = TEST_FILE_NAME;
  mockHelpers.TEST_FILE_CONTENT = TEST_FILE_CONTENT;
});

// Mock the resource/test-helpers.ts module
jest.mock('./resource/test-helpers.ts', () => {
  return require('./resource/test-helpers.mock.js');
});
