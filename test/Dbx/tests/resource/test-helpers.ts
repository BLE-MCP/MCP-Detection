import { jest } from '@jest/globals';

// Import our mocks directly
import * as mockDbxApi from '../mocks/dbx-api.js';

// Helper function to get the mocked API
export function getMockedApi() {
  return mockDbxApi;
}

// Helper function to create a mock content response
export function createMockContent(text: string, encoding: string = 'utf-8') {
  return { 
    content: [{ 
      text, 
      encoding 
    }] 
  };
}

// Helper function to create a mock metadata response
export function createMockMetadata(data: any) {
  return { 
    content: [{ 
      text: JSON.stringify(data)
    }] 
  };
}

// Helper function to create a mock files list response
export function createMockFilesList(files: any[]) {
  return { 
    content: [{ 
      text: JSON.stringify(files)
    }] 
  };
}
