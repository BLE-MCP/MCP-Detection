// Mock dbx-api.js to avoid import.meta.url issues in tests
import { config } from './config.js';

export const downloadFile = jest.fn().mockImplementation((path, options = {}) => {
    return Promise.resolve({
        content: [{
            text: 'mock file content',
            encoding: options.encoding || 'utf-8'
        }]
    });
});

export const uploadFile = jest.fn().mockResolvedValue({
    content: [{
        text: JSON.stringify({
            name: 'mock-file.txt',
            path_display: '/mock-file.txt',
            id: 'mock-file-id',
            size: 100,
            server_modified: new Date().toISOString()
        })
    }]
});

export const listFiles = jest.fn().mockResolvedValue({
    content: [{
        text: JSON.stringify([
            {
                '.tag': 'file',
                name: 'mock-file.txt',
                path_display: '/mock-file.txt',
                id: 'mock-file-id',
                size: 100,
                server_modified: new Date().toISOString()
            }
        ])
    }]
});

export const getFileMetadata = jest.fn().mockResolvedValue({
    content: [{
        text: JSON.stringify({
            name: 'mock-file.txt',
            path_display: '/mock-file.txt',
            id: 'mock-file-id',
            size: 100,
            server_modified: new Date().toISOString()
        })
    }]
});

export const createFolder = jest.fn().mockResolvedValue({
    content: [{
        text: JSON.stringify({
            name: 'mock-folder',
            path_display: '/mock-folder',
            id: 'mock-folder-id'
        })
    }]
});

export const deleteItem = jest.fn().mockResolvedValue({
    content: [{
        text: JSON.stringify({
            status: 'success',
            message: 'Item deleted successfully'
        })
    }]
});

export const searchFiles = jest.fn().mockResolvedValue({
    content: [{
        text: JSON.stringify({
            matches: [
                {
                    metadata: {
                        name: 'mock-file.txt',
                        path_display: '/mock-file.txt',
                        id: 'mock-file-id'
                    }
                }
            ],
            total_results: 1
        })
    }]
});

export const getAccountInfo = jest.fn().mockResolvedValue({
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
