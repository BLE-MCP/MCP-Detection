import { log } from './config.js';
import { spawn } from 'child_process';
import { McpError } from '@modelcontextprotocol/sdk/types.js';

async function testMcpOperations() {
    try {
        // Start the MCP server process
        const server = spawn('node', ['build/src/index.js'], {
            stdio: ['pipe', 'pipe', 'pipe']
        });

        // Helper function to send MCP requests
        async function sendRequest(method: string, params: any = {}): Promise<any> {
            return new Promise((resolve, reject) => {
                const request = {
                    jsonrpc: '2.0',
                    id: Date.now(),
                    method: 'tools/call',
                    params: {
                        name: method,
                        arguments: params
                    }
                };

                let buffer = '';
                server.stdout.on('data', (data) => {
                    buffer += data.toString();
                    // Try to find complete JSON objects in the buffer
                    const lines = buffer.split('\n');
                    for (const line of lines) {
                        if (!line) continue;
                        try {
                            const response = JSON.parse(line);
                            if (response.id === request.id) {
                                if (response.error) {
                                    reject(new McpError(response.error.code, response.error.message));
                                } else {
                                    resolve(response.result);
                                }
                                buffer = '';
                                return;
                            }
                        } catch (error) {
                            // Not a JSON line or not our response, ignore it
                        }
                    }
                });

                server.stdin.write(JSON.stringify(request) + '\n');
            });
        }

        // Test file listing
        log.info('Testing file listing...');
        const listResult = await sendRequest('list_files', {
            path: '/'
        });
        log.info('File listing successful:', {
            entries: listResult.content?.length || 0
        });

        // Test file upload
        log.info('Testing file upload...');
        const testContent = Buffer.from('Test file content').toString('base64');
        const uploadResult = await sendRequest('upload_file', {
            path: '/test-mcp.txt',
            content: testContent
        });
        log.info('File upload successful:', {
            path: uploadResult.content?.path
        });

        // Test file download
        log.info('Testing file download...');
        const downloadResult = await sendRequest('download_file', {
            path: '/test-mcp.txt'
        });
        log.info('File download successful:', {
            path: downloadResult.content?.path
        });

        // Test file metadata
        log.info('Testing file metadata...');
        const metadataResult = await sendRequest('get_file_metadata', {
            path: '/test-mcp.txt'
        });
        log.info('File metadata successful:', {
            metadata: metadataResult.content
        });

        // Test file search
        log.info('Testing file search...');
        const searchResult = await sendRequest('search_file_db', {
            query: 'test-mcp'
        });
        log.info('File search successful:', {
            results: searchResult.content?.matches?.length || 0
        });

        // Test file deletion
        log.info('Testing file deletion...');
        const deleteResult = await sendRequest('safe_delete_item', {
            path: '/test-mcp.txt',
            userId: 'test-user',
            reason: 'MCP test cleanup'
        });
        log.info('File deletion successful');

        log.info('All MCP operations completed successfully! 🎉');

        // Clean up
        server.kill();
        process.exit(0);
    } catch (error) {
        log.error('MCP test failed:', {
            error: error instanceof Error ? error.message : 'Unknown error'
        });
        process.exit(1);
    }
}

// Run the tests
testMcpOperations(); 