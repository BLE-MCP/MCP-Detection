import { Dropbox } from 'dropbox';
import { McpToolResponse } from './interfaces.js';
import { getValidAccessToken } from './auth.js';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { config, log } from './config.js';
import { files } from 'dropbox/types';
import axios from 'axios';

// Error mapping for better error messages
const ERROR_MESSAGES = {
    path_not_found: 'The specified path was not found in Dropbox',
    path_malformed: 'The path format is invalid',
    insufficient_permissions: 'The access token does not have the required permissions',
    invalid_access_token: 'The access token is invalid or has expired',
    rate_limit: 'Rate limit exceeded. Please try again later',
    server_error: 'Dropbox server error occurred',
    network_error: 'Network error occurred while connecting to Dropbox'
} as const;

// Default timeout for API calls (15 seconds instead of 3)
const DEFAULT_TIMEOUT = 15000;

// Helper function to handle Dropbox API errors
function handleDropboxError(error: any): never {
    const errorMessage = error?.error?.error_summary || error?.message || 'Unknown error';
    log.error('Dropbox API error:', { error: errorMessage, stack: error?.stack });

    // Map common error patterns to user-friendly messages
    for (const [key, message] of Object.entries(ERROR_MESSAGES)) {
        if (errorMessage.includes(key)) {
            throw new McpError(
                key === 'path_not_found' || key === 'path_malformed' 
                    ? ErrorCode.InvalidParams 
                    : ErrorCode.InternalError,
                message
            );
        }
    }

    // Generic error case
    throw new McpError(
        ErrorCode.InternalError,
        `Dropbox API error: ${errorMessage}`
    );
}

// Get a Dropbox client with a valid token
async function getDropboxClient(): Promise<Dropbox> {
    try {
        const token = await getValidAccessToken();
        return new Dropbox({ accessToken: token });
    } catch (error) {
        log.error('Failed to get valid access token:', error);
        throw new McpError(
            ErrorCode.InvalidRequest,
            'Failed to get valid access token. Please re-authenticate.'
        );
    }
}

// Helper function to format paths for Dropbox API
function formatDropboxPath(path: string): string {
    if (!path || path === '/') return '';
    return '/' + path.replace(/^\/+|\/+$/g, '');
}

async function uploadFile(path: string, content: string): Promise<McpToolResponse> {
    try {
        const buffer = Buffer.from(content, 'base64');
        const client = await getDropboxClient();
        
        await client.filesUpload({
            path: formatDropboxPath(path),
            contents: buffer,
            mode: { '.tag': 'overwrite' },
        });

        return {
            content: [{
                type: 'text',
                text: `File uploaded successfully to ${path}`,
            }],
        };
    } catch (error: any) {
        handleDropboxError(error);
    }
}

async function downloadFile(path: string): Promise<McpToolResponse> {
    try {
        const client = await getDropboxClient();
        
        // Get metadata first to check if it's a file or folder
        const metadata = await client.filesGetMetadata({
            path: formatDropboxPath(path)
        });
        
        if (metadata.result['.tag'] === 'folder') {
            // For folders, get contents and format as ResourceContent
            const folderContents = await client.filesListFolder({
                path: formatDropboxPath(path),
                recursive: false,
                include_media_info: true,
                include_deleted: false,
                include_has_explicit_shared_members: false,
                include_mounted_folders: true,
                include_non_downloadable_files: true
            });

            // For folders, return a list of ResourceReference objects
            const references = folderContents.result.entries.map(entry => ({
                type: entry['.tag'] === 'folder' ? 'collection' : 'inline',
                uri: `dbx://${entry.path_display}`,
                content: {
                    uri: `dbx://${entry.path_display}`,
                    mimeType: entry['.tag'] === 'folder' ? 
                        'application/x-directory' : 
                        getMimeType(entry.name),
                    content: '',  // Content is loaded on demand when accessing individual items
                    encoding: 'utf8',
                    metadata: {
                        size: entry['.tag'] === 'file' && entry.size ? entry.size : 0,
                        path: entry.path_display || path,
                        modified: entry['.tag'] === 'file' && (entry.server_modified || entry.client_modified) ? 
                            entry.server_modified || entry.client_modified : 
                            new Date().toISOString()
                    }
                }
            }));

            return {
                content: [{
                    type: 'text',
                    text: JSON.stringify(references, null, 2)
                }],
            };
        }

        // For files, proceed with download and format as ResourceContent
        const response = await client.filesDownload({ 
            path: formatDropboxPath(path)
        });

        const fileData = response.result as any;
        if (!fileData?.fileBinary) {
            throw new Error('No file data received from Dropbox');
        }

        // For files, return a single ResourceReference with base64 encoded content
        const reference = {
            type: 'inline',
            uri: `dbx://${path}`,
            content: {
                uri: `dbx://${path}`,
                mimeType: fileData.name ? getMimeType(fileData.name) : 'application/octet-stream',
                content: fileData.fileBinary.toString('base64'),
                encoding: 'base64',
                metadata: {
                    size: fileData.size || 0,
                    path: fileData.path_display || path,
                    modified: fileData.server_modified || fileData.client_modified || new Date().toISOString()
                }
            }
        };

        return {
            content: [{
                type: 'text',
                text: JSON.stringify(reference, null, 2)
            }],
        };
    } catch (error: any) {
        handleDropboxError(error);
    }
}

// Helper function to determine MIME type
function getMimeType(filename: string | undefined): string {
    if (!filename) return 'application/octet-stream';
    const ext = filename.split('.').pop()?.toLowerCase();
    if (!ext) return 'application/octet-stream';
    
    const mimeTypes: { [key: string]: string } = {
        'txt': 'text/plain',
        'pdf': 'application/pdf',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'json': 'application/json',
        'md': 'text/markdown',
        'html': 'text/html',
        'css': 'text/css',
        'js': 'application/javascript',
        'ts': 'application/typescript',
        'zip': 'application/zip',
        'mp3': 'audio/mpeg',
        'mp4': 'video/mp4',
    };

    return mimeTypes[ext] || 'application/octet-stream';
}

// Interface for delete operation tracking
interface DeleteOperation {
    timestamp: Date;
    path: string;
    userId: string;
}

// Keep track of delete operations for rate limiting
const deleteOperations: DeleteOperation[] = [];

// Helper function to check if path is allowed
function isPathAllowed(path: string): boolean {
    const normalizedPath = formatDropboxPath(path);
    
    // First check if path is in blocked paths - this takes precedence
    const isBlocked = config.safety.blockedPaths.some((blockedPath: string) => {
        const normalizedBlockedPath = formatDropboxPath(blockedPath);
        // Exact match or subdirectory of blocked path
        return normalizedPath === normalizedBlockedPath || 
               normalizedPath.startsWith(normalizedBlockedPath + '/');
    });

    if (isBlocked) {
        log.warn('Attempted access to blocked path', { path: normalizedPath });
        return false;
    }

    // Then check if path is in allowed paths
    const isAllowed = config.safety.allowedPaths.some((allowedPath: string) => {
        const normalizedAllowedPath = formatDropboxPath(allowedPath);
        // Exact match or subdirectory of allowed path
        return normalizedPath === normalizedAllowedPath || 
               normalizedPath.startsWith(normalizedAllowedPath + '/');
    });

    if (!isAllowed) {
        log.warn('Path not in allowed paths', { path: normalizedPath });
    }

    return isAllowed;
}

// Helper function to check delete rate limit
function checkDeleteRateLimit(userId: string): boolean {
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    
    // Clean up old operations
    const recentOperations = deleteOperations.filter(op => op.timestamp > oneDayAgo);
    deleteOperations.length = 0;
    deleteOperations.push(...recentOperations);
    
    // Count operations for this user in last 24 hours
    const userOperations = deleteOperations.filter(op => op.userId === userId);
    return userOperations.length < config.safety.maxDeletesPerDay;
}

// Helper function to generate version ID
function generateVersionId(): string {
    return `v${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

async function safeDeleteItem(options: {
    path: string;
    userId: string;
    skipConfirmation?: boolean;
    retentionDays?: number;
    reason?: string;
    permanent?: boolean;
}): Promise<McpToolResponse> {
    try {
        const {
            path,
            userId,
            skipConfirmation = false,
            retentionDays = config.safety.retentionDays,
            reason = '',
            permanent = false
        } = options;

        // Validate path
        if (!isPathAllowed(path)) {
            const normalizedPath = formatDropboxPath(path);
            const isBlocked = config.safety.blockedPaths.some((blockedPath: string) => {
                const normalizedBlockedPath = formatDropboxPath(blockedPath);
                return normalizedPath === normalizedBlockedPath || 
                       normalizedPath.startsWith(normalizedBlockedPath + '/');
            });

            throw new McpError(
                ErrorCode.InvalidParams,
                isBlocked ? 
                    `Path ${path} is blocked and cannot be deleted` :
                    `Path ${path} is not in allowed paths for deletion`
            );
        }

        // Check rate limit
        if (!checkDeleteRateLimit(userId)) {
            throw new McpError(
                ErrorCode.InvalidRequest,
                `Delete rate limit exceeded for user ${userId}`
            );
        }

        const client = await getDropboxClient();
        const normalizedPath = formatDropboxPath(path);

        // Get file metadata before deletion
        const metadata = await client.filesGetMetadata({
            path: normalizedPath
        });

        if (!skipConfirmation) {
            // Log confirmation requirement
            config.auditLogger.info('Delete confirmation required', {
                path: normalizedPath,
                userId,
                metadata: metadata.result
            });

            return {
                content: [{
                    type: 'text',
                    text: JSON.stringify({
                        status: 'confirmation_required',
                        message: 'Please confirm deletion',
                        path: normalizedPath,
                        metadata: metadata.result
                    }, null, 2)
                }]
            };
        }

        if (permanent) {
            // Permanent deletion
            await client.filesDeleteV2({
                path: normalizedPath
            });

            // Log permanent deletion
            config.auditLogger.info('Permanent deletion', {
                path: normalizedPath,
                userId,
                reason,
                metadata: metadata.result
            });

            return {
                content: [{
                    type: 'text',
                    text: JSON.stringify({
                        status: 'success',
                        operation: 'permanent_delete',
                        path: normalizedPath
                    }, null, 2)
                }]
            };
        }

        // Soft deletion - move to recycle bin
        const versionId = generateVersionId();
        const recyclePath = `${config.safety.recycleBinPath as string}/${versionId}_${path.split('/').pop()}`;
        
        // Create recycle bin if it doesn't exist
        try {
            await client.filesCreateFolderV2({
                path: config.safety.recycleBinPath as string,
                autorename: false
            });
        } catch (error) {
            // Ignore error if folder already exists
        }

        // Move file to recycle bin
        await client.filesMoveV2({
            from_path: normalizedPath,
            to_path: recyclePath,
            autorename: true
        });

        // Save metadata for version history
        const versionMetadata = {
            id: versionId,
            originalPath: normalizedPath,
            deletedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + retentionDays * 24 * 60 * 60 * 1000).toISOString(),
            metadata: metadata.result,
            userId,
            reason
        };

        // Track delete operation for rate limiting
        deleteOperations.push({
            timestamp: new Date(),
            path: normalizedPath,
            userId
        });

        // Log soft deletion
        config.auditLogger.info('Soft deletion', {
            ...versionMetadata,
            recyclePath
        });

        return {
            content: [{
                type: 'text',
                text: JSON.stringify({
                    status: 'success',
                    operation: 'soft_delete',
                    versionId,
                    originalPath: normalizedPath,
                    recyclePath,
                    expiresAt: versionMetadata.expiresAt
                }, null, 2)
            }]
        };
    } catch (error: any) {
        // Log deletion error
        config.auditLogger.error('Deletion error', {
            path: options.path,
            userId: options.userId,
            error: error.message,
            stack: error.stack
        });

        handleDropboxError(error);
    }
}

// Keep original deleteItem for backward compatibility
async function deleteItem(path: string): Promise<McpToolResponse> {
    return safeDeleteItem({
        path,
        userId: 'legacy_user',
        skipConfirmation: true,
        permanent: true
    });
}

async function createFolder(path: string): Promise<McpToolResponse> {
    try {
        const client = await getDropboxClient();
        await client.filesCreateFolderV2({
            path: formatDropboxPath(path),
            autorename: false,
        });

        return {
            content: [{
                type: 'text',
                text: `Created folder at ${path}`,
            }],
        };
    } catch (error: any) {
        handleDropboxError(error);
    }
}

async function copyItem(fromPath: string, toPath: string): Promise<McpToolResponse> {
    try {
        const client = await getDropboxClient();
        await client.filesCopyV2({
            from_path: formatDropboxPath(fromPath),
            to_path: formatDropboxPath(toPath),
            allow_shared_folder: true,
            autorename: false,
            allow_ownership_transfer: false,
        });

        return {
            content: [{
                type: 'text',
                text: `Copied from ${fromPath} to ${toPath}`,
            }],
        };
    } catch (error: any) {
        handleDropboxError(error);
    }
}

async function moveItem(fromPath: string, toPath: string): Promise<McpToolResponse> {
    try {
        const client = await getDropboxClient();
        await client.filesMoveV2({
            from_path: formatDropboxPath(fromPath),
            to_path: formatDropboxPath(toPath),
            allow_shared_folder: true,
            autorename: false,
            allow_ownership_transfer: false,
        });

        return {
            content: [{
                type: 'text',
                text: `Moved from ${fromPath} to ${toPath}`,
            }],
        };
    } catch (error: any) {
        handleDropboxError(error);
    }
}

async function getFileMetadata(path: string): Promise<McpToolResponse> {
    try {
        const client = await getDropboxClient();
        const response = await client.filesGetMetadata({
            path: formatDropboxPath(path),
            include_media_info: true,
            include_deleted: false,
            include_has_explicit_shared_members: true,
        });

        return {
            content: [{
                type: 'text',
                text: JSON.stringify(response.result, null, 2),
            }],
        };
    } catch (error: any) {
        handleDropboxError(error);
    }
}

interface SearchOptions {
    query: string;
    path?: string;
    maxResults?: number;
    fileExtensions?: string[];
    fileCategories?: string[];
    dateRange?: {
        start: string;
        end: string;
    };
    includeContentMatch?: boolean;
    sortBy?: 'relevance' | 'last_modified_time' | 'file_size';
    order?: 'asc' | 'desc';
}

function getFileCategory(metadata: any): string {
    if (!metadata?.name) return 'other';
    const extension = metadata.name.split('.').pop()?.toLowerCase();
    const mimeType = metadata.media_info?.metadata?.mime_type;

    if (mimeType?.startsWith('image/') || ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'].includes(extension)) {
        return 'image';
    }
    if (['doc', 'docx', 'rtf', 'odt'].includes(extension)) {
        return 'document';
    }
    if (extension === 'pdf' || mimeType === 'application/pdf') {
        return 'pdf';
    }
    if (['xls', 'xlsx', 'csv', 'ods'].includes(extension)) {
        return 'spreadsheet';
    }
    if (['ppt', 'pptx', 'odp'].includes(extension)) {
        return 'presentation';
    }
    if (mimeType?.startsWith('audio/') || ['mp3', 'wav', 'ogg', 'm4a'].includes(extension)) {
        return 'audio';
    }
    if (mimeType?.startsWith('video/') || ['mp4', 'avi', 'mov', 'wmv'].includes(extension)) {
        return 'video';
    }
    if (metadata['.tag'] === 'folder') {
        return 'folder';
    }
    return 'other';
}

async function searchFiles(options: SearchOptions): Promise<McpToolResponse> {
    try {
        const client = await getDropboxClient();
        const response = await client.filesSearchV2({
            query: options.query,
            options: {
                path: formatDropboxPath(options.path || ''),
                max_results: Math.min(Math.max(1, options.maxResults || 20), 1000),
                file_status: { '.tag': 'active' },
                filename_only: !options.includeContentMatch,
            },
            match_field_options: {
                include_highlights: true,
            },
        });

        let matches = response.result.matches
            .map(match => ({
                metadata: (match.metadata as any).metadata,
                match_type: match.match_type,
                highlights: match.highlight_spans,
            }))
            .filter(match => {
                // Apply filters
                if (options.fileExtensions?.length && match.metadata?.name) {
                    const ext = match.metadata.name.split('.').pop()?.toLowerCase();
                    if (!ext || !options.fileExtensions.includes(ext)) return false;
                }
                if (options.fileCategories?.length) {
                    const category = getFileCategory(match.metadata);
                    if (!options.fileCategories.includes(category)) return false;
                }
                if (options.dateRange && match.metadata?.['.tag'] === 'file' && match.metadata?.server_modified) {
                    const modTime = new Date(match.metadata.server_modified).getTime();
                    const startTime = options.dateRange.start ? new Date(options.dateRange.start).getTime() : 0;
                    const endTime = options.dateRange.end ? new Date(options.dateRange.end).getTime() : Infinity;
                    if (modTime < startTime || modTime > endTime) return false;
                }
                return true;
            });

        // Apply sorting
        if (options.sortBy && options.sortBy !== 'relevance') {
            matches.sort((a, b) => {
                if (options.sortBy === 'last_modified_time' && a.metadata && b.metadata) {
                    const timeA = new Date(a.metadata.server_modified || 0).getTime();
                    const timeB = new Date(b.metadata.server_modified || 0).getTime();
                    return options.order === 'asc' ? timeA - timeB : timeB - timeA;
                }
                if (options.sortBy === 'file_size' && a.metadata && b.metadata) {
                    const sizeA = a.metadata['.tag'] === 'file' && a.metadata.size ? a.metadata.size : 0;
                    const sizeB = b.metadata['.tag'] === 'file' && b.metadata.size ? b.metadata.size : 0;
                    return options.order === 'asc' ? sizeA - sizeB : sizeB - sizeA;
                }
                return 0;
            });
        } else if (options.order === 'asc') {
            matches.reverse();
        }

        return {
            content: [{
                type: 'text',
                text: JSON.stringify({
                    total_results: matches.length,
                    search_criteria: {
                        query: options.query,
                        path: options.path,
                        file_extensions: options.fileExtensions,
                        file_categories: options.fileCategories,
                        date_range: options.dateRange,
                        include_content_match: options.includeContentMatch,
                        sort_by: options.sortBy,
                        order: options.order,
                    },
                    matches: matches.map(match => ({
                        ...match,
                        category: getFileCategory(match.metadata),
                    })),
                }, null, 2),
            }],
        };
    } catch (error: any) {
        handleDropboxError(error);
    }
}

async function getSharingLink(path: string): Promise<McpToolResponse> {
    try {
        const client = await getDropboxClient();
        try {
            const response = await client.sharingCreateSharedLinkWithSettings({
                path: formatDropboxPath(path),
                settings: {
                    requested_visibility: { '.tag': 'public' },
                    audience: { '.tag': 'public' },
                    access: { '.tag': 'viewer' },
                },
            });

            return {
                content: [{
                    type: 'text',
                    text: JSON.stringify({
                        url: response.result.url,
                        path: response.result.path_lower,
                        visibility: response.result.link_permissions?.resolved_visibility?.['.tag'] || 'unknown',
                    }, null, 2),
                }],
            };
        } catch (error: any) {
            // Handle case where link already exists
            if (error?.error?.error_summary?.includes('shared_link_already_exists')) {
                const listResponse = await client.sharingListSharedLinks({
                    path: formatDropboxPath(path),
                    direct_only: true,
                });

                if (listResponse.result.links?.[0]) {
                    const link = listResponse.result.links[0];
                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                url: link.url,
                                path: link.path_lower,
                                visibility: link.link_permissions?.resolved_visibility?.['.tag'] || 'unknown',
                                note: 'Existing shared link retrieved',
                            }, null, 2),
                        }],
                    };
                }
            }
            throw error;
        }
    } catch (error: any) {
        handleDropboxError(error);
    }
}

async function getAccountInfo(): Promise<McpToolResponse> {
    try {
        const client = await getDropboxClient();
        const response = await client.usersGetCurrentAccount();

        const accountInfo = {
            account_id: response.result.account_id,
            name: response.result.name,
            email: response.result.email,
            email_verified: response.result.email_verified,
            profile_photo_url: response.result.profile_photo_url,
            country: response.result.country,
            locale: response.result.locale,
            team: response.result.team ? {
                name: response.result.team.name,
                team_id: response.result.team.id,
            } : null,
            account_type: response.result.account_type['.tag'] || 'unknown',
        };

        return {
            content: [{
                type: 'text',
                text: JSON.stringify(accountInfo, null, 2),
            }],
        };
    } catch (error: any) {
        handleDropboxError(error);
    }
}

async function getFileContent(path: string): Promise<McpToolResponse> {
    try {
        const client = await getDropboxClient();
        
        // Get metadata first to verify it's a file
        const metadata = await client.filesGetMetadata({
            path: formatDropboxPath(path)
        });
        
        if (metadata.result['.tag'] !== 'file') {
            throw new McpError(
                ErrorCode.InvalidParams,
                'Cannot get content of a folder'
            );
        }

        const response = await client.filesDownload({ 
            path: formatDropboxPath(path)
        });

        const fileData = response.result as any;
        if (!fileData?.fileBinary) {
            throw new Error('No file data received from Dropbox');
        }

        const reference = {
            type: 'inline',
            uri: `dbx://${path}`,
            content: {
                uri: `dbx://${path}`,
                mimeType: metadata.result.name ? getMimeType(metadata.result.name) : 'application/octet-stream',
                content: fileData.fileBinary.toString('base64'),
                encoding: 'base64',
                metadata: {
                    size: metadata.result.size || 0,
                    path: metadata.result.path_display || path,
                    modified: metadata.result.server_modified || metadata.result.client_modified || new Date().toISOString()
                }
            }
        };

        return {
            content: [{
                type: 'text',
                text: JSON.stringify(reference, null, 2)
            }],
        };
    } catch (error: any) {
        handleDropboxError(error);
    }
}

// Get access token directly from environment if available
function getAccessTokenFromEnv(): string | null {
    if (process.env.DROPBOX_ACCESS_TOKEN) {
        log.info('Using access token from environment variable');
        return process.env.DROPBOX_ACCESS_TOKEN;
    }
    return null;
}

// Add this to the beginning of makeDbxApiCall function
async function makeDbxApiCall(
    endpoint: string, 
    method: 'post' | 'get' = 'post', 
    data: any = null, 
    additionalHeaders: Record<string, string> = {}
): Promise<any> {
    try {
        // First try to get token from environment
        let accessToken = getAccessTokenFromEnv();
        
        // If not available, get from auth module
        if (!accessToken) {
            accessToken = await getValidAccessToken();
        }
        
        // Log a partial token for debugging
        log.debug('Using access token', {
            tokenPrefix: accessToken ? accessToken.substring(0, 10) + '...' : 'null',
            tokenLength: accessToken ? accessToken.length : 0,
            fromEnv: !!getAccessTokenFromEnv()
        });
        
        const headers = {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
            ...additionalHeaders
        };

        const requestConfig = {
            method,
            url: `https://api.dropboxapi.com/2/${endpoint}`,
            headers,
            data: data ? JSON.stringify(data) : undefined,
            timeout: DEFAULT_TIMEOUT
        };

        log.debug('Making Dropbox API request', {
            endpoint,
            method,
            dataKeys: data ? Object.keys(data) : []
        });

        const response = await axios(requestConfig);
        return response.data;
    } catch (error) {
        log.error('Dropbox API error:', error);
        
        if (axios.isAxiosError(error) && error.response) {
            log.error('Response details:', {
                status: error.response.status,
                data: error.response.data
            });
        }
        
        throw error;
    }
}

async function listFiles(path: string): Promise<any> {
    try {
        // Normalize the path to be either empty string for root or Dropbox format
        const normalizedPath = path === '/' ? '' : path;
        
        log.debug('Listing files with normalized path', {
            originalPath: path,
            normalizedPath
        });
        
        const result = await makeDbxApiCall('files/list_folder', 'post', {
            path: normalizedPath,
            recursive: false,
            include_media_info: false,
            include_deleted: false,
            include_has_explicit_shared_members: false
        });
        
        const entries = result.entries.map((entry: any) => ({
            name: entry.name,
            path: entry.path_display,
            type: entry['.tag'],
            size: entry.size,
            isFolder: entry['.tag'] === 'folder'
        }));
        
        return {
            content: [{
                type: 'text',
                text: JSON.stringify(entries, null, 2)
            }]
        };
    } catch (error) {
        log.error('Error listing files:', error);
        throw handleDropboxError(error);
    }
}

export { 
    uploadFile, 
    downloadFile, 
    deleteItem,
    safeDeleteItem,
    createFolder, 
    copyItem, 
    moveItem, 
    getFileMetadata, 
    searchFiles, 
    getSharingLink, 
    getAccountInfo,
    getFileContent,
    listFiles,
};
