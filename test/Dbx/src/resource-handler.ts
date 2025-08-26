import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { listFiles, downloadFile, getFileMetadata } from './dbx-api.js';

// Interface for resource metadata
interface ResourceMetadata {
  id: string;
  path: string;
  modified: string;
  size: number;
  parentFolder: string;
  sharing_info?: any;
  hasChildren: boolean;
  childCount?: number;
}

// Helper function to determine MIME type from file extension
function getMimeType(filename: string): string {
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
    'zip': 'application/zip',
    'mp3': 'audio/mpeg',
    'mp4': 'video/mp4',
  };

  return mimeTypes[ext] || 'application/octet-stream';
}

// Helper function to get resource metadata
function getResourceMetadata(item: any, parentItems?: any[]): ResourceMetadata {
  const metadata: ResourceMetadata = {
    id: item.id,
    path: item.path_display,
    modified: item.client_modified,
    size: item.size || 0,
    parentFolder: item.path_display.split('/').slice(0, -1).join('/'),
    sharing_info: item.sharing_info,
    hasChildren: item['.tag'] === 'folder' && (parentItems?.some(
      (child: any) => child.path_display.startsWith(item.path_display + '/')
    ) || false)
  };

  if (item['.tag'] === 'folder' && parentItems) {
    metadata.childCount = parentItems.filter(
      (child: any) => child.path_display.startsWith(item.path_display + '/')
    ).length;
  }

  return metadata;
}

// Helper function to normalize Dropbox path
function normalizePath(path: string): string {
  // Remove leading slash if present
  return path.replace(/^\/+/, '');
}

async function handleListResources(request: any): Promise<any> {
  try {
    const args = request.params?.arguments as { path?: string } | undefined;
    const path = args?.path || '';

    const dropboxFiles = await listFiles(normalizePath(path));
    const items = JSON.parse(dropboxFiles.content[0].text) as any[];

    const resources = items.map((item: any) => {
      const mimeType = item['.tag'] === 'folder' ? 
        'folder' : 
        getMimeType(item.name);

      // Get children info for folders
      const children = item['.tag'] === 'folder' ?
        items
          .filter(child => child.path_display.startsWith(item.path_display + '/'))
          .map(child => child.name)
          .join(', ') : 
        undefined;

      return {
        uri: `dbx://${normalizePath(item.path_display)}`,
        name: item.name,
        type: item['.tag'] === 'file' ? 'dbx-file' : 'dbx-folder',
        mimeType,
        description: item['.tag'] === 'folder' ?
          `Folder containing: ${children || 'empty'} (integrates with Dropbox)` :
          `File (${mimeType}) (integrates with Dropbox)`,
        metadata: getResourceMetadata(item, items)
      };
    });

    return {
      resources: resources
    };
  } catch (error: any) {
    console.error("Error listing resources:", error);
    if (error.message.includes('path not found')) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Path not found: ${request.params?.arguments?.path || '/'}`
      );
    }
    throw new McpError(
      ErrorCode.InternalError,
      `Failed to list resources: ${error.message}`
    );
  }
}

async function handleReadResource(request: any): Promise<any> {
  try {
    const uri = request.params.uri;
    
    // Validate and parse URI
    if (!uri.startsWith('dbx://')) {
      throw new McpError(
        ErrorCode.InvalidRequest,
        `Invalid URI format: ${uri}`
      );
    }

    // Handle URI templates
    let path = '';
    if (uri.startsWith('dbx:///shared/')) {
      const shareId = uri.replace('dbx:///shared/', '');
      // Here you would implement share ID resolution logic
      throw new McpError(
        ErrorCode.MethodNotFound,
        'Shared item access not yet implemented'
      );
    } else {
      path = normalizePath(uri.replace('dbx://', ''));
    }

    // Try to get the file directly first
    try {
      const result = await downloadFile(path);
      const mimeType = getMimeType(path);
      const metadata = await getFileMetadata(path);
      const metadataObj = JSON.parse(metadata.content[0].text);
      
      return {
        contents: [
          {
            uri: uri,
            mimeType,
            text: result.content[0].text,
            encoding: result.content[0].encoding,
            metadata: {
              accessed: new Date().toISOString(),
              size: metadataObj.size,
              path,
              modified: metadataObj.client_modified,
              rev: metadataObj.rev
            }
          }
        ]
      };
    } catch (error: any) {
      // If file download fails, try listing as a folder
      if (error.message.includes('path not found')) {
        const folderContents = await listFiles(path);
        const items = JSON.parse(folderContents.content[0].text);
        
        return {
          contents: [
            {
              uri: uri,
              mimeType: 'application/json',
              text: JSON.stringify({
                path,
                items: items.map((item: any) => ({
                  name: item.name,
                  path: item.path_display,
                  type: item['.tag'],
                  modified: item.client_modified,
                  metadata: getResourceMetadata(item, items)
                }))
              }, null, 2)
            }
          ]
        };
      }
      throw error;
    }
  } catch (error: any) {
    console.error("Error reading resource:", error);
    if (error.message.includes('path not found')) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Resource not found: ${request.params.uri}`
      );
    }
    if (error.message.includes('insufficient permissions')) {
      throw new McpError(
        ErrorCode.InvalidRequest,
        `Access denied to resource: ${request.params.uri}`
      );
    }
    throw new McpError(
      ErrorCode.InternalError,
      `Failed to read resource: ${error.message}`
    );
  }
}

export { handleListResources, handleReadResource };
