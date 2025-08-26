import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { downloadFile, listFiles, getFileMetadata } from '../dbx-api.js';
import {
  ResourceContent,
  ResourceReference,
  ResourceOptions,
  PromptWithResources,
  ResourceCollection
} from '../types/resource-types.js';

export class ResourceResolver {
  private async getFileContent(path: string, options: ResourceOptions = {}): Promise<ResourceContent> {
    try {
      const result = await downloadFile(path);
      const metadata = await getFileMetadata(path);
      const metadataObj = JSON.parse(metadata.content[0].text);
      
      return {
        uri: `dbx://${path}`,
        mimeType: this.getMimeType(path),
        content: result.content[0].text,
        encoding: options.encoding || 'utf8',
        metadata: {
          size: metadataObj.size,
          path,
          modified: metadataObj.client_modified,
          isAttachment: options.asAttachment || false
        }
      };
    } catch (error: any) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to get file content: ${error.message}`
      );
    }
  }

  private getMimeType(filename: string): string {
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

  public async resolveResource(uri: string, options: ResourceOptions = {}): Promise<ResourceContent> {
    if (!uri.startsWith('dbx://')) {
      throw new McpError(
        ErrorCode.InvalidRequest,
        `Invalid URI format: ${uri}`
      );
    }

    const path = uri.replace('dbx://', '');
    return this.getFileContent(path, options);
  }

  public async resolveCollection(uri: string, options: ResourceOptions = {}): Promise<ResourceContent[]> {
    if (!uri.startsWith('dbx://')) {
      throw new McpError(
        ErrorCode.InvalidRequest,
        `Invalid URI format: ${uri}`
      );
    }

    const path = uri.replace('dbx://', '');
    const result = await listFiles(path);
    const items = JSON.parse(result.content[0].text);

    const contents: ResourceContent[] = [];
    for (const item of items) {
      const isFolder = item['.tag'] === 'folder';
      const itemPath = item.path_display;
      
      // Skip if file doesn't match filter
      if (!isFolder && options.filter && !options.filter.some(ext => item.name.endsWith(ext))) {
        continue;
      }

      // Create ResourceContent object
      const content: ResourceContent = {
        uri: `dbx://${itemPath}`,
        mimeType: isFolder ? 'application/x-directory' : this.getMimeType(item.name),
        content: '', // Empty content by default, loaded on demand if needed
        encoding: 'utf8',
        metadata: {
          size: isFolder ? 0 : item.size || 0,
          path: itemPath,
          modified: isFolder ? new Date().toISOString() : item.server_modified || item.client_modified,
          isAttachment: options.asAttachment || false
        }
      };

      // If content is requested and it's a file, load it
      if (!isFolder && options.includeContent) {
        try {
          const fileContent = await this.getFileContent(itemPath, options);
          content.content = fileContent.content;
          content.encoding = fileContent.encoding;
        } catch (error) {
          console.error(`Failed to get content for ${itemPath}:`, error);
        }
      }

      contents.push(content);

      // Handle recursive folder traversal
      if (isFolder && options.recursive) {
        try {
          const subContents = await this.resolveCollection(
            `dbx://${itemPath}`,
            options
          );
          contents.push(...subContents);
        } catch (error) {
          console.error(`Failed to get contents for folder ${itemPath}:`, error);
        }
      }
    }

    return contents;
  }

  public async processResources(prompt: PromptWithResources): Promise<void> {
    const resources = prompt.resources;
    if (!resources) return;

    const processInlineResources = async () => {
      if (!resources.inline) return;
      for (const ref of resources.inline) {
        ref.content = await this.resolveResource(ref.uri, { asAttachment: false });
      }
    };

    const processAttachments = async () => {
      if (!resources.attachments) return;
      for (const ref of resources.attachments) {
        ref.content = await this.resolveResource(ref.uri, { asAttachment: true });
      }
    };

    const processCollections = async () => {
      if (!resources.collections) return;
      const newAttachments: ResourceReference[] = [];

      for (const ref of resources.collections) {
        const contents = await this.resolveCollection(ref.uri, {
          recursive: true,
          asAttachment: true
        });
        
        newAttachments.push(...contents.map(content => ({
          type: 'attachment' as const,
          uri: content.uri,
          content
        })));
      }

      resources.attachments = [
        ...(resources.attachments || []),
        ...newAttachments
      ];
    };

    // Process all resource types concurrently
    await Promise.all([
      processInlineResources(),
      processAttachments(),
      processCollections()
    ]);
  }
}
