import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import {
  ResourceContent,
  ResourceReference,
  ResourceOptions,
  ResourceHandlerAPI,
  ResourceCollection
} from '../types/resource-types.js';
import { ResourceResolver } from './resource-resolver.js';

export class ResourceHandler implements ResourceHandlerAPI {
  private resolver: ResourceResolver;

  constructor() {
    this.resolver = new ResourceResolver();
  }

  public async listResources(path: string, options: ResourceOptions = {}): Promise<ResourceReference[]> {
    try {
      const uri = `dbx://${path}`;
      const contents = await this.resolver.resolveCollection(uri, options);
      
      return contents.map(content => ({
        type: content.mimeType === 'application/x-directory' ? 'collection' : 
              options.asAttachment ? 'attachment' : 'inline',
        uri: content.uri,
        content: options.includeContent ? content : undefined
      }));
    } catch (error: any) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to list resources: ${error.message}`
      );
    }
  }

  public async readResource(uri: string, options: ResourceOptions = {}): Promise<ResourceContent> {
    try {
      return await this.resolver.resolveResource(uri, options);
    } catch (error: any) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to read resource: ${error.message}`
      );
    }
  }

  public async readCollection(uri: string): Promise<ResourceContent[]> {
    try {
      return await this.resolver.resolveCollection(uri, {
        recursive: true,
        includeContent: true
      });
    } catch (error: any) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to read collection: ${error.message}`
      );
    }
  }

  // Helper method to process resources for a prompt
  public async processPromptResources(resources: ResourceCollection): Promise<void> {
    try {
      await this.resolver.processResources({ resources, name: 'temp' });
    } catch (error: any) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to process prompt resources: ${error.message}`
      );
    }
  }

  // Helper method to handle binary files
  public async readBinaryResource(uri: string): Promise<ResourceContent> {
    return this.readResource(uri, {
      encoding: 'base64'
    });
  }

  // Helper method to filter resources by type
  public async listResourcesByType(path: string, extensions: string[]): Promise<ResourceReference[]> {
    return this.listResources(path, {
      filter: extensions,
      includeContent: false
    });
  }
}
