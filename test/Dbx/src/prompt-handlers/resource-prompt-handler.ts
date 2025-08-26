import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { ResourceHandler } from '../resource/resource-handler.js';
import { PromptWithResources, ResourceCollection, ResourceReference } from '../types/resource-types.js';

export class ResourcePromptHandler {
  private resourceHandler: ResourceHandler;

  constructor() {
    this.resourceHandler = new ResourceHandler();
  }

  private replaceArguments(text: string, args: Record<string, any>): string {
    return text.replace(/\{(\w+)\}/g, (match, key) => {
      if (args[key] === undefined) {
        throw new McpError(
          ErrorCode.InvalidParams,
          `Missing argument: ${key}`
        );
      }
      return String(args[key]);
    });
  }

  private async resolveResourceUris(resources: ResourceCollection, args: Record<string, any>): Promise<void> {
    const resolveUris = (refs: ResourceReference[] | undefined) => {
      if (!refs || !Array.isArray(refs)) return;
      for (const ref of refs) {
        ref.uri = this.replaceArguments(ref.uri, args);
      }
    };

    if (resources.inline) resolveUris(resources.inline);
    if (resources.attachments) resolveUris(resources.attachments);
    if (resources.collections) resolveUris(resources.collections);
  }

  public async processPrompt(prompt: PromptWithResources, args: Record<string, any>): Promise<PromptWithResources> {
    try {
      // Validate required arguments
      if (prompt.arguments) {
        for (const arg of prompt.arguments) {
          if (arg.required && args[arg.name] === undefined) {
            throw new McpError(
              ErrorCode.InvalidParams,
              `Missing required argument: ${arg.name}`
            );
          }
        }
      }

      // Clone the prompt to avoid modifying the original
      const processedPrompt: PromptWithResources = JSON.parse(JSON.stringify(prompt));

      // Replace argument placeholders in messages
      if (Array.isArray(processedPrompt.messages)) {
        processedPrompt.messages = processedPrompt.messages.map(msg => ({
          ...msg,
          content: {
            ...msg.content,
            text: typeof msg.content === 'object' && msg.content && 'text' in msg.content
              ? this.replaceArguments(msg.content.text, args)
              : ''
          }
        }));
      }

      // Process resources if present
      if (processedPrompt.resources) {
        // Replace argument placeholders in resource URIs
        await this.resolveResourceUris(processedPrompt.resources, args);

        // Process and load resources
        await this.resourceHandler.processPromptResources(processedPrompt.resources);
      }

      return processedPrompt;
    } catch (error: any) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to process prompt: ${error.message}`
      );
    }
  }

  // Helper method to process a folder review prompt
  public async processFolderReview(path: string, fileTypes?: string): Promise<PromptWithResources> {
    const args: Record<string, any> = {
      path,
      fileTypes: fileTypes || '*'
    };

    // If specific file types are provided, update the collection options
    if (fileTypes) {
      const extensions = fileTypes.split(',').map(ext => ext.trim());
      args.fileTypes = extensions.join(', ');
    }

    return this.processPrompt({
      name: 'folder_review',
      description: 'Review contents of a folder',
      messages: [
        {
          role: 'assistant',
          content: {
            type: 'text',
            text: 'Analyzing folder: {path}\nFile types: {fileTypes}\n\n',
            resources: []
          }
        }
      ],
      resources: {
        collections: [{
          type: 'collection',
          uri: 'dbx://{path}'
        }]
      }
    }, args);
  }

  // Helper method to process a file comparison prompt
  public async processFileComparison(file1: string, file2: string): Promise<PromptWithResources> {
    return this.processPrompt({
      name: 'file_comparison',
      description: 'Compare two files',
      messages: [
        {
          role: 'assistant',
          content: {
            type: 'text',
            text: 'Comparing files:\n1. {file1}\n2. {file2}\n\n',
            resources: []
          }
        }
      ],
      resources: {
        inline: [
          {
            type: 'inline',
            uri: 'dbx://{file1}'
          },
          {
            type: 'inline',
            uri: 'dbx://{file2}'
          }
        ]
      }
    }, { file1, file2 });
  }
}
