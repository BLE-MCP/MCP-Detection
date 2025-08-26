import { Prompt, PromptMessage } from '@modelcontextprotocol/sdk/types.js';

export interface ResourceContent {
  uri: string;
  mimeType: string;
  content: string | Buffer;
  encoding: 'utf8' | 'base64';
  metadata: {
    size: number;
    path: string;
    modified: string;
    isAttachment?: boolean;
  };
}

export interface ResourceReference {
  type: 'inline' | 'attachment' | 'collection';
  uri: string;
  content?: ResourceContent;
}

export interface ResourceOptions {
  recursive?: boolean;
  includeContent?: boolean;
  filter?: string[];
  asAttachment?: boolean;
  encoding?: 'utf8' | 'base64';
}

export interface ResourceCollection {
  inline?: ResourceReference[];
  attachments?: ResourceReference[];
  collections?: ResourceReference[];
}

export interface PromptWithResources extends Prompt {
  resources?: ResourceCollection;
}

export type EnhancedPromptContent = {
  type: 'text';
  text: string;
  resources?: ResourceReference[];
} | {
  type: 'image';
  data: string;
  mimeType: string;
  resources?: ResourceReference[];
} | {
  type: 'file';
  data: string;
  mimeType: string;
  resources?: ResourceReference[];
};

export interface EnhancedPromptMessage {
  role: 'user' | 'assistant';
  content: EnhancedPromptContent;
}

export interface ResourceHandlerAPI {
  listResources(path: string, options: ResourceOptions): Promise<ResourceReference[]>;
  readResource(uri: string, options: ResourceOptions): Promise<ResourceContent>;
  readCollection(uri: string): Promise<ResourceContent[]>;
}
