import { Prompt } from '@modelcontextprotocol/sdk/types.js';
import { PromptWithResources } from '../types/resource-types.js';

// Example prompt for reviewing files in a folder
export const fileReviewPrompt: PromptWithResources = {
  name: 'file_review',
  description: 'Review files in a specified folder and provide analysis',
  arguments: [
    {
      name: 'path',
      description: 'Path to the folder to review',
      required: true
    },
    {
      name: 'fileTypes',
      description: 'Comma-separated list of file extensions to include (e.g., "ts,js,json")',
      required: false
    }
  ],
  messages: [
    {
      role: 'assistant',
      content: {
        type: 'text',
        text: 'I will analyze the files in the specified folder. Here are my findings:\n\n{analysis}',
        resources: []  // Will be populated during execution
      }
    }
  ],
  resources: {
    collections: [
      {
        type: 'collection',
        uri: 'dbx://{path}'  // Will be replaced with actual path
      }
    ]
  }
};

// Example prompt for reviewing a specific file with attachments
export const fileDetailPrompt: PromptWithResources = {
  name: 'file_detail',
  description: 'Provide detailed analysis of a specific file',
  arguments: [
    {
      name: 'path',
      description: 'Path to the file to analyze',
      required: true
    }
  ],
  messages: [
    {
      role: 'assistant',
      content: {
        type: 'text',
        text: 'Here is my analysis of the file:\n\n{analysis}',
        resources: []  // Will be populated during execution
      }
    }
  ],
  resources: {
    attachments: [
      {
        type: 'attachment',
        uri: 'dbx://{path}'  // Will be replaced with actual path
      }
    ]
  }
};

// Example prompt for comparing two files
export const fileComparePrompt: PromptWithResources = {
  name: 'file_compare',
  description: 'Compare two files and highlight differences',
  arguments: [
    {
      name: 'file1',
      description: 'Path to the first file',
      required: true
    },
    {
      name: 'file2',
      description: 'Path to the second file',
      required: true
    }
  ],
  messages: [
    {
      role: 'assistant',
      content: {
        type: 'text',
        text: 'Here is my comparison of the two files:\n\n{comparison}',
        resources: []  // Will be populated during execution
      }
    }
  ],
  resources: {
    inline: [
      {
        type: 'inline',
        uri: 'dbx://{file1}'  // Will be replaced with actual path
      },
      {
        type: 'inline',
        uri: 'dbx://{file2}'  // Will be replaced with actual path
      }
    ]
  }
};
