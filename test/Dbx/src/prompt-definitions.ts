import { Prompt, PromptMessage } from '@modelcontextprotocol/sdk/types.js';

// Example prompt for getting help with file operations
const helpPrompt: Prompt = {
  name: 'dbx_help',
  description: 'Get help with file operations and commands (integrates with Dropbox)',
  messages: [
    {
      role: 'user',
      content: {
        type: 'text',
        text: 'How can I help you with your file operations today?'
      }
    }
  ]
};

// Prompt for reviewing file operations before execution
const reviewOperationPrompt: Prompt = {
  name: 'review_operation',
  description: 'Review a file operation before executing it (integrates with Dropbox)',
  arguments: [
    {
      name: 'operation',
      description: 'The operation to review (e.g., delete, move, copy)',
      required: true
    },
    {
      name: 'path',
      description: 'The file/folder path involved',
      required: true
    }
  ],
  messages: [
    {
      role: 'assistant',
      content: {
        type: 'text',
        text: 'I will help you review the {operation} operation on path "{path}". This helps ensure safe execution of file operations.\n\nOperation details:\n- Type: {operation}\n- Path: {path}\n\nWould you like me to explain what this operation will do?'
      }
    }
  ]
};

// Collection of all available prompts
export const promptDefinitions: Prompt[] = [
  helpPrompt,
  reviewOperationPrompt
];

// Handler for getting a specific prompt with arguments
export const getPromptWithArgs = (name: string, args?: Record<string, any>): Prompt | null => {
  const prompt = promptDefinitions.find(p => p.name === name);
  if (!prompt) return null;

  // Clone the prompt to avoid modifying the original
  const promptCopy = JSON.parse(JSON.stringify(prompt));

  // If the prompt has arguments, validate and inject them
  if (args && promptCopy.arguments) {
    // Validate required arguments
    for (const arg of promptCopy.arguments) {
      if (arg.required && !args[arg.name]) {
        throw new Error(`Missing required argument: ${arg.name}`);
      }
    }

    // Inject arguments into the messages
    promptCopy.messages = promptCopy.messages.map((msg: PromptMessage) => {
      if (msg.content.type === 'text') {
        let text = msg.content.text;
        // Replace argument placeholders
        Object.entries(args).forEach(([key, value]) => {
          text = text.replaceAll(`{${key}}`, String(value));
        });
        return {
          ...msg,
          content: { ...msg.content, text }
        };
      }
      return msg;
    });
  }

  return promptCopy;
};
