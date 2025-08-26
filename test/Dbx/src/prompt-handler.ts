import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { promptDefinitions, getPromptWithArgs } from './prompt-definitions.js';

export const handleListPrompts = async () => {
  return {
    prompts: promptDefinitions.map(prompt => ({
      name: prompt.name,
      description: prompt.description,
      arguments: prompt.arguments
    }))
  };
};

export const handleGetPrompt = async (request: any) => {
  const { name, arguments: args } = request.params;
  
  try {
    const prompt = getPromptWithArgs(name, args);
    if (!prompt) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Prompt not found: ${name}`
      );
    }
    
    return prompt;
  } catch (error) {
    if (error instanceof Error) {
      throw new McpError(
        ErrorCode.InvalidParams,
        error.message
      );
    }
    throw error;
  }
};
