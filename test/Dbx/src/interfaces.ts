// Define response type for MCP tools
interface McpContent {
  type: string;
  text: string;
  encoding?: 'base64' | 'utf8';  // Optional encoding property
}

interface McpToolResponse {
  content: McpContent[];
}

export { McpContent, McpToolResponse };
