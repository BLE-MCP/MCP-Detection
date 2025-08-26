import { ResourcePromptHandler } from '../prompt-handlers/resource-prompt-handler.js';
import { fileReviewPrompt, fileDetailPrompt, fileComparePrompt } from '../prompt-definitions/file-review-prompt.js';

async function runExamples() {
  const handler = new ResourcePromptHandler();

  try {
    // Example 1: Review files in a folder
    console.log('Example 1: Folder Review');
    const folderReview = await handler.processPrompt(fileReviewPrompt, {
      path: '/documents/project',
      fileTypes: 'ts,js,json'
    });
    console.log('Folder review prompt processed:', JSON.stringify(folderReview, null, 2));

    // Example 2: Detailed file analysis
    console.log('\nExample 2: File Analysis');
    const fileAnalysis = await handler.processPrompt(fileDetailPrompt, {
      path: '/documents/project/src/index.ts'
    });
    console.log('File analysis prompt processed:', JSON.stringify(fileAnalysis, null, 2));

    // Example 3: Compare two files
    console.log('\nExample 3: File Comparison');
    const fileComparison = await handler.processPrompt(fileComparePrompt, {
      file1: '/documents/project/src/old.ts',
      file2: '/documents/project/src/new.ts'
    });
    console.log('File comparison prompt processed:', JSON.stringify(fileComparison, null, 2));

    // Example 4: Using helper methods
    console.log('\nExample 4: Using Helper Methods');
    
    // Review a specific folder
    const folderReviewHelper = await handler.processFolderReview(
      '/documents/project/src',
      'ts,js'
    );
    console.log('Folder review helper result:', JSON.stringify(folderReviewHelper, null, 2));

    // Compare two specific files
    const fileComparisonHelper = await handler.processFileComparison(
      '/documents/project/v1/config.json',
      '/documents/project/v2/config.json'
    );
    console.log('File comparison helper result:', JSON.stringify(fileComparisonHelper, null, 2));

  } catch (error) {
    console.error('Error running examples:', error);
  }
}

// Run the examples
runExamples().catch(console.error);

/*
Usage:

To run these examples:
1. Ensure you have the required environment variables set (e.g., Dropbox API credentials)
2. Make sure the paths in the examples exist in your Dropbox account
3. Run the example:
   ```
   npm run build
   node build/examples/resource-prompt-example.js
   ```

The examples demonstrate:
- How to use different types of resource-enabled prompts
- How to handle file collections and attachments
- How to process arguments and resolve resource URIs
- How to use helper methods for common operations
*/
