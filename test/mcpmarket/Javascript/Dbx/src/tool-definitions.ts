const toolDefinitions = [
    {
      name: 'list_files',
      description: 'List files in a folder (integrates with Dropbox)',
      inputSchema: {
        type: 'object',
        properties: {
          path: {
            type: 'string',
            description: 'Path to the folder (default: root)',
            default: '',
          },
        },
      },
    },
    {
      name: 'upload_file',
      description: 'Upload a file (integrates with Dropbox)',
      inputSchema: {
        type: 'object',
        properties: {
          path: {
            type: 'string',
            description: 'Path to upload the file to',
          },
          content: {
            type: 'string',
            description: 'File content (base64 encoded)',
          },
        },
        required: ['path', 'content'],
      },
    },
    {
      name: 'download_file',
      description: 'Download a file to local disk and return the file path. Files are saved to the "downloads" directory. (Integrates with Dropbox)',
      inputSchema: {
        type: 'object',
        properties: {
          path: {
            type: 'string',
            description: 'Path to the file to download from Dropbox',
          },
        },
        required: ['path'],
      },
    },
    {
      name: 'safe_delete_item',
      description: 'Safely delete a file or folder with recycle bin support, confirmation, and audit logging',
      inputSchema: {
        type: 'object',
        properties: {
          path: {
            type: 'string',
            description: 'Path to the file or folder to delete',
          },
          userId: {
            type: 'string',
            description: 'User ID for tracking and rate limiting',
          },
          skipConfirmation: {
            type: 'boolean',
            description: 'Skip deletion confirmation (default: false)',
            default: false,
          },
          retentionDays: {
            type: 'number',
            description: 'Number of days to keep in recycle bin (default: from config)',
          },
          reason: {
            type: 'string',
            description: 'Reason for deletion (for audit logs)',
          },
          permanent: {
            type: 'boolean',
            description: 'Permanently delete instead of moving to recycle bin (default: false)',
            default: false,
          }
        },
        required: ['path', 'userId'],
      },
    },
    {
      name: 'delete_item',
      description: 'Legacy delete operation (deprecated, use safe_delete_item instead)',
      inputSchema: {
        type: 'object',
        properties: {
          path: {
            type: 'string',
            description: 'Path to the file or folder to delete',
          },
        },
        required: ['path'],
      },
    },
    {
      name: 'create_folder',
      description: 'Create a new folder (integrates with Dropbox)',
      inputSchema: {
        type: 'object',
        properties: {
          path: {
            type: 'string',
            description: 'Path where the folder should be created (e.g., "/New Folder")',
          },
        },
        required: ['path'],
      },
    },
    {
      name: 'copy_item',
      description: 'Copy a file or folder to a new location',
      inputSchema: {
        type: 'object',
        properties: {
          from_path: {
            type: 'string',
            description: 'Path of the source file or folder',
          },
          to_path: {
            type: 'string',
            description: 'Path for the destination file or folder',
          },
        },
        required: ['from_path', 'to_path'],
      },
    },
    {
      name: 'move_item',
      description: 'Move or rename a file or folder',
      inputSchema: {
        type: 'object',
        properties: {
          from_path: {
            type: 'string',
            description: 'Path of the source file or folder',
          },
          to_path: {
            type: 'string',
            description: 'New path for the file or folder',
          },
        },
        required: ['from_path', 'to_path'],
      },
    },
    {
      name: 'get_file_metadata',
      description: 'Get metadata for a file or folder',
      inputSchema: {
        type: 'object',
        properties: {
          path: {
            type: 'string',
            description: 'Path to the file or folder',
          },
        },
        required: ['path'],
      },
    },
    {
      name: 'search_file_db',
      description: 'Advanced search for files and folders with filtering capabilities (integrates with Dropbox)',
      inputSchema: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            description: 'Search query string',
          },
          path: {
            type: 'string',
            description: 'Path to search within (defaults to root)',
            default: '',
          },
          max_results: {
            type: 'number',
            description: 'Maximum number of results to return (1-1000)',
            default: 20,
          },
          file_extensions: {
            type: 'array',
            items: {
              type: 'string'
            },
            description: 'Filter by file extensions (e.g., ["pdf", "doc", "txt"])',
          },
          file_categories: {
            type: 'array',
            items: {
              type: 'string',
              enum: ['image', 'document', 'pdf', 'spreadsheet', 'presentation', 'audio', 'video', 'folder']
            },
            description: 'Filter by file categories',
          },
          date_range: {
            type: 'object',
            properties: {
              start: {
                type: 'string',
                description: 'Start date in ISO format (e.g., "2024-01-01")',
              },
              end: {
                type: 'string',
                description: 'End date in ISO format (e.g., "2024-12-31")',
              }
            }
          },
          include_content_match: {
            type: 'boolean',
            description: 'Search within file contents (may be slower)',
            default: false
          },
          sort_by: {
            type: 'string',
            enum: ['relevance', 'last_modified_time', 'file_size'],
            description: 'Sort results by specified criteria',
            default: 'relevance'
          },
          order: {
            type: 'string',
            enum: ['asc', 'desc'],
            description: 'Sort order (ascending or descending)',
            default: 'desc'
          }
        },
        required: ['query'],
      },
    },
    {
      name: 'get_sharing_link',
      description: 'Create a shared link for a file or folder',
      inputSchema: {
        type: 'object',
        properties: {
          path: {
            type: 'string',
            description: 'Path to the file or folder to share',
          },
        },
        required: ['path'],
      },
    },
    {
      name: 'get_account_info',
      description: 'Get information about the connected account (integrates with Dropbox)',
      inputSchema: {
        type: 'object',
        properties: {},
      },
    },
    {
      name: 'get_file_content',
      description: 'Get the content of a file (integrates with Dropbox)',
      inputSchema: {
        type: 'object',
        properties: {
          path: {
            type: 'string',
            description: 'Path to the file in Dropbox',
          },
        },
        required: ['path'],
      },
    },
  ];

// Note: This project is not affiliated with, endorsed by, or sponsored by Dropbox.
// It is an independent integration that works with Dropbox's public API.
export { toolDefinitions };
