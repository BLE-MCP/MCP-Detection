export interface SearchOptions {
  query: string;
  path?: string;
  maxResults?: number;
  fileExtensions?: string[];
  fileCategories?: string[];
  dateRange?: {
    start: string;
    end: string;
  };
  includeContentMatch?: boolean;
  sortBy?: 'relevance' | 'last_modified_time' | 'file_size';
  order?: 'asc' | 'desc';
} 