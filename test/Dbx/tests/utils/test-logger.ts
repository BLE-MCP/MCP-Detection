/**
 * Custom logger utility for tests that suppresses stack traces
 * while preserving the actual log messages.
 */

// Store original console methods
const originalConsole = {
  log: console.log,
  error: console.error,
  warn: console.warn,
  info: console.info,
  debug: console.debug
};

// Create wrapper functions that use a direct approach to avoid stack traces
export const logger = {
  log: (...args: any[]) => {
    process.stdout.write(args.map(arg => 
      typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
    ).join(' ') + '\n');
  },
  
  error: (...args: any[]) => {
    process.stderr.write('ERROR: ' + args.map(arg => 
      typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
    ).join(' ') + '\n');
  },
  
  warn: (...args: any[]) => {
    process.stdout.write('WARNING: ' + args.map(arg => 
      typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
    ).join(' ') + '\n');
  },
  
  info: (...args: any[]) => {
    process.stdout.write('INFO: ' + args.map(arg => 
      typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
    ).join(' ') + '\n');
  },
  
  debug: (...args: any[]) => {
    process.stdout.write('DEBUG: ' + args.map(arg => 
      typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
    ).join(' ') + '\n');
  }
};

/**
 * Replaces the global console methods with our custom logger
 * Call this at the beginning of your test file
 */
export function setupTestLogger() {
  console.log = logger.log;
  console.error = logger.error;
  console.warn = logger.warn;
  console.info = logger.info;
  console.debug = logger.debug;
}

/**
 * Restores the original console methods
 * Call this in afterAll to clean up
 */
export function restoreConsole() {
  console.log = originalConsole.log;
  console.error = originalConsole.error;
  console.warn = originalConsole.warn;
  console.info = originalConsole.info;
  console.debug = originalConsole.debug;
}
