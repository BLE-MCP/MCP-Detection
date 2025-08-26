#!/usr/bin/env node
import DbxServer from './dbx-server.js';
import { config, log } from './config.js';
import { startHealthCheckServer } from './health-check.js';

// Start the health check server if in production
if (process.env.NODE_ENV === 'production') {
  const port = process.env.HEALTH_CHECK_PORT ? parseInt(process.env.HEALTH_CHECK_PORT, 10) : 8080;
  startHealthCheckServer(port);
}

// Start the server
const server = new DbxServer();

// Run the server
server.run().catch((error: Error) => {
    log.error('Failed to start server:', {
        error: error.message,
        stack: error.stack
    });
    process.exit(1);
});
