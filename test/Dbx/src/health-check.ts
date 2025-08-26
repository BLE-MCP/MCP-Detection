import http from 'http';
import { log } from './config.js';

// Create a simple HTTP server for health checks
export function startHealthCheckServer(port: number = 8080): void {
  const server = http.createServer((req, res) => {
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }));
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  server.listen(port, () => {
    log.info(`Health check server listening on port ${port}`);
  });

  server.on('error', (error) => {
    log.error('Health check server error:', { 
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    });
  });
}
