#!/usr/bin/env node
// Serve the 3D Visualizer

import { createServer } from 'http';
import { readFileSync, existsSync } from 'fs';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VISUALIZER_DIR = join(__dirname, '..', 'visualizer');
const PORT = parseInt(process.env.VISUALIZER_PORT ?? '8080', 10);

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

const server = createServer((req, res) => {
  // CORS headers for SLOP API access
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Use minimal UI by default, or classic with ?classic
  const useClassic = req.url?.includes('classic');
  const defaultPage = useClassic ? 'index.html' : 'index-minimal.html';
  let filePath = join(VISUALIZER_DIR, req.url === '/' || req.url === '/?classic' ? defaultPage : req.url!.split('?')[0]);

  if (!existsSync(filePath)) {
    res.writeHead(404);
    res.end('Not found');
    return;
  }

  const ext = extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  try {
    const content = readFileSync(filePath);
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(content);
  } catch (err) {
    res.writeHead(500);
    res.end('Server error');
  }
});

server.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║         SLOP 3D VISUALIZER - CONTROL PLANE                ║
╠═══════════════════════════════════════════════════════════╣
║  Visualizer: http://127.0.0.1:${PORT}                        ║
║  SLOP API:   http://127.0.0.1:3000                        ║
╚═══════════════════════════════════════════════════════════╝

Open the visualizer URL in your browser to see the 3D control plane.
The visualizer polls the SLOP API every 2 seconds for updates.
`);
});
