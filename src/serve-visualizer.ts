#!/usr/bin/env node
// Serve the 3D Visualizer

import { createServer } from 'http';
import { readFileSync, existsSync } from 'fs';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { exec } from 'child_process';
import { platform } from 'os';

// Open URL in default browser
function openBrowser(url: string): void {
  const plat = platform();
  let cmd: string;

  if (plat === 'darwin') {
    cmd = `open "${url}"`;
  } else if (plat === 'win32') {
    cmd = `start "" "${url}"`;
  } else {
    cmd = `xdg-open "${url}"`;
  }

  exec(cmd, (err) => {
    if (err) {
      console.log(`\n  Open manually: ${url}\n`);
    }
  });
}

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
  // CORS headers for Aura API access
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = req.url?.split('?')[0] ?? '/';
  let filePath: string;

  // Route: / -> landing page
  // Route: /app -> dashboard (3D visualizer)
  // Route: /app/classic -> classic dashboard
  if (url === '/') {
    filePath = join(VISUALIZER_DIR, 'landing.html');
  } else if (url === '/app' || url === '/app/') {
    filePath = join(VISUALIZER_DIR, 'dashboard.html');
  } else if (url === '/app/visualizer') {
    filePath = join(VISUALIZER_DIR, 'index-minimal.html');
  } else if (url === '/app/classic') {
    filePath = join(VISUALIZER_DIR, 'index.html');
  } else {
    filePath = join(VISUALIZER_DIR, url);
  }

  if (!existsSync(filePath)) {
    res.writeHead(404);
    res.end('Not found');
    return;
  }

  const ext = extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  try {
    const content = readFileSync(filePath);
    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
    res.end(content);
  } catch (err) {
    res.writeHead(500);
    res.end('Server error');
  }
});

server.listen(PORT, () => {
  const dashboardUrl = `http://127.0.0.1:${PORT}/app`;

  console.log(`
╔═══════════════════════════════════════════════════════════╗
║              AURASECURITY - WEB SERVER                    ║
╠═══════════════════════════════════════════════════════════╣
║  Landing:    http://127.0.0.1:${PORT}                        ║
║  Dashboard:  http://127.0.0.1:${PORT}/app                    ║
║  Aura API:   http://127.0.0.1:3000                        ║
╚═══════════════════════════════════════════════════════════╝

Routes:
  /              Landing page
  /app           Dashboard (scan-first UI)
  /app/visualizer  3D Visualizer (legacy)
  /app/classic     Classic dashboard UI
`);

  // Auto-open browser (skip if NO_OPEN env var is set)
  if (!process.env.NO_OPEN) {
    console.log('  Opening browser...\n');
    openBrowser(dashboardUrl);
  }
});
