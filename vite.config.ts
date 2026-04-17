import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  // Relative base so the built index.html's asset URLs work under
  // Electron's file:// protocol. Without this, references resolve from
  // the drive root and the app shows a black screen with ERR_FILE_NOT_FOUND
  // on every chunk. Web/server mode serves from '/' anyway, so './' is safe.
  base: './',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: (() => {
    // Proxy target port resolution (dev flow):
    //   1. VITE_API_PORT or VULNFORGE_PORT env (explicit override)
    //   2. `.vulnforge-port` file written by a running server on startup
    //      - handles the case where the server's port-retry landed on
    //        something other than 3001
    //   3. 3001 default
    // Re-reading this file on every proxy request ensures that if the
    // user restarts the server on a different port without restarting
    // vite, the proxy catches up.
    let fs;
    try { fs = require('fs'); } catch { fs = null; }
    const readPortFromFile = (): string | null => {
      try {
        if (fs && fs.existsSync('.vulnforge-port')) {
          const p = fs.readFileSync('.vulnforge-port', 'utf8').trim();
          if (/^\d+$/.test(p)) return p;
        }
      } catch { /* ignore */ }
      return null;
    };
    const envPort = process.env.VITE_API_PORT || process.env.VULNFORGE_PORT;
    const filePort = readPortFromFile();
    const initialPort = envPort || filePort || '3001';
    console.log(
      `[vite] proxying /api /ws /mcp -> http://localhost:${initialPort}` +
      (envPort ? ' (env)' : filePort ? ' (from .vulnforge-port)' : ' (default)')
    );
    const targetFor = (proto: 'http' | 'ws') => {
      // Prefer env > file > default on every call so a restarted server
      // on a different port is followed without restarting vite.
      const p = envPort || readPortFromFile() || '3001';
      return `${proto}://localhost:${p}`;
    };
    return {
      port: 5173,
      proxy: {
        '/api': {
          target: targetFor('http'),
          changeOrigin: true,
          router: () => targetFor('http'),
        },
        '/ws': {
          target: targetFor('ws'),
          ws: true,
          changeOrigin: true,
          router: () => targetFor('ws'),
        },
        '/mcp': {
          target: targetFor('http'),
          changeOrigin: true,
          router: () => targetFor('http'),
        },
      },
    };
  })(),
  build: {
    outDir: 'dist/client',
    sourcemap: true,
  },
});
