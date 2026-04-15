/**
 * VulnForge Electron Main Process
 *
 * This makes VulnForge run as a native desktop app.
 * It starts the Express backend server internally and opens
 * the frontend in a native window.
 *
 * Usage:
 *   npm run electron:dev   — dev mode (Vite + Electron)
 *   npm run electron:build — package as .exe/.dmg/.AppImage
 */

import { app, BrowserWindow, shell } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import { fork } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isDev = process.env.NODE_ENV === 'development';

let mainWindow: BrowserWindow | null = null;
let serverProcess: any = null;

function startServer() {
  // Start the Express backend as a child process
  const serverPath = path.join(__dirname, '..', 'server', 'index.ts');
  serverProcess = fork(serverPath, [], {
    execArgv: ['--import', 'tsx'],
    env: { ...process.env, PORT: '3001' },
    stdio: 'pipe'
  });

  serverProcess.stdout?.on('data', (data: Buffer) => {
    console.log('[server]', data.toString().trim());
  });

  serverProcess.stderr?.on('data', (data: Buffer) => {
    console.error('[server]', data.toString().trim());
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 700,
    title: 'VulnForge',
    titleBarStyle: 'hiddenInset',
    backgroundColor: '#0d1117',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.ts')
    }
  });

  // Load the frontend
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
  }

  // Open external links in system browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.on('ready', async () => {
  startServer();
  // Wait for server to be ready
  await new Promise(resolve => setTimeout(resolve, 2000));
  createWindow();
});

app.on('window-all-closed', () => {
  if (serverProcess) serverProcess.kill();
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (mainWindow === null) createWindow();
});
