/**
 * VulnForge Electron Main Process
 *
 * Runs VulnForge as a native desktop app with:
 * - Express backend as child process
 * - System tray icon with minimize-to-tray
 * - Headless mode (--headless or minimize to tray)
 * - Auto-start option
 *
 * Usage:
 *   npm run electron:dev   — dev mode (Vite + Electron)
 *   npm run electron:build — package as .exe/.dmg/.AppImage
 */

import { app, BrowserWindow, shell, Tray, Menu, nativeImage } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import { fork } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isDev = process.env.NODE_ENV === 'development';
const startHeadless = process.argv.includes('--headless') || process.env.VULNFORGE_HEADLESS === '1';

let mainWindow: BrowserWindow | null = null;
let serverProcess: any = null;
let tray: Tray | null = null;
let isQuitting = false;

// ── Server management ────────────────────────────────────────────────────

function startServer() {
  const serverPath = isDev
    ? path.join(__dirname, '..', 'server', 'index.ts')
    : path.join(__dirname, '..', 'dist', 'server', 'index.js');

  const execArgv = isDev ? ['--import', 'tsx'] : [];

  serverProcess = fork(serverPath, [], {
    execArgv,
    env: {
      ...process.env,
      PORT: '3001',
      VULNFORGE_HEADLESS: startHeadless ? '1' : '0',
    },
    stdio: 'pipe',
  });

  serverProcess.stdout?.on('data', (data: Buffer) => {
    console.log('[server]', data.toString().trim());
  });

  serverProcess.stderr?.on('data', (data: Buffer) => {
    console.error('[server]', data.toString().trim());
  });

  serverProcess.on('exit', (code: number) => {
    console.log(`[server] exited with code ${code}`);
    if (!isQuitting) {
      console.log('[server] restarting...');
      setTimeout(startServer, 2000);
    }
  });
}

// ── Window ───────────────────────────────────────────────────────────────

function createWindow() {
  if (mainWindow) {
    mainWindow.show();
    mainWindow.focus();
    return;
  }

  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 700,
    title: 'VulnForge',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    backgroundColor: '#0d1117',
    icon: path.join(__dirname, '..', 'assets', 'icon.png'),
    show: !startHeadless,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: isDev
        ? path.join(__dirname, 'preload.ts')
        : path.join(__dirname, 'preload.js'),
    },
  });

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'client', 'index.html'));
  }

  // Open external links in system browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  // Minimize to tray instead of closing
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow?.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ── System Tray ──────────────────────────────────────────────────────────

function createTray() {
  // Create a simple 16x16 tray icon (fallback if assets/icon.png doesn't exist)
  let icon: nativeImage;
  try {
    icon = nativeImage.createFromPath(path.join(__dirname, '..', 'assets', 'icon.png'));
    if (icon.isEmpty()) throw new Error('empty');
  } catch {
    // Create a minimal icon programmatically
    icon = nativeImage.createFromDataURL(
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAADxJREFUOI1j/P///38GKgImahkAAENjwCgYKGAUDFgwYOZiYGD4T6YLGBkZGRjINwCbCyiPBlIMGJ0XBgoAAI7+E/Go+GdCAAAAAElFTkSuQmCC'
    );
  }

  if (process.platform === 'win32') {
    icon = icon.resize({ width: 16, height: 16 });
  }

  tray = new Tray(icon);
  tray.setToolTip('VulnForge — Vulnerability Research Platform');

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Show VulnForge',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        } else {
          createWindow();
        }
      },
    },
    {
      label: 'Open in Browser',
      click: () => shell.openExternal('http://localhost:3001'),
    },
    { type: 'separator' },
    {
      label: 'MCP Server',
      sublabel: 'http://localhost:3001/mcp',
      enabled: false,
    },
    {
      label: 'API',
      sublabel: 'http://localhost:3001/api',
      enabled: false,
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        isQuitting = true;
        if (serverProcess) serverProcess.kill();
        app.quit();
      },
    },
  ]);

  tray.setContextMenu(contextMenu);

  tray.on('double-click', () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    } else {
      createWindow();
    }
  });
}

// ── App lifecycle ────────────────────────────────────────────────────────

app.on('ready', async () => {
  startServer();

  // Wait for server to be ready
  await new Promise(resolve => setTimeout(resolve, 2500));

  createTray();

  if (!startHeadless) {
    createWindow();
  } else {
    console.log('[Electron] Running in headless mode. Server available at http://localhost:3001');
    console.log('[Electron] Right-click the system tray icon to show the window or quit.');
  }
});

app.on('window-all-closed', () => {
  // Don't quit — keep running in tray
  // On macOS this is standard behavior
});

app.on('activate', () => {
  // macOS: re-create window when dock icon clicked
  if (!mainWindow) createWindow();
});

app.on('before-quit', () => {
  isQuitting = true;
  if (serverProcess) {
    serverProcess.kill();
  }
});
