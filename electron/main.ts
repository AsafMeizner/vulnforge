/**
 * VulnForge Electron Main Process
 *
 * Runs VulnForge as a native desktop app with:
 * - Express backend as a forked child process
 * - System tray icon with hide/show + workflow shortcuts
 * - Single-instance lock (second launch focuses the first)
 * - Headless mode (--headless or VULNFORGE_HEADLESS=1 starts with window hidden)
 * - Per-user data dir (userData) so the app works when installed in
 *   Program Files (no write permission to the install dir)
 *
 * Usage:
 *   npm run electron:dev       - dev: vite + tsx-watched server + electron
 *   npm run build:desktop       - package as .exe/.dmg/.AppImage
 */

import {
  app,
  BrowserWindow,
  shell,
  Tray,
  Menu,
  nativeImage,
  ipcMain,
  dialog,
} from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import { fork, type ChildProcess } from 'child_process';
import { existsSync } from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isDev = process.env.NODE_ENV === 'development';
const startHeadless =
  process.argv.includes('--headless') ||
  process.env.VULNFORGE_HEADLESS === '1';
const remoteServer = process.env.VULNFORGE_REMOTE_SERVER || '';

let mainWindow: BrowserWindow | null = null;
let serverProcess: ChildProcess | null = null;
let tray: Tray | null = null;
let isQuitting = false;

// ── Single-instance lock ────────────────────────────────────────────────
//
// Second-launch behaviour: focus the running instance instead of starting
// another process. Without this, a user clicking the shortcut twice gets
// two VulnForge backends fighting for port 3001.

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  // Another instance already owns the lock — bail out immediately.
  app.quit();
  process.exit(0);
}

app.on('second-instance', () => {
  // A user started VulnForge again while we're running. Focus our window.
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    if (!mainWindow.isVisible()) mainWindow.show();
    mainWindow.focus();
  } else {
    createWindow();
  }
});

// ── Server management ───────────────────────────────────────────────────

function resolveServerPath(): string {
  // Dev mode: run TS via tsx loader. Compiled mode: use dist-server.
  if (isDev) return path.join(__dirname, '..', 'server', 'index.ts');
  // The compiled server lives next to the electron main inside the packaged
  // asar. dist-server is copied to asar root by electron-builder's files
  // glob so the path is <asar>/dist-server/server/index.js.
  return path.join(__dirname, '..', 'dist-server', 'server', 'index.js');
}

function startServer(): void {
  if (remoteServer) return; // user is using a remote backend
  if (serverProcess) return;

  const serverPath = resolveServerPath();
  const execArgv = isDev ? ['--import', 'tsx'] : [];

  // Per-user data directory - critical for Program Files installs where
  // the app dir is read-only.
  const userDataDir = app.getPath('userData');
  const dbPath = path.join(userDataDir, 'vulnforge.db');

  serverProcess = fork(serverPath, [], {
    execArgv,
    env: {
      ...process.env,
      VULNFORGE_PORT: '3001',
      VULNFORGE_HEADLESS: startHeadless ? '1' : '0',
      VULNFORGE_DB_PATH: process.env.VULNFORGE_DB_PATH || dbPath,
      VULNFORGE_DATA_DIR: process.env.VULNFORGE_DATA_DIR || userDataDir,
    },
    stdio: 'pipe',
  });

  serverProcess.stdout?.on('data', (data: Buffer) => {
    const line = data.toString().trim();
    if (line) console.log('[server]', line);
  });

  serverProcess.stderr?.on('data', (data: Buffer) => {
    const line = data.toString().trim();
    if (line) console.error('[server]', line);
  });

  serverProcess.on('exit', (code) => {
    console.log(`[server] exited with code ${code}`);
    serverProcess = null;
    if (!isQuitting) {
      console.log('[server] restarting in 2s...');
      setTimeout(startServer, 2000);
    }
  });
}

function stopServer(): void {
  if (!serverProcess) return;
  try {
    serverProcess.kill();
  } catch {
    /* already gone */
  }
  serverProcess = null;
}

// ── Window ──────────────────────────────────────────────────────────────

function createWindow(): void {
  if (mainWindow) {
    if (!mainWindow.isVisible()) mainWindow.show();
    mainWindow.focus();
    return;
  }

  const preloadPath = path.join(__dirname, 'preload.js');
  const iconPath = path.join(__dirname, '..', 'assets', 'icon.png');

  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 700,
    title: 'VulnForge',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    backgroundColor: '#0d1117',
    icon: existsSync(iconPath) ? iconPath : undefined,
    show: !startHeadless,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      preload: preloadPath,
    },
  });

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
  } else {
    mainWindow.loadFile(
      path.join(__dirname, '..', 'dist', 'client', 'index.html')
    );
  }

  // External links open in the system browser, not a new Electron window.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  // Close button minimises to tray unless the user explicitly chose Quit.
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow?.hide();
      updateTrayMenu();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
    updateTrayMenu();
  });

  mainWindow.on('show', updateTrayMenu);
  mainWindow.on('hide', updateTrayMenu);
}

/** Route the window to a hash-routed page, creating it if needed. */
function navigate(hash: string): void {
  if (!mainWindow) {
    createWindow();
  }
  const win = mainWindow;
  if (!win) return;
  if (!win.isVisible()) win.show();
  win.focus();
  // The renderer uses hash-based routing (#scanner, #findings, etc.)
  win.webContents.executeJavaScript(
    `window.location.hash = ${JSON.stringify(hash)};`
  ).catch(() => { /* renderer may not be ready yet */ });
}

// ── System tray ─────────────────────────────────────────────────────────

function loadTrayIcon() {
  // Try the asset first, fall back to a bundled 16x16 data URL.
  const iconPath = path.join(__dirname, '..', 'assets', 'icon.png');
  let icon = nativeImage.createFromPath(iconPath);
  if (icon.isEmpty()) {
    icon = nativeImage.createFromDataURL(
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAADxJREFUOI1j/P///38GKgImahkAAENjwCgYKGAUDFgwYOZiYGD4T6YLGBkZGRjINwCbCyiPBlIMGJ0XBgoAAI7+E/Go+GdCAAAAAElFTkSuQmCC'
    );
  }
  if (process.platform === 'win32') {
    icon = icon.resize({ width: 16, height: 16 });
  }
  return icon;
}

function buildTrayMenu(): Menu {
  const windowVisible = mainWindow && mainWindow.isVisible();
  const showHideLabel = windowVisible ? 'Hide window' : 'Show window';
  const showHide = () => {
    if (!mainWindow) {
      createWindow();
      return;
    }
    if (mainWindow.isVisible()) mainWindow.hide();
    else {
      mainWindow.show();
      mainWindow.focus();
    }
  };

  return Menu.buildFromTemplate([
    {
      label: showHideLabel,
      click: showHide,
    },
    {
      label: 'Open in Browser',
      click: () => shell.openExternal('http://localhost:3001'),
    },
    { type: 'separator' },
    {
      label: 'Workflow',
      submenu: [
        { label: 'Run a new hunt...', click: () => navigate('scanner') },
        { label: 'Open findings queue', click: () => navigate('review') },
        { label: 'Open dashboard', click: () => navigate('dashboard') },
        { label: 'Open AI page', click: () => navigate('ai') },
      ],
    },
    { type: 'separator' },
    {
      label: `Server: ${remoteServer || 'http://localhost:3001'}`,
      enabled: false,
    },
    {
      label: 'MCP endpoint',
      sublabel: `${remoteServer || 'http://localhost:3001'}/mcp`,
      enabled: false,
    },
    {
      label: 'Restart server',
      enabled: !remoteServer,
      click: () => {
        stopServer();
        setTimeout(startServer, 200);
      },
    },
    { type: 'separator' },
    {
      label: 'Check for updates',
      click: () =>
        shell.openExternal('https://github.com/AsafMeizner/vulnforge/releases'),
    },
    {
      label: `About VulnForge v${app.getVersion()}`,
      enabled: false,
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        isQuitting = true;
        stopServer();
        app.quit();
      },
    },
  ]);
}

function createTray(): void {
  if (tray) return;
  const icon = loadTrayIcon();
  tray = new Tray(icon);
  tray.setToolTip('VulnForge - Vulnerability Research Platform');
  tray.setContextMenu(buildTrayMenu());
  tray.on('double-click', () => {
    if (mainWindow) {
      mainWindow.isVisible() ? mainWindow.hide() : mainWindow.show();
      if (mainWindow.isVisible()) mainWindow.focus();
    } else {
      createWindow();
    }
  });
}

function updateTrayMenu(): void {
  if (!tray) return;
  try {
    tray.setContextMenu(buildTrayMenu());
  } catch {
    /* tray destroyed during shutdown */
  }
}

// ── IPC (preload bridge targets) ────────────────────────────────────────

function registerIpcHandlers(): void {
  ipcMain.handle('get-version', () => app.getVersion());
  ipcMain.handle('quit', () => {
    isQuitting = true;
    stopServer();
    app.quit();
  });
  ipcMain.handle('open-external', (_evt, url: string) => {
    if (typeof url !== 'string' || !/^https?:\/\//.test(url)) return false;
    shell.openExternal(url);
    return true;
  });
  ipcMain.handle('open-path', (_evt, p: string) => {
    if (typeof p !== 'string' || !p) return '';
    return shell.openPath(p);
  });
  ipcMain.handle('open-file-dialog', async () => {
    const r = await dialog.showOpenDialog({ properties: ['openFile'] });
    return r.canceled ? null : r.filePaths[0];
  });
  ipcMain.handle('open-directory-dialog', async () => {
    const r = await dialog.showOpenDialog({ properties: ['openDirectory'] });
    return r.canceled ? null : r.filePaths[0];
  });
}

// ── App lifecycle ───────────────────────────────────────────────────────

app.on('ready', async () => {
  registerIpcHandlers();

  if (!remoteServer) {
    startServer();
    // Give the server a small head-start so the window's initial fetch
    // hits a live backend.
    await new Promise((r) => setTimeout(r, 2500));
  } else {
    console.log(`[Electron] Connecting to remote server: ${remoteServer}`);
  }

  createTray();

  if (!startHeadless) {
    createWindow();
  } else {
    console.log(
      '[Electron] Headless mode. Backend at http://localhost:3001; tray icon is your control surface.'
    );
  }
});

// Keep running in the tray when the last window closes.
app.on('window-all-closed', () => {
  /* no-op - tray keeps us alive until explicit Quit */
});

app.on('activate', () => {
  // macOS: re-create window when the dock icon is clicked.
  if (!mainWindow) createWindow();
});

app.on('before-quit', () => {
  isQuitting = true;
  stopServer();
});
