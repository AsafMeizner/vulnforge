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
  nativeTheme,
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

// The port the backend actually bound to. Starts as the preferred 3001
// but the server will increment on EADDRINUSE and report back the real
// value. Window + tray display + renderer injection all use this.
let actualPort = 3001;
let portResolved: Promise<number> | null = null;
let resolvePortListener: ((p: number) => void) | null = null;

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

  // In a packaged app, sql.js's native .wasm file lives inside
  // app.asar.unpacked/node_modules/sql.js/dist/sql-wasm.wasm (it must be
  // unpacked because asar's read-only overlay doesn't expose .wasm to
  // child processes the way it exposes .js). We derive that path from
  // app.getAppPath() and hand it to the forked server explicitly so it
  // doesn't have to guess.
  const appPath = app.getAppPath(); // e.g. .../resources/app.asar
  const unpackedRoot = appPath.replace(/\.asar$/, '.asar.unpacked');
  const wasmCandidate = path.join(
    unpackedRoot,
    'node_modules',
    'sql.js',
    'dist',
    'sql-wasm.wasm'
  );
  const wasmPath = existsSync(wasmCandidate) ? wasmCandidate : '';

  // Establish a fresh port-resolved promise for this server life.
  portResolved = new Promise<number>((resolve) => {
    resolvePortListener = resolve;
  });

  serverProcess = fork(serverPath, [], {
    execArgv,
    env: {
      ...process.env,
      VULNFORGE_PORT: '3001',
      VULNFORGE_HEADLESS: startHeadless ? '1' : '0',
      VULNFORGE_DB_PATH: process.env.VULNFORGE_DB_PATH || dbPath,
      VULNFORGE_DATA_DIR: process.env.VULNFORGE_DATA_DIR || userDataDir,
      // Point server at the unpacked sql.js WASM. Only set when the
      // candidate actually exists so in dev mode we fall through to the
      // server's own resolver.
      ...(wasmPath ? { VULNFORGE_WASM_PATH: wasmPath } : {}),
      // Bind to loopback only in desktop mode. Default server binding is
      // 0.0.0.0 (LAN-reachable), which is wrong for a desktop app - any
      // other device on the Wi-Fi could hit /api/*.
      VULNFORGE_HOST: process.env.VULNFORGE_HOST || '127.0.0.1',
      // Electron loads the renderer from file:// (origin is "null" or
      // "file://" depending on platform/version). The server's default
      // CORS allowlist is localhost:5173 etc.; without this, the
      // renderer's fetch() to /api/* is blocked. Since the server is
      // bound to 127.0.0.1 above, the * here is not externally exposed.
      VULNFORGE_CORS_ORIGIN: process.env.VULNFORGE_CORS_ORIGIN || '*',
    },
    stdio: 'pipe',
  });

  serverProcess.stdout?.on('data', (data: Buffer) => {
    const text = data.toString();
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      // Parse the structured marker the server prints once the listen()
      // callback fires. This is our canonical source for the bound port.
      const m = trimmed.match(/^VULNFORGE_READY_PORT=(\d+)/);
      if (m) {
        const p = parseInt(m[1], 10);
        if (Number.isFinite(p) && p > 0 && p < 65536) {
          actualPort = p;
          if (resolvePortListener) {
            resolvePortListener(p);
            resolvePortListener = null;
          }
          updateTrayMenu();
        }
      }
      console.log('[server]', trimmed);
    }
  });

  // IPC from fork() - backup channel for the same port signal,
  // guarantees we don't miss it if stdout buffers.
  serverProcess.on('message', (msg: any) => {
    if (msg && msg.type === 'vulnforge:ready' && typeof msg.port === 'number') {
      actualPort = msg.port;
      if (resolvePortListener) {
        resolvePortListener(msg.port);
        resolvePortListener = null;
      }
      updateTrayMenu();
    }
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
  const iconPath = resolveWindowIcon();

  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 700,
    title: 'VulnForge',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    backgroundColor: '#0d1117',
    icon: iconPath ? iconPath : undefined,
    show: !startHeadless,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      preload: preloadPath,
    },
  });

  // Pass the live port to the renderer via the URL search string. The
  // frontend's api.ts reads `?api=...` and `?ws=...` (fallback to '/api'
  // for the dev vite proxy). This is what unbreaks file:// packaged
  // fetches which would otherwise hit `file:///api/...`.
  const apiOrigin = remoteServer || `http://127.0.0.1:${actualPort}`;
  const wsOrigin = remoteServer
    ? remoteServer.replace(/^http/, 'ws')
    : `ws://127.0.0.1:${actualPort}`;
  const search = `api=${encodeURIComponent(apiOrigin + '/api')}&ws=${encodeURIComponent(wsOrigin + '/ws')}`;

  if (isDev) {
    mainWindow.loadURL(`http://localhost:5173/?${search}`);
  } else {
    mainWindow.loadFile(
      path.join(__dirname, '..', 'dist', 'client', 'index.html'),
      { search }
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

// ── Theme-aware icon resolution ─────────────────────────────────────────

/**
 * Return a PNG path for the window/tray icon that matches the OS
 * dark/light theme - light logo on dark themes, dark logo on light
 * themes - so the icon stays readable against the taskbar/titlebar.
 *
 * Falls back through candidates so the app still launches if some
 * assets are missing in a stripped-down package.
 */
function resolveWindowIcon(): string | null {
  const dark = nativeTheme.shouldUseDarkColors;
  const base = path.join(__dirname, '..');
  const candidates = [
    // Packaged + dev: brand assets copied into the app
    path.join(base, 'public', 'brand', dark ? 'logo-square-white.png' : 'logo-square.png'),
    // Legacy single icon
    path.join(base, 'assets', 'icon.png'),
    // Always-white fallback (light theme looks fine with it too)
    path.join(base, 'public', 'brand', 'logo-square-white.png'),
  ];
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return null;
}

// ── System tray ─────────────────────────────────────────────────────────

function loadTrayIcon() {
  // Picks a theme-matched icon first; falls through to the legacy
  // asset, then a baked-in 16x16 data URL if nothing else resolves.
  let icon: Electron.NativeImage;
  const themed = resolveWindowIcon();
  if (themed) {
    icon = nativeImage.createFromPath(themed);
  } else {
    icon = nativeImage.createFromDataURL(
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAADxJREFUOI1j/P///38GKgImahkAAENjwCgYKGAUDFgwYOZiYGD4T6YLGBkZGRjINwCbCyiPBlIMGJ0XBgoAAI7+E/Go+GdCAAAAAElFTkSuQmCC'
    );
  }
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

/**
 * Swap window + tray icon whenever the OS theme flips. Called from the
 * `ready` handler via nativeTheme.on('updated', ...).
 */
function refreshThemeAwareIcons(): void {
  const windowIconPath = resolveWindowIcon();
  if (windowIconPath && mainWindow) {
    try { mainWindow.setIcon(windowIconPath); } catch { /* ignore */ }
  }
  if (tray) {
    try { tray.setImage(loadTrayIcon()); } catch { /* ignore */ }
  }
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
      click: () =>
        shell.openExternal(remoteServer || `http://localhost:${actualPort}`),
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
      label: `Server: ${remoteServer || `http://localhost:${actualPort}`}`,
      enabled: false,
    },
    {
      label: 'MCP endpoint',
      sublabel: `${remoteServer || `http://localhost:${actualPort}`}/mcp`,
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
    // Wait for the server to actually bind before opening the window,
    // so the renderer's first fetch hits a live port. Cap the wait so
    // we never hang forever if the server errors out - if the timeout
    // fires we fall through and open the window against the default
    // port anyway, and it'll recover on retry.
    if (portResolved) {
      await Promise.race([
        portResolved,
        new Promise<number>((resolve) => setTimeout(() => resolve(actualPort), 8000)),
      ]);
    }
  } else {
    console.log(`[Electron] Connecting to remote server: ${remoteServer}`);
  }

  createTray();

  // React to OS theme flips: swap the window + tray icon so the app
  // matches the taskbar/titlebar contrast the user just switched into.
  // Registered once here at app ready so it fires for every future flip.
  nativeTheme.on('updated', refreshThemeAwareIcons);

  if (!startHeadless) {
    createWindow();
  } else {
    console.log(
      `[Electron] Headless mode. Backend at http://localhost:${actualPort}; tray icon is your control surface.`
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
