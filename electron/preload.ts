/**
 * VulnForge Electron Preload
 *
 * Minimal safe API surface exposed to the renderer. The renderer remains
 * sandboxed; every exposed method routes through ipcRenderer.invoke so
 * main.ts can validate inputs before touching the OS.
 *
 * Access from the frontend:  window.vulnforge.<method>()
 */

import { contextBridge, ipcRenderer } from 'electron';

type VulnForgeBridge = {
  /** 'win32' | 'darwin' | 'linux' - same shape as process.platform */
  platform: NodeJS.Platform;
  /** Always true when running inside Electron. */
  isElectron: true;
  /** App version from package.json via main.app.getVersion(). */
  getVersion: () => Promise<string>;
  /** Terminate the app (server included). Triggered from UI "Quit" affordance. */
  quit: () => Promise<void>;
  /** Open a URL in the system browser. Only http(s) URLs are honored. */
  openExternal: (url: string) => Promise<boolean>;
  /** Open a path in the OS shell (file explorer / Finder / xdg-open). */
  openPath: (path: string) => Promise<string>;
  /** Prompt the user to choose a file. Returns the path or null on cancel. */
  openFileDialog: () => Promise<string | null>;
  /** Prompt the user to choose a directory. Returns the path or null on cancel. */
  openDirectoryDialog: () => Promise<string | null>;
};

const bridge: VulnForgeBridge = {
  platform: process.platform,
  isElectron: true,
  getVersion: () => ipcRenderer.invoke('get-version'),
  quit: () => ipcRenderer.invoke('quit'),
  openExternal: (url) => ipcRenderer.invoke('open-external', url),
  openPath: (p) => ipcRenderer.invoke('open-path', p),
  openFileDialog: () => ipcRenderer.invoke('open-file-dialog'),
  openDirectoryDialog: () => ipcRenderer.invoke('open-directory-dialog'),
};

contextBridge.exposeInMainWorld('vulnforge', bridge);
