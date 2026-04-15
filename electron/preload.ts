/**
 * VulnForge Electron Preload Script
 *
 * Exposes safe APIs to the renderer process.
 * The renderer (React app) can use these to interact
 * with native OS features without full node access.
 */

import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('vulnforge', {
  // Platform info
  platform: process.platform,
  isElectron: true,

  // File system (via IPC to main process)
  openFileDialog: () => ipcRenderer.invoke('open-file-dialog'),
  openDirectoryDialog: () => ipcRenderer.invoke('open-directory-dialog'),

  // Shell
  openExternal: (url: string) => ipcRenderer.invoke('open-external', url),
  openPath: (path: string) => ipcRenderer.invoke('open-path', path),

  // App
  getVersion: () => ipcRenderer.invoke('get-version'),
  quit: () => ipcRenderer.invoke('quit'),
});
