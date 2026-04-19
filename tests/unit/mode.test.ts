import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  getDeploymentMode,
  isServerMode,
  isDesktopMode,
  __resetDeploymentModeForTests,
} from '../../server/deployment/mode';

describe('deployment mode', () => {
  const original = process.env.VULNFORGE_MODE;

  beforeEach(() => {
    __resetDeploymentModeForTests();
  });

  afterEach(() => {
    if (original === undefined) delete process.env.VULNFORGE_MODE;
    else process.env.VULNFORGE_MODE = original;
    __resetDeploymentModeForTests();
  });

  it('env=server → server mode', () => {
    process.env.VULNFORGE_MODE = 'server';
    expect(getDeploymentMode()).toBe('server');
    expect(isServerMode()).toBe(true);
    expect(isDesktopMode()).toBe(false);
  });

  it('env=desktop → desktop mode', () => {
    process.env.VULNFORGE_MODE = 'desktop';
    expect(getDeploymentMode()).toBe('desktop');
    expect(isDesktopMode()).toBe(true);
    expect(isServerMode()).toBe(false);
  });

  it('caches first call', () => {
    process.env.VULNFORGE_MODE = 'server';
    expect(getDeploymentMode()).toBe('server');
    process.env.VULNFORGE_MODE = 'desktop';
    // Without reset, we expect the cache to still hold 'server'
    expect(getDeploymentMode()).toBe('server');
    __resetDeploymentModeForTests();
    expect(getDeploymentMode()).toBe('desktop');
  });

  it('unset + no electron + explicit 0.0.0.0 host → server', () => {
    delete process.env.VULNFORGE_MODE;
    delete process.env.ELECTRON_RUN_AS_NODE;
    process.env.VULNFORGE_HOST = '0.0.0.0';
    try {
      expect(getDeploymentMode()).toBe('server');
    } finally {
      delete process.env.VULNFORGE_HOST;
    }
  });

  it('unset + no electron + default (unset) host → desktop', () => {
    // Plain `npm run dev` case - no env vars set. The canonical
    // helper now matches what the legacy auth.ts local helper did
    // so local-dev keeps working without extra plumbing.
    delete process.env.VULNFORGE_MODE;
    delete process.env.ELECTRON_RUN_AS_NODE;
    delete process.env.VULNFORGE_HOST;
    expect(getDeploymentMode()).toBe('desktop');
  });

  it('unset + no electron + loopback host → desktop', () => {
    delete process.env.VULNFORGE_MODE;
    delete process.env.ELECTRON_RUN_AS_NODE;
    process.env.VULNFORGE_HOST = '127.0.0.1';
    try {
      expect(getDeploymentMode()).toBe('desktop');
    } finally {
      delete process.env.VULNFORGE_HOST;
    }
  });

  it('ELECTRON_RUN_AS_NODE → desktop mode', () => {
    delete process.env.VULNFORGE_MODE;
    process.env.ELECTRON_RUN_AS_NODE = '1';
    expect(getDeploymentMode()).toBe('desktop');
    delete process.env.ELECTRON_RUN_AS_NODE;
  });
});
