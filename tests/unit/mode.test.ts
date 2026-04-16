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

  it('unset + no electron → defaults to server', () => {
    delete process.env.VULNFORGE_MODE;
    delete process.env.ELECTRON_RUN_AS_NODE;
    expect(getDeploymentMode()).toBe('server');
  });

  it('ELECTRON_RUN_AS_NODE → desktop mode', () => {
    delete process.env.VULNFORGE_MODE;
    process.env.ELECTRON_RUN_AS_NODE = '1';
    expect(getDeploymentMode()).toBe('desktop');
    delete process.env.ELECTRON_RUN_AS_NODE;
  });
});
