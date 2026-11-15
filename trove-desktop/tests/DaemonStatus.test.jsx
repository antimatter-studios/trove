// The Settings panel says who runs the trove daemon: this app, another
// troved, or nobody, or why hosting failed.

import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(() => Promise.resolve(() => {})) }));

import { invoke } from '@tauri-apps/api/core';
import { SettingsModal } from '../src/overlays.jsx';

const SETTINGS = { systemAgent: true, systemAgentLifetime: 3600, idleLockMinutes: 5, materialize: true };

async function line(status) {
  invoke.mockImplementation(async (command) => {
    if (command !== 'daemon_status') return null;
    if (status instanceof Error) throw status;
    return status;
  });
  render(<SettingsModal settings={SETTINGS} onChange={() => {}} onClose={() => {}} />);
  expect(invoke).toHaveBeenCalledWith('daemon_status');
  return screen.findByText(/^Daemon: (?!checking)/);
}

beforeEach(() => vi.clearAllMocks());

describe('daemon line in Settings', () => {
  it('says the app hosts the daemon', async () => {
    expect(await line({ mode: 'hosted' })).toHaveTextContent('Daemon: hosted by this app');
  });

  it('names the troved it is a client of', async () => {
    expect(await line({ mode: 'client', pid: 4242 })).toHaveTextContent('Daemon: using troved (pid 4242)');
  });

  it('shows why hosting failed', async () => {
    expect(await line({ mode: 'failed', error: 'binding /tmp/trove.sock: Address in use' }))
      .toHaveTextContent('Daemon: binding /tmp/trove.sock: Address in use');
  });

  it('says when nobody runs it', async () => {
    expect(await line({ mode: 'stopped' })).toHaveTextContent('Daemon: not running');
  });

  it('shows a failed status call rather than nothing', async () => {
    expect(await line(new Error('daemon_status unavailable'))).toHaveTextContent('Daemon: daemon_status unavailable');
  });
});
