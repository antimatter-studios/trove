// The app boots against the real Tauri command surface (mocked here via
// src/api.js). These assert the chrome/theme render, and that the real unlock
// flow (unlock_vault) turns a locked vault into the live three-pane.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/react';

// The native file dialog is unavailable under happy-dom; stub it.
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));
// api.js is the ONLY module that talks to the backend — mock the whole surface.
vi.mock('../src/api.js', () => ({
  listVaults: vi.fn(),
  registerVault: vi.fn(),
  createVault: vi.fn(),
  unlockVault: vi.fn(),
  lockVault: vi.fn(),
  listEntries: vi.fn(),
  getField: vi.fn(),
  getEntryDetail: vi.fn(),
  saveEntry: vi.fn(),
  deleteEntry: vi.fn(),
  setFavorite: vi.fn(),
}));

import * as api from '../src/api.js';
import App from '../src/App.jsx';

const ENTRIES = [
  { id: 'e1', path: 'infra/prod/postgres', title: 'postgres', group: ['infra', 'prod'], groupPath: 'infra/prod', username: 'trove_app', url: 'postgres://db.prod', type: 'db', entryType: 'db', strength: 93, pwLen: 20, fav: true, created: '2025-02-01T09:00:00Z', modified: '2026-07-01T06:20:00Z', attachmentNames: [] },
  { id: 'e2', path: 'personal/email/fastmail', title: 'fastmail', group: ['personal', 'email'], groupPath: 'personal/email', username: 'you@fastmail.com', url: 'https://app.fastmail.com', type: 'login', entryType: 'login', strength: 95, pwLen: 30, fav: false, created: '2024-11-01T08:00:00Z', modified: '2026-06-29T20:10:00Z', attachmentNames: [] },
];
const DETAIL = { notes: 'primary db', fields: [{ k: 'Host', v: 'db.prod' }], password: 'pg-Pr0d-8842!zQmx-vK' };
const LOCKED_VAULT = { id: 'v1', name: 'Personal', file: 'personal.kdbx', path: '/vaults/personal.kdbx', locked: true };

beforeEach(() => {
  vi.clearAllMocks();
  document.documentElement.removeAttribute('data-theme');
  document.documentElement.removeAttribute('data-accent');
  try { localStorage.clear(); } catch { /* happy-dom always has it */ }
  api.listVaults.mockResolvedValue([]);
  api.unlockVault.mockResolvedValue(ENTRIES);
  api.listEntries.mockResolvedValue(ENTRIES);
  api.getEntryDetail.mockResolvedValue(DETAIL);
  api.getField.mockResolvedValue(DETAIL.password);
});

describe('app chrome + theme', () => {
  it('applies the dark theme + brass accent to <html>', async () => {
    render(<App />);
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe('dark'));
    expect(document.documentElement.dataset.accent).toBe('brass');
  });

  it('renders the windowed chrome: titlebar with three traffic lights + status pill', async () => {
    const { container: c } = render(<App />);
    await waitFor(() => expect(c.querySelector('.window')).toBeTruthy());
    expect(c.querySelector('.titlebar')).toBeTruthy();
    expect(c.querySelectorAll('.titlebar .traffic .tl')).toHaveLength(3);
    expect(c.querySelector('.toolbar .status-pill')).toBeTruthy();
  });

  it('a fresh boot with no registered vaults opens the Open-vault modal', async () => {
    const { container: c } = render(<App />);
    await waitFor(() => expect(c.querySelector('.modal') || document.querySelector('.modal')).toBeTruthy());
    expect(api.listVaults).toHaveBeenCalled();
  });
});

describe('real unlock flow', () => {
  it('unlocking a locked vault renders the live three-pane from unlock_vault', async () => {
    api.listVaults.mockResolvedValue([LOCKED_VAULT]);
    const { container: c } = render(<App />);
    // Locked → the Unlock card is shown.
    const input = await waitFor(() => {
      const el = c.querySelector('.unlock-card .ul-field input');
      if (!el) throw new Error('no unlock input yet');
      return el;
    });
    fireEvent.change(input, { target: { value: 'correct horse' } });
    fireEvent.submit(c.querySelector('.unlock-card'));

    await waitFor(() => expect(c.querySelector('.body .pane.sidebar')).toBeTruthy());
    expect(api.unlockVault).toHaveBeenCalledWith('v1', 'correct horse');
    expect(c.querySelector('.body .pane.list')).toBeTruthy();
    expect(c.querySelector('.body .pane.detail')).toBeTruthy();
    expect(c.querySelectorAll('.list .erow').length).toBe(2);
  });

  it('a wrong password surfaces the backend error and stays locked', async () => {
    api.listVaults.mockResolvedValue([LOCKED_VAULT]);
    api.unlockVault.mockRejectedValue('Incorrect master password');
    const { container: c } = render(<App />);
    const input = await waitFor(() => {
      const el = c.querySelector('.unlock-card .ul-field input');
      if (!el) throw new Error('no unlock input yet');
      return el;
    });
    fireEvent.change(input, { target: { value: 'nope' } });
    fireEvent.submit(c.querySelector('.unlock-card'));
    await waitFor(() => expect(c.querySelector('.ul-err').textContent).toContain('Incorrect master password'));
    expect(c.querySelector('.body .pane.sidebar')).toBeFalsy();
  });
});
