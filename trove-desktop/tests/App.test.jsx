// The app boots against the real Tauri command surface (mocked here via
// src/api.js). These assert the chrome/theme render, and that the real unlock
// flow (unlock_vault) turns a locked vault into the live three-pane.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/react';

// The native file dialog is unavailable under happy-dom; stub it.
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));
// api.js is the ONLY module that talks to the backend — mock the whole surface.
// overlays.jsx listens for unlock progress events. There is no Tauri IPC in a
// test process, so stub the bridge rather than letting the real one reject
// asynchronously in the middle of an unlock assertion.
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(() => Promise.resolve()) }));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

// The titlebar starts window drags through this; there is no window to drag in
// a test process.
vi.mock('@tauri-apps/api/window', () => ({
  getCurrentWindow: () => ({
    startDragging: () => Promise.resolve(),
    toggleMaximize: () => Promise.resolve(),
  }),
}));

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
  getSettings: vi.fn(),
  buildInfo: vi.fn(),
  setAgentKey: vi.fn(),
  setSettings: vi.fn(),
  vaultChangedOnDisk: vi.fn(),
  reloadVault: vi.fn(),
  biometricStatus: vi.fn(),
  biometricUnlock: vi.fn(),
  biometricEnroll: vi.fn(),
  biometricForget: vi.fn(),
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
  api.buildInfo.mockResolvedValue({ version: '0.8.0', mode: 'dev', commit: 'abc12345' });
  api.getSettings.mockResolvedValue({ systemAgent: false, systemAgentLifetime: 900, systemAgentConfirm: false, materialize: false });
  api.setSettings.mockResolvedValue(undefined);
  // Nothing has touched the file unless a test says so.
  api.vaultChangedOnDisk.mockResolvedValue(false);
  // Touch ID absent by default; the tests that care set it themselves.
  api.biometricStatus.mockResolvedValue({ available: false, enrolled: false });
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

  it('renders the windowed chrome: titlebar without drawn window buttons, and no toolbar row', async () => {
    const { container: c } = render(<App />);
    await waitFor(() => expect(c.querySelector('.window')).toBeTruthy());
    expect(c.querySelector('.titlebar')).toBeTruthy();
    // No drawn traffic lights: the OS draws the window buttons, and our own
    // put a second, dead set below the working ones.
    expect(c.querySelectorAll('.titlebar .tl')).toHaveLength(0);
    // The toolbar row is gone: lock state moved onto the vault chip, search
    // above the list it filters, and the app controls to the detail column.
    expect(c.querySelector('.toolbar')).toBeFalsy();
    expect(c.querySelector('.status-pill')).toBeFalsy();
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

  it('offers Touch ID only when the Mac can do it AND this vault is enrolled', async () => {
    api.listVaults.mockResolvedValue([LOCKED_VAULT]);

    // Neither: no button. A machine without a reader must not advertise one.
    api.biometricStatus.mockResolvedValue({ available: false, enrolled: false });
    const { container: a, unmount } = render(<App />);
    await waitFor(() => expect(a.querySelector('.unlock-card')).toBeTruthy());
    expect(a.querySelector('.ul-touchid')).toBeFalsy();
    unmount();

    // Available but nothing stored: still no button — prompting for a finger
    // and then admitting there is no password would read as a bug.
    api.biometricStatus.mockResolvedValue({ available: true, enrolled: false });
    const { container: b, unmount: unmountB } = render(<App />);
    await waitFor(() => expect(b.querySelector('.unlock-card')).toBeTruthy());
    expect(b.querySelector('.ul-touchid')).toBeFalsy();
    unmountB();

    // Both: the button appears.
    api.biometricStatus.mockResolvedValue({ available: true, enrolled: true });
    const { container: c } = render(<App />);
    await waitFor(() => expect(c.querySelector('.ul-touchid')).toBeTruthy());
  });

  it('a cancelled Touch ID prompt leaves the password field, not an error', async () => {
    api.listVaults.mockResolvedValue([LOCKED_VAULT]);
    api.biometricStatus.mockResolvedValue({ available: true, enrolled: true });
    // null is the cancel signal — a decision, not a failure.
    api.biometricUnlock.mockResolvedValue(null);

    const { container: c } = render(<App />);
    const button = await waitFor(() => {
      const el = c.querySelector('.ul-touchid');
      if (!el) throw new Error('no touch id button yet');
      return el;
    });
    fireEvent.click(button);

    await waitFor(() => expect(api.biometricUnlock).toHaveBeenCalledWith('v1'));
    // Still locked, still asking for a password, and nothing red.
    await waitFor(() => expect(c.querySelector('.unlock-card .ul-field input')).toBeTruthy());
    expect(c.querySelector('.ul-err').textContent.trim()).toBe('');
    expect(c.querySelector('.body .pane.sidebar')).toBeFalsy();
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
    // Submitting in the same tick as the change used to race the re-render and
    // be dropped; `submit` reads the field directly now, so this only asserts
    // the keystroke landed.
    expect(input.value).toBe('nope');
    fireEvent.submit(c.querySelector('.unlock-card'));
    await waitFor(() => expect(c.querySelector('.ul-err').textContent).toContain('Incorrect master password'));
    expect(c.querySelector('.body .pane.sidebar')).toBeFalsy();
  });
});

describe('selected-entry detail stays fresh after an edit', () => {
  // Regression: editing the selected entry keeps the same entry id but replaces
  // `entries` with a bumped `modified` stamp. The detail-fetch effect must
  // re-run so the old password/notes/fields don't linger (shown + copyable).
  it('re-fetches the detail when the selected entry is saved', async () => {
    api.listVaults.mockResolvedValue([LOCKED_VAULT]);
    const { container: c } = render(<App />);

    const input = await waitFor(() => {
      const el = c.querySelector('.unlock-card .ul-field input');
      if (!el) throw new Error('no unlock input yet');
      return el;
    });
    fireEvent.change(input, { target: { value: 'correct horse' } });
    fireEvent.submit(c.querySelector('.unlock-card'));
    await waitFor(() => expect(c.querySelector('.body .pane.detail')).toBeTruthy());

    // Open the edit form for the auto-selected entry (e1).
    fireEvent.click(c.querySelector('.pane.detail .icon-btn[title="Edit (E)"]'));
    await waitFor(() => expect(document.querySelector('.modal h2')?.textContent).toBe('Edit entry'));

    // From here the backend returns a fresh detail and a list where the saved
    // entry keeps its id but gets a new `modified` stamp.
    const NEW_DETAIL = { notes: 'rotated', fields: [], password: 'new-Pa55w0rd-rotated' };
    const bumped = ENTRIES.map((e) => (e.id === 'e1' ? { ...e, modified: '2026-07-27T10:00:00Z' } : e));
    api.getEntryDetail.mockClear();
    api.getEntryDetail.mockResolvedValue(NEW_DETAIL);
    api.saveEntry.mockResolvedValue({ entries: bumped, id: 'e1' });

    fireEvent.click(document.querySelector('.modal-foot .btn-primary'));

    // The effect re-runs on the bumped `modified` → the stale detail is replaced.
    await waitFor(() => expect(api.getEntryDetail).toHaveBeenCalledWith('v1', 'e1'));
  });
});
