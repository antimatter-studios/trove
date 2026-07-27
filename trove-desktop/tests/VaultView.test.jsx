// Interactions on an unlocked vault: entries load from the backend
// (list_entries), selecting drives the detail pane (get_entry_detail),
// revealing unmasks the fetched password, and the command palette opens.
// All backend calls are mocked via src/api.js.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/react';

vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));
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
// An already-unlocked vault so the app lazily loads its entries via list_entries.
const OPEN_VAULT = { id: 'v1', name: 'Personal', file: 'personal.kdbx', path: '/vaults/personal.kdbx', locked: false };

async function mountUnlocked() {
  const utils = render(<App />);
  const c = utils.container;
  await waitFor(() => expect(c.querySelectorAll('.list .erow').length).toBe(2));
  return c;
}

beforeEach(() => {
  vi.clearAllMocks();
  try { localStorage.clear(); } catch { /* ignore */ }
  api.listVaults.mockResolvedValue([OPEN_VAULT]);
  api.listEntries.mockResolvedValue(ENTRIES);
  api.getEntryDetail.mockResolvedValue(DETAIL);
  api.getField.mockResolvedValue(DETAIL.password);
});

describe('unlocked vault interactions', () => {
  it('loads entries into the three-pane', async () => {
    const c = await mountUnlocked();
    expect(c.querySelector('.body .pane.sidebar')).toBeTruthy();
    expect(c.querySelector('.body .pane.list')).toBeTruthy();
    expect(c.querySelector('.body .pane.detail')).toBeTruthy();
    expect(c.textContent).toContain('All entries');
    expect(api.listEntries).toHaveBeenCalledWith('v1');
  });

  it('selecting a different entry updates the detail title (via get_entry_detail)', async () => {
    const c = await mountUnlocked();
    const before = c.querySelector('.detail .dt-title')?.textContent;
    const rows = [...c.querySelectorAll('.list .erow')];
    const other = rows.find((r) => r.querySelector('.etitle-txt')?.textContent !== before);
    fireEvent.click(other);
    await waitFor(() => {
      const after = c.querySelector('.detail .dt-title')?.textContent;
      expect(after).toBeTruthy();
      expect(after).not.toBe(before);
    });
    expect(api.getEntryDetail).toHaveBeenCalled();
  });

  it('revealing unmasks the fetched password', async () => {
    const c = await mountUnlocked();
    const secretField = await waitFor(() => {
      const f = [...c.querySelectorAll('.detail .field')].find((x) => x.querySelector('.fv.secret'));
      if (!f) throw new Error('secret field not ready');
      return f;
    });
    expect(secretField.querySelector('.fv.secret').textContent).toMatch(/^•+$/);
    fireEvent.click(secretField.querySelector('.facts .fact')); // reveal is the first fact button
    await waitFor(() => expect(secretField.querySelector('.fv.secret')).toBeFalsy());
    expect(secretField.querySelector('.fv').textContent).toContain(DETAIL.password);
  });

  it('opens the command palette from the toolbar', async () => {
    const c = await mountUnlocked();
    const palBtn = c.querySelector('button[title*="Command palette"]');
    expect(palBtn).toBeTruthy();
    fireEvent.click(palBtn);
    await waitFor(() => expect(document.querySelector('.palette')).toBeTruthy());
    expect(document.querySelector('.pal-input input')).toBeTruthy();
  });
});
