// Interactions on an unlocked vault: entries load from the backend
// (list_entries), selecting drives the detail pane (get_entry_detail),
// revealing unmasks the fetched password, and the command palette opens.
// All backend calls are mocked via src/api.js.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/react';

vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));
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
  listGroups: vi.fn(),
  setGroupTags: vi.fn(),
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
// An already-unlocked vault so the app lazily loads its entries via list_entries.
const OPEN_VAULT = { id: 'v1', name: 'Personal', file: 'personal.kdbx', path: '/vaults/personal.kdbx', locked: false };

async function mountUnlocked() {
  const utils = render(<App />);
  const c = utils.container;
  await waitFor(() => expect(c.querySelectorAll('.list .erow').length).toBe(2));
  return c;
}

beforeEach(() => {
  api.buildInfo.mockResolvedValue({ version: '0.8.0', mode: 'dev', commit: 'abc12345' });
  api.getSettings.mockResolvedValue({ systemAgent: false, systemAgentLifetime: 900, systemAgentConfirm: false, materialize: false });
  api.setSettings.mockResolvedValue(undefined);
  // Nothing has touched the file unless a test says so.
  api.vaultChangedOnDisk.mockResolvedValue(false);
  // Touch ID absent by default; the tests that care set it themselves.
  api.biometricStatus.mockResolvedValue({ available: false, enrolled: false });
  vi.clearAllMocks();
  try { localStorage.clear(); } catch { /* ignore */ }
  api.listVaults.mockResolvedValue([OPEN_VAULT]);
  api.listEntries.mockResolvedValue(ENTRIES);
  api.listGroups.mockResolvedValue([]);
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

  it('reloads when the vault file is changed by something else', async () => {
    const c = await mountUnlocked();
    expect(c.querySelectorAll('.list .erow').length).toBe(ENTRIES.length);

    // The CLI (or KeePassXC, or another Mac via iCloud) writes the file.
    const AFTER = [...ENTRIES, { ...ENTRIES[0], id: 'e-new', title: 'added-elsewhere',
      path: 'Work/added-elsewhere', groupPath: 'Work' }];
    api.vaultChangedOnDisk.mockResolvedValue(true);
    api.reloadVault.mockResolvedValue(AFTER);

    // Regaining focus is one of the two triggers (the other is a 3s poll,
    // which a test should not have to wait for).
    fireEvent.focus(window);

    await waitFor(() => expect(api.reloadVault).toHaveBeenCalledWith('v1'));
    await waitFor(() =>
      expect(c.querySelectorAll('.list .erow').length).toBe(AFTER.length));
    expect(c.textContent).toContain('added-elsewhere');
  });

  it('does not reload when nothing has touched the file', async () => {
    const c = await mountUnlocked();
    api.vaultChangedOnDisk.mockResolvedValue(false);
    fireEvent.focus(window);
    await waitFor(() => expect(api.vaultChangedOnDisk).toHaveBeenCalled());
    expect(api.reloadVault).not.toHaveBeenCalled();
    expect(c.querySelectorAll('.list .erow').length).toBe(ENTRIES.length);
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

  // Attribute editing. The detail pane could always SHOW attributes and copy
  // them, but there was no way to add or change one without leaving the app for
  // KeePassXC or the CLI — which is how a `git.token` attribute would have to
  // be created.
  async function openEditForm(c) {
    fireEvent.click(c.querySelectorAll('.list .erow')[0]);
    await waitFor(() => expect(api.getEntryDetail).toHaveBeenCalled());
    const edit = [...c.querySelectorAll('.detail button')].find((b) => /edit/i.test(b.textContent || b.title || ''));
    fireEvent.click(edit);
    await waitFor(() => expect(c.querySelector('.modal')).toBeTruthy());
    return c.querySelector('.modal');
  }

  it('prefills the edit form with the entry existing attributes', async () => {
    const c = await mountUnlocked();
    const modal = await openEditForm(c);
    const names = [...modal.querySelectorAll('input')].map((i) => i.value);
    expect(names).toContain('Host');
    expect(names).toContain('db.prod');
  });

  it('saves a newly added attribute', async () => {
    api.saveEntry.mockResolvedValue({ id: 'e1', entries: ENTRIES });
    const c = await mountUnlocked();
    const modal = await openEditForm(c);

    const add = [...modal.querySelectorAll('button')].find((b) => /add attribute/i.test(b.textContent));
    expect(add).toBeTruthy();
    fireEvent.click(add);

    const nameInputs = [...modal.querySelectorAll('input[aria-label^="Attribute name"]')];
    const valueInputs = [...modal.querySelectorAll('input[aria-label^="Attribute value"]')];
    fireEvent.change(nameInputs[nameInputs.length - 1], { target: { value: 'git.token' } });
    fireEvent.change(valueInputs[valueInputs.length - 1], { target: { value: 'tok_abc' } });

    const save = [...modal.querySelectorAll('button')].find((b) => /save changes/i.test(b.textContent));
    fireEvent.click(save);

    await waitFor(() => expect(api.saveEntry).toHaveBeenCalled());
    const input = api.saveEntry.mock.calls[0][1];
    expect(input.fields).toEqual(
      expect.arrayContaining([{ k: 'git.token', v: 'tok_abc' }]),
    );
    // The attribute it already had must still be there — adding one is not
    // replacing them.
    expect(input.fields).toEqual(expect.arrayContaining([{ k: 'Host', v: 'db.prod' }]));
  });

  it('a removed attribute is absent from the saved payload', async () => {
    api.saveEntry.mockResolvedValue({ id: 'e1', entries: ENTRIES });
    const c = await mountUnlocked();
    const modal = await openEditForm(c);

    const remove = [...modal.querySelectorAll('button')].find((b) => /remove attribute/i.test(b.title || ''));
    expect(remove).toBeTruthy();
    fireEvent.click(remove);

    const save = [...modal.querySelectorAll('button')].find((b) => /save changes/i.test(b.textContent));
    fireEvent.click(save);

    await waitFor(() => expect(api.saveEntry).toHaveBeenCalled());
    expect(api.saveEntry.mock.calls[0][1].fields).toEqual([]);
  });

  it('a half-typed attribute row is not sent', async () => {
    api.saveEntry.mockResolvedValue({ id: 'e1', entries: ENTRIES });
    const c = await mountUnlocked();
    const modal = await openEditForm(c);

    // Add a row and leave the name blank — someone who thinks better of it
    // should not have to delete the row before they can save.
    const add = [...modal.querySelectorAll('button')].find((b) => /add attribute/i.test(b.textContent));
    fireEvent.click(add);

    const save = [...modal.querySelectorAll('button')].find((b) => /save changes/i.test(b.textContent));
    fireEvent.click(save);

    await waitFor(() => expect(api.saveEntry).toHaveBeenCalled());
    const sent = api.saveEntry.mock.calls[0][1].fields;
    expect(sent.every((f) => f.k.trim() !== '')).toBe(true);
  });

  // Saving used to reset the folder to All Entries, losing your place on every
  // edit (#123). The rule now is "follow the entry": go to the folder it landed
  // in and select it. An edit in place therefore leaves you exactly where you
  // were, because the entry's folder is the folder you are browsing.
  it('an edit in place leaves the browsed folder alone', async () => {
    api.saveEntry.mockResolvedValue({ id: 'e1', entries: ENTRIES });
    const c = await mountUnlocked();
    // Navigate into the folder the entry is actually filed in. Sidebar folders
    // are `.tree-row`; the previous selector matched `.srow`, matched nothing,
    // and clicked conditionally — so this silently tested All Entries instead.
    //
    // `infra` itself holds no entries (postgres is in `infra/prod`) and now
    // lists nothing, so the leaf is where the entry is: expand, then select.
    const row = (re) => [...c.querySelectorAll('.pane.sidebar .tree-row')].find((r) => re.test(r.textContent));
    const infra = row(/infra/i);
    expect(infra).toBeTruthy();
    fireEvent.click(infra.querySelector('.tw'));
    await waitFor(() => expect(row(/prod/i)).toBeTruthy());
    fireEvent.click(row(/prod/i));
    await waitFor(() => expect(c.querySelectorAll('.list .erow').length).toBe(1));

    fireEvent.click(c.querySelectorAll('.list .erow')[0]);
    await waitFor(() => expect(api.getEntryDetail).toHaveBeenCalled());
    const edit = [...c.querySelectorAll('.detail button')].find((b) => /edit/i.test(b.textContent || b.title || ''));
    fireEvent.click(edit);
    await waitFor(() => expect(c.querySelector('.modal')).toBeTruthy());
    const save = [...c.querySelectorAll('.modal button')].find((b) => /save changes/i.test(b.textContent));
    fireEvent.click(save);

    await waitFor(() => expect(api.saveEntry).toHaveBeenCalled());
    // The entry stays selected rather than the list jumping back to the top.
    await waitFor(() => expect(c.querySelector('.erow.sel')).toBeTruthy());
  });

  it('the path sent is resolved against the folder being browsed', async () => {
    api.saveEntry.mockResolvedValue({ id: 'e1', entries: ENTRIES });
    const c = await mountUnlocked();
    fireEvent.click(c.querySelectorAll('.list .erow')[0]);
    await waitFor(() => expect(api.getEntryDetail).toHaveBeenCalled());
    const edit = [...c.querySelectorAll('.detail button')].find((b) => /edit/i.test(b.textContent || b.title || ''));
    fireEvent.click(edit);
    await waitFor(() => expect(c.querySelector('.modal')).toBeTruthy());

    const save = [...c.querySelectorAll('.modal button')].find((b) => /save changes/i.test(b.textContent));
    fireEvent.click(save);
    await waitFor(() => expect(api.saveEntry).toHaveBeenCalled());
    // Browsing All entries, so relative and absolute coincide: the entry keeps
    // the path it already had rather than being re-prefixed. The list is
    // title-sorted, so row 0 is fastmail.
    expect(api.saveEntry.mock.calls[0][1].path).toBe('personal/email/fastmail');
  });

  // Without a key on EntryForm, React reused the instance and its useState
  // initialiser did not re-run: pressing New entry while the form was open for
  // an existing entry kept that entry's values on screen while `entry` became
  // null — so saving created a duplicate of it instead of a new entry.
  it('New entry after editing shows an empty form, not the previous entry', async () => {
    const c = await mountUnlocked();
    fireEvent.click(c.querySelectorAll('.list .erow')[0]);
    await waitFor(() => expect(api.getEntryDetail).toHaveBeenCalled());
    const edit = [...c.querySelectorAll('.detail button')].find((b) => /edit/i.test(b.textContent || b.title || ''));
    fireEvent.click(edit);
    await waitFor(() => expect(c.querySelector('.modal')).toBeTruthy());
    const pathOf = (el) => el.querySelector('input.mono').value;
    expect(pathOf(c.querySelector('.modal'))).not.toBe('');

    // ⌘N while the form is open.
    fireEvent.keyDown(window, { key: 'n', metaKey: true });
    await waitFor(() => {
      expect(c.querySelector('.modal').textContent).toContain('New entry');
    });
    expect(pathOf(c.querySelector('.modal'))).toBe('');
  });

  it('a new entry starts with an empty password', async () => {
    const c = await mountUnlocked();
    fireEvent.keyDown(window, { key: 'n', metaKey: true });
    await waitFor(() => expect(c.querySelector('.modal')).toBeTruthy());
    const pw = c.querySelector('.modal input[type="password"]');
    expect(pw).toBeTruthy();
    expect(pw.value).toBe('');
  });

  // A folder holding only subfolders lists nothing. The detail pane resolves
  // the selection against ALL entries, so without clearing it you would be
  // reading the details of an entry the list in front of you does not contain.
  it('an empty folder clears the selection rather than showing a stale detail', async () => {
    const c = await mountUnlocked();
    fireEvent.click(c.querySelectorAll('.list .erow')[0]);
    await waitFor(() => expect(c.querySelector('.erow.sel')).toBeTruthy());

    const row = (re) => [...c.querySelectorAll('.pane.sidebar .tree-row')].find((r) => re.test(r.textContent));
    fireEvent.click(row(/infra/i));
    await waitFor(() => expect(c.querySelectorAll('.list .erow').length).toBe(0));
    expect(c.querySelector('.erow.sel')).toBeFalsy();
  });

  it('opens the command palette from the toolbar', async () => {
    const c = await mountUnlocked();
    const palBtn = c.querySelector('button[title*="Command palette"]');
    expect(palBtn).toBeTruthy();
    fireEvent.click(palBtn);
    await waitFor(() => expect(document.querySelector('.palette')).toBeTruthy());
    expect(document.querySelector('.pal-input input')).toBeTruthy();
  });

  it('renders two draggable pane dividers between the three panes', async () => {
    const c = await mountUnlocked();
    const dividers = c.querySelectorAll('.body .pane-divider');
    expect(dividers).toHaveLength(2);
    dividers.forEach((d) => expect(d.getAttribute('role')).toBe('separator'));
  });
});
