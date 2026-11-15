// The app boots against the real Tauri command surface (mocked here via
// src/api.js). These assert the chrome/theme render, and that the real unlock
// flow (unlock_database) turns a locked database into the live three-pane.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { act, render, fireEvent, waitFor } from '@testing-library/react';
import { listen } from '@tauri-apps/api/event';

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
  entryCapabilities: vi.fn(() => Promise.resolve([])),
  groupCapabilities: vi.fn(() => Promise.resolve([])),
  listDatabases: vi.fn(),
  registerDatabase: vi.fn(),
  createDatabase: vi.fn(),
  unlockDatabase: vi.fn(),
  lockDatabase: vi.fn(),
  listEntries: vi.fn(),
  listGroups: vi.fn(),
  setGroupTags: vi.fn(),
  createGroup: vi.fn(),
  getField: vi.fn(),
  getEntryDetail: vi.fn(),
  getDatabaseMetadata: vi.fn(),
  setDatabaseMetadata: vi.fn(),
  setCustomAttribute: vi.fn(),
  removeCustomAttribute: vi.fn(),
  saveEntry: vi.fn(),
  deleteEntry: vi.fn(),
  setFavorite: vi.fn(),
  getSettings: vi.fn(),
  buildInfo: vi.fn(),
  setAgentKey: vi.fn(),
  setSettings: vi.fn(),
  databaseChangedOnDisk: vi.fn(),
  reloadDatabase: vi.fn(),
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
const LOCKED_DATABASE = { id: 'v1', name: 'Personal', file: 'personal.kdbx', path: '/databases/personal.kdbx', locked: true };
const OPEN_DATABASE = { id: 'v1', name: 'Personal', file: 'personal.kdbx', path: '/databases/personal.kdbx', locked: false };
const SECOND_LOCKED_DATABASE = { id: 'v2', name: 'Work', file: 'work.kdbx', path: '/databases/work.kdbx', locked: true };

beforeEach(() => {
  api.buildInfo.mockResolvedValue({ version: '0.8.0', mode: 'dev', commit: 'abc12345' });
  api.getSettings.mockResolvedValue({ systemAgent: false, systemAgentLifetime: 900, systemAgentConfirm: false, materialize: false });
  api.setSettings.mockResolvedValue(undefined);
  // Nothing has touched the file unless a test says so.
  api.databaseChangedOnDisk.mockResolvedValue(false);
  // Touch ID absent by default; the tests that care set it themselves.
  api.biometricStatus.mockResolvedValue({ available: false, enrolled: false });
  vi.clearAllMocks();
  document.documentElement.removeAttribute('data-theme');
  document.documentElement.removeAttribute('data-accent');
  try { localStorage.clear(); } catch { /* happy-dom always has it */ }
  api.listDatabases.mockResolvedValue([]);
  api.unlockDatabase.mockResolvedValue(ENTRIES);
  api.listEntries.mockResolvedValue(ENTRIES);
  api.listGroups.mockResolvedValue([]);
  api.createGroup.mockResolvedValue([]);
  api.getEntryDetail.mockResolvedValue(DETAIL);
  api.getDatabaseMetadata.mockResolvedValue({ name: 'Personal', description: '', defaultUsername: '', troveUuid: null });
  api.setDatabaseMetadata.mockResolvedValue({});
  api.setCustomAttribute.mockResolvedValue(DETAIL);
  api.removeCustomAttribute.mockResolvedValue(DETAIL);
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
    // The toolbar row is gone: lock state moved onto the database chip, search
    // above the list it filters, and the app controls to the detail column.
    expect(c.querySelector('.toolbar')).toBeFalsy();
    expect(c.querySelector('.status-pill')).toBeFalsy();
  });

  it('shows the database path beside its filename in the centered title', async () => {
    api.listDatabases.mockResolvedValue([LOCKED_DATABASE]);
    const { container: c } = render(<App />);
    // The title renders "—" until the database list arrives, so wait for the
    // text itself, not merely for the element.
    const title = c.querySelector('.win-database-name');
    await waitFor(() => expect(title.textContent).toBe('personal.kdbx (/databases/personal.kdbx)'));
    expect(title).toHaveAttribute('title', 'personal.kdbx (/databases/personal.kdbx)');
  });

  it('shows full paths on separate lines in the database switcher', async () => {
    const linkId = '3c7e4e44-5fca-4e2f-bb19-0912ebf2ab09';
    api.listDatabases.mockResolvedValue([
      { ...LOCKED_DATABASE, path: '/Volumes/homelab/backups/christhomas.kdbx', file: 'christhomas.kdbx', name: 'christhomas', troveUuid: linkId },
      { ...SECOND_LOCKED_DATABASE, path: '/Users/chris/Library/Databases/christhomas.kdbx', file: 'christhomas.kdbx', name: 'christhomas', troveUuid: linkId },
      { id: 'v3', name: 'Archive', file: 'archive.kdbx', path: '/Users/chris/archive.kdbx', locked: true },
    ]);
    const { container: c } = render(<App />);
    await waitFor(() => expect(c.querySelector('.vc-change')).toBeTruthy());
    fireEvent.click(c.querySelector('.vc-change'));
    await waitFor(() => expect(c.querySelectorAll('.vsw .database-option .vrf')).toHaveLength(3));
    const paths = c.querySelectorAll('.vsw .database-option .vrf');
    expect([...paths].map((path) => path.textContent)).toEqual([
      '/Users/chris/Library/Databases/christhomas.kdbx',
      '/Volumes/homelab/backups/christhomas.kdbx',
      '/Users/chris/archive.kdbx',
    ]);
    expect(c.querySelector('.popover.vsw')).toHaveClass('vsw');
    expect(c.querySelector('.vsw .database-option')).toBeTruthy();
    expect(c.querySelector('.database-link-group')).toBeTruthy();
    expect(c.querySelector('.database-group-items')).toContainElement(paths[0].closest('.database-option'));
    expect(c.querySelector('.database-group-heading')).toHaveTextContent('Linked copies');
    expect(c.querySelector('.database-group-heading svg')).toBeTruthy();
  });

  it('marks a read-only database in the centered title', async () => {
    api.listDatabases.mockResolvedValue([{ ...LOCKED_DATABASE, readOnly: true }]);
    const { container: c, findByText } = render(<App />);
    const badge = await findByText('READ ONLY');
    expect(badge).toBeTruthy();
    expect(c.querySelector('.win-title .dot')).toHaveClass('read-only');
  });

  it('opens and saves database metadata from the sidebar', async () => {
    api.listDatabases.mockResolvedValue([OPEN_DATABASE]);
    const { container: c, getByRole, findByLabelText } = render(<App />);
    await waitFor(() => expect(c.querySelector('.sb-database')).toBeTruthy());
    expect(c.textContent).not.toContain('Library');
    expect(c.textContent).not.toContain('All entries');
    expect(c.textContent).not.toContain('Favorites');
    fireEvent.click(getByRole('button', { name: 'Database metadata' }));

    const name = await findByLabelText('Name');
    fireEvent.change(name, { target: { value: 'Shared records' } });
    fireEvent.click(getByRole('button', { name: 'Save metadata' }));
    await waitFor(() => expect(api.setDatabaseMetadata).toHaveBeenCalledWith('v1', {
      name: 'Shared records', description: null, defaultUsername: null, troveUuid: null,
    }));
  });

  it('uses native copy in the database UUID field instead of copying the entry password', async () => {
    api.listDatabases.mockResolvedValue([OPEN_DATABASE]);
    const { getByRole, findByLabelText } = render(<App />);
    await waitFor(() => expect(document.querySelector('.sb-database')).toBeTruthy());
    fireEvent.click(await getByRole('button', { name: 'Database metadata' }));
    const uuid = await findByLabelText('Trove database UUID');
    api.getField.mockClear();

    expect(fireEvent.keyDown(uuid, { key: 'c', metaKey: true })).toBe(true);
    expect(api.getField).not.toHaveBeenCalled();
  });

  it('creates an empty folder from Create item without adding an entry', async () => {
    api.listDatabases.mockResolvedValue([OPEN_DATABASE]);
    api.createGroup.mockResolvedValue([{ path: ['infra', 'empty'], tags: [], inheritedTags: [], recycleBin: false }]);
    const { container: c } = render(<App />);
    await waitFor(() => expect([...c.querySelectorAll('.btn-accent')].some((button) => button.textContent.includes('Create item'))).toBe(true));
    const create = [...c.querySelectorAll('.btn-accent')].find((button) => button.textContent.includes('Create item'));
    fireEvent.click(create);
    fireEvent.click([...document.querySelectorAll('.modal button')].find((button) => button.textContent === 'Folder'));
    const path = document.querySelector('.modal-body input.inp');
    fireEvent.change(path, { target: { value: 'empty' } });
    fireEvent.click(document.querySelector('.modal-foot .btn-primary'));
    await waitFor(() => expect(api.createGroup).toHaveBeenCalledWith('v1', 'infra/prod/empty'));
    expect(api.saveEntry).not.toHaveBeenCalled();
  });

  it('a fresh boot with no registered databases opens the Open-database modal', async () => {
    const { container: c } = render(<App />);
    await waitFor(() => expect(c.querySelector('.modal') || document.querySelector('.modal')).toBeTruthy());
    expect(api.listDatabases).toHaveBeenCalled();
  });
});

// An unlock is several async hops — the backend call, progress events, then
// the database view mounting — and on a loaded CI runner that exceeds waitFor's
// one-second default even though nothing is wrong. These assertions have
// flaked four times in a day and blocked releases each time, so they wait as
// long as the work can legitimately take. The suite's own testTimeout (20s)
// still catches a genuine hang.
const UNLOCK_WAIT = { timeout: 10000 };

// The unlock card for the database under test. Before `listDatabases` resolves the
// card shows the "No database" placeholder, and the real database arriving resets the
// field — so typing into the placeholder loses the password and the submit is
// dropped. Wait for the database itself, not just for an input.
async function unlockInput(c) {
  return waitFor(() => {
    const el = c.querySelector('.unlock-card .ul-field input');
    if (!el || c.querySelector('.unlock-card .vc-name')?.textContent !== LOCKED_DATABASE.name) throw new Error('no unlock input for the database yet');
    return el;
  }, UNLOCK_WAIT);
}

describe('real unlock flow', () => {
  it('renders unlock progress events and drains queued steps before opening the database', async () => {
    let emitProgress;
    listen.mockImplementation((_event, callback) => {
      emitProgress = callback;
      return Promise.resolve(() => {});
    });
    api.listDatabases.mockResolvedValue([LOCKED_DATABASE]);
    const { container: c } = render(<App />);
    const input = await unlockInput(c);
    await waitFor(() => expect(emitProgress).toBeTypeOf('function'));
    fireEvent.change(input, { target: { value: 'correct horse' } });
    fireEvent.submit(c.querySelector('.unlock-card'));

    act(() => emitProgress({ payload: { step: 'open', state: 'done' } }));
    await waitFor(() => expect(c.querySelector('.ustep.done .ulabel')?.textContent).toBe('Decrypting the database'));
    act(() => emitProgress({ payload: { step: 'entries', state: 'done', detail: '2 entries' } }));
    await waitFor(() => expect(c.querySelectorAll('.ustep.done')).toHaveLength(2), UNLOCK_WAIT);
    expect(c.querySelector('.ustep.done .udetail')?.textContent).toBe('2 entries');

    await waitFor(() => expect(c.querySelector('.body .pane.sidebar')).toBeTruthy(), UNLOCK_WAIT);
  });

  it('opens the first entry folder after unlock instead of listing every entry together', async () => {
    api.listDatabases.mockResolvedValue([LOCKED_DATABASE]);
    const { container: c } = render(<App />);
    // Locked → the Unlock card is shown.
    const input = await unlockInput(c);
    fireEvent.change(input, { target: { value: 'correct horse' } });
    fireEvent.submit(c.querySelector('.unlock-card'));

    await waitFor(() => expect(c.querySelector('.body .pane.sidebar')).toBeTruthy(), UNLOCK_WAIT);
    expect(api.unlockDatabase).toHaveBeenCalledWith('v1', 'correct horse');
    expect(c.querySelector('.body .pane.list')).toBeTruthy();
    expect(c.querySelector('.body .pane.detail')).toBeTruthy();
    expect(c.querySelectorAll('.list .erow').length).toBe(1);
  });

  it('offers Touch ID only when the Mac can do it AND this database is enrolled', async () => {
    api.listDatabases.mockResolvedValue([LOCKED_DATABASE]);

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
    api.listDatabases.mockResolvedValue([LOCKED_DATABASE]);
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
    api.listDatabases.mockResolvedValue([LOCKED_DATABASE]);
    api.unlockDatabase.mockRejectedValue('Incorrect master password');
    const { container: c } = render(<App />);
    const input = await unlockInput(c);
    fireEvent.change(input, { target: { value: 'nope' } });
    // Submitted in the same tick as the change on purpose: that used to race
    // the re-render and be dropped silently, and `submit` reads the field
    // directly now so it cannot be. Asserting the field's value here would race
    // the other way — a rejected unlock clears it.
    fireEvent.submit(c.querySelector('.unlock-card'));
    await waitFor(
      () => expect((c.querySelector('.ul-err') || {}).textContent || '').toContain('Incorrect master password'),
      UNLOCK_WAIT,
    );
    expect(c.querySelector('.body .pane.sidebar')).toBeFalsy();
  });
});

describe('app idle lock', () => {
  it('continues counting down when the selected database is locked but another is open', async () => {
    api.listDatabases.mockResolvedValue([OPEN_DATABASE, SECOND_LOCKED_DATABASE]);
    api.getSettings.mockResolvedValue({
      systemAgent: false,
      systemAgentLifetime: 900,
      systemAgentConfirm: false,
      materialize: false,
      idleLockMinutes: 0.01,
    });
    const { container: c } = render(<App />);

    await waitFor(() => expect(c.querySelector('.body .pane.sidebar')).toBeTruthy());
    // Switch to a registered but locked database, reproducing the case where the
    // active view used to tear down the app-wide idle timer.
    fireEvent.keyDown(window, { key: '2', ctrlKey: true });
    await waitFor(() => expect(c.querySelector('.unlock-card')).toBeTruthy());

    await waitFor(
      () => expect(api.lockDatabase).toHaveBeenCalledWith('v1', false),
      { timeout: 4000 },
    );
  });
});

describe('selected-entry detail stays fresh after an edit', () => {
  // Regression: editing the selected entry keeps the same entry id but replaces
  // `entries` with a bumped `modified` stamp. The detail-fetch effect must
  // re-run so the old password/notes/fields don't linger (shown + copyable).
  it('re-fetches the detail when the selected entry is saved', async () => {
    api.listDatabases.mockResolvedValue([LOCKED_DATABASE]);
    const { container: c } = render(<App />);

    const input = await unlockInput(c);
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

describe('custom attributes can be managed from the detail pane', () => {
  it('edits, duplicates, and confirms deletion of an attribute', async () => {
    api.listDatabases.mockResolvedValue([OPEN_DATABASE]);
    const { container: c } = render(<App />);
    await waitFor(() => expect(c.querySelector('.body .pane.detail')).toBeTruthy());
    await waitFor(() => expect(c.querySelector('[aria-label="Edit Host"]')).toBeTruthy());

    fireEvent.click(c.querySelector('[aria-label="Edit Host"]'));
    fireEvent.change(c.querySelector('[aria-label="Attribute name Host"]'), { target: { value: 'Server' } });
    fireEvent.change(c.querySelector('[aria-label="Attribute value Host"]'), { target: { value: 'db.stage' } });
    api.setCustomAttribute.mockResolvedValue({ ...DETAIL, fields: [{ k: 'Server', v: 'db.stage' }] });
    fireEvent.click([...c.querySelectorAll('.fld button')].find((button) => button.textContent === 'Save'));
    await waitFor(() => expect(api.setCustomAttribute).toHaveBeenCalledWith('v1', 'e1', 'Host', 'Server', 'db.stage'));

    fireEvent.click(c.querySelector('[aria-label="Duplicate Server"]'));
    expect(c.querySelector('[aria-label="Attribute name Server"]')).toHaveValue('Server(2)');
    api.setCustomAttribute.mockResolvedValue({ ...DETAIL, fields: [{ k: 'Server', v: 'db.stage' }, { k: 'Server(2)', v: 'db.stage' }] });
    fireEvent.click([...c.querySelectorAll('.fld button')].find((button) => button.textContent === 'Save'));
    await waitFor(() => expect(api.setCustomAttribute).toHaveBeenLastCalledWith('v1', 'e1', null, 'Server(2)', 'db.stage'));

    fireEvent.click(c.querySelector('[aria-label="Delete Server"]'));
    fireEvent.click([...c.querySelectorAll('.btn-danger')].find((button) => button.textContent === 'Confirm delete'));
    await waitFor(() => expect(api.removeCustomAttribute).toHaveBeenCalledWith('v1', 'e1', 'Server'));
  });
});
