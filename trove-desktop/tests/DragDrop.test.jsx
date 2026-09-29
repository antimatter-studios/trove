// Dragging entries and folders onto the sidebar tree: the target lights up
// green when it would take the drop and red when it would not, and a release
// calls the backend with what the drop means.

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
  dropEntry: vi.fn(),
  dropGroup: vi.fn(),
}));

import * as api from '../src/api.js';
import App from '../src/App.jsx';

const E = (id, group, title) => ({ id, path: [...group, title].join('/'), title, group, groupPath: group.join('/'), username: 'u', url: '', type: 'login', entryType: 'login', strength: 90, pwLen: 20, fav: false, created: '2025-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z', attachmentNames: [] });
const ENTRIES = [E('e1', ['Alpha'], 'mail'), E('e2', ['Beta'], 'bank')];
const GROUPS = [[], ['Alpha'], ['Beta']].map((path) => ({ path, tags: [], inheritedTags: [], recycleBin: false, position: null }));
const ROW_H = 30;

// happy-dom lays nothing out. Stack the drop rows 30px apart, in document order,
// so the pointer can be aimed at one.
function layoutRows() {
  const rows = [...document.querySelectorAll('[data-drop-path]')];
  rows.forEach((el, i) => {
    el.getBoundingClientRect = () => ({ top: i * ROW_H, bottom: (i + 1) * ROW_H, left: 0, right: 200, height: ROW_H, width: 200 });
  });
  return rows.map((el) => el.dataset.dropPath);
}
const rowY = (paths, path, frac = 0.5) => paths.indexOf(path) * ROW_H + ROW_H * frac;
const move = (x, y, init = {}) => act(() => { window.dispatchEvent(new MouseEvent('pointermove', { clientX: x, clientY: y, ...init })); });

beforeEach(() => {
  vi.clearAllMocks();
  api.buildInfo.mockResolvedValue({ version: '0.8.0' });
  api.getSettings.mockResolvedValue({});
  api.vaultChangedOnDisk.mockResolvedValue(false);
  api.biometricStatus.mockResolvedValue({ available: false, enrolled: false });
  api.listVaults.mockResolvedValue([{ id: 'v1', name: 'P', file: 'p.kdbx', path: '/p.kdbx', locked: false }]);
  api.listEntries.mockResolvedValue(ENTRIES);
  api.listGroups.mockResolvedValue(GROUPS);
  api.getEntryDetail.mockResolvedValue({ notes: '', fields: [], password: '' });
  api.dropEntry.mockResolvedValue({ id: 'e1', entries: ENTRIES, groups: GROUPS });
  api.dropGroup.mockResolvedValue({ entries: ENTRIES, groups: GROUPS });
});

async function openApp() {
  const view = render(<App />);
  await waitFor(() => expect(view.container.querySelectorAll('.erow').length).toBe(2));
  return view;
}
const startDrag = (el, init = {}) => fireEvent.pointerDown(el, { button: 0, clientX: 500, clientY: 500, ...init });

describe('dragging an entry onto a folder', () => {
  it('shows green over a folder that takes it, and moves it on release', async () => {
    const { container: c } = await openApp();
    const mail = [...c.querySelectorAll('.erow')].find((r) => r.textContent.includes('mail'));
    startDrag(mail);
    move(400, 400);
    const paths = layoutRows();
    move(50, rowY(paths, 'Beta'));
    const ghost = document.querySelector('.dnd-ghost');
    expect(ghost.className).toContain(' ok');
    expect(ghost.textContent).toContain('move');
    const beta = document.querySelector('[data-drop-path="Beta"]');
    expect(beta.className).toContain('dnd-into');
    expect(beta.className).not.toContain('nodrop');
    await act(async () => { window.dispatchEvent(new MouseEvent('pointerup')); });
    expect(api.dropEntry).toHaveBeenCalledWith('v1', 'e1', 'Beta', false);
  });

  it('shows red over its own folder, and drops nothing there', async () => {
    const { container: c } = await openApp();
    const mail = [...c.querySelectorAll('.erow')].find((r) => r.textContent.includes('mail'));
    startDrag(mail);
    move(400, 400);
    const paths = layoutRows();
    move(50, rowY(paths, 'Alpha'));
    expect(document.querySelector('.dnd-ghost').className).toContain(' no');
    expect(document.querySelector('[data-drop-path="Alpha"]').className).toContain('nodrop');
    await act(async () => { window.dispatchEvent(new MouseEvent('pointerup')); });
    expect(api.dropEntry).not.toHaveBeenCalled();
  });

  it('copies with the modifier held', async () => {
    const { container: c } = await openApp();
    const mail = [...c.querySelectorAll('.erow')].find((r) => r.textContent.includes('mail'));
    startDrag(mail);
    move(400, 400);
    const paths = layoutRows();
    move(50, rowY(paths, 'Beta'), { altKey: true, ctrlKey: true });
    expect(document.querySelector('.dnd-ghost').textContent).toContain('copy');
    await act(async () => { window.dispatchEvent(new MouseEvent('pointerup')); });
    expect(api.dropEntry).toHaveBeenCalledWith('v1', 'e1', 'Beta', true);
  });
});

describe('carrying something over the entry list', () => {
  it('shows red on the card and the list, and drops nothing', async () => {
    const { container: c } = await openApp();
    const list = c.querySelector('.pane.list');
    list.getBoundingClientRect = () => ({ top: 0, bottom: 800, left: 300, right: 700, height: 800, width: 400 });
    startDrag(c.querySelector('.erow'));
    move(450, 400);
    expect(document.querySelector('.dnd-ghost').className).toContain(' no');
    expect(list.className).toContain('dnd-no');
    await act(async () => { window.dispatchEvent(new MouseEvent('pointerup')); });
    expect(api.dropEntry).not.toHaveBeenCalled();
    expect(list.className).not.toContain('dnd-no');
  });
});

describe('dragging a folder', () => {
  it('reorders siblings when dropped at the top edge of another', async () => {
    await openApp();
    const beta = document.querySelector('[data-path="Beta"]');
    startDrag(beta);
    move(400, 400);
    const paths = layoutRows();
    move(50, rowY(paths, 'Alpha', 0.1));
    expect(document.querySelector('.dnd-ghost').className).toContain(' ok');
    await act(async () => { window.dispatchEvent(new MouseEvent('pointerup')); });
    expect(api.dropGroup).toHaveBeenCalledWith('v1', 'Beta', '', false, ['Beta', 'Alpha']);
  });
});
