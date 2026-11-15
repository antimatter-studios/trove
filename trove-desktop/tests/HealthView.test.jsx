// The Password Health view: opened from the sidebar, it lists what
// database_health reports and leads back to each entry. The backend is mocked at
// the Tauri bridge so the real api.js wrapper is exercised.

import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(() => Promise.resolve(() => {})) }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }));
vi.mock('@tauri-apps/api/window', () => ({ getCurrentWindow: () => ({ startDragging: vi.fn(), toggleMaximize: vi.fn() }) }));

import { invoke } from '@tauri-apps/api/core';
import App from '../src/App.jsx';

const DATABASE = { id: 'v1', path: '/tmp/health.kdbx', name: 'health', file: 'health.kdbx', locked: false };
const entry = (id, path) => {
  const parts = path.split('/');
  return { id, path, title: parts.at(-1), group: parts.slice(0, -1), groupPath: parts.slice(0, -1).join('/'), username: '', url: '', entryType: 'login', modified: '2026-11-10T00:00:00Z', attachmentNames: [] };
};
const ENTRIES = [
  entry('a', 'Web/a'),
  entry('b', 'Web/b'),
  entry('weak', 'Web/weak'),
  entry('old', 'Mail/old'),
  entry('cert', 'Certs/expired'),
];
const FINDINGS = {
  reused: [{ entries: [{ id: 'a', path: 'Web/a' }, { id: 'b', path: 'Web/b' }] }],
  weak: [{ id: 'weak', path: 'Web/weak', score: 1 }],
  stale: [{ id: 'old', path: 'Mail/old', ageDays: 812 }],
  expired: [{ id: 'cert', path: 'Certs/expired', expiredAt: '2001-01-01T00:00:00+00:00' }],
};
const CLEAN = { reused: [], weak: [], stale: [], expired: [] };

let database;
let health;
let entries;

beforeEach(() => {
  vi.clearAllMocks();
  database = DATABASE;
  health = FINDINGS;
  entries = ENTRIES;
  invoke.mockImplementation(async (command) => {
    switch (command) {
      case 'list_databases': return [database];
      case 'list_entries': return entries;
      case 'get_entry_detail': return { notes: '', fields: [], password: 'hidden' };
      case 'get_settings': return {};
      case 'build_info': return { version: 'test' };
      case 'database_changed_on_disk': return false;
      case 'database_health': return health;
      case 'save_entry': return { id: 'new', entries, groups: [] };
      default: return [];
    }
  });
});

const healthCalls = () => invoke.mock.calls.filter(([command]) => command === 'database_health');

async function openHealth() {
  const result = render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: 'Password Health' }));
  expect(await screen.findByRole('heading', { name: 'Password Health' })).toBeInTheDocument();
  return result;
}

describe('password health view', () => {
  it('opens from the sidebar and lists each finding', async () => {
    await openHealth();
    expect(invoke).toHaveBeenCalledWith('database_health', { id: 'v1' });
    const section = async (name) => within(await screen.findByRole('region', { name }));
    const reused = await section('Reused');
    expect(reused.getByRole('heading')).toHaveTextContent('Reused 2');
    expect(reused.getByText('Web/a')).toBeInTheDocument();
    expect(reused.getByText('Web/b')).toBeInTheDocument();
    const weak = await section('Weak');
    expect(weak.getByRole('heading')).toHaveTextContent('Weak 1');
    expect(weak.getByText('Web/weak')).toBeInTheDocument();
    const old = await section('Old');
    expect(old.getByRole('heading')).toHaveTextContent('Old 1');
    expect(old.getByText('Mail/old')).toBeInTheDocument();
    expect(old.getByText('Unchanged for 812 days')).toBeInTheDocument();
    const expired = await section('Expired');
    expect(expired.getByRole('heading')).toHaveTextContent('Expired 1');
    expect(expired.getByText('Certs/expired')).toBeInTheDocument();
    expect(screen.queryByText('No problems found')).not.toBeInTheDocument();
  });

  it('clicking a finding selects the entry', async () => {
    const { container } = await openHealth();
    fireEvent.click(await screen.findByText('Mail/old'));
    expect(screen.queryByRole('heading', { name: 'Password Health' })).not.toBeInTheDocument();
    await waitFor(() => expect(container.querySelector('.list .erow.sel')).toBeTruthy());
    expect(container.querySelector('.list .erow.sel')).toHaveTextContent('old');
    expect([...container.querySelectorAll('.list .erow')].map((row) => row.textContent).join(' ')).not.toContain('weak');
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('get_entry_detail', { id: 'v1', entryId: 'old' }));
  });

  it('shows "No problems found" for a clean database', async () => {
    health = CLEAN;
    await openHealth();
    expect(await screen.findByText('No problems found')).toBeInTheDocument();
    for (const name of ['Reused', 'Weak', 'Old', 'Expired']) {
      expect(screen.queryByRole('region', { name })).not.toBeInTheDocument();
    }
  });

  it('refreshes after an entry is saved', async () => {
    const { container } = await openHealth();
    await screen.findByText('Web/weak');
    expect(healthCalls().length).toBe(1);
    health = CLEAN;
    entries = [...ENTRIES, entry('new', 'Web/new')];
    const create = [...container.querySelectorAll('.btn-accent')].find((button) => button.textContent.includes('Create item'));
    fireEvent.click(create);
    const modal = container.querySelector('.modal');
    fireEvent.change(modal.querySelector('input.inp.mono'), { target: { value: 'Web/new' } });
    fireEvent.change(modal.querySelector('input[type="password"]'), { target: { value: 'Unique-and-long-7$Qx!pL0' } });
    fireEvent.click(within(modal).getByRole('button', { name: 'Add entry' }));
    await waitFor(() => expect(invoke.mock.calls.some(([command]) => command === 'save_entry')).toBe(true));
    expect(await screen.findByText('No problems found')).toBeInTheDocument();
    expect(healthCalls().length).toBeGreaterThan(1);
    expect(screen.getByRole('heading', { name: 'Password Health' })).toBeInTheDocument();
  });

  it('has no Password Health button while the database is locked', async () => {
    database = { ...DATABASE, locked: true };
    render(<App />);
    expect(await screen.findByPlaceholderText('Master password')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Password Health' })).not.toBeInTheDocument();
  });
});
