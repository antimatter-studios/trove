import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(() => Promise.resolve(() => {})) }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }));
vi.mock('@tauri-apps/api/window', () => ({ getCurrentWindow: () => ({ startDragging: vi.fn(), toggleMaximize: vi.fn() }) }));

import { invoke } from '@tauri-apps/api/core';
import App from '../src/App.jsx';

let databases;
let saveError;
let removeError;
let refreshError;
const entry = { id: 'entry', title: 'Example', path: 'Example', group: [], groupPath: '', username: 'chris', url: '', entryType: 'login', modified: '2026-11-10T00:00:00Z', attachmentNames: [] };

beforeEach(() => {
  vi.clearAllMocks();
  databases = ['local', 'remote'].map((id) => ({ id, path: `/${id}/same.kdbx`, name: 'same.kdbx', file: 'same.kdbx', locked: false }));
  saveError = null;
  removeError = null;
  refreshError = false;
  invoke.mockImplementation(async (command, args) => {
    switch (command) {
      case 'list_databases': return databases;
      case 'list_entries':
        if (refreshError) throw new Error('refresh unavailable');
        return [entry];
      case 'get_entry_detail': return { notes: '', fields: [], password: 'hidden' };
      case 'get_settings': return {};
      case 'build_info': return { version: 'test' };
      case 'database_changed_on_disk': return false;
      case 'save_database':
        if (saveError) throw new Error(saveError);
        return;
      case 'remove_database':
        if (removeError) throw new Error(removeError);
        databases = databases.filter((database) => database.id !== args.id);
        return;
      default: return [];
    }
  });
});

async function openSwitcher(container) {
  await waitFor(() => expect(container.querySelector('.database-option')).toBeNull());
  await waitFor(() => expect(container.querySelector('.sb-database, .vc-change')).toBeTruthy());
  fireEvent.click(container.querySelector('.sb-database, .vc-change'));
  await screen.findByRole('button', { name: 'Remove database /local/same.kdbx' });
}

describe('database actions through the native API', () => {
  it('saves a non-active database and refreshes that database without switching', async () => {
    const { container } = render(<App />);
    await screen.findByRole('button', { name: 'Entry history' });
    await openSwitcher(container);
    fireEvent.click(screen.getByRole('button', { name: 'Save database /remote/same.kdbx' }));
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('save_database', { id: 'remote' }));
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('list_entries', { id: 'remote' }));
    expect(await screen.findByText('Database saved: /remote/same.kdbx')).toBeInTheDocument();
    expect(container.querySelector('.win-database-name')).toHaveTextContent('/local/same.kdbx');
  });

  it('removes an inactive database without switching the active one', async () => {
    const { container } = render(<App />);
    await screen.findByRole('button', { name: 'Entry history' });
    await openSwitcher(container);
    fireEvent.click(screen.getByRole('button', { name: 'Remove database /remote/same.kdbx' }));
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('remove_database', { id: 'remote' }));
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Remove database /remote/same.kdbx' })).not.toBeInTheDocument());
    expect(container.querySelector('.win-database-name')).toHaveTextContent('/local/same.kdbx');
    expect(await screen.findByText('Removed from Trove; file kept: /remote/same.kdbx')).toBeInTheDocument();
  });

  it('removes the active database and switches to another unlocked database', async () => {
    const { container } = render(<App />);
    await screen.findByRole('button', { name: 'Entry history' });
    await openSwitcher(container);
    fireEvent.click(screen.getByRole('button', { name: 'Remove database /local/same.kdbx' }));
    await waitFor(() => expect(container.querySelector('.win-database-name')).toHaveTextContent('/remote/same.kdbx'));
    expect(screen.queryByText('Unlock database')).not.toBeInTheDocument();
    expect(databases.map((database) => database.id)).toEqual(['remote']);
  });

  it('shows the open dialog after removing the final locked database', async () => {
    databases = [{ ...databases[0], locked: true }];
    const { container } = render(<App />);
    await openSwitcher(container);
    fireEvent.click(screen.getByRole('button', { name: 'Remove database /local/same.kdbx' }));
    expect(await screen.findByRole('heading', { name: 'Open database' })).toBeInTheDocument();
    expect(await screen.findByText(/No recent databases/)).toBeInTheDocument();
    expect(invoke.mock.calls.some(([command]) => command === 'save_database')).toBe(false);
  });

  it('keeps a database registered and visible when removal fails', async () => {
    removeError = 'cannot write registered databases';
    const { container } = render(<App />);
    await screen.findByRole('button', { name: 'Entry history' });
    await openSwitcher(container);
    fireEvent.click(screen.getByRole('button', { name: 'Remove database /local/same.kdbx' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(removeError);
    expect(screen.getByRole('button', { name: 'Remove database /local/same.kdbx' })).toBeEnabled();
    expect(container.querySelector('.win-database-name')).toHaveTextContent('/local/same.kdbx');
    expect(databases).toHaveLength(2);
  });

  it('reports native save failure without showing success', async () => {
    saveError = 'database is read only';
    const { container } = render(<App />);
    await screen.findByRole('button', { name: 'Entry history' });
    await openSwitcher(container);
    fireEvent.click(screen.getByRole('button', { name: 'Save database /local/same.kdbx' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(saveError);
    expect(screen.queryByText(/^Database saved:/)).not.toBeInTheDocument();
  });

  it('distinguishes a successful save from a later refresh failure', async () => {
    const { container } = render(<App />);
    await screen.findByRole('button', { name: 'Entry history' });
    await openSwitcher(container);
    refreshError = true;
    fireEvent.click(screen.getByRole('button', { name: 'Save database /local/same.kdbx' }));
    expect(await screen.findByText('Database saved, but refresh failed: Error: refresh unavailable')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});
