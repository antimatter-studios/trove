import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(() => Promise.resolve(() => {})) }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }));
vi.mock('@tauri-apps/api/window', () => ({ getCurrentWindow: () => ({ startDragging: vi.fn(), toggleMaximize: vi.fn() }) }));

import { invoke } from '@tauri-apps/api/core';
import App from '../src/App.jsx';

const databases = ['left', 'right'].map((id) => ({ id, path: `/${id}/same.kdbx`, name: 'same.kdbx', file: 'same.kdbx', locked: false, troveUuid: 'linked' }));
const entry = { id: 'entry', title: 'Example', path: 'Example', group: [], groupPath: '', username: 'chris', url: '', entryType: 'login', modified: '2026-11-10T00:00:00Z', attachmentNames: [] };

beforeEach(() => {
  vi.clearAllMocks();
  invoke.mockImplementation(async (command, args) => {
    switch (command) {
      case 'list_databases': return databases;
      case 'list_entries': return [entry];
      case 'get_entry_detail': return { notes: '', fields: [], password: 'hidden' };
      case 'get_settings': return {};
      case 'build_info': return { version: 'test' };
      case 'database_changed_on_disk': return false;
      case 'list_revision_entries': return [{ id: entry.id, title: entry.title, path: entry.path, token: args.id }];
      case 'get_entry_revisions': return [{ index: null, token: args.id, modified: entry.modified, fields: [{ name: 'Password', value: args.id + '-secret', protected: true }], attachments: [], properties: {} }];
      default: return [];
    }
  });
});

describe('database sync app navigation', () => {
  it('opens real history from the entry toolbar and returns from sync to groups', async () => {
    const { container } = render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: 'Entry history' }));
    expect(await screen.findByRole('dialog', { name: 'Entry history' })).toBeInTheDocument();
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('get_entry_revisions', { id: 'left', entryId: 'entry' }));
    fireEvent.click(screen.getByRole('button', { name: 'Close history' }));
    fireEvent.click(screen.getByRole('button', { name: 'Database Sync' }));
    expect(await screen.findByRole('heading', { name: 'Database Sync' })).toBeInTheDocument();
    await screen.findByText('1 different entries');
    fireEvent.click(container.querySelector('.tree-row[data-path="__root"]'));
    expect(screen.queryByRole('heading', { name: 'Database Sync' })).not.toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Entry history' })).toBeInTheDocument();
  });

  it('applies through the real API wrapper and refreshes the database actually written', async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: 'Database Sync' }));
    await screen.findByText('1 difference');
    fireEvent.click(screen.getByRole('button', { name: 'Use left version' }));
    expect(invoke.mock.calls.some(([command]) => command === 'apply_entry_revision')).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Apply version' }));
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('apply_entry_revision', {
      id: 'right', sourceId: 'left', entryId: 'entry', index: null, sourceToken: 'left', targetToken: 'right',
    }));
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('list_entries', { id: 'right' }));
    expect(await screen.findByText('Entry version saved to /right/same.kdbx')).toBeInTheDocument();
  });
});
