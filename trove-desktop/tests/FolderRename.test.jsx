// Renaming a folder from the Edit Folder dialog. These go through the real
// src/api.js, so they assert the exact Tauri command and arguments.

import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(() => Promise.resolve(() => {})) }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }));
vi.mock('@tauri-apps/api/window', () => ({ getCurrentWindow: () => ({ startDragging: vi.fn(), toggleMaximize: vi.fn() }) }));

import { invoke } from '@tauri-apps/api/core';
import App from '../src/App.jsx';
import { EditFolderModal } from '../src/overlays.jsx';

const entry = (id, group, title) => ({ id, title, path: [...group, title].join('/'), group, groupPath: group.join('/'), username: 'u', url: '', entryType: 'login', modified: '2026-11-10T00:00:00Z', attachmentNames: [] });
const group = (path, extra = {}) => ({ path, tags: [], inheritedTags: [], recycleBin: false, position: null, ...extra });

let entries;
let groups;
let renameError;

beforeEach(() => {
  vi.clearAllMocks();
  entries = [entry('e1', ['Web'], 'deploy'), entry('e2', ['Ops'], 'pager')];
  groups = [group([]), group(['Ops']), group(['Web'], { tags: ['prod'] }), group(['Recycle Bin'], { recycleBin: true }), group(['Recycle Bin', 'Old'])];
  renameError = null;
  invoke.mockImplementation(async (command, args) => {
    switch (command) {
      case 'list_databases': return [{ id: 'v1', path: '/v1.kdbx', name: 'v1.kdbx', file: 'v1.kdbx', locked: false }];
      case 'list_entries': return entries;
      case 'list_groups': return groups;
      case 'get_entry_detail': return { notes: '', fields: [], password: 'hidden' };
      case 'get_settings': return {};
      case 'build_info': return { version: 'test' };
      case 'database_changed_on_disk': return false;
      case 'set_group_tags':
        groups = groups.map((g) => (g.path.join('/') === args.path ? { ...g, tags: args.tags } : g));
        return groups;
      case 'rename_group': {
        if (renameError) throw renameError;
        const from = args.path.split('/');
        const to = [...from.slice(0, -1), args.name];
        const swap = (p) => (p.join('/') === args.path || p.join('/').startsWith(args.path + '/') ? [...to, ...p.slice(from.length)] : p);
        groups = groups.map((g) => ({ ...g, path: swap(g.path) }));
        entries = entries.map((e) => entry(e.id, swap(e.group), e.title));
        return { entries, groups };
      }
      default: return [];
    }
  });
});

async function openEditor(container, name) {
  await waitFor(() => expect(container.querySelector(`.tree-row[data-path="${name}"]`)).toBeTruthy());
  fireEvent.click(screen.getByRole('button', { name: `Edit ${name} folder` }));
  return screen.findByRole('heading', { name: 'Edit Folder' });
}

const renameCalls = () => invoke.mock.calls.filter(([command]) => command === 'rename_group');

describe('renaming a folder', () => {
  it('renames a folder from the Edit Folder dialog', async () => {
    const { container } = render(<App />);
    // The database opens in the folder of its first entry: Web.
    await waitFor(() => expect(container.querySelector('.tree-row.sel')?.dataset.path).toBe('Web'));
    await openEditor(container, 'Web');
    const name = screen.getByLabelText('Name');
    expect(name).toHaveValue('Web');
    fireEvent.change(name, { target: { value: 'Frontend' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(invoke).toHaveBeenCalledWith('rename_group', { id: 'v1', path: 'Web', name: 'Frontend' }));
    expect(await screen.findByText('Folder renamed')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Edit Folder' })).not.toBeInTheDocument();
    expect(container.querySelector('.tree-row[data-path="Frontend"] .tr-name')).toHaveTextContent('Frontend');
    expect(container.querySelector('.tree-row[data-path="Web"]')).toBeNull();
    expect(container.querySelector('.tree-row.sel').dataset.path).toBe('Frontend');
    // Tags were not touched, so only the rename was written.
    expect(invoke.mock.calls.some(([command]) => command === 'set_group_tags')).toBe(false);
  });

  it('shows the clash error and keeps the dialog open', async () => {
    renameError = 'a folder named "Ops" already exists in Root';
    const { container } = render(<App />);
    await openEditor(container, 'Web');
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Ops' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('a folder named "Ops" already exists in Root');
    expect(screen.getByRole('heading', { name: 'Edit Folder' })).toBeInTheDocument();
    expect(screen.getByLabelText('Name')).toHaveValue('Ops');
    expect(screen.getByRole('button', { name: 'Save' })).not.toBeDisabled();
    expect(container.querySelector('.tree-row[data-path="Web"]')).toBeTruthy();
  });

  it('no Name field for the recycle bin', () => {
    const bin = { name: 'Recycle Bin', groupPath: ['Recycle Bin'], tags: [], inheritedTags: [], recycleBin: true, inRecycleBin: true };
    const inside = { name: 'Old', groupPath: ['Recycle Bin', 'Old'], tags: [], inheritedTags: [], recycleBin: false, inRecycleBin: true };
    const root = { name: 'Root', groupPath: [], tags: [], inheritedTags: [] };
    for (const g of [bin, inside, root]) {
      const view = render(<EditFolderModal group={g} entries={[]} onClose={() => {}} onSave={() => {}} onDelete={() => {}} />);
      expect(screen.queryByLabelText('Name')).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument();
      view.unmount();
    }
  });

  it('saving tags without a name change does not call rename_group', async () => {
    const { container } = render(<App />);
    await openEditor(container, 'Web');
    const tagInput = screen.getByPlaceholderText('Add a folder tag');
    fireEvent.change(tagInput, { target: { value: 'edge' } });
    fireEvent.keyDown(tagInput, { key: 'Enter' });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(invoke).toHaveBeenCalledWith('set_group_tags', { id: 'v1', path: 'Web', tags: ['prod', 'edge'] }));
    expect(await screen.findByText('Folder tags saved')).toBeInTheDocument();
    expect(renameCalls()).toEqual([]);
  });

  it('applies a name change and a tag change from the same click', async () => {
    const { container } = render(<App />);
    await openEditor(container, 'Web');
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Frontend' } });
    const tagInput = screen.getByPlaceholderText('Add a folder tag');
    fireEvent.change(tagInput, { target: { value: 'edge' } });
    fireEvent.keyDown(tagInput, { key: 'Enter' });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(invoke).toHaveBeenCalledWith('set_group_tags', { id: 'v1', path: 'Frontend', tags: ['prod', 'edge'] }));
    expect(renameCalls()).toEqual([['rename_group', { id: 'v1', path: 'Web', name: 'Frontend' }]]);
    expect(await screen.findByText('Folder renamed')).toBeInTheDocument();
  });
});
