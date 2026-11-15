import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('../src/api.js', () => ({ getEntryRevisions: vi.fn(), applyEntryRevision: vi.fn(), listRevisionEntries: vi.fn(), databaseChangedOnDisk: vi.fn(), reloadDatabase: vi.fn() }));
import * as api from '../src/api.js';
import { DatabaseSync, RevisionComparison } from '../src/DatabaseSync.jsx';

const left = { id: 'left', path: '/local/same.kdbx', troveUuid: 'linked' };
const right = { id: 'right', path: '/remote/same.kdbx', troveUuid: 'linked' };
const revision = (token, value, index = null) => ({ index, token, fields: [{ name: 'Password', value, protected: true }], attachments: [], properties: {} });

describe('revision choice UI', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.databaseChangedOnDisk.mockResolvedValue(false);
    api.reloadDatabase.mockResolvedValue([]);
    api.getEntryRevisions.mockImplementation((id) => Promise.resolve(id === 'left' ? [revision('left-current', 'left-secret'), revision('left-old', 'old-secret', 0)] : [revision('right-current', 'right-secret')]));
    api.applyEntryRevision.mockResolvedValue();
  });

  it('masks secrets and writes the selected version only after confirmation', async () => {
    render(<RevisionComparison database={left} otherDatabase={right} entryId="entry" />);
    await screen.findByText('1 difference');
    expect(screen.queryByText('left-secret')).not.toBeInTheDocument();
    expect(screen.queryByText('right-secret')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Reveal protected values' }));
    expect(screen.getByText('right-secret')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Use right version' }));
    expect(api.applyEntryRevision).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Apply version' }));
    await waitFor(() => expect(api.applyEntryRevision).toHaveBeenCalledWith('left', 'right', 'entry', null, 'right-current', 'left-current'));
  });

  it('can pick the left version and write to the right-hand database', async () => {
    render(<RevisionComparison database={left} otherDatabase={right} entryId="entry" />);
    await screen.findByText('1 difference');
    fireEvent.click(screen.getByRole('button', { name: 'Use left version' }));
    fireEvent.click(screen.getByRole('button', { name: 'Apply version' }));
    await waitFor(() => expect(api.applyEntryRevision).toHaveBeenCalledWith('right', 'left', 'entry', null, 'left-current', 'right-current'));
  });

  it('compares real history and restores an older version as a new edit', async () => {
    render(<RevisionComparison database={left} entryId="entry" />);
    await screen.findByText('1 difference');
    expect(screen.getByLabelText('Right version')).toHaveValue('1');
    fireEvent.click(screen.getByRole('button', { name: 'Use right version' }));
    fireEvent.click(screen.getByRole('button', { name: 'Apply version' }));
    await waitFor(() => expect(api.applyEntryRevision).toHaveBeenCalledWith('left', 'left', 'entry', 0, 'left-old', 'left-current'));
  });

  it('does not write to a read-only database but allows copying out of it', async () => {
    render(<RevisionComparison database={{ ...left, readOnly: true }} otherDatabase={right} entryId="entry" />);
    await screen.findByText('1 difference');
    expect(screen.getByRole('button', { name: 'Use right version' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Use left version' })).not.toBeDisabled();
  });

  it('shows save errors instead of claiming success', async () => {
    api.applyEntryRevision.mockRejectedValue('Target changed; refresh the comparison');
    const onSaved = vi.fn();
    render(<RevisionComparison database={left} otherDatabase={right} entryId="entry" onSaved={onSaved} />);
    await screen.findByText('1 difference');
    fireEvent.click(screen.getByRole('button', { name: 'Use right version' }));
    fireEvent.click(screen.getByRole('button', { name: 'Apply version' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Target changed');
    expect(onSaved).not.toHaveBeenCalled();
  });

  it('offers no comparison until a linked database is unlocked', () => {
    render(<DatabaseSync database={left} databases={[left, { ...right, locked: true }]} />);
    expect(screen.getByText(/Unlock another database/)).toBeInTheDocument();
    expect(api.listRevisionEntries).not.toHaveBeenCalled();
  });

  it('rereads both files on opening and manual refresh even when change detection reports no change', async () => {
    let leftEntries = [];
    let rightEntries = [];
    api.listRevisionEntries.mockImplementation((id) => Promise.resolve(id === 'left' ? leftEntries : rightEntries));
    const onRefreshed = vi.fn();
    render(<DatabaseSync database={left} databases={[left, right]} onRefreshed={onRefreshed} />);
    await screen.findByText('No entry content differences.');
    expect(api.reloadDatabase).toHaveBeenCalledTimes(2);
    expect(api.databaseChangedOnDisk).not.toHaveBeenCalled();
    api.reloadDatabase.mockImplementation(async (id) => {
      if (id === 'left') leftEntries = [{ id: 'entry', title: 'Restorable', path: 'Services/Restorable', token: 'active' }];
      else rightEntries = [];
      return [];
    });

    fireEvent.click(screen.getByRole('button', { name: 'Refresh comparison' }));

    expect(await screen.findByRole('button', { name: /Restorable/ })).toBeInTheDocument();
    expect(screen.getByText('Only in this database')).toBeInTheDocument();
    expect(api.reloadDatabase).toHaveBeenCalledWith('left');
    expect(api.reloadDatabase).toHaveBeenCalledWith('right');
    expect(api.reloadDatabase).toHaveBeenCalledTimes(4);
    expect(api.databaseChangedOnDisk).not.toHaveBeenCalled();
    expect(onRefreshed).toHaveBeenCalledWith('left');
    expect(onRefreshed).toHaveBeenCalledWith('right');
    for (const id of ['left', 'right']) {
      const reads = api.listRevisionEntries.mock.calls.flatMap(([side], index) => side === id ? [api.listRevisionEntries.mock.invocationCallOrder[index]] : []);
      const reloads = api.reloadDatabase.mock.calls.flatMap(([side], index) => side === id ? [api.reloadDatabase.mock.invocationCallOrder[index]] : []);
      expect(reloads[0]).toBeLessThan(reads[0]);
      expect(reloads[1]).toBeLessThan(reads[1]);
    }
  });

  it('rereads both sides immediately whenever the linked database selection changes', async () => {
    const third = { ...right, id: 'third', path: '/third/same.kdbx' };
    let peerTitle = 'Original peer entry';
    api.listRevisionEntries.mockImplementation(async (id) => id === 'left' ? [] : [{ id: 'entry', title: id === 'third' ? 'Third database entry' : peerTitle, path: id, token: id }]);
    render(<DatabaseSync database={left} databases={[left, right, third]} />);
    await screen.findByRole('button', { name: /Original peer entry/ });

    fireEvent.change(screen.getByRole('combobox', { name: 'Linked database' }), { target: { value: 'third' } });

    await screen.findByRole('button', { name: /Third database entry/ });
    expect(screen.queryByRole('button', { name: /Original peer entry/ })).not.toBeInTheDocument();
    expect(api.reloadDatabase.mock.calls.map(([id]) => id)).toEqual(['left', 'right', 'left', 'third']);
    peerTitle = 'Updated peer entry';

    fireEvent.change(screen.getByRole('combobox', { name: 'Linked database' }), { target: { value: 'right' } });

    await screen.findByRole('button', { name: /Updated peer entry/ });
    expect(api.reloadDatabase.mock.calls.map(([id]) => id)).toEqual(['left', 'right', 'left', 'third', 'left', 'right']);
  });

  it('rereads both files immediately when the primary database changes', async () => {
    api.listRevisionEntries.mockResolvedValue([]);
    const view = render(<DatabaseSync database={left} databases={[left, right]} />);
    await screen.findByText('No entry content differences.');

    view.rerender(<DatabaseSync database={right} databases={[left, right]} />);

    await screen.findByText('No entry content differences.');
    expect(screen.getByRole('combobox', { name: 'Linked database' })).toHaveValue('left');
    expect(api.reloadDatabase.mock.calls.map(([id]) => id)).toEqual(['left', 'right', 'right', 'left']);
  });

  it.each([['left', 'right'], ['right', 'left']])('saves %s into %s before refreshing and stepping through the remaining differences', async (sourceId, targetId) => {
    const files = Object.fromEntries(['left', 'right'].map((id) => [id, ['first', 'second'].map((entryId, index) => ({ id: entryId, title: `${index + 1} ${entryId}`, path: entryId, token: `${id}-${entryId}` }))]));
    let finishSave;
    const saveFinished = new Promise((resolve) => { finishSave = resolve; });
    api.listRevisionEntries.mockImplementation(async (id) => files[id]);
    api.getEntryRevisions.mockImplementation(async (id, entryId) => {
      const token = files[id].find((entry) => entry.id === entryId).token;
      return [revision(token, token)];
    });
    api.applyEntryRevision.mockImplementation(async (target, source, entryId) => {
      await saveFinished;
      const token = files[source].find((entry) => entry.id === entryId).token;
      files[target] = files[target].map((entry) => entry.id === entryId ? { ...entry, token } : entry);
    });
    const onSaved = vi.fn();
    render(<DatabaseSync database={left} databases={[left, right]} onSaved={onSaved} />);
    await screen.findByText('2 different entries');
    fireEvent.click(await screen.findByRole('button', { name: `Use ${sourceId} version` }));
    fireEvent.click(screen.getByRole('button', { name: 'Apply version' }));

    await waitFor(() => expect(api.applyEntryRevision).toHaveBeenCalledWith(targetId, sourceId, 'first', null, `${sourceId}-first`, `${targetId}-first`));
    expect(onSaved).not.toHaveBeenCalled();
    expect(screen.getByText('2 different entries')).toBeInTheDocument();

    await act(async () => finishSave());

    await screen.findByText('1 different entries');
    expect(onSaved).toHaveBeenCalledWith(targetId);
    expect(screen.getByRole('heading', { name: '2 second' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /1 first/ })).not.toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Linked database' })).toHaveValue('right');
    fireEvent.click(await screen.findByRole('button', { name: `Use ${sourceId} version` }));
    fireEvent.click(screen.getByRole('button', { name: 'Apply version' }));

    await screen.findByText('No entry content differences.');
    expect(api.applyEntryRevision).toHaveBeenLastCalledWith(targetId, sourceId, 'second', null, `${sourceId}-second`, `${targetId}-second`);
    expect(onSaved).toHaveBeenCalledTimes(2);
    expect(api.reloadDatabase).toHaveBeenCalledTimes(6);
  });

  it('updates on the live refresh timer and stops polling after leaving sync', async () => {
    const interval = vi.spyOn(globalThis, 'setInterval');
    let rightToken = 'same';
    let diskToken = 'same';
    api.reloadDatabase.mockImplementation(async (id) => {
      if (id === 'right') rightToken = diskToken;
      return [];
    });
    api.listRevisionEntries.mockImplementation(async (id) => [{ id: 'entry', title: 'Live change', path: 'Live change', token: id === 'left' ? 'same' : rightToken }]);
    const view = render(<DatabaseSync database={left} databases={[left, right]} />);
    await screen.findByText('No entry content differences.');
    const poll = interval.mock.calls.find(([, delay]) => delay === 3000)[0];
    diskToken = 'changed';

    await act(async () => poll());

    expect(await screen.findByRole('button', { name: /Live change/ })).toBeInTheDocument();
    expect(api.reloadDatabase).toHaveBeenCalledTimes(4);
    expect(api.databaseChangedOnDisk).not.toHaveBeenCalled();
    view.unmount();
    const calls = api.listRevisionEntries.mock.calls.length;
    await act(async () => poll());
    expect(api.listRevisionEntries).toHaveBeenCalledTimes(calls);
    interval.mockRestore();
  });

  it('refreshes selected version details when the same entry changes', async () => {
    let token = 'old';
    api.listRevisionEntries.mockImplementation(async (id) => [{ id: 'entry', title: 'Changes', path: 'Changes', token: id === 'left' ? token : 'other' }]);
    render(<DatabaseSync database={left} databases={[left, right]} />);
    await screen.findByText('1 difference');
    fireEvent.click(screen.getByRole('button', { name: 'Use left version' }));
    expect(screen.getByRole('alertdialog')).toBeInTheDocument();
    api.getEntryRevisions.mockImplementation(async (id) => [revision(id + '-new', id + '-new-secret')]);
    token = 'new';

    fireEvent.focus(window);

    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    await waitFor(() => expect(api.getEntryRevisions).toHaveBeenCalledTimes(4));
    fireEvent.click(screen.getByRole('button', { name: 'Reveal protected values' }));
    expect(screen.getByText('left-new-secret')).toBeInTheDocument();
    expect(screen.getByText('right-new-secret')).toBeInTheDocument();
  });

  it('surfaces reload failure instead of presenting a stale cached comparison', async () => {
    api.listRevisionEntries.mockResolvedValue([]);
    render(<DatabaseSync database={left} databases={[left, right]} />);
    await screen.findByText('No entry content differences.');
    api.reloadDatabase.mockRejectedValue('Cannot read changed database');

    fireEvent.click(screen.getByRole('button', { name: 'Refresh comparison' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Cannot read changed database');
    expect(screen.queryByText('No entry content differences.')).not.toBeInTheDocument();
  });

  it('can restore identical content when only the recycle-bin status differs', async () => {
    api.getEntryRevisions.mockImplementation(async (id) => [{ ...revision(id, 'same-secret'), properties: { 'Entry status': id === 'left' ? 'Active' : 'In recycle bin' } }]);
    render(<RevisionComparison database={left} otherDatabase={right} entryId="entry" />);

    await screen.findByText('1 difference');
    expect(screen.getByText('Entry status')).toBeInTheDocument();
    expect(screen.getByText('In recycle bin')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Use left version' })).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: 'Use left version' }));
    fireEvent.click(screen.getByRole('button', { name: 'Apply version' }));
    await waitFor(() => expect(api.applyEntryRevision).toHaveBeenCalledWith('right', 'left', 'entry', null, 'left', 'right'));
  });

  it('distinguishes a saved version from a subsequent refresh failure', async () => {
    const onSaved = vi.fn().mockRejectedValue('refresh unavailable');
    render(<RevisionComparison database={left} otherDatabase={right} entryId="entry" onSaved={onSaved} />);
    await screen.findByText('1 difference');
    fireEvent.click(screen.getByRole('button', { name: 'Use right version' }));
    fireEvent.click(screen.getByRole('button', { name: 'Apply version' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Version saved, but refreshing the view failed');
  });

  it('lists changed and unique entries without reading unrelated entry secrets', async () => {
    api.listRevisionEntries.mockImplementation((id) => Promise.resolve(id === 'left' ? [{ id: 'entry', title: 'Changed', path: 'Changed', token: 'a' }, { id: 'matching', title: 'Matching', path: 'Matching', token: 'equal' }] : [{ id: 'entry', title: 'Changed', path: 'Changed', token: 'b' }, { id: 'matching', title: 'Matching', path: 'Matching', token: 'equal' }, { id: 'unique', title: 'New', path: 'New', token: 'new' }]));
    render(<DatabaseSync database={left} databases={[left, right]} />);
    await screen.findByText('2 different entries');
    expect(screen.queryByRole('button', { name: /Matching/ })).not.toBeInTheDocument();
    await waitFor(() => expect(api.getEntryRevisions).toHaveBeenCalledTimes(2));
    expect(api.getEntryRevisions.mock.calls.every(([, entryId]) => entryId === 'entry')).toBe(true);
  });
});
