// Global undo: every entry change made in this app session is recorded with
// the entry's revision token from before the change, and Cmd/Ctrl+Z puts that
// version back as a new edit. The controller is tested against a fake backend
// that keeps real per-entry version lists, so tokens move the way they do in
// trove-core.

import { describe, it, expect, beforeEach } from 'vitest';
import { createUndo, isTypingTarget } from '../src/undo.js';

/// A backend holding one entry's versions, newest first, plus its folder.
function fakeBackend() {
  const state = { versions: [{ token: 't0', content: 'original' }], group: 'Work', calls: [] };
  const revisions = () => state.versions.map((version, position) => ({
    index: position === 0 ? null : position - 1,
    token: version.token,
  }));
  let next = 1;
  const write = (content) => {
    state.versions.unshift({ token: 't' + next++, content });
  };
  return {
    state,
    write,
    api: {
      getEntryRevisions: async (databaseId, entryId) => {
        state.calls.push(['getEntryRevisions', databaseId, entryId]);
        return revisions();
      },
      applyEntryRevision: async (id, sourceId, entryId, index, sourceToken, targetToken) => {
        state.calls.push(['applyEntryRevision', id, sourceId, entryId, index, sourceToken, targetToken]);
        if (state.versions[0].token !== targetToken) throw 'Target changed; refresh the comparison';
        const chosen = index == null ? state.versions[0] : state.versions[index + 1];
        if (chosen.token !== sourceToken) throw 'History changed; refresh the comparison';
        write(chosen.content);
      },
      dropEntry: async (id, entryId, group) => {
        state.calls.push(['dropEntry', id, entryId, group]);
        state.group = group;
      },
    },
  };
}

const database = { id: 'db', locked: false, readOnly: false };
const entry = { id: 'e1', title: 'GitHub', groupPath: 'Work' };

describe('global undo', () => {
  let backend;
  let undo;
  beforeEach(() => {
    backend = fakeBackend();
    undo = createUndo(backend.api);
  });

  it('undo_after_edit_calls_applyEntryRevision_with_previous_token', async () => {
    await undo.track(database, entry, async () => backend.write('edited'));
    expect(undo.label([database])).toBe('Undo GitHub');
    const title = await undo.undo([database]);
    expect(title).toBe('GitHub');
    const apply = backend.state.calls.find(([name]) => name === 'applyEntryRevision');
    expect(apply).toEqual(['applyEntryRevision', 'db', 'db', 'e1', 0, 't0', 't1']);
    expect(backend.state.versions[0].content).toBe('original');
  });

  it('undo_of_undo_restores_the_edit', async () => {
    await undo.track(database, entry, async () => backend.write('edited'));
    await undo.undo([database]);
    expect(backend.state.versions[0].content).toBe('original');
    await undo.undo([database]);
    expect(backend.state.versions[0].content).toBe('edited');
  });

  it('undo_ignored_while_typing_in_input', () => {
    const input = document.createElement('input');
    const textarea = document.createElement('textarea');
    const div = document.createElement('div');
    expect(isTypingTarget(input)).toBe(true);
    expect(isTypingTarget(textarea)).toBe(true);
    expect(isTypingTarget(div)).toBe(false);
    expect(isTypingTarget(null)).toBe(false);
  });

  it('undo_disabled_for_read_only_database', async () => {
    await undo.track(database, entry, async () => backend.write('edited'));
    expect(undo.blockedReason([{ ...database, readOnly: true }])).toBe('Database is read only');
    expect(undo.blockedReason([{ ...database, locked: true }])).toBe('Database is locked');
    await expect(undo.undo([{ ...database, readOnly: true }])).rejects.toBe('Database is read only');
    expect(backend.state.calls.some(([name]) => name === 'applyEntryRevision')).toBe(false);
  });

  it('stale_target_shows_error_and_keeps_stack', async () => {
    await undo.track(database, entry, async () => backend.write('edited'));
    backend.write('changed elsewhere');
    await expect(undo.undo([database])).rejects.toBe('Target changed; refresh the comparison');
    expect(backend.state.versions[0].content).toBe('changed elsewhere');
    expect(undo.label([database])).toBe('Undo GitHub');
  });

  it('lock_clears_undo_stack', async () => {
    await undo.track(database, entry, async () => backend.write('edited'));
    undo.clear('db');
    expect(undo.label([database])).toBe(null);
  });

  it('undone_move_returns_the_entry_to_its_folder', async () => {
    await undo.track(database, entry, async () => { backend.state.group = 'Recycle Bin'; }, { location: true });
    await undo.undo([database]);
    expect(backend.state.calls.find(([name]) => name === 'dropEntry')).toEqual(['dropEntry', 'db', 'e1', 'Work']);
    expect(backend.state.group).toBe('Work');
  });

  it('permanently_deleted_entry_cannot_be_undone', async () => {
    await undo.track(database, entry, async () => backend.write('edited'));
    backend.api.getEntryRevisions = async () => { throw 'entry not found: e1'; };
    await expect(undo.undo([database])).rejects.toBe('Entry was permanently deleted');
  });
});
