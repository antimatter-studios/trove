import { describe, it, expect } from 'vitest';
import { compareEntries, linkedDatabases, revisionDiff } from '../src/revisions.js';

describe('manual revision comparison', () => {
  it('links only unlocked copies with the same nonempty UUID', () => {
    const current = { id: 'a', troveUuid: 'UUID' };
    const peers = [{ ...current }, { id: 'b', troveUuid: 'uuid' }, { id: 'c', troveUuid: 'uuid', locked: true }, { id: 'd', troveUuid: 'other' }];
    expect(linkedDatabases(current, peers).map((database) => database.id)).toEqual(['b']);
    expect(linkedDatabases({ id: 'a' }, peers)).toEqual([]);
  });

  it('matches entry UUIDs rather than titles, and includes entries unique to either copy', () => {
    const left = [{ id: 'same', title: 'Same', token: 'unchanged' }, { id: 'changed', title: 'Edited', token: 'left' }, { id: 'left', title: 'Duplicate', token: 'one' }];
    const right = [{ id: 'same', title: 'Same', token: 'unchanged' }, { id: 'changed', title: 'Edited', token: 'right' }, { id: 'right', title: 'Duplicate', token: 'two' }];
    const result = compareEntries(left, right);
    expect(result).toHaveLength(3);
    expect(result.find((entry) => entry.id === 'changed').status).toBe('Different');
    expect(result.find((entry) => entry.id === 'left').status).toBe('Only in this database');
    expect(result.find((entry) => entry.id === 'right').status).toBe('Only in linked database');
    expect(compareEntries(left, right, true)).toHaveLength(4);
  });

  it('distinguishes missing, empty, protected, and same-sized attachment changes', () => {
    const rows = revisionDiff({ fields: [{ name: 'Password', value: 'old', protected: true }, { name: 'Empty', value: '' }], attachments: [{ name: 'file', size: 4, digest: 'AAAA' }] }, { fields: [{ name: 'Password', value: 'new' }], attachments: [{ name: 'file', size: 4, digest: 'BBBB' }] });
    expect(rows).toHaveLength(3);
    expect(rows.every((row) => row.changed)).toBe(true);
    expect(rows.find((row) => row.label === 'Password').protected).toBe(true);
    expect(rows.find((row) => row.label === 'Empty')).toMatchObject({ left: '', right: undefined });
  });
});
