// Drop rules for the sidebar and entry list: where a dragged folder or entry
// lands, what order the parent ends up in, and which drops are refused.

import { describe, it, expect } from 'vitest';
import { buildTree } from '../src/tree.js';
import { dropZone, indexTree, resolveGroupDrop, resolveEntryDrop, visibleRows } from '../src/dnd.js';

const g = (path, position) => ({ path, tags: [], inheritedTags: [], position });
const entry = (group, title) => ({ group, groupPath: group.join('/'), title, path: [...group, title].join('/') });

// Root ─ Alpha, Beta (─ Inner), Gamma
const groups = [g([]), g(['Alpha']), g(['Beta']), g(['Beta', 'Inner']), g(['Gamma'])];
const tree = buildTree([entry(['Alpha'], 'mail')], groups);
const idx = indexTree(tree);
const closed = () => false;

describe('dropZone', () => {
  it('splits a row into before / into / after, and entries only drop into', () => {
    expect(dropZone(2, 30)).toBe('before');
    expect(dropZone(15, 30)).toBe('into');
    expect(dropZone(28, 30)).toBe('after');
    expect(dropZone(2, 30, false)).toBe('into');
  });
});

describe('buildTree order', () => {
  it('puts arranged folders first, in their order, then the rest alphabetically', () => {
    const t = buildTree([], [g([]), g(['a']), g(['b'], 1), g(['c'], 0), g(['d'])]);
    expect(t[0].children.map((n) => n.name)).toEqual(['c', 'b', 'a', 'd']);
  });
});

describe('resolveGroupDrop', () => {
  it('reorders among siblings', () => {
    const d = resolveGroupDrop(idx, 'Gamma', 'Alpha', 'before', false, closed);
    expect(d).toMatchObject({ valid: true, parent: '', order: ['Gamma', 'Alpha', 'Beta'], gapBefore: 'Alpha' });
    const e = resolveGroupDrop(idx, 'Alpha', 'Beta', 'after', false, closed);
    expect(e).toMatchObject({ valid: true, order: ['Beta', 'Alpha', 'Gamma'], gapBefore: '__after:Beta' });
  });

  it('treats putting a folder back where it was as nothing to do', () => {
    expect(resolveGroupDrop(idx, 'Alpha', 'Beta', 'before', false, closed).valid).toBe(false);
  });

  it('drops into a folder, appending it to the children', () => {
    const d = resolveGroupDrop(idx, 'Gamma', 'Beta', 'into', false, closed);
    expect(d).toMatchObject({ valid: true, parent: 'Beta', order: ['Inner', 'Gamma'], into: 'Beta' });
  });

  it('lands first inside an open folder when dropped just below it', () => {
    const d = resolveGroupDrop(idx, 'Gamma', 'Beta', 'after', false, (p) => p === 'Beta');
    expect(d).toMatchObject({ valid: true, parent: 'Beta', order: ['Gamma', 'Inner'], gapBefore: 'Beta/Inner' });
  });

  it('only drops into Root, never beside it', () => {
    const d = resolveGroupDrop(idx, 'Beta/Inner', '__root', 'before', false, closed);
    expect(d).toMatchObject({ valid: true, parent: '', into: '__root', order: ['Alpha', 'Beta', 'Gamma', 'Inner'] });
  });

  it('refuses a folder into itself or below itself', () => {
    expect(resolveGroupDrop(idx, 'Beta', 'Beta', 'into', false, closed).valid).toBe(false);
    expect(resolveGroupDrop(idx, 'Beta', 'Beta/Inner', 'into', false, closed).valid).toBe(false);
  });

  it('refuses a name clash, and a copy beside its original', () => {
    const t = buildTree([], [g([]), g(['A']), g(['A', 'X']), g(['X'])]);
    const i = indexTree(t);
    expect(resolveGroupDrop(i, 'A/X', 'X', 'before', false, closed).valid).toBe(false);
    expect(resolveGroupDrop(idx, 'Alpha', 'Gamma', 'after', true, closed).valid).toBe(false);
    expect(resolveGroupDrop(idx, 'Alpha', 'Beta', 'into', true, closed)).toMatchObject({ valid: true, parent: 'Beta' });
  });
});

describe('resolveEntryDrop', () => {
  const mail = entry(['Alpha'], 'mail');
  it('drops into another folder', () => {
    expect(resolveEntryDrop(idx, mail, 'Beta', [mail])).toMatchObject({ valid: true, parent: 'Beta', into: 'Beta' });
    expect(resolveEntryDrop(idx, mail, '__root', [mail])).toMatchObject({ valid: true, parent: '' });
  });
  it('refuses its own folder and a title already taken there', () => {
    expect(resolveEntryDrop(idx, mail, 'Alpha', [mail]).valid).toBe(false);
    const other = entry(['Beta'], 'Mail');
    expect(resolveEntryDrop(idx, mail, 'Beta', [mail, other]).valid).toBe(false);
  });
});

describe('visibleRows', () => {
  it('lists rows top to bottom through open folders only', () => {
    expect(visibleRows(tree, (p) => p === '__root')).toEqual(['__root', 'Alpha', 'Beta', 'Gamma']);
    expect(visibleRows(tree, (p) => p === '__root' || p === 'Beta')).toEqual(['__root', 'Alpha', 'Beta', 'Beta/Inner', 'Gamma']);
  });
});
