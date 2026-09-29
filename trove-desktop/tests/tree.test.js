// buildTree turns the flat entry list into the sidebar's nested folder tree.
// Folders must come out alphabetically sorted at every level (natural,
// case-insensitive), regardless of the order entries arrive in.

import { describe, it, expect } from 'vitest';
import { buildTree, splitRecycleBin, resolveEntryPath, displayEntryPath, isVisibleIn, recycleBinPath } from '../src/tree.js';

const entry = (group) => ({ group, groupPath: group.join('/'), path: `${group.join('/')}/x`, title: 'x' });

describe('buildTree', () => {
  it('sorts folders alphabetically at every level (natural, case-insensitive)', () => {
    // Deliberately unsorted insertion order, mixed case, and numeric names.
    const tree = buildTree([
      entry(['zebra']),
      entry(['Alpha']),
      entry(['Alpha', 'sub-z']),
      entry(['Alpha', 'sub-a']),
      entry(['10-late']),
      entry(['2-early']),
    ]);
    // Top level: numbers sort naturally (2 before 10), then letters.
    expect(tree[0].children.map((n) => n.name)).toEqual(['2-early', '10-late', 'Alpha', 'zebra']);
    // Nested children are sorted too (the recursion applies at every depth).
    const alpha = tree[0].children.find((n) => n.name === 'Alpha');
    expect(alpha.children.map((n) => n.name)).toEqual(['sub-a', 'sub-z']);
  });
});

describe('splitRecycleBin', () => {
  it('lifts the bin out of the tree and marks its contents as in the bin', () => {
    const tree = buildTree(
      [entry(['Work']), entry(['Recycle Bin', 'Old'])],
      [{ path: ['Recycle Bin'], tags: [], inheritedTags: [], recycleBin: true }],
    );
    const { tree: rest, bin } = splitRecycleBin(tree);
    expect(rest[0].children.map((n) => n.name)).toEqual(['Work']);
    expect(bin.name).toBe('Recycle Bin');
    expect(bin.recycleBin).toBe(true);
    expect(bin.children[0].inRecycleBin).toBe(true);
    expect(rest[0].children[0].inRecycleBin).toBe(false);
  });

  it('a folder merely named "Recycle Bin" is not the bin', () => {
    const { tree: rest, bin } = splitRecycleBin(buildTree([entry(['Recycle Bin'])]));
    expect(bin).toBeNull();
    expect(rest[0].children.map((n) => n.name)).toEqual(['Recycle Bin']);
  });
});

describe('entry paths are relative to the folder you are in', () => {
  it('a bare name lands inside the current folder', () => {
    expect(resolveEntryPath('ssh', 'Infra')).toBe('Infra/ssh');
    expect(resolveEntryPath('Personal/thing', 'Infra')).toBe('Infra/Personal/thing');
  });

  it('a leading slash escapes to the root', () => {
    expect(resolveEntryPath('/Personal/thing', 'Infra')).toBe('Personal/thing');
    expect(resolveEntryPath('/thing', 'Infra/prod')).toBe('thing');
  });

  // `__all` is every entry and `__fav` is a selection; neither is a folder, so
  // both resolve against the root — which is exactly how paths behaved before
  // they were relative at all.
  it('the non-folder views resolve against the root', () => {
    for (const g of ['__all', '__fav', '', null, undefined]) {
      expect(resolveEntryPath('Personal/thing', g)).toBe('Personal/thing');
    }
  });

  // The bug this shape exists to avoid: the form used to show the full path,
  // so saving an entry unchanged while inside its own folder would have
  // re-prefixed it into Infra/Infra/prod/postgres.
  it('an existing entry shows relative, so saving it unchanged is a no-op', () => {
    const shown = displayEntryPath('Infra/prod/postgres', 'Infra');
    expect(shown).toBe('prod/postgres');
    expect(resolveEntryPath(shown, 'Infra')).toBe('Infra/prod/postgres');
  });

  it('round-trips from a nested folder too', () => {
    const shown = displayEntryPath('Infra/prod/postgres', 'Infra/prod');
    expect(shown).toBe('postgres');
    expect(resolveEntryPath(shown, 'Infra/prod')).toBe('Infra/prod/postgres');
  });

  // Reachable through Favourites, which is not a folder: the entry can live
  // anywhere, and absolute is the only spelling that round-trips.
  it('an entry outside the current folder is shown absolute and round-trips', () => {
    const shown = displayEntryPath('Personal/email', 'Infra');
    expect(shown).toBe('/Personal/email');
    expect(resolveEntryPath(shown, 'Infra')).toBe('Personal/email');
  });

  it('relocation out of the current folder is still possible', () => {
    // Without the absolute form this would be impossible — everything typed
    // would land back under Infra.
    expect(resolveEntryPath('/Archive/postgres', 'Infra')).toBe('Archive/postgres');
  });
});

describe('saving only navigates when the entry leaves the view', () => {
  const at = (groupPath, fav = false) => ({ id: 'x', groupPath, fav });

  // A folder lists what is filed directly in it, like a file browser: a
  // subfolder is something you click into in the tree, not contents that spill
  // into the list.
  it('a folder lists only what is filed directly in it', () => {
    expect(isVisibleIn(at('Infra'), 'Infra')).toBe(true);
    expect(isVisibleIn(at('Infra/Personal'), 'Infra')).toBe(false);
  });

  it('an entry outside the folder is not visible', () => {
    expect(isVisibleIn(at('Personal'), 'Infra')).toBe(false);
    // Not a prefix match on the string — Infrastructure is not inside Infra.
    expect(isVisibleIn(at('Infrastructure'), 'Infra')).toBe(false);
  });

  // Creating `Personal/thing` while in `Infra` makes `Infra/Personal/thing`,
  // which this view does not list — so saving takes you to where it went.
  it('an entry created into a subfolder has left the view', () => {
    expect(isVisibleIn(at(resolveEntryPath('Personal/thing', 'Infra').replace(/\/[^/]+$/, '')), 'Infra')).toBe(false);
  });

  it('all entries shows everything', () => {
    expect(isVisibleIn(at('anywhere'), '__all')).toBe(true);
  });

  it('favourites shows favourites wherever they live', () => {
    expect(isVisibleIn(at('Personal', true), '__fav')).toBe(true);
    expect(isVisibleIn(at('Personal', false), '__fav')).toBe(false);
  });
});

describe('the recycle bin lists everything in it', () => {
  const at = (groupPath) => ({ groupPath });
  const groups = [{ path: ['Recycle Bin'], recycleBin: true }, { path: ['Work'] }];

  it('includes entries inside deleted folders, however deep', () => {
    const bin = recycleBinPath(groups);
    expect(bin).toBe('Recycle Bin');
    expect(isVisibleIn(at('Recycle Bin'), bin, bin)).toBe(true);
    expect(isVisibleIn(at('Recycle Bin/absolute/path/to'), bin, bin)).toBe(true);
    expect(isVisibleIn(at('Recycle Binge'), bin, bin)).toBe(false);
    expect(isVisibleIn(at('Work'), bin, bin)).toBe(false);
  });

  it('a folder inside the bin still lists only its own entries', () => {
    const bin = recycleBinPath(groups);
    expect(isVisibleIn(at('Recycle Bin/absolute'), 'Recycle Bin/absolute', bin)).toBe(true);
    expect(isVisibleIn(at('Recycle Bin/absolute/path'), 'Recycle Bin/absolute', bin)).toBe(false);
  });

  it('a folder merely named "Recycle Bin" lists only its own entries', () => {
    const bin = recycleBinPath([{ path: ['Recycle Bin'] }]);
    expect(bin).toBeNull();
    expect(isVisibleIn(at('Recycle Bin/sub'), 'Recycle Bin', bin)).toBe(false);
  });
});

describe('folder counts match what clicking shows', () => {
  const e = (group) => ({ group, path: group.concat('x').join('/'), title: 'x' });

  it('own counts what is filed directly in the folder', () => {
    const t = buildTree([e(['Infra']), e(['Infra', 'Personal']), e(['Infra', 'Personal'])]);
    const infra = t[0].children.find((n) => n.name === 'Infra');
    expect(infra.own).toBe(1);
    expect(infra.count).toBe(3);
    const personal = infra.children.find((n) => n.name === 'Personal');
    expect(personal.own).toBe(2);
  });

  // A folder holding only subfolders lists nothing, and the badge says so
  // rather than implying entries are there.
  it('a pure container folder owns nothing', () => {
    const t = buildTree([e(['Infra', 'Personal'])]);
    const infra = t[0].children.find((n) => n.name === 'Infra');
    expect(infra.own).toBe(0);
    expect(infra.count).toBe(1);
  });
});

// Every folder's badge is the number of entries somewhere under it — each
// entry once, however deep. The expected numbers come from a brute-force count
// over the flat entry list, not from the tree code. The cases are shaped to
// tempt a counter into counting one entry more than once: chains of folders
// that hold nothing but the next folder, entries at several depths of one
// branch, repeated names, folders that exist only as groups, and a recycle bin
// inside Root (shown on its own row, so Root must not count it as well).
describe('folder badges count each entry once', () => {
  const e = (group) => ({ group, groupPath: group.join('/'), path: group.concat('x').join('/'), title: 'x' });
  const BIN = { path: ['Recycle Bin'], tags: [], inheritedTags: [], recycleBin: true };
  const g = (...path) => ({ path, tags: [], inheritedTags: [] });

  const under = (entries, path) => entries.filter((x) => x.groupPath === path || x.groupPath.startsWith(path + '/'));
  const expected = (entries, node) => node.path === '__root'
    ? entries.filter((x) => under([x], 'Recycle Bin').length === 0).length
    : under(entries, node.path).length;
  const allNodes = (nodes) => nodes.flatMap((n) => [n, ...allNodes(n.children)]);

  const CASES = {
    'one entry at the end of a chain of empty folders': {
      entries: [e(['absolute', 'path', 'to'])],
    },
    'two chains that each end in one entry': {
      entries: [e(['absolute', 'path', 'to']), e(['some', 'relative'])],
    },
    'entries at every depth of one branch': {
      entries: [e([]), e(['a']), e(['a', 'b']), e(['a', 'b', 'c']), e(['a', 'b', 'c'])],
    },
    'the same name repeated down a branch': {
      entries: [e(['a', 'a', 'a']), e(['a'])],
    },
    'empty folders that exist only as groups': {
      entries: [e(['kept'])],
      groups: [g('empty'), g('empty', 'deeper'), g('kept', 'hollow')],
    },
    'a bin holding deleted chains and a loose entry': {
      entries: [e(['live']), e(['Recycle Bin', 'absolute', 'path', 'to']), e(['Recycle Bin', 'some', 'relative']), e(['Recycle Bin'])],
      groups: [BIN],
    },
  };

  for (const [name, { entries, groups = [] }] of Object.entries(CASES)) {
    it(name, () => {
      const { tree, bin } = splitRecycleBin(buildTree(entries, groups));
      for (const node of allNodes(bin ? [...tree, bin] : tree)) {
        expect(node.count, node.path).toBe(expected(entries, node));
      }
    });
  }

  it('each folder in a chain shows the one entry at its end', () => {
    const { tree } = splitRecycleBin(buildTree([e(['absolute', 'path', 'to'])]));
    const counts = Object.fromEntries(allNodes(tree).map((n) => [n.path, n.count]));
    expect(counts).toEqual({ __root: 1, absolute: 1, 'absolute/path': 1, 'absolute/path/to': 1 });
  });

  it('Root does not count what is in the bin', () => {
    const { tree, bin } = splitRecycleBin(buildTree([e(['live']), e(['Recycle Bin'])], [BIN]));
    expect(tree[0].count).toBe(1);
    expect(bin.count).toBe(1);
  });
});

describe('typed paths are not silently rewritten', () => {
  // An imported entry may legitimately have whitespace in its title. Opening
  // and saving it unchanged must not rename it — the same silent rewrite
  // displayEntryPath avoids on the way out.
  it('whitespace in a name survives a round trip', () => {
    const shown = displayEntryPath('Infra/ spaced ', 'Infra');
    expect(shown).toBe(' spaced ');
    expect(resolveEntryPath(shown, 'Infra')).toBe('Infra/ spaced ');
  });

  it('a whitespace-only entry is still treated as empty', () => {
    expect(resolveEntryPath('   ', 'Infra')).toBe('Infra');
  });
});
