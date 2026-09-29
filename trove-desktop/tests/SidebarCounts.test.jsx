// Every folder badge in the rendered sidebar must equal the number of entries
// somewhere under that folder, each counted once, whichever folders are open.
// tree.test.js proves the counting; this proves the sidebar shows it, by
// opening and closing folders and checking every visible badge after each
// click against a brute-force count.

import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/react';

vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(() => Promise.resolve()) }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(() => Promise.resolve(() => {})) }));

import { Sidebar } from '../src/views.jsx';
import { buildTree } from '../src/tree.js';

const e = (group) => ({ group, groupPath: group.join('/'), path: group.concat('x').join('/'), title: 'x' });
const ENTRIES = [
  e(['absolute', 'path', 'to']),
  e(['other', 'deep', 'tree']),
  e(['a']), e(['a', 'a']), e(['a', 'a', 'a']),
  e(['Recycle Bin', 'absolute', 'path', 'to']),
  e(['Recycle Bin', 'some', 'relative']),
  e(['Recycle Bin']),
];
const GROUPS = [{ path: ['Recycle Bin'], tags: [], inheritedTags: [], recycleBin: true }];
const VAULT = { id: 'v1', name: 'Test', locked: false };

const inBin = (x) => x.groupPath === 'Recycle Bin' || x.groupPath.startsWith('Recycle Bin/');
const expected = (path) => path === '__root'
  ? ENTRIES.filter((x) => !inBin(x)).length
  : ENTRIES.filter((x) => x.groupPath === path || x.groupPath.startsWith(path + '/')).length;
const folderRows = (c) => [...c.querySelectorAll('.sidebar .tree-row[data-path]')];
const seen = new Set();
const checkBadges = (c) => {
  for (const row of folderRows(c)) {
    seen.add(row.dataset.path);
    expect(Number(row.querySelector('.tr-count').textContent), row.dataset.path).toBe(expected(row.dataset.path));
  }
};

describe('sidebar folder badges', () => {
  it('match the entries under each folder after every open and close', () => {
    const { container: c } = render(
      <Sidebar tree={buildTree(ENTRIES, GROUPS)} total={ENTRIES.length} favCount={0}
        selectedGroup="__all" onSelectGroup={() => {}} onEditGroupTags={() => {}}
        vault={VAULT} onSwitcher={() => {}} onNew={() => {}} onDataLock={() => {}} />,
    );
    checkBadges(c);
    // Open everything, top to bottom, then close it all again.
    for (let pass = 0; pass < 2; pass++) {
      for (let i = 0; i < folderRows(c).length; i++) {
        fireEvent.click(folderRows(c)[i]);
        checkBadges(c);
      }
    }
    // The chain must actually have been on screen to have been checked.
    expect([...seen]).toContain('absolute/path/to');
    expect([...seen]).toContain('Recycle Bin/absolute/path/to');
  });
});
