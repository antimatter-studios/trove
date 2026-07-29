// buildTree turns the flat entry list into the sidebar's nested folder tree.
// Folders must come out alphabetically sorted at every level (natural,
// case-insensitive), regardless of the order entries arrive in.

import { describe, it, expect } from 'vitest';
import { buildTree } from '../src/tree.js';

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
    expect(tree.map((n) => n.name)).toEqual(['2-early', '10-late', 'Alpha', 'zebra']);
    // Nested children are sorted too (the recursion applies at every depth).
    const alpha = tree.find((n) => n.name === 'Alpha');
    expect(alpha.children.map((n) => n.name)).toEqual(['sub-a', 'sub-z']);
  });
});
