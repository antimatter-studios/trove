import { describe, it, expect } from 'vitest';
import { buildTree, filterEntries, groupPath } from '../src/store/tree';

// EntryDto shape from the backend: display_path is the source of truth.
const mk = (id, display_path, username = '', url = '') => ({
  id,
  title: display_path.split('/').pop(),
  username,
  url,
  display_path,
  attachment_names: [],
});

const ENTRIES = [
  mk('1', 'Infra/prod/postgres', 'app', 'postgres://db.prod'),
  mk('2', 'Infra/prod/redis', 'default'),
  mk('3', 'Infra/staging/postgres', 'app'),
  mk('4', 'Personal/github', 'octocat', 'https://github.com'),
  mk('5', 'toplevel', 'root'),
];

describe('groupPath', () => {
  it('drops the leaf title (display_path fallback)', () => {
    expect(groupPath(mk('x', 'a/b/c'))).toEqual(['a', 'b']);
    expect(groupPath(mk('x', 'solo'))).toEqual([]);
  });

  it('prefers structured group_path so names containing "/" are not split', () => {
    // A single group literally named "a/b"; splitting display_path would
    // wrongly yield ['a', 'b'] and nest it two levels deep.
    const e = {
      id: 'x',
      title: 'leaf',
      username: '',
      url: '',
      group_path: ['a/b'],
      display_path: 'a/b/leaf',
      attachment_names: [],
    };
    expect(groupPath(e)).toEqual(['a/b']);
    const tree = buildTree([e]);
    expect(tree.map((n) => n.name)).toEqual(['a/b']);
    expect(tree[0].count).toBe(1);
  });
});

describe('buildTree', () => {
  it('nests groups with recursive counts', () => {
    const tree = buildTree(ENTRIES);
    const byName = Object.fromEntries(tree.map((n) => [n.name, n]));
    // Two top-level groups (toplevel is a root entry, not a group).
    expect(tree.map((n) => n.name).sort()).toEqual(['Infra', 'Personal']);
    expect(byName.Infra.count).toBe(3); // postgres, redis, staging/postgres
    expect(byName.Personal.count).toBe(1);
    const prod = byName.Infra.children.find((c) => c.name === 'prod');
    expect(prod.count).toBe(2);
    expect(prod.path).toBe('Infra/prod');
  });

  it('is empty for a flat vault', () => {
    expect(buildTree([mk('1', 'a'), mk('2', 'b')])).toEqual([]);
  });
});

describe('filterEntries', () => {
  it('filters by group prefix', () => {
    const ids = (g) => filterEntries(ENTRIES, g, '').map((e) => e.id);
    expect(ids('__all')).toEqual(['1', '2', '3', '4', '5']);
    expect(ids('Infra')).toEqual(['1', '2', '3']);
    expect(ids('Infra/prod')).toEqual(['1', '2']);
    expect(ids('Personal')).toEqual(['4']);
  });

  it('filters by query over path/username/url, case-insensitively', () => {
    expect(filterEntries(ENTRIES, '__all', 'POSTGRES').map((e) => e.id)).toEqual(['1', '3']);
    expect(filterEntries(ENTRIES, '__all', 'octocat').map((e) => e.id)).toEqual(['4']);
    expect(filterEntries(ENTRIES, '__all', 'github.com').map((e) => e.id)).toEqual(['4']);
    expect(filterEntries(ENTRIES, '__all', 'nomatch')).toEqual([]);
  });

  it('combines group and query', () => {
    expect(filterEntries(ENTRIES, 'Infra', 'redis').map((e) => e.id)).toEqual(['2']);
    // postgres exists in Infra but the Personal filter excludes it.
    expect(filterEntries(ENTRIES, 'Personal', 'postgres')).toEqual([]);
  });

  it('disambiguates a literal "a/b" group from a nested a > b path', () => {
    const entries = [
      { id: 'lit', title: 'x', username: '', url: '', group_path: ['a/b'], display_path: 'a/b/x', attachment_names: [] },
      { id: 'nst', title: 'y', username: '', url: '', group_path: ['a', 'b'], display_path: 'a/b/y', attachment_names: [] },
    ];
    const tree = buildTree(entries);
    // Two distinct top-level groups: the literal "a/b", and "a" (with child "b").
    expect(tree.map((n) => n.name).sort()).toEqual(['a', 'a/b']);
    const literal = tree.find((n) => n.name === 'a/b');
    const nestedB = tree.find((n) => n.name === 'a').children.find((n) => n.name === 'b');
    // Each group's identity selects only its own entry — no cross-matching.
    expect(filterEntries(entries, literal.path, '').map((e) => e.id)).toEqual(['lit']);
    expect(filterEntries(entries, nestedB.path, '').map((e) => e.id)).toEqual(['nst']);
  });
});
