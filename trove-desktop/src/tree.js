// Trove — pure view helpers over the entry list returned by the backend.
// (All mock vault/entry data has been removed; entries now come from trove-core
// via src/api.js.)
//
// Entries carry a `group` array (root→leaf group path); the last path segment is
// the entry name. buildTree turns the flat list into a nested group tree with
// recursive counts, which the sidebar renders.

// Build a nested group tree with counts
function buildTree(entries, groups = []) {
  const root = { name: "Root", path: "__root", groupPath: [], children: {}, count: 0, tags: [], inheritedTags: [] };
  const ensurePath = (segments) => {
    let node = root;
    const acc = [];
    for (const seg of segments) {
      acc.push(seg);
      if (!node.children[seg]) {
        node.children[seg] = { name: seg, path: acc.join("/"), groupPath: [...acc], children: {}, count: 0, tags: [], inheritedTags: [] };
      }
      node = node.children[seg];
    }
    return node;
  };
  const rootGroup = groups.find((group) => group.path.length === 0);
  if (rootGroup) {
    root.tags = rootGroup.tags || [];
    root.inheritedTags = rootGroup.inheritedTags || [];
  }
  for (const e of entries) {
    let node = root;
    node.count++;
    for (const seg of e.group) {
      if (!node.children[seg]) ensurePath([...node.groupPath, seg]);
      node = node.children[seg];
      node.count++;
    }
  }
  for (const group of groups) {
    const node = group.path.length ? ensurePath(group.path) : root;
    node.tags = group.tags || [];
    node.inheritedTags = group.inheritedTags || [];
  }
  const toArr = (node) => ({
    name: node.name,
    path: node.path,
    groupPath: node.groupPath,
    count: node.count,
    tags: node.tags,
    inheritedTags: node.inheritedTags,
    // Sort each level's folders alphabetically (natural, case-insensitive);
    // the recursion through toArr applies it at every depth.
    children: Object.values(node.children)
      .sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" }))
      .map(toArr),
  });
  return [toArr(root)];
}

export { buildTree };
