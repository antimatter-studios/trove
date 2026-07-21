// Trove — pure view helpers over the entry list returned by the backend.
// (All mock vault/entry data has been removed; entries now come from trove-core
// via src/api.js.)
//
// Entries carry a `group` array (root→leaf group path); the last path segment is
// the entry name. buildTree turns the flat list into a nested group tree with
// recursive counts, which the sidebar renders.

// Build a nested group tree with counts
function buildTree(entries) {
  const root = { name: "", path: "", children: {}, count: 0 };
  for (const e of entries) {
    let node = root;
    node.count++;
    let acc = [];
    for (const seg of e.group) {
      acc.push(seg);
      if (!node.children[seg]) {
        node.children[seg] = { name: seg, path: acc.join("/"), children: {}, count: 0 };
      }
      node = node.children[seg];
      node.count++;
    }
  }
  const toArr = (node) => ({
    name: node.name,
    path: node.path,
    count: node.count,
    children: Object.values(node.children).map(toArr),
  });
  return toArr(root).children;
}

export { buildTree };
