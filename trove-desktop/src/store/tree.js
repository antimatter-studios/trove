// Pure helpers over the non-secret entry list. No Tauri, no secrets — unit
// tested in isolation. Entries arrive from the `list_entries`/`open_vault`
// commands as EntryDto: { id, title, username, url, group_path, display_path,
// attachment_names }.

/// Group segments of an entry (root → parent group). Prefer the backend's
/// structured `group_path` — its segments are exact, so a group or title that
/// contains `/` is not mis-split. Fall back to slicing `display_path` only for
/// payloads that predate the structured field (lossy for `/`-in-name cases).
export function groupPath(entry) {
  if (Array.isArray(entry.group_path)) return entry.group_path;
  const segs = entry.display_path.split('/');
  return segs.slice(0, -1);
}

// Join group segments into one opaque identity string. Each segment is escaped
// (`\` → `\\`, then `/` → `\/`) before joining on `/`, so a group named
// literally `a/b` (one segment) never collides with the nested path `a` → `b`
// (two segments). Used as the tree node's `path` identity and the filter key —
// never shown to the user (the UI renders raw `name`).
function joinPath(segs) {
  return segs.map((s) => s.replace(/\\/g, '\\\\').replace(/\//g, '\\/')).join('/');
}

/// Build a nested group tree with per-node counts (recursive: a group's count
/// includes its descendants). Returns an array of root-level nodes:
/// { name, path, count, children }.
export function buildTree(entries) {
  const root = { name: '', path: '', count: 0, children: {} };
  for (const e of entries) {
    let node = root;
    node.count += 1;
    const acc = [];
    for (const seg of groupPath(e)) {
      acc.push(seg);
      if (!node.children[seg]) {
        node.children[seg] = { name: seg, path: joinPath(acc), count: 0, children: {} };
      }
      node = node.children[seg];
      node.count += 1;
    }
  }
  const toArr = (n) => ({
    name: n.name,
    path: n.path,
    count: n.count,
    children: Object.values(n.children).map(toArr),
  });
  return toArr(root).children;
}

/// Filter entries by selected group and a free-text query. `group` is a tree
/// node `path` (the escaped, joined identity from buildTree), or the sentinel
/// '__all'. The query matches title/username/url/path, case-insensitively;
/// protected values are never in scope (they aren't in the summary). Returns a
/// new array, input order preserved.
export function filterEntries(entries, group, query) {
  let out = entries;
  if (group && group !== '__all') {
    out = out.filter((e) => {
      const gp = joinPath(groupPath(e));
      return gp === group || gp.startsWith(`${group}/`);
    });
  }
  const q = (query || '').trim().toLowerCase();
  if (q) {
    out = out.filter(
      (e) =>
        e.display_path.toLowerCase().includes(q) ||
        (e.username || '').toLowerCase().includes(q) ||
        (e.url || '').toLowerCase().includes(q),
    );
  }
  return out;
}
