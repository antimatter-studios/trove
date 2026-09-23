// Trove — pure view helpers over the entry list returned by the backend.
// (All mock vault/entry data has been removed; entries now come from trove-core
// via src/api.js.)
//
// Entries carry a `group` array (root→leaf group path); the last path segment is
// the entry name. buildTree turns the flat list into a nested group tree with
// recursive counts, which the sidebar renders.

// Build a nested group tree with direct and recursive counts plus native tags.
function buildTree(entries, groups = []) {
  const root = { name: "Root", path: "__root", groupPath: [], children: {}, count: 0, own: 0, tags: [], inheritedTags: [] };
  const ensurePath = (segments) => {
    let node = root;
    const acc = [];
    for (const seg of segments) {
      acc.push(seg);
      if (!node.children[seg]) {
        node.children[seg] = { name: seg, path: acc.join("/"), groupPath: [...acc], children: {}, count: 0, own: 0, tags: [], inheritedTags: [] };
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
    // Where the entry is actually filed, as opposed to every folder above it.
    node.own++;
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
    // What clicking this folder lists. The badge shows this rather than
    // `count`, because a folder listing its direct contents while displaying a
    // recursive total is a badge that lies about what clicking does.
    own: node.own,
    // Sort each level's folders alphabetically (natural, case-insensitive);
    // the recursion through toArr applies it at every depth.
    children: Object.values(node.children)
      .sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" }))
      .map(toArr),
  });
  return [toArr(root)];
}

export { buildTree };

/* ============ ENTRY PATHS, RELATIVE TO WHERE YOU ARE ============ */

/// The folder a typed path is interpreted against.
///
/// `__all`, `__fav`, and `__root` resolve against the vault root.
/// That makes relative and absolute identical in those views, which is
/// precisely the behaviour they had before paths were relative at all.
export function baseGroup(group) {
  return !group || group === "__all" || group === "__fav" || group === "__root" ? "" : group;
}

/// Resolve what someone typed in the path field into a full entry path.
///
/// A leading `/` means "from the root, ignore where I am". Anything else is
/// relative to the folder being browsed, so typing `thing` while in `Infra`
/// creates `Infra/thing` — you make entries where you are, which is what the
/// folder tree in front of you implies.
export function resolveEntryPath(typed, group) {
  // Not trimmed. An entry whose title legitimately begins or ends with a space
  // would otherwise be renamed by opening and saving it unchanged — the same
  // silent rewrite that `displayEntryPath` is careful to avoid on the way out.
  // Blankness is judged separately, where it is a question about the row.
  const t = typed || "";
  if (t.startsWith("/")) return t.replace(/^\/+/, "");
  const base = baseGroup(group);
  if (!base) return t;
  return t.trim() ? base + "/" + t : base;
}

/// How an existing entry's path should appear in the form: relative to the
/// folder being browsed, so saving it unchanged is a no-op.
///
/// Showing the full path here would double the prefix on save — `Infra/x`
/// typed while in `Infra` means `Infra/Infra/x`. An entry outside the current
/// folder (reachable through Favourites, which is not a folder) is shown
/// absolute, with the leading `/`, because that is the only spelling that
/// round-trips from there.
export function displayEntryPath(fullPath, group) {
  const base = baseGroup(group);
  if (!base) return fullPath;
  if (fullPath === base) return "";
  if (fullPath.startsWith(base + "/")) return fullPath.slice(base.length + 1);
  return "/" + fullPath;
}

/// Whether an entry is shown by the folder currently selected in the sidebar.
///
/// A folder lists what is filed directly in it, the way a file browser does —
/// subfolders are things you click into in the tree, not contents that spill
/// into the list. Selecting `Infra` therefore shows `Infra/ssh` but not
/// `Infra/Personal/thing`; `Personal` is a folder in the sidebar.
///
/// `__all` shows everything and `__fav` shows favourites wherever they live;
/// neither is a folder.
///
/// The list filter and the post-save navigation MUST agree on this, which is
/// why it is one function. If they drifted, saving an entry that is plainly on
/// screen could navigate away from it, or one that has left the view could
/// leave you staring at a list it is not in.
export function isVisibleIn(entry, group) {
  if (!entry) return false;
  if (!group || group === "__all") return true;
  if (group === "__fav") return !!entry.fav;
  if (group === "__root") return entry.groupPath === "";
  return entry.groupPath === group;
}
