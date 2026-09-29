// Trove — what a drag in the sidebar or entry list would do if released here.
//
// Pure functions over the tree buildTree returns, so the rules are testable
// without a pointer. The drag controller (drag.jsx) does the hit-testing and
// hands the row under the pointer to these.
//
// Moving is the default everywhere, as in Finder and Explorer; holding the
// copy modifier copies. A copy nobody meant leaves two secrets that drift apart
// when one is rotated, while a move nobody meant is visible and easy to undo.

/// The copy modifier: Option on macOS, Ctrl elsewhere — what the platform's
/// own file manager uses.
export const IS_MAC = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "");
export const copyHeld = (e) => (IS_MAC ? !!e.altKey : !!e.ctrlKey);

/// Which part of a folder row the pointer is over. The top and bottom quarters
/// place a dragged folder beside the row; the middle drops it inside. Entries
/// are not arranged by hand, so for them the whole row means "inside".
export function dropZone(offsetY, height, siblings = true) {
  if (!siblings) return "into";
  if (offsetY < height * 0.25) return "before";
  if (offsetY > height * 0.75) return "after";
  return "into";
}

/// Index every node of the tree by `path`, with its parent alongside.
export function indexTree(tree) {
  const byPath = new Map();
  const walk = (node, parent) => {
    byPath.set(node.path, { node, parent });
    for (const c of node.children || []) walk(c, node);
  };
  for (const n of tree) walk(n, null);
  return byPath;
}

const startsWith = (path, prefix) => prefix.every((seg, i) => path[i] === seg);
const sameName = (a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }) === 0;

/// Where a dragged folder lands when released over `target` in `zone`.
///
/// Returns `{ valid, parent, order, gapBefore, into }`:
///   * `parent` — group path (string, "" for the root) it would move into;
///   * `order`  — that parent's child names afterwards, what the backend stores;
///   * `gapBefore` — path of the row the opening gap sits above (null: after
///     the last row), or `into` — the folder to highlight — whichever applies.
///
/// `isOpen(path)` says whether a folder is expanded: "after" an open folder
/// with children means "first inside it", which is where the gap then shows.
export function resolveGroupDrop(byPath, sourcePath, targetPath, zone, copy, isOpen) {
  const src = byPath.get(sourcePath);
  const tgt = byPath.get(targetPath);
  const none = { valid: false };
  if (!src || !tgt || !src.parent) return none;

  let parent, index, gapBefore = null, into = null;
  const tgtKids = tgt.node.children || [];
  if (!tgt.parent) zone = "into"; // nothing sits beside Root
  if (zone === "after" && tgtKids.length && isOpen(tgt.node.path)) {
    parent = tgt.node; index = 0; gapBefore = tgtKids[0].path;
  } else if (zone === "into") {
    parent = tgt.node; index = tgtKids.length; into = tgt.node.path;
  } else {
    parent = tgt.parent;
    index = parent.children.indexOf(tgt.node) + (zone === "after" ? 1 : 0);
    gapBefore = zone === "before" ? tgt.node.path : "__after:" + tgt.node.path;
  }

  const base = { parent: parent.groupPath.join("/"), gapBefore, into };
  // Into itself or anything below it.
  if (startsWith(parent.groupPath, src.node.groupPath)) return { ...base, valid: false };

  const sameParent = parent === src.parent;
  const names = parent.children.map((c) => c.name);
  let order;
  if (sameParent) {
    // A copy beside the original would need a new name; there is none to give.
    if (copy) return { ...base, valid: false };
    const from = names.indexOf(src.node.name);
    names.splice(from, 1);
    if (from < index) index--;
    names.splice(index, 0, src.node.name);
    order = names;
    // Put back where it was: nothing to write.
    if (order.every((n, i) => n === parent.children[i].name)) return { ...base, valid: false, order };
  } else {
    if (names.some((n) => sameName(n, src.node.name))) return { ...base, valid: false };
    names.splice(index, 0, src.node.name);
    order = names;
  }
  return { ...base, valid: true, order };
}

/// Where a dragged entry lands when released over the folder `targetPath`.
/// Refused when it is already there, or when an entry of the same title is.
export function resolveEntryDrop(byPath, entry, targetPath, entries) {
  const tgt = byPath.get(targetPath);
  if (!tgt) return { valid: false };
  const parent = tgt.node.groupPath.join("/");
  const base = { parent, into: tgt.node.path, gapBefore: null };
  if (parent === entry.groupPath) return { ...base, valid: false };
  const clash = entries.some((e) => e.groupPath === parent && sameName(e.title, entry.title));
  return { ...base, valid: !clash };
}

/// Paths of the rows on screen, top to bottom, given which folders are open.
export function visibleRows(tree, isOpen) {
  const out = [];
  const walk = (node) => {
    out.push(node.path);
    if (isOpen(node.path)) for (const c of node.children || []) walk(c);
  };
  for (const n of tree) walk(n);
  return out;
}
