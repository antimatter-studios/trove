import React from 'react';
import { Icon } from './icons.jsx';
import { copyHeld } from './dnd.js';
// Trove — the pointer side of drag and drop: following the pointer, finding the
// row under it, and drawing what is being carried.
//
// Pointer events rather than HTML5 drag and drop. The native API draws its own
// translucent snapshot that cannot carry a live move/copy badge, never reports
// a modifier pressed mid-drag on WebKit, and on Windows is swallowed by Tauri's
// file-drop handler unless that is switched off for the whole window.

const THRESHOLD = 5; // px of travel before a press becomes a drag

/// Where a row would sit with no drag transform applied. Rows slide aside to
/// open a gap, and hit-testing against where they slid to makes the gap chase
/// the pointer; the transform is subtracted so the row keeps its own place.
function naturalRect(el) {
  const r = el.getBoundingClientRect();
  const t = getComputedStyle(el).transform;
  const dy = t && t !== "none" ? new DOMMatrixReadOnly(t).m42 : 0;
  return { top: r.top - dy, bottom: r.bottom - dy, left: r.left, right: r.right, height: r.height };
}

/// The drop row under (x, y): any element carrying `data-drop-path`, measured
/// where it would sit undisturbed. Returns `{ path, offsetY, height }` or null.
export function rowAt(x, y) {
  for (const el of document.querySelectorAll("[data-drop-path]")) {
    const r = naturalRect(el);
    if (x >= r.left && x <= r.right && y >= r.top && y < r.bottom) {
      return { path: el.dataset.dropPath, offsetY: y - r.top, height: r.height };
    }
  }
  return null;
}

/// Whether (x, y) is over the entry list pane.
export function overList(x, y) {
  const el = document.querySelector(".pane.list");
  if (!el) return false;
  const r = el.getBoundingClientRect();
  return x >= r.left && x <= r.right && y >= r.top && y < r.bottom;
}

/// Drive one drag at a time. `resolve(item, x, y, copy)` says what a drop there
/// would do; `onDrop(state)` runs when a valid drop is released.
export function useDragController({ resolve, onDrop }) {
  const [drag, setDrag] = React.useState(null);
  const resolveRef = React.useRef(resolve);
  const onDropRef = React.useRef(onDrop);
  resolveRef.current = resolve;
  onDropRef.current = onDrop;
  const cleanup = React.useRef(null);
  React.useEffect(() => () => cleanup.current && cleanup.current(), []);

  const start = React.useCallback((e, item) => {
    if (e.button !== 0 || cleanup.current) return;
    const sx = e.clientX, sy = e.clientY;
    let active = false;
    let cur = { item, x: sx, y: sy, copy: copyHeld(e), drop: null };

    const update = (patch) => {
      cur = { ...cur, ...patch };
      cur.drop = resolveRef.current(cur.item, cur.x, cur.y, cur.copy);
      setDrag(cur);
    };
    const move = (ev) => {
      if (!active) {
        if (Math.hypot(ev.clientX - sx, ev.clientY - sy) < THRESHOLD) return;
        active = true;
        document.body.classList.add("dnd-active");
      }
      update({ x: ev.clientX, y: ev.clientY, copy: copyHeld(ev) });
    };
    const key = (ev) => {
      if (!active) return;
      if (ev.key === "Escape") { ev.stopPropagation(); finish(false); return; }
      update({ copy: copyHeld(ev) });
    };
    const up = () => finish(active);
    const cancel = () => finish(false);
    // Releasing on the row that was pressed would also click it, which opens
    // or closes a folder that was only being carried. Eat that one click.
    const eatClick = (ev) => { ev.stopPropagation(); ev.preventDefault(); };
    const finish = (commit) => {
      cleanup.current();
      if (active) {
        window.addEventListener("click", eatClick, { capture: true, once: true });
        setTimeout(() => window.removeEventListener("click", eatClick, { capture: true }), 0);
      }
      setDrag(null);
      if (commit && cur.drop && cur.drop.valid) onDropRef.current(cur);
    };
    cleanup.current = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      window.removeEventListener("pointercancel", up);
      window.removeEventListener("keydown", key, true);
      window.removeEventListener("keyup", key, true);
      window.removeEventListener("blur", cancel);
      document.body.classList.remove("dnd-active");
      cleanup.current = null;
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
    window.addEventListener("pointercancel", up);
    // Capture, so Escape ends the drag before the app's own Escape handling
    // closes whatever else is open.
    window.addEventListener("keydown", key, true);
    window.addEventListener("keyup", key, true);
    window.addEventListener("blur", cancel);
  }, []);

  return { drag, start };
}

/// What follows the pointer: the item being carried, and in its bottom-right
/// corner whether letting go moves or copies it.
export function DragGhost({ drag }) {
  if (!drag) return null;
  const { item, x, y, copy, drop } = drag;
  // Over nothing: neutral. Over a target: whether it would take the drop.
  const state = !drop ? "" : drop.valid ? " ok" : " no";
  return (
    <div className={"dnd-ghost" + state} style={{ transform: `translate(${x + 14}px, ${y + 10}px)` }} aria-hidden="true">
      <span className="dnd-ghost-ic"><Icon name={item.icon} size={15} /></span>
      <span className="dnd-ghost-label">{item.label}</span>
      <span className={"dnd-badge " + (copy ? "copy" : "move")}>
        {copy && <Icon name="plus" size={10} />}
        {copy ? "copy" : "move"}
      </span>
    </div>
  );
}
