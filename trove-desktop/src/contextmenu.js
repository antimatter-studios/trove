// Trove — no web page context menu.
//
// Trove has no right-click menu of its own, so the webview's (Reload, Inspect
// Element, Back) is all a right click shows, and it reads as a web page.
// Text fields keep theirs, because Cut / Copy / Paste there is what people
// expect, and so does a right click on selected text, which offers Copy.

const EDITABLE = "input, textarea, [contenteditable='true']";

/// Whether a right click on `target` should get the system menu.
export function wantsNativeMenu(target, selection = window.getSelection()) {
  if (target instanceof Element && target.closest(EDITABLE)) return true;
  return !!selection && !selection.isCollapsed && selection.toString().trim() !== "";
}

export function suppressContextMenu(win = window) {
  const onMenu = (e) => { if (!wantsNativeMenu(e.target)) e.preventDefault(); };
  win.addEventListener("contextmenu", onMenu);
  return () => win.removeEventListener("contextmenu", onMenu);
}
