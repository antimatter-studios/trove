import React from 'react';
import { open, save } from '@tauri-apps/plugin-dialog';
import { Icon } from './icons.jsx';
import { buildTree, resolveEntryPath, isVisibleIn, recycleBinPath } from './tree.js';
import * as api from './api.js';
import { Sidebar, EntryList, Detail } from './views.jsx';
import { DatabaseSync, EntryHistoryModal } from './DatabaseSync.jsx';
import { useDragController, DragGhost, rowAt, overList } from './drag.jsx';
import { dropZone, indexTree, resolveGroupDrop, resolveEntryDrop } from './dnd.js';
import { Unlock, CommandPalette, EntryForm, ConfirmDelete, HelpModal, ThemeMenu, DatabaseSwitcher, DatabaseMetadataModal, OpenDatabaseModal, ClipboardToast, PlainToast, SettingsModal, NewDatabaseModal, EditFolderModal } from './overlays.jsx';
// Trove — main app (multi-database, backed by real .kdbx files via src/api.js)

const { useState, useEffect, useRef, useCallback } = React;

// Three-pane sizing: the sidebar and entry-list widths are user-draggable (and
// persisted); the detail pane flexes to fill the rest.
const DEFAULT_SIDEBAR_W = 230;
const DEFAULT_LIST_W = 320;
const SIDEBAR_MIN = 170, SIDEBAR_MAX = 420;
const LIST_MIN = 240, LIST_MAX = 620;
const clampW = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const isFavoriteTag = (tag) => tag.toLowerCase() === "favorite";

// A draggable vertical divider between two panes. Reports incremental cursor
// deltas while dragging; double-click resets the adjacent pane to its default.
function ResizeHandle({ onDelta, onReset, label }) {
  const [drag, setDrag] = useState(false);
  const last = useRef(0);
  // Keep the latest onDelta in a ref so the drag effect depends only on `drag`
  // (onDelta is a fresh closure each render). The effect then runs once per drag
  // and its cleanup reliably restores the body styles on drag-end AND on
  // unmount — if a shortcut locks/switches the database mid-drag the handle
  // unmounts with no mouseup, and must not leave the resize cursor + disabled
  // text selection stuck until reload.
  const onDeltaRef = useRef(onDelta);
  onDeltaRef.current = onDelta;
  useEffect(() => {
    if (!drag) return;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    const move = (e) => { const inc = e.clientX - last.current; last.current = e.clientX; if (inc) onDeltaRef.current(inc); };
    const up = () => setDrag(false);
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
    return () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [drag]);
  const down = (e) => { e.preventDefault(); last.current = e.clientX; setDrag(true); };
  return (
    <div
      className={"pane-divider" + (drag ? " dragging" : "")}
      role="separator" aria-orientation="vertical" aria-label={label} tabIndex={-1}
      onMouseDown={down} onDoubleClick={onReset}
    />
  );
}

// Placeholder so the chrome renders before any database is registered (fresh
// install with no persisted recents). It reads as a locked, empty database.
// Countdown text. Coarse while it is far away (nobody reads "1:04:59" as
// anything but "about an hour") and precise under a minute, when it does start
// to matter.
function fmtLeft(ms) {
  const s = Math.ceil(ms / 1000);
  if (s >= 3600) {
    // Floor, not round: rounding the remainder produces "24h60m" at 90000s
    // instead of carrying into "25h".
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return m ? `${h}h${m}m` : `${h}h`;
  }
  if (s >= 60) return `${Math.floor(s / 60)}m`;
  return `${s}s`;
}

const NO_DATABASE = { id: null, name: "No database", file: "—", path: "", locked: true, entries: [], groups: [], group: "__root", selId: null, query: "", sort: "title", loaded: false };

// Give a fetched DatabaseDto the per-database view state the UI layers on top.
function withViewState(v) {
  return { ...v, entries: [], groups: [], group: "__root", selId: null, query: "", sort: "title", loaded: false };
}

function App() {
  // databases: each is a DatabaseDto (id/name/file/path/locked) + per-database view state.
  const [databases, setDatabases] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const databaseStateRef = useRef({ databases, activeId });
  databaseStateRef.current = { databases, activeId };
  const database = databases.find((v) => v.id === activeId) || databases[0] || NO_DATABASE;
  const hasUnlockedDatabase = databases.some((v) => !v.locked);
  const patch = useCallback((p) => {
    setDatabases((vs) => vs.map((v) => v.id === activeId ? { ...v, ...(typeof p === "function" ? p(v) : p) } : v));
  }, [activeId]);

  const { locked, entries, group, selId, query, sort } = database;
  const setGroup = (g) => { setSyncOpen(false); patch({ group: g }); };
  const setSelId = (id) => patch({ selId: id });
  const setQuery = (q) => patch({ query: q });

  const [theme, setTheme] = useState(() => { try { return localStorage.getItem("trove.theme") || "dark"; } catch (e) { return "dark"; } });
  const [accent, setAccent] = useState(() => { try { return localStorage.getItem("trove.accent") || "brass"; } catch (e) { return "brass"; } });

  const [palette, setPalette] = useState(false);
  const [form, setForm] = useState(null);
  const [groupEditor, setGroupEditor] = useState(null);
  const [del, setDel] = useState(null);
  const [help, setHelp] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settings, setSettings] = useState(null);
  const [themeMenu, setThemeMenu] = useState(false);
  const [switcher, setSwitcher] = useState(false);
  const [metadataOpen, setMetadataOpen] = useState(false);
  const [syncOpen, setSyncOpen] = useState(false);
  const [historyEntry, setHistoryEntry] = useState(null);
  const [openDatabase, setOpenDatabase] = useState(false);
  // Which build this is. A dev window and an installed one look identical
  // otherwise, which makes "is this even my change?" a guess.
  const [build, setBuild] = useState(null);
  const [newDatabasePath, setNewDatabasePath] = useState(null);
  const [revealed, setRevealed] = useState(false);
  // Secret detail for the selected entry, fetched on selection (get_entry_detail).
  const [detail, setDetail] = useState({ notes: "", fields: [], password: "" });

  // Draggable pane widths (persisted). Detail flexes to fill the remainder.
  const [sidebarW, setSidebarW] = useState(() => { try { return Number(localStorage.getItem("trove.sidebarW")) || DEFAULT_SIDEBAR_W; } catch (e) { return DEFAULT_SIDEBAR_W; } });
  const [listW, setListW] = useState(() => { try { return Number(localStorage.getItem("trove.listW")) || DEFAULT_LIST_W; } catch (e) { return DEFAULT_LIST_W; } });
  useEffect(() => { try { localStorage.setItem("trove.sidebarW", String(sidebarW)); } catch (e) {} }, [sidebarW]);
  useEffect(() => { try { localStorage.setItem("trove.listW", String(listW)); } catch (e) {} }, [listW]);

  const [copiedKey, setCopiedKey] = useState(null);
  const [clip, setClip] = useState(null);
  const [plain, setPlain] = useState(null);
  const searchRef = useRef(null);
  const clipTimer = useRef(null);
  const copiedTimer = useRef(null);
  const plainTimer = useRef(null);

  // App settings live in the backend (they drive what unlock does to the
  // machine), not in localStorage. Read on first open rather than at mount:
  // nothing on the main screen needs them, and a promise resolving at mount
  // lands a state update in the middle of whatever else is starting up — which
  // made the unlock tests flaky on a loaded machine.
  useEffect(() => {
    api.buildInfo().then(setBuild).catch(() => {});
    api.getSettings().then(setSettings).catch(() => {});
  }, []);

  // A production build is just its version; anything else carries the mode and
  // the commit, so "which build is this?" is answerable from the title bar.
  const buildLabel = !build
    ? ""
    : build.mode
      ? `${build.version}-${build.mode}${build.commit ? ` · ${build.commit}` : ""}`
      : build.version;

  // The pill says what the timer actually does, so changing the setting is
  // visible without opening the panel again.
  // One second-tick drives both countdowns; two intervals would drift apart.
  const appLockAt = useRef(null);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!hasUnlockedDatabase) return undefined;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [hasUnlockedDatabase]);

  const openCount = databases.filter((v) => !v.locked).length;
  const agentKeys = databases.reduce((n, v) => n + (v.agentKeys || 0), 0);
  const idleMins = settings && Number.isFinite(settings.idleLockMinutes) ? settings.idleLockMinutes : 5;
  // Counts down to the window locking; resets on every interaction, so it also
  // shows that trove noticed you are still here.
  const appLockLeft = idleMins > 0 && hasUnlockedDatabase && appLockAt.current
    ? Math.max(0, appLockAt.current - now)
    : null;
  const idleLabel = idleMins > 0
    ? `App lock ${appLockLeft == null ? `${idleMins}m` : fmtLeft(appLockLeft)}`
    : "No app lock";

  // Counts down to the first forwarded key dropping out of the agent. Not a
  // "data lock" timer — a data lock is something you do, not something that
  // happens — this is the expiry those keys were given.
  const expireAt = databases.reduce(
    (soonest, v) => (v.keysExpireAt && (!soonest || v.keysExpireAt < soonest) ? v.keysExpireAt : soonest),
    null
  );
  const keysLeft = expireAt ? Math.max(0, expireAt * 1000 - now) : null;

  const openSettings = useCallback(() => {
    setSettingsOpen(true);
    if (settings) return;
    api.getSettings()
      .then(setSettings)
      .catch((e) => console.error("settings load failed", e));
  }, [settings]);
  // Per-key opt-in. The backend writes KeeAgent.settings into the database and
  // adds/removes the key in the running agent, then hands back a fresh list.
  const saveSettings = useCallback((next) => {
    setSettings(next);
    api.setSettings(next).catch((e) => console.error("settings save failed", e));
  }, []);

  useEffect(() => { document.documentElement.dataset.theme = theme; try { localStorage.setItem("trove.theme", theme); } catch (e) {} }, [theme]);
  useEffect(() => { document.documentElement.dataset.accent = accent; try { localStorage.setItem("trove.accent", accent); } catch (e) {} }, [accent]);

  // ---- startup: load persisted registered databases (all come back locked) ----
  useEffect(() => {
    api.listDatabases().then((vs) => {
      const mapped = (vs || []).map(withViewState);
      setDatabases(mapped);
      if (mapped.length) setActiveId(mapped[0].id);
      else setOpenDatabase(true);
    }).catch(() => {});
  }, []);

  // ---- tree, filtered + sorted list ----
  const tree = React.useMemo(() => buildTree(entries, database.groups), [entries, database.groups]);
  const binPath = recycleBinPath(database.groups);

  const filtered = React.useMemo(() => {
    let out = entries;
    out = out.filter((e) => isVisibleIn(e, group, binPath));
    const q = query.trim().toLowerCase();
    if (q) out = out.filter((e) => e.path.toLowerCase().includes(q) || e.username.toLowerCase().includes(q) || (e.url || "").toLowerCase().includes(q));
    out = out.slice().sort((a, b) => {
      if (sort === "title") return a.title.localeCompare(b.title) || a.path.localeCompare(b.path);
      if (sort === "modified") return (new Date(b.modified).getTime() || 0) - (new Date(a.modified).getTime() || 0);
      if (sort === "strength") return a.strength - b.strength;
      return 0;
    });
    return out;
  }, [entries, group, query, sort, binPath]);

  // Keep the selection inside the list that is on screen. An empty list must
  // clear it, not keep the old one: the detail pane resolves `selId` against
  // ALL entries, so a folder listing nothing would still show the entry you
  // had selected elsewhere — a detail pane describing something the list in
  // front of it does not contain. Folders that hold only subfolders list
  // nothing, so this is reachable by ordinary clicking.
  useEffect(() => {
    if (!filtered.length) {
      if (selId !== null) patch({ selId: null });
      return;
    }
    if (!filtered.some((e) => e.id === selId)) patch({ selId: filtered[0].id });
  }, [filtered, selId, patch]);

  const selected = entries.find((e) => e.id === selId) || null;
  const anyOverlay = palette || form || del || help || openDatabase || metadataOpen || historyEntry;

  // ---- fetch secret detail (notes / custom fields / password) on selection ----
  // Re-runs on selection change AND when the selected entry's content changes:
  // its `modified` stamp bumps on every save, so editing the selected entry
  // (same id, replaced `entries`) re-fetches instead of leaving the old
  // password/notes/fields shown and copyable.
  useEffect(() => {
    setRevealed(false);
    if (!selected || database.locked || database.id == null) { setDetail({ notes: "", fields: [], password: "" }); return; }
    const eid = selected.id;
    let cancelled = false;
    api.getEntryDetail(database.id, eid)
      .then((d) => { if (!cancelled) setDetail(d || { notes: "", fields: [], password: "" }); })
      .catch(() => { if (!cancelled) setDetail({ notes: "", fields: [], password: "" }); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selId, activeId, database.locked, database.id, selected?.modified]);

  // ---- lazily load entries for an unlocked-but-not-yet-loaded database ----
  useEffect(() => {
    const v = databases.find((x) => x.id === activeId);
    if (!v || v.locked || v.loaded) return;
    let cancelled = false;
    Promise.all([api.listEntries(v.id), api.listGroups(v.id)]).then(([list, groups]) => {
      if (cancelled) return;
      const firstEntry = list.find((entry) => entry.id === v.selId) || list[0];
      setDatabases((vs) => vs.map((x) => x.id === v.id
        ? { ...x, entries: list, groups, loaded: true, group: firstEntry?.groupPath || "__root", selId: firstEntry?.id || null }
        : x));
    }).catch(() => {});
    return () => { cancelled = true; };
  }, [activeId, databases]);

  // ---- notice when something else writes the database file ----
  // A database is one file with several writers: the CLI, KeePassXC, and the same
  // file synced onto another Mac. Without this the window shows a list that
  // stopped being true. Saving is safe either way (the core merges the other
  // writer's changes in), but the list should show them.
  //
  // Polled rather than watched. It is one `stat` per interval, it only runs
  // while a database is actually open and this window is visible, and there is no
  // watcher to unregister when a database closes or the app hides.
  useEffect(() => {
    if (!database || database.locked || !database.loaded) return;
    const id = database.id;
    let stopped = false;

    const check = async () => {
      if (stopped || document.hidden) return;
      try {
        if (!(await api.databaseChangedOnDisk(id))) return;
        const [list, groups] = await Promise.all([api.reloadDatabase(id), api.listGroups(id)]);
        if (stopped) return;
        setDatabases((vs) => vs.map((x) => x.id === id
          // Keep the selection if that entry still exists, so a reload does not
          // yank the reader somewhere else; fall back to the first entry.
          ? { ...x, entries: list, groups,
              selId: list.some((e) => e.id === x.selId) ? x.selId : (list[0] ? list[0].id : null) }
          : x));
        flashPlain("Reloaded — the database changed outside this window");
      } catch (e) { /* transient: a half-written file, a lock — try again next tick */ }
    };

    const t = setInterval(check, 3000);
    // Also on regaining focus: coming back to the window is exactly when a
    // stale list is most likely and most annoying.
    window.addEventListener("focus", check);
    return () => { stopped = true; clearInterval(t); window.removeEventListener("focus", check); };
  }, [database]); // eslint-disable-line react-hooks/exhaustive-deps

  // ---- clipboard ----
  const clearCopiedSoon = () => {
    clearTimeout(copiedTimer.current);
    copiedTimer.current = setTimeout(() => setCopiedKey(null), 1100);
  };
  const flashPlain = (text) => {
    setPlain({ text });
    clearTimeout(plainTimer.current);
    plainTimer.current = setTimeout(() => setPlain(null), 1800);
  };
  const stopClip = useCallback(() => {
    if (clipTimer.current) {
      clearInterval(clipTimer.current); clipTimer.current = null;
      // "Clear now" (and lock) wipe the OS clipboard while a copy is live.
      try { navigator.clipboard && navigator.clipboard.writeText(""); } catch (e) {}
    }
    setClip(null);
  }, []);
  // Copy a password: fetch it on demand (get_field), copy, run the 12s countdown
  // toast, and actually clear the OS clipboard at 0.
  const copyPassword = useCallback(async (entry) => {
    if (!entry || database.id == null) return;
    let pw = "";
    try { pw = (await api.getField(database.id, entry.id, "Password")) || ""; } catch (e) { return; }
    try { navigator.clipboard && navigator.clipboard.writeText(pw); } catch (e) {}
    setCopiedKey(entry.id + ":pass"); clearCopiedSoon();
    const total = 12;
    clearInterval(clipTimer.current);
    setClip({ label: "Password", total, left: total });
    clipTimer.current = setInterval(() => {
      setClip((c) => {
        if (!c) return null;
        if (c.left <= 1) {
          clearInterval(clipTimer.current); clipTimer.current = null;
          try { navigator.clipboard && navigator.clipboard.writeText(""); } catch (e) {}
          return null;
        }
        return { ...c, left: c.left - 1 };
      });
    }, 1000);
  }, [database.id]);
  // Non-secret copies carry their value already; password routes to copyPassword.
  const copy = useCallback((value, key, kind) => {
    if (kind === "password") { copyPassword(selected); return; }
    try { navigator.clipboard && navigator.clipboard.writeText(value); } catch (e) {}
    if (key) { setCopiedKey(key); clearCopiedSoon(); }
    const nice = kind === "url" ? "URL" : kind.charAt(0).toUpperCase() + kind.slice(1);
    flashPlain(nice + " copied");
  }, [selected, copyPassword]);

  // ---- database actions ----
  // `retractKeys` decides whether forwarded keys come back out of the OS agent.
  // An explicit lock says yes; the idle timer says no — see the auto-lock below.
  // Lock ONE database. `retractKeys` false is the app-lock case: hide it, leave
  // what it handed the machine alone.
  const lockOne = useCallback(async (id, retractKeys) => {
    if (id == null) return;
    try { await api.lockDatabase(id, retractKeys); } catch (e) {}
    setDatabases((vs) => vs.map((v) => v.id === id ? { ...v, locked: true, entries: [], groups: [], loaded: false, selId: null } : v));
  }, []);

  // Data lock: this database only. Its keys come out of the agent and its files
  // go, and if another database is still open you land on that one rather than at
  // a login screen — you have not finished with the app, only with this database.
  const dataLock = useCallback(async () => {
    stopClip();
    setSyncOpen(false); setHistoryEntry(null);
    setPalette(false); setForm(null); setDel(null);
    const id = activeId;
    await lockOne(id, true);
    const next = databases.find((v) => v.id !== id && !v.locked);
    if (next) setActiveId(next.id);
  }, [activeId, databases, lockOne, stopClip]);

  // App lock: the whole app steps away, so every open database hides. Nothing is
  // taken back from the machine — that is what the data lock is for.
  const appLock = useCallback(async () => {
    stopClip();
    setSyncOpen(false); setHistoryEntry(null);
    setPalette(false); setForm(null); setDel(null);
    const open = databases.filter((v) => !v.locked).map((v) => v.id);
    for (const id of open) await lockOne(id, false);
  }, [databases, lockOne, stopClip]);

  // Kept for callers that just mean "lock what I am looking at".
  const lock = useCallback((retractKeys = true) => (retractKeys ? dataLock() : appLock()), [dataLock, appLock]);
  // Async: decrypt via the backend. Resolves on success (parent unmounts Unlock),
  // rejects (bad password) so <Unlock> can surface the error.
  // Resolves with the entry list and deliberately does NOT flip the view:
  // <Unlock> shows a progress checklist while the backend works, and flipping
  // here would unmount it mid-list. It calls `unlockReady` when it's finished.
  const unlock = async (pw) => await api.unlockDatabase(database.id, pw);
  // Same contract as `unlock`, except it can resolve with null: a cancelled
  // fingerprint prompt is a decision, not a failure, and <Unlock> puts the
  // password field back rather than showing an error.
  const touchIdUnlock = async () => await api.biometricUnlock(database.id);
  // Called after a successful password unlock, with the password that worked.
  const touchIdRemember = async (pw) => await api.biometricEnroll(database.id, pw);
  const unlockReady = async (list) => {
    const [groups, metadata] = await Promise.all([
      api.listGroups(database.id).catch(() => []),
      api.getDatabaseMetadata(database.id).catch(() => null),
    ]);
    const firstEntry = list[0];
    patch({ locked: false, troveUuid: metadata?.troveUuid || null, entries: list, groups, loaded: true, group: firstEntry?.groupPath || "__root", selId: firstEntry?.id || null });
  };
  const switchDatabase = (id) => {
    setActiveId(id); setSwitcher(false);
    setSyncOpen(false); setHistoryEntry(null);
    setPalette(false); setForm(null); setDel(null); setRevealed(false);
  };
  const revisionRefreshed = async (id = database.id) => {
    const [entries, groups] = await Promise.all([api.listEntries(id), api.listGroups(id)]);
    setDatabases((current) => current.map((item) => item.id === id ? { ...item, entries, groups } : item));
  };
  const revisionSaved = async (id = database.id) => {
    await revisionRefreshed(id);
    flashPlain("Entry version saved to " + (databases.find((item) => item.id === id)?.path || database.path));
  };
  const saveDatabase = async (id) => {
    const target = databaseStateRef.current.databases.find((item) => item.id === id);
    await api.saveDatabase(id);
    flashPlain("Database saved: " + (target?.path || target?.file || id));
    try {
      const [entries, groups] = await Promise.all([api.listEntries(id), api.listGroups(id)]);
      setDatabases((current) => current.map((item) => item.id === id ? { ...item, entries, groups } : item));
    } catch (error) {
      flashPlain("Database saved, but refresh failed: " + String(error));
    }
  };
  const removeDatabase = async (id) => {
    await api.removeDatabase(id);
    const current = databaseStateRef.current;
    const removed = current.databases.find((item) => item.id === id);
    const remaining = current.databases.filter((item) => item.id !== id);
    setDatabases((items) => items.filter((item) => item.id !== id));
    if (current.activeId === id) {
      stopClip();
      setDetail({ notes: "", fields: [], password: "" });
      setMetadataOpen(false); setGroupEditor(null);
      switchDatabase((remaining.find((item) => !item.locked) || remaining[0])?.id || null);
    }
    if (!remaining.length) {
      setSwitcher(false); setOpenDatabase(true);
    }
    flashPlain("Removed from Trove; file kept: " + (removed?.path || removed?.file || id));
  };
  // Native file dialog → register the picked .kdbx (locked) → switch to it.
  // Create: choose where the .kdbx goes, then set its master password. Split in
  // two because the native save dialog can't collect a password.
  const newDatabase = async () => {
    let picked;
    try {
      picked = await save({ defaultPath: "database.kdbx", filters: [{ name: "KeePass database", extensions: ["kdbx"] }] });
    } catch (e) { return; }
    if (!picked) return;
    // A typed filename may arrive without the extension depending on the platform.
    setNewDatabasePath(picked.endsWith(".kdbx") ? picked : picked + ".kdbx");
  };

  const createDatabase = async (path, password) => {
    const dto = await api.createDatabase(path, password);
    setDatabases((vs) => vs.some((v) => v.id === dto.id) ? vs : [...vs, withViewState(dto)]);
    setActiveId(dto.id);
    setNewDatabasePath(null);
    setOpenDatabase(false);
    flashPlain("Created " + dto.file);
  };

  const browseDatabase = async () => {
    let picked;
    try {
      picked = await open({ multiple: false, directory: false, filters: [{ name: "KeePass database", extensions: ["kdbx"] }] });
    } catch (e) { return; }
    if (!picked) return;
    const path = Array.isArray(picked) ? picked[0] : picked;
    let dto;
    try { dto = await api.registerDatabase(path); } catch (e) { flashPlain("Couldn't open database"); return; }
    setDatabases((vs) => vs.some((v) => v.id === dto.id) ? vs : [...vs, withViewState(dto)]);
    setActiveId(dto.id);
    setOpenDatabase(false);
    flashPlain("Opened " + dto.file + (dto.locked ? " — locked" : ""));
  };

  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"));
  const cycleSort = () => patch((v) => ({ sort: v.sort === "title" ? "modified" : v.sort === "modified" ? "strength" : "title" }));
  const toggleFav = async (id) => {
    const cur = entries.find((e) => e.id === id);
    try {
      const list = await api.setFavorite(database.id, id, !(cur && cur.fav));
      patch({ entries: list });
    } catch (e) {}
  };

  // Per-key opt-in. The backend writes KeeAgent.settings into the database and
  // adds/removes the key in the running agent, then hands back a fresh list.
  const toggleAgentKey = async (entryId, enabled, policy) => {
    try {
      const list = await api.setAgentKey(database.id, entryId, enabled, policy);
      patch({ entries: list });
    } catch (e) {
      console.error("agent key toggle failed", e);
    }
  };

  const openNew = () => setForm({ entry: null, detail: null });
  // Existing entries have no secret on the list DTO — fetch it before editing.
  const openEdit = async (e) => {
    let d = { notes: "", fields: [], password: "" };
    try { d = await api.getEntryDetail(database.id, e.id); } catch (err) {}
    setForm({ entry: e, detail: d });
  };
  const saveEntry = async (f, orig) => {
    const input = {
      entryId: orig ? orig.id : null,
      // What was typed is relative to the folder being browsed unless it
      // starts with `/`. Resolving here rather than in the form keeps the
      // form showing what the user typed.
      path: resolveEntryPath(f.path, group), username: f.username, password: f.password,
      url: f.url, notes: f.notes, entryType: f.type,
      tags: [...f.tags.filter((tag) => !isFavoriteTag(tag)), ...(orig?.fav ? ["Favorite"] : [])],
      // Blank-named rows are dropped here rather than sent: the form keeps an
      // empty row around while someone is typing into it, and a half-added
      // attribute should not reach the database.
      fields: (f.fields || []).filter((x) => x.k.trim() !== ""),
    };
    const res = await api.saveEntry(database.id, input);
    // Stay put unless the entry would no longer be on screen.
    //
    // Saving must not move you for no reason: browsing `Infra` shows
    // `Infra/Personal/thing`, so editing that entry there and following it to
    // `Infra/Personal` would navigate away from a view that was already
    // showing it. Only when the saved entry has left the current view — a new
    // entry created elsewhere, or one moved out — is there anything to follow,
    // and then the folder it actually landed in is where you want to be.
    const saved = res.entries.find((e) => e.id === res.id);
    patch((v) => ({
      entries: res.entries,
      groups: res.groups,
      selId: res.id,
      group: isVisibleIn(saved, v.group, recycleBinPath(res.groups)) ? v.group : (saved && saved.groupPath) || "__root",
    }));
    setForm(null);
    flashPlain(orig ? "Entry saved" : "Entry added");
  };
  const createFolder = async (typedPath) => {
    const path = typedPath;
    const groups = await api.createGroup(database.id, path);
    patch({ groups, group: path, selId: null });
    setForm(null);
    flashPlain("Folder created");
  };
  const saveCustomAttribute = async (entryId, oldName, name, value) => {
    const detail = await api.setCustomAttribute(database.id, entryId, oldName, name, value);
    if (selId === entryId) setDetail(detail);
    patch({ entries: await api.listEntries(database.id) });
  };
  const deleteCustomAttribute = async (entryId, name) => {
    const detail = await api.removeCustomAttribute(database.id, entryId, name);
    if (selId === entryId) setDetail(detail);
    patch({ entries: await api.listEntries(database.id) });
  };
  // Edit Folder's Save: a rename (when `name` is set) and the tags, in one
  // click. A refused rename throws, so the dialog stays open and shows why.
  const saveFolder = async (group, tags, name) => {
    let path = group.groupPath.join("/");
    if (name != null) {
      const source = path;
      const res = await api.renameGroup(database.id, source, name);
      path = [...group.groupPath.slice(0, -1), name].join("/");
      // Browsing the renamed folder, or one inside it: follow it.
      patch((v) => ({
        entries: res.entries,
        groups: res.groups,
        group: v.group === source || v.group.startsWith(source + "/") ? path + v.group.slice(source.length) : v.group,
      }));
    }
    const before = group.tags || [];
    const tagsChanged = tags.length !== before.length || tags.some((t, i) => t !== before[i]);
    if (tagsChanged || name == null) {
      const groups = await api.setGroupTags(database.id, path, tags);
      const entries = await api.listEntries(database.id);
      patch({ groups, entries });
    }
    setGroupEditor(null);
    flashPlain(name != null ? "Folder renamed" : "Folder tags saved");
  };
  const deleteFolder = async (folder) => {
    const path = folder.groupPath.join("/");
    let res;
    try { res = await api.deleteGroup(database.id, path); } catch (err) { flashPlain("Delete failed"); throw err; }
    const gone = (g) => g === path || (typeof g === "string" && g.startsWith(path + "/"));
    patch((v) => ({
      entries: res.entries,
      groups: res.groups,
      group: gone(v.group) ? "__root" : v.group,
      selId: res.entries.some((x) => x.id === v.selId) ? v.selId : (res.entries[0] ? res.entries[0].id : null),
    }));
    setGroupEditor(null);
    flashPlain(res.recycled ? "Folder moved to recycle bin" : "Folder deleted");
  };
  // ---- drag and drop ----
  // Folders move (or copy) within the tree and slide into order; entries drop
  // onto a folder. See dnd.js for the rules, drag.jsx for the pointer work.
  const treeIndex = React.useMemo(() => indexTree(tree), [tree]);
  const resolveDrop = (item, x, y, copy) => {
    const row = rowAt(x, y);
    // The entry list takes nothing, and says so rather than going quiet.
    if (!row) return overList(x, y) ? { valid: false, overList: true } : null;
    const isOpen = (p) => document.querySelector(`[data-drop-path="${CSS.escape(p)}"]`)?.dataset.open === "1";
    const node = treeIndex.get(row.path);
    const closedWithKids = node && node.node.children.length > 0 && !isOpen(row.path);
    if (item.kind === "entry") {
      const entry = entries.find((e) => e.id === item.id);
      if (!entry) return null;
      const d = resolveEntryDrop(treeIndex, entry, row.path, entries);
      return { ...d, hover: closedWithKids ? row.path : null };
    }
    const zone = dropZone(row.offsetY, row.height);
    const d = resolveGroupDrop(treeIndex, item.path, row.path, zone, copy, isOpen);
    return { ...d, hover: zone === "into" && closedWithKids ? row.path : null };
  };
  const folderName = (parent) => (parent ? parent.split("/").pop() : "Root");
  const dropped = async ({ item, copy, drop }) => {
    try {
      if (item.kind === "entry") {
        const res = await api.dropEntry(database.id, item.id, drop.parent, copy);
        patch({ entries: res.entries, groups: res.groups });
        flashPlain(`${copy ? "Copied" : "Moved"} ${item.label} to ${folderName(drop.parent)}`);
        return;
      }
      const source = item.path;
      const res = await api.dropGroup(database.id, source, drop.parent, copy, drop.order);
      const moved = drop.parent ? drop.parent + "/" + item.label : item.label;
      // Browsing the folder that moved, or one inside it: follow it.
      patch((v) => ({
        entries: res.entries,
        groups: res.groups,
        group: !copy && (v.group === source || v.group.startsWith(source + "/")) ? moved + v.group.slice(source.length) : v.group,
      }));
      const sameParent = source.split("/").slice(0, -1).join("/") === drop.parent;
      flashPlain(copy ? `Copied ${item.label} to ${folderName(drop.parent)}` : sameParent ? `Reordered ${folderName(drop.parent)}` : `Moved ${item.label} to ${folderName(drop.parent)}`);
    } catch (err) {
      flashPlain(String(err));
    }
  };
  const { drag, start: startDrag } = useDragController({ resolve: resolveDrop, onDrop: dropped });

  const doDelete = async (e) => {
    let list;
    try { list = await api.deleteEntry(database.id, e.id); } catch (err) { setDel(null); flashPlain("Delete failed"); return; }
    patch((v) => ({ entries: list, selId: list.some((x) => x.id === v.selId) ? v.selId : (list[0] ? list[0].id : null) }));
    setDel(null); setForm(null); flashPlain("Entry deleted");
  };

  // ---- app lock (idle) ----
  // Locks the APP: closes the database view and drops the decrypted database. It
  // deliberately leaves keys in the OS agent. Those are machine-wide credentials with their own expiry;
  // yanking them because nobody clicked this window for five minutes would kill
  // a `git push` running in a terminal. An explicit Lock still retracts them.
  useEffect(() => {
    if (!hasUnlockedDatabase) return;
    let t;
    const mins = settings && Number.isFinite(settings.idleLockMinutes) ? settings.idleLockMinutes : 5;
    if (mins <= 0) return undefined; // 0 = never lock on idle
    const reset = () => {
      clearTimeout(t);
      appLockAt.current = Date.now() + mins * 60 * 1000;
      t = setTimeout(() => { appLock(); }, mins * 60 * 1000);
    };
    const evs = ["mousemove", "mousedown", "keydown", "wheel", "touchstart"];
    evs.forEach((ev) => window.addEventListener(ev, reset, { passive: true }));
    reset();
    return () => { clearTimeout(t); evs.forEach((ev) => window.removeEventListener(ev, reset)); };
  }, [hasUnlockedDatabase, appLock, settings]);

  const paletteActions = [
    { label: "New entry", icon: "plus", kbd: "⌘N", run: openNew },
    { label: "Copy password", icon: "key", kbd: "⌘C", run: () => copy(null, null, "password") },
    { label: "Data lock — remove keys + files", icon: "lock", kbd: "⌘L", run: dataLock },
    ...databases.filter((v) => v.id !== activeId).map((v) => ({
      label: "Switch to " + v.name + (v.locked ? " (locked)" : ""), icon: "shield",
      kbd: "⌘" + (databases.indexOf(v) + 1), run: () => switchDatabase(v.id),
    })),
    { label: "Open database…", icon: "file", kbd: "⌘O", run: () => setOpenDatabase(true) },
    { label: theme === "dark" ? "Switch to light theme" : "Switch to dark theme", icon: theme === "dark" ? "sun" : "moon", kbd: "⌘J", run: toggleTheme },
    { label: "Change color theme…", icon: "droplet", run: () => setThemeMenu(true) },
    { label: "Keyboard shortcuts", icon: "command", kbd: "?", run: () => setHelp(true) },
    { label: "Settings…", icon: "gear", run: openSettings },
    { label: "New database…", icon: "plus", run: () => newDatabase() },
  ];

  // ---- keyboard ----
  useEffect(() => {
    const onKey = (e) => {
      const mod = e.metaKey || e.ctrlKey;
      const activeElement = document.activeElement;
      const typing = ["INPUT", "TEXTAREA"].includes(activeElement && activeElement.tagName) || activeElement?.isContentEditable;
      if (typing && mod && ["a", "c", "v", "x"].includes(e.key.toLowerCase())) return;

      if (mod && e.key >= "1" && e.key <= "9") {
        const v = databases[parseInt(e.key, 10) - 1];
        if (v) { e.preventDefault(); switchDatabase(v.id); }
        return;
      }
      if (mod && e.key.toLowerCase() === "o") { e.preventDefault(); setOpenDatabase(true); return; }
      if (mod && e.key.toLowerCase() === "j") { e.preventDefault(); return toggleTheme(); }
      if (e.key === "Escape") {
        if (historyEntry) return setHistoryEntry(null);
        if (palette) return setPalette(false);
        if (switcher) return setSwitcher(false);
        if (themeMenu) return setThemeMenu(false);
        if (openDatabase) return setOpenDatabase(false);
        if (form) return setForm(null);
        if (del) return setDel(null);
        if (help) return setHelp(false);
        if (clip) return stopClip();
        if (!locked && query) return setQuery("");
        return;
      }
      if (mod && e.key.toLowerCase() === "k") { e.preventDefault(); if (!locked) setPalette((p) => !p); return; }
      if (locked) return;

      if (mod && e.key.toLowerCase() === "l") { e.preventDefault(); return dataLock(); }
      if (mod && e.key.toLowerCase() === "n") { e.preventDefault(); return openNew(); }
      if (anyOverlay || switcher || themeMenu || syncOpen) return;
      if (mod && e.key.toLowerCase() === "c") { e.preventDefault(); if (selected) copy(null, null, "password"); return; }
      if (mod && e.key.toLowerCase() === "b") { e.preventDefault(); if (selected) copy(selected.username, selected.id + ":user", "username"); return; }

      if (typing) return;
      if (e.key === "/") { e.preventDefault(); searchRef.current && searchRef.current.focus(); return; }
      if (e.key === "?") { e.preventDefault(); setHelp(true); return; }
      if (e.key.toLowerCase() === "e") { if (selected) { e.preventDefault(); openEdit(selected); } return; }
      if (e.key.toLowerCase() === "r") { if (selected) { e.preventDefault(); setRevealed((r) => !r); } return; }
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const i = filtered.findIndex((x) => x.id === selId);
        const ni = e.key === "ArrowDown" ? Math.min(filtered.length - 1, i + 1) : Math.max(0, i - 1);
        if (filtered[ni]) patch({ selId: filtered[ni].id });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  useEffect(() => () => { clearInterval(clipTimer.current); clearTimeout(copiedTimer.current); clearTimeout(plainTimer.current); }, []);

  // ---- render ----
  const groupTitle = group === "__all" ? "All entries" : group === "__fav" ? "Favorites" : group === "__root" ? "Root" : group.split("/").pop();
  const groupSub = (query ? filtered.length + " of " + entries.length + " match “" + query + "”" : filtered.length + (filtered.length === 1 ? " entry" : " entries"))
    + (group !== "__all" && group !== "__fav" && group !== "__root" ? " · " + group : "");


  // The old toolbar row held these; they sit at the top of the detail column now.
  const appActions = (
    <>
      <button className="icon-btn" onClick={() => setPalette(true)} title="Command palette (⌘K)"><Icon name="command" size={17} /></button>
      <div className="divider-v" />
      <button className="icon-btn" onClick={toggleTheme} title="Toggle theme (⌘J)"><Icon name={theme === "dark" ? "sun" : "moon"} size={17} /></button>
      <button className={"icon-btn" + (themeMenu ? " active" : "")} onClick={() => setThemeMenu((m) => !m)} title="Appearance"><Icon name="droplet" size={17} /></button>
      <button className="icon-btn" onClick={openSettings} title="Settings"><Icon name="gear" size={17} /></button>
      <button className="icon-btn" onClick={() => setHelp(true)} title="Shortcuts (?)" style={{ fontWeight: 700, fontSize: 15 }}>?</button>
    </>
  );

  return (
    <div className="desk">
      <div className="window">
        {/* titlebar */}
        {/* The OS draws the window buttons and owns dragging. An overlay title
            bar was tried and reverted: it hands the drag region to the webview,
            and every variant either dragged once per focus or turned the press
            into a text selection. This strip carries the build stamp and database
            database identity only. */}
        <div className="titlebar">
          {/* Left: who this is. */}
          <div className="win-brand">
            <img src="/favicon.svg" alt="" width="15" height="15" />
            <span>Trove</span>
          </div>
          {/* Centre: which database you are looking at, of possibly several. */}
          <div className="win-title">
            <span className={"dot" + (database.readOnly ? " read-only" : locked ? " locked" : "")} />
            <span className="win-database-name" title={database.path ? `${database.file} (${database.path})` : database.file}>
              {database.file}{database.path ? ` (${database.path})` : ""}
            </span>
            {database.readOnly && <span className="win-read-only">READ ONLY</span>}
            {openCount > 1 && <span className="win-of"> · {openCount} open</span>}
          </div>
          {/* Right: what trove is currently doing to the machine, then which
              build is doing it. The key count is the only view anyone has of
              the system agent without opening a terminal. */}
          <div className="rgt">
            {agentKeys > 0 && (
              <span
                className="win-keys"
                title={
                  `${agentKeys} key${agentKeys === 1 ? "" : "s"} in the system agent` +
                  (keysLeft == null ? " · no expiry" : ` · expires in ${fmtLeft(keysLeft)}`)
                }
              >
                <Icon name="key" size={12} /> {agentKeys}
                {keysLeft != null && <span className="win-keys-left">{fmtLeft(keysLeft)}</span>}
              </span>
            )}
            <span className="win-ver">{buildLabel}</span>
          </div>
        </div>

        {/* body */}
        {locked ? (
          <Unlock database={database} onUnlock={unlock} onReady={unlockReady} onChange={() => setSwitcher(true)} onTouchId={touchIdUnlock} onRemember={touchIdRemember} />
        ) : (
          <div className="body" style={{ "--sidebar-w": sidebarW + "px", "--list-w": listW + "px" }}>
            <Sidebar tree={tree} selectedGroup={syncOpen ? null : group} onSelectGroup={setGroup} onEditGroupTags={setGroupEditor} drag={syncOpen ? null : drag} onDragStart={syncOpen ? undefined : startDrag} database={database} onSwitcher={() => setSwitcher(true)} onEditMetadata={() => setMetadataOpen(true)} onSync={() => setSyncOpen(true)} syncSelected={syncOpen} onNew={openNew} onDataLock={dataLock} idleLabel={idleLabel} />
            <ResizeHandle
              label="Resize sidebar"
              onDelta={(inc) => setSidebarW((w) => clampW(w + inc, SIDEBAR_MIN, SIDEBAR_MAX))}
              onReset={() => setSidebarW(DEFAULT_SIDEBAR_W)}
            />
            {syncOpen ? <DatabaseSync key={database.id} database={database} databases={databases} onSaved={revisionSaved} onRefreshed={revisionRefreshed} appActions={appActions} /> : <><EntryList
              entries={filtered} selectedId={selId} onSelect={setSelId}
              title={groupTitle} subtitle={groupSub} sort={sort} onCycleSort={cycleSort}
              query={query} onQuery={setQuery} searchRef={searchRef} databaseName={database.name}
              drag={drag} onDragStart={startDrag}
            />
            <ResizeHandle
              label="Resize entry list"
              onDelta={(inc) => setListW((w) => clampW(w + inc, LIST_MIN, LIST_MAX))}
              onReset={() => setListW(DEFAULT_LIST_W)}
            />
            <Detail
              databaseId={database.id}
              appActions={appActions}
              entry={selected} notes={detail.notes} fields={detail.fields} password={detail.password}
              onCopy={copy} copiedKey={copiedKey}
              onEdit={openEdit} onDelete={(e) => setDel(e)} onToggleFav={toggleFav}
              onSaveAttribute={saveCustomAttribute} onDeleteAttribute={deleteCustomAttribute}
              revealed={revealed} onToggleReveal={() => setRevealed((r) => !r)}
              onToggleAgentKey={toggleAgentKey}
              onHistory={setHistoryEntry}
            />
            </>}
          </div>
        )}

        {/* overlays */}
        {historyEntry && !database.locked && <EntryHistoryModal key={database.id + historyEntry.id} database={database} entry={historyEntry} onClose={() => setHistoryEntry(null)} onSaved={revisionSaved} />}
        {palette && <CommandPalette entries={entries} actions={paletteActions} onClose={() => setPalette(false)} onOpenEntry={(id) => { setSyncOpen(false); const entry = entries.find((item) => item.id === id); patch({ selId: id, group: entry?.groupPath || "__root" }); }} />}
        {form && <EntryForm key={form.entry ? form.entry.id : "new"} entry={form.entry} detail={form.detail} group={group} onClose={() => setForm(null)} onSave={saveEntry} onCreateFolder={createFolder} onDelete={(e) => { setForm(null); setDel(e); }} />}
        {groupEditor && <EditFolderModal group={groupEditor} entries={entries} databaseId={database?.id} onClose={() => setGroupEditor(null)} onSave={saveFolder} onDelete={deleteFolder} />}
        {del && <ConfirmDelete entry={del} onCancel={() => setDel(null)} onConfirm={doDelete} />}
        {help && <HelpModal onClose={() => setHelp(false)} />}
        {settingsOpen && settings && <SettingsModal settings={settings} onChange={saveSettings} onClose={() => setSettingsOpen(false)} />}
        {themeMenu && <ThemeMenu theme={theme} accent={accent} onTheme={setTheme} onAccent={setAccent} onClose={() => setThemeMenu(false)} />}
        {switcher && <DatabaseSwitcher databases={databases} activeId={activeId} onSwitch={switchDatabase} onSave={saveDatabase} onRemove={removeDatabase} onOpenNew={() => setOpenDatabase(true)} onNewDatabase={newDatabase} onClose={() => setSwitcher(false)} />}
        {metadataOpen && !database.locked && <DatabaseMetadataModal databaseId={database.id} databaseName={database.name} onClose={() => setMetadataOpen(false)} onSaved={(metadata) => { patch({ troveUuid: metadata?.troveUuid || null }); flashPlain("Database metadata saved"); }} />}
        {newDatabasePath && <NewDatabaseModal path={newDatabasePath} onCreate={createDatabase} onClose={() => setNewDatabasePath(null)} />}
        {openDatabase && <OpenDatabaseModal recents={databases} activeId={activeId} onPick={(v) => { setOpenDatabase(false); switchDatabase(v.id); }} onBrowse={browseDatabase} onClose={() => setOpenDatabase(false)} />}

        <DragGhost drag={drag} />

        {/* toasts */}
        <div className="toast-wrap">
          {plain && <PlainToast text={plain.text} />}
          {clip && <ClipboardToast data={clip} onClear={stopClip} />}
        </div>
      </div>
    </div>
  );
}

export default App;
