import React from 'react';
import { open, save } from '@tauri-apps/plugin-dialog';
import { Icon } from './icons.jsx';
import { buildTree } from './tree.js';
import * as api from './api.js';
import { Sidebar, EntryList, Detail } from './views.jsx';
import { Unlock, CommandPalette, EntryForm, ConfirmDelete, HelpModal, ThemeMenu, VaultSwitcher, OpenVaultModal, ClipboardToast, PlainToast, SettingsModal, NewVaultModal } from './overlays.jsx';
// Trove — main app (multi-vault, backed by real .kdbx files via src/api.js)

const { useState, useEffect, useRef, useCallback } = React;

// Three-pane sizing: the sidebar and entry-list widths are user-draggable (and
// persisted); the detail pane flexes to fill the rest.
const DEFAULT_SIDEBAR_W = 230;
const DEFAULT_LIST_W = 320;
const SIDEBAR_MIN = 170, SIDEBAR_MAX = 420;
const LIST_MIN = 240, LIST_MAX = 620;
const clampW = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

// A draggable vertical divider between two panes. Reports incremental cursor
// deltas while dragging; double-click resets the adjacent pane to its default.
function ResizeHandle({ onDelta, onReset, label }) {
  const [drag, setDrag] = useState(false);
  const last = useRef(0);
  // Keep the latest onDelta in a ref so the drag effect depends only on `drag`
  // (onDelta is a fresh closure each render). The effect then runs once per drag
  // and its cleanup reliably restores the body styles on drag-end AND on
  // unmount — if a shortcut locks/switches the vault mid-drag the handle
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

// Placeholder so the chrome renders before any vault is registered (fresh
// install with no persisted recents). It reads as a locked, empty vault.
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

const NO_VAULT = { id: null, name: "No vault", file: "—", path: "", locked: true, entries: [], group: "__all", selId: null, query: "", sort: "title", loaded: false };

// Give a fetched VaultDto the per-vault view state the UI layers on top.
function withViewState(v) {
  return { ...v, entries: [], group: "__all", selId: null, query: "", sort: "title", loaded: false };
}

function App() {
  // vaults: each is a VaultDto (id/name/file/path/locked) + per-vault view state.
  const [vaults, setVaults] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const vault = vaults.find((v) => v.id === activeId) || vaults[0] || NO_VAULT;
  const patch = useCallback((p) => {
    setVaults((vs) => vs.map((v) => v.id === activeId ? { ...v, ...(typeof p === "function" ? p(v) : p) } : v));
  }, [activeId]);

  const { locked, entries, group, selId, query, sort } = vault;
  const setGroup = (g) => patch({ group: g });
  const setSelId = (id) => patch({ selId: id });
  const setQuery = (q) => patch({ query: q });

  const [theme, setTheme] = useState(() => { try { return localStorage.getItem("trove.theme") || "dark"; } catch (e) { return "dark"; } });
  const [accent, setAccent] = useState(() => { try { return localStorage.getItem("trove.accent") || "brass"; } catch (e) { return "brass"; } });

  const [palette, setPalette] = useState(false);
  const [form, setForm] = useState(null);
  const [del, setDel] = useState(null);
  const [help, setHelp] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settings, setSettings] = useState(null);
  const [themeMenu, setThemeMenu] = useState(false);
  const [switcher, setSwitcher] = useState(false);
  const [openVault, setOpenVault] = useState(false);
  // Which build this is. A dev window and an installed one look identical
  // otherwise, which makes "is this even my change?" a guess.
  const [build, setBuild] = useState(null);
  const [newVaultPath, setNewVaultPath] = useState(null);
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
    if (vault.locked) return undefined;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [vault.locked]);

  const openCount = vaults.filter((v) => !v.locked).length;
  const agentKeys = vaults.reduce((n, v) => n + (v.agentKeys || 0), 0);
  const idleMins = settings && Number.isFinite(settings.idleLockMinutes) ? settings.idleLockMinutes : 5;
  // Counts down to the window locking; resets on every interaction, so it also
  // shows that trove noticed you are still here.
  const appLockLeft = idleMins > 0 && !locked && appLockAt.current
    ? Math.max(0, appLockAt.current - now)
    : null;
  const idleLabel = idleMins > 0
    ? `App lock ${appLockLeft == null ? `${idleMins}m` : fmtLeft(appLockLeft)}`
    : "No app lock";

  // Counts down to the first forwarded key dropping out of the agent. Not a
  // "data lock" timer — a data lock is something you do, not something that
  // happens — this is the expiry those keys were given.
  const expireAt = vaults.reduce(
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
  // Per-key opt-in. The backend writes KeeAgent.settings into the vault and
  // adds/removes the key in the running agent, then hands back a fresh list.
  const saveSettings = useCallback((next) => {
    setSettings(next);
    api.setSettings(next).catch((e) => console.error("settings save failed", e));
  }, []);

  useEffect(() => { document.documentElement.dataset.theme = theme; try { localStorage.setItem("trove.theme", theme); } catch (e) {} }, [theme]);
  useEffect(() => { document.documentElement.dataset.accent = accent; try { localStorage.setItem("trove.accent", accent); } catch (e) {} }, [accent]);

  // ---- startup: load persisted registered vaults (all come back locked) ----
  useEffect(() => {
    api.listVaults().then((vs) => {
      const mapped = (vs || []).map(withViewState);
      setVaults(mapped);
      if (mapped.length) setActiveId(mapped[0].id);
      else setOpenVault(true);
    }).catch(() => {});
  }, []);

  // ---- tree, filtered + sorted list ----
  const tree = React.useMemo(() => buildTree(entries), [entries]);
  const favCount = entries.filter((e) => e.fav).length;

  const filtered = React.useMemo(() => {
    let out = entries;
    if (group === "__fav") out = out.filter((e) => e.fav);
    else if (group !== "__all") out = out.filter((e) => e.groupPath === group || e.groupPath.startsWith(group + "/"));
    const q = query.trim().toLowerCase();
    if (q) out = out.filter((e) => e.path.toLowerCase().includes(q) || e.username.toLowerCase().includes(q) || (e.url || "").toLowerCase().includes(q));
    out = out.slice().sort((a, b) => {
      if (sort === "title") return a.title.localeCompare(b.title) || a.path.localeCompare(b.path);
      if (sort === "modified") return (new Date(b.modified).getTime() || 0) - (new Date(a.modified).getTime() || 0);
      if (sort === "strength") return a.strength - b.strength;
      return 0;
    });
    return out;
  }, [entries, group, query, sort]);

  useEffect(() => {
    if (filtered.length && !filtered.some((e) => e.id === selId)) patch({ selId: filtered[0].id });
  }, [filtered, selId, patch]);

  const selected = entries.find((e) => e.id === selId) || null;
  const anyOverlay = palette || form || del || help || openVault;

  // ---- fetch secret detail (notes / custom fields / password) on selection ----
  // Re-runs on selection change AND when the selected entry's content changes:
  // its `modified` stamp bumps on every save, so editing the selected entry
  // (same id, replaced `entries`) re-fetches instead of leaving the old
  // password/notes/fields shown and copyable.
  useEffect(() => {
    setRevealed(false);
    if (!selected || vault.locked || vault.id == null) { setDetail({ notes: "", fields: [], password: "" }); return; }
    const eid = selected.id;
    let cancelled = false;
    api.getEntryDetail(vault.id, eid)
      .then((d) => { if (!cancelled) setDetail(d || { notes: "", fields: [], password: "" }); })
      .catch(() => { if (!cancelled) setDetail({ notes: "", fields: [], password: "" }); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selId, activeId, vault.locked, vault.id, selected?.modified]);

  // ---- lazily load entries for an unlocked-but-not-yet-loaded vault ----
  useEffect(() => {
    const v = vaults.find((x) => x.id === activeId);
    if (!v || v.locked || v.loaded) return;
    let cancelled = false;
    api.listEntries(v.id).then((list) => {
      if (cancelled) return;
      setVaults((vs) => vs.map((x) => x.id === v.id
        ? { ...x, entries: list, loaded: true, selId: x.selId || (list[0] ? list[0].id : null) }
        : x));
    }).catch(() => {});
    return () => { cancelled = true; };
  }, [activeId, vaults]);

  // ---- notice when something else writes the vault file ----
  // A vault is one file with several writers: the CLI, KeePassXC, and the same
  // file synced onto another Mac. Without this the window shows a list that
  // stopped being true, and — before the core refused it — saving over it threw
  // the other writer's work away.
  //
  // Polled rather than watched. It is one `stat` per interval, it only runs
  // while a vault is actually open and this window is visible, and there is no
  // watcher to unregister when a vault closes or the app hides.
  useEffect(() => {
    if (!vault || vault.locked || !vault.loaded) return;
    const id = vault.id;
    let stopped = false;

    const check = async () => {
      if (stopped || document.hidden) return;
      try {
        if (!(await api.vaultChangedOnDisk(id))) return;
        const list = await api.reloadVault(id);
        if (stopped) return;
        setVaults((vs) => vs.map((x) => x.id === id
          // Keep the selection if that entry still exists, so a reload does not
          // yank the reader somewhere else; fall back to the first entry.
          ? { ...x, entries: list,
              selId: list.some((e) => e.id === x.selId) ? x.selId : (list[0] ? list[0].id : null) }
          : x));
        flashPlain("Reloaded — the vault changed outside this window");
      } catch (e) { /* transient: a half-written file, a lock — try again next tick */ }
    };

    const t = setInterval(check, 3000);
    // Also on regaining focus: coming back to the window is exactly when a
    // stale list is most likely and most annoying.
    window.addEventListener("focus", check);
    return () => { stopped = true; clearInterval(t); window.removeEventListener("focus", check); };
  }, [vault]); // eslint-disable-line react-hooks/exhaustive-deps

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
    if (!entry || vault.id == null) return;
    let pw = "";
    try { pw = (await api.getField(vault.id, entry.id, "Password")) || ""; } catch (e) { return; }
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
  }, [vault.id]);
  // Non-secret copies carry their value already; password routes to copyPassword.
  const copy = useCallback((value, key, kind) => {
    if (kind === "password") { copyPassword(selected); return; }
    try { navigator.clipboard && navigator.clipboard.writeText(value); } catch (e) {}
    if (key) { setCopiedKey(key); clearCopiedSoon(); }
    const nice = kind === "url" ? "URL" : kind.charAt(0).toUpperCase() + kind.slice(1);
    flashPlain(nice + " copied");
  }, [selected, copyPassword]);

  // ---- vault actions ----
  // `retractKeys` decides whether forwarded keys come back out of the OS agent.
  // An explicit lock says yes; the idle timer says no — see the auto-lock below.
  // Lock ONE vault. `retractKeys` false is the app-lock case: hide it, leave
  // what it handed the machine alone.
  const lockOne = useCallback(async (id, retractKeys) => {
    if (id == null) return;
    try { await api.lockVault(id, retractKeys); } catch (e) {}
    setVaults((vs) => vs.map((v) => v.id === id ? { ...v, locked: true, entries: [], loaded: false, selId: null } : v));
  }, []);

  // Data lock: this database only. Its keys come out of the agent and its files
  // go, and if another vault is still open you land on that one rather than at
  // a login screen — you have not finished with the app, only with this vault.
  const dataLock = useCallback(async () => {
    stopClip();
    setPalette(false); setForm(null); setDel(null);
    const id = activeId;
    await lockOne(id, true);
    const next = vaults.find((v) => v.id !== id && !v.locked);
    if (next) setActiveId(next.id);
  }, [activeId, vaults, lockOne, stopClip]);

  // App lock: the whole app steps away, so every open vault hides. Nothing is
  // taken back from the machine — that is what the data lock is for.
  const appLock = useCallback(async () => {
    stopClip();
    setPalette(false); setForm(null); setDel(null);
    const open = vaults.filter((v) => !v.locked).map((v) => v.id);
    for (const id of open) await lockOne(id, false);
  }, [vaults, lockOne, stopClip]);

  // Kept for callers that just mean "lock what I am looking at".
  const lock = useCallback((retractKeys = true) => (retractKeys ? dataLock() : appLock()), [dataLock, appLock]);
  // Async: decrypt via the backend. Resolves on success (parent unmounts Unlock),
  // rejects (bad password) so <Unlock> can surface the error.
  // Resolves with the entry list and deliberately does NOT flip the view:
  // <Unlock> shows a progress checklist while the backend works, and flipping
  // here would unmount it mid-list. It calls `unlockReady` when it's finished.
  const unlock = async (pw) => await api.unlockVault(vault.id, pw);
  // Same contract as `unlock`, except it can resolve with null: a cancelled
  // fingerprint prompt is a decision, not a failure, and <Unlock> puts the
  // password field back rather than showing an error.
  const touchIdUnlock = async () => await api.biometricUnlock(vault.id);
  // Called after a successful password unlock, with the password that worked.
  const touchIdRemember = async (pw) => await api.biometricEnroll(vault.id, pw);
  const unlockReady = (list) =>
    patch({ locked: false, entries: list, loaded: true, group: "__all", selId: list[0] ? list[0].id : null });
  const switchVault = (id) => {
    setActiveId(id); setSwitcher(false);
    setPalette(false); setForm(null); setDel(null); setRevealed(false);
  };
  // Native file dialog → register the picked .kdbx (locked) → switch to it.
  // Create: choose where the .kdbx goes, then set its master password. Split in
  // two because the native save dialog can't collect a password.
  const newVault = async () => {
    let picked;
    try {
      picked = await save({ defaultPath: "vault.kdbx", filters: [{ name: "KeePass vault", extensions: ["kdbx"] }] });
    } catch (e) { return; }
    if (!picked) return;
    // A typed filename may arrive without the extension depending on the platform.
    setNewVaultPath(picked.endsWith(".kdbx") ? picked : picked + ".kdbx");
  };

  const createVault = async (path, password) => {
    const dto = await api.createVault(path, password);
    setVaults((vs) => vs.some((v) => v.id === dto.id) ? vs : [...vs, withViewState(dto)]);
    setActiveId(dto.id);
    setNewVaultPath(null);
    setOpenVault(false);
    flashPlain("Created " + dto.file);
  };

  const browseVault = async () => {
    let picked;
    try {
      picked = await open({ multiple: false, directory: false, filters: [{ name: "KeePass vault", extensions: ["kdbx"] }] });
    } catch (e) { return; }
    if (!picked) return;
    const path = Array.isArray(picked) ? picked[0] : picked;
    let dto;
    try { dto = await api.registerVault(path); } catch (e) { flashPlain("Couldn't open vault"); return; }
    setVaults((vs) => vs.some((v) => v.id === dto.id) ? vs : [...vs, withViewState(dto)]);
    setActiveId(dto.id);
    setOpenVault(false);
    flashPlain("Opened " + dto.file + (dto.locked ? " — locked" : ""));
  };

  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"));
  const cycleSort = () => patch((v) => ({ sort: v.sort === "title" ? "modified" : v.sort === "modified" ? "strength" : "title" }));
  const toggleFav = async (id) => {
    const cur = entries.find((e) => e.id === id);
    try {
      const list = await api.setFavorite(vault.id, id, !(cur && cur.fav));
      patch({ entries: list });
    } catch (e) {}
  };

  // Per-key opt-in. The backend writes KeeAgent.settings into the vault and
  // adds/removes the key in the running agent, then hands back a fresh list.
  const toggleAgentKey = async (entryId, enabled, policy) => {
    try {
      const list = await api.setAgentKey(vault.id, entryId, enabled, policy);
      patch({ entries: list });
    } catch (e) {
      console.error("agent key toggle failed", e);
    }
  };

  const openNew = () => setForm({ entry: null, detail: null });
  // Existing entries have no secret on the list DTO — fetch it before editing.
  const openEdit = async (e) => {
    let d = { notes: "", fields: [], password: "" };
    try { d = await api.getEntryDetail(vault.id, e.id); } catch (err) {}
    setForm({ entry: e, detail: d });
  };
  const saveEntry = async (f, orig) => {
    const input = {
      entryId: orig ? orig.id : null,
      path: f.path, username: f.username, password: f.password,
      url: f.url, notes: f.notes, entryType: f.type,
    };
    const res = await api.saveEntry(vault.id, input);
    patch({ entries: res.entries, selId: res.id, group: "__all" });
    setForm(null);
    flashPlain(orig ? "Entry saved" : "Entry added");
  };
  const doDelete = async (e) => {
    let list;
    try { list = await api.deleteEntry(vault.id, e.id); } catch (err) { setDel(null); flashPlain("Delete failed"); return; }
    patch((v) => ({ entries: list, selId: list.some((x) => x.id === v.selId) ? v.selId : (list[0] ? list[0].id : null) }));
    setDel(null); setForm(null); flashPlain("Entry deleted");
  };

  // ---- app lock (idle) ----
  // Locks the APP: closes the vault view and drops the decrypted database. It
  // deliberately leaves keys in the OS agent. Those are machine-wide credentials with their own expiry;
  // yanking them because nobody clicked this window for five minutes would kill
  // a `git push` running in a terminal. An explicit Lock still retracts them.
  useEffect(() => {
    if (vault.locked || vault.id == null) return;
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
  }, [vault.locked, vault.id, appLock, settings]);

  const paletteActions = [
    { label: "New entry", icon: "plus", kbd: "⌘N", run: openNew },
    { label: "Copy password", icon: "key", kbd: "⌘C", run: () => copy(null, null, "password") },
    { label: "Data lock — remove keys + files", icon: "lock", kbd: "⌘L", run: dataLock },
    ...vaults.filter((v) => v.id !== activeId).map((v) => ({
      label: "Switch to " + v.name + (v.locked ? " (locked)" : ""), icon: "shield",
      kbd: "⌘" + (vaults.indexOf(v) + 1), run: () => switchVault(v.id),
    })),
    { label: "Open vault…", icon: "file", kbd: "⌘O", run: () => setOpenVault(true) },
    { label: theme === "dark" ? "Switch to light theme" : "Switch to dark theme", icon: theme === "dark" ? "sun" : "moon", kbd: "⌘J", run: toggleTheme },
    { label: "Change color theme…", icon: "droplet", run: () => setThemeMenu(true) },
    { label: "Keyboard shortcuts", icon: "command", kbd: "?", run: () => setHelp(true) },
    { label: "Settings…", icon: "gear", run: openSettings },
    { label: "New vault…", icon: "plus", run: () => newVault() },
  ];

  // ---- keyboard ----
  useEffect(() => {
    const onKey = (e) => {
      const mod = e.metaKey || e.ctrlKey;
      const typing = ["INPUT", "TEXTAREA"].includes(document.activeElement && document.activeElement.tagName);

      if (mod && e.key >= "1" && e.key <= "9") {
        const v = vaults[parseInt(e.key, 10) - 1];
        if (v) { e.preventDefault(); switchVault(v.id); }
        return;
      }
      if (mod && e.key.toLowerCase() === "o") { e.preventDefault(); setOpenVault(true); return; }
      if (mod && e.key.toLowerCase() === "j") { e.preventDefault(); return toggleTheme(); }
      if (e.key === "Escape") {
        if (palette) return setPalette(false);
        if (switcher) return setSwitcher(false);
        if (themeMenu) return setThemeMenu(false);
        if (openVault) return setOpenVault(false);
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
      if (anyOverlay || switcher || themeMenu) return;
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
  const groupTitle = group === "__all" ? "All entries" : group === "__fav" ? "Favorites" : group.split("/").pop();
  const groupSub = (query ? filtered.length + " of " + entries.length + " match “" + query + "”" : filtered.length + (filtered.length === 1 ? " entry" : " entries"))
    + (group !== "__all" && group !== "__fav" ? " · " + group : "");


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
            into a text selection. This strip carries the build stamp and vault
            name only. */}
        <div className="titlebar">
          {/* Left: who this is. */}
          <div className="win-brand">
            <img src="/favicon.svg" alt="" width="15" height="15" />
            <span>Trove</span>
          </div>
          {/* Centre: which vault you are looking at, of possibly several. */}
          <div className="win-title">
            <span className={"dot" + (locked ? " locked" : "")} />
            {vault.file}
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
          <Unlock vault={vault} onUnlock={unlock} onReady={unlockReady} onChange={() => setSwitcher(true)} onTouchId={touchIdUnlock} onRemember={touchIdRemember} />
        ) : (
          <div className="body" style={{ "--sidebar-w": sidebarW + "px", "--list-w": listW + "px" }}>
            <Sidebar tree={tree} total={entries.length} favCount={favCount} selectedGroup={group} onSelectGroup={setGroup} vault={vault} onSwitcher={() => setSwitcher(true)} onNew={openNew} onDataLock={dataLock} idleLabel={idleLabel} />
            <ResizeHandle
              label="Resize sidebar"
              onDelta={(inc) => setSidebarW((w) => clampW(w + inc, SIDEBAR_MIN, SIDEBAR_MAX))}
              onReset={() => setSidebarW(DEFAULT_SIDEBAR_W)}
            />
            <EntryList
              entries={filtered} selectedId={selId} onSelect={setSelId}
              title={groupTitle} subtitle={groupSub} sort={sort} onCycleSort={cycleSort}
              query={query} onQuery={setQuery} searchRef={searchRef} vaultName={vault.name}
            />
            <ResizeHandle
              label="Resize entry list"
              onDelta={(inc) => setListW((w) => clampW(w + inc, LIST_MIN, LIST_MAX))}
              onReset={() => setListW(DEFAULT_LIST_W)}
            />
            <Detail
              appActions={appActions}
              entry={selected} notes={detail.notes} fields={detail.fields} password={detail.password}
              onCopy={copy} copiedKey={copiedKey}
              onEdit={openEdit} onDelete={(e) => setDel(e)} onToggleFav={toggleFav}
              revealed={revealed} onToggleReveal={() => setRevealed((r) => !r)}
              onToggleAgentKey={toggleAgentKey}
            />
          </div>
        )}

        {/* overlays */}
        {palette && <CommandPalette entries={entries} actions={paletteActions} onClose={() => setPalette(false)} onOpenEntry={(id) => patch({ selId: id, group: "__all" })} />}
        {form && <EntryForm entry={form.entry} detail={form.detail} onClose={() => setForm(null)} onSave={saveEntry} onDelete={(e) => { setForm(null); setDel(e); }} />}
        {del && <ConfirmDelete entry={del} onCancel={() => setDel(null)} onConfirm={doDelete} />}
        {help && <HelpModal onClose={() => setHelp(false)} />}
        {settingsOpen && settings && <SettingsModal settings={settings} onChange={saveSettings} onClose={() => setSettingsOpen(false)} />}
        {themeMenu && <ThemeMenu theme={theme} accent={accent} onTheme={setTheme} onAccent={setAccent} onClose={() => setThemeMenu(false)} />}
        {switcher && <VaultSwitcher vaults={vaults} activeId={activeId} onSwitch={switchVault} onOpenNew={() => setOpenVault(true)} onNewVault={newVault} onClose={() => setSwitcher(false)} />}
        {newVaultPath && <NewVaultModal path={newVaultPath} onCreate={createVault} onClose={() => setNewVaultPath(null)} />}
        {openVault && <OpenVaultModal recents={vaults} activeId={activeId} onPick={(v) => { setOpenVault(false); switchVault(v.id); }} onBrowse={browseVault} onClose={() => setOpenVault(false)} />}

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
