import React from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { Icon } from './icons.jsx';
import { buildTree } from './tree.js';
import * as api from './api.js';
import { Sidebar, EntryList, Detail } from './views.jsx';
import { Unlock, CommandPalette, EntryForm, ConfirmDelete, HelpModal, ThemeMenu, VaultSwitcher, OpenVaultModal, ClipboardToast, PlainToast } from './overlays.jsx';
// Trove — main app (multi-vault, backed by real .kdbx files via src/api.js)

const { useState, useEffect, useRef, useCallback } = React;

// Placeholder so the chrome renders before any vault is registered (fresh
// install with no persisted recents). It reads as a locked, empty vault.
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
  const [themeMenu, setThemeMenu] = useState(false);
  const [switcher, setSwitcher] = useState(false);
  const [openVault, setOpenVault] = useState(false);
  const [revealed, setRevealed] = useState(false);
  // Secret detail for the selected entry, fetched on selection (get_entry_detail).
  const [detail, setDetail] = useState({ notes: "", fields: [], password: "" });

  const [copiedKey, setCopiedKey] = useState(null);
  const [clip, setClip] = useState(null);
  const [plain, setPlain] = useState(null);
  const searchRef = useRef(null);
  const clipTimer = useRef(null);
  const copiedTimer = useRef(null);
  const plainTimer = useRef(null);

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
  useEffect(() => {
    setRevealed(false);
    const sel = entries.find((e) => e.id === selId);
    if (!sel || vault.locked || vault.id == null) { setDetail({ notes: "", fields: [], password: "" }); return; }
    let cancelled = false;
    api.getEntryDetail(vault.id, sel.id)
      .then((d) => { if (!cancelled) setDetail(d || { notes: "", fields: [], password: "" }); })
      .catch(() => { if (!cancelled) setDetail({ notes: "", fields: [], password: "" }); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selId, activeId, vault.locked]);

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
  const lock = useCallback(async () => {
    stopClip();
    setPalette(false); setForm(null); setDel(null);
    const id = activeId;
    if (id == null) return;
    try { await api.lockVault(id); } catch (e) {}
    setVaults((vs) => vs.map((v) => v.id === id ? { ...v, locked: true, entries: [], loaded: false, selId: null } : v));
  }, [activeId, stopClip]);
  // Async: decrypt via the backend. Resolves on success (parent unmounts Unlock),
  // rejects (bad password) so <Unlock> can surface the error.
  const unlock = async (pw) => {
    const list = await api.unlockVault(vault.id, pw);
    patch({ locked: false, entries: list, loaded: true, group: "__all", selId: list[0] ? list[0].id : null });
  };
  const switchVault = (id) => {
    setActiveId(id); setSwitcher(false);
    setPalette(false); setForm(null); setDel(null); setRevealed(false);
  };
  // Native file dialog → register the picked .kdbx (locked) → switch to it.
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

  // ---- idle auto-lock (5 minutes) ----
  useEffect(() => {
    if (vault.locked || vault.id == null) return;
    let t;
    const reset = () => { clearTimeout(t); t = setTimeout(() => { lock(); }, 5 * 60 * 1000); };
    const evs = ["mousemove", "mousedown", "keydown", "wheel", "touchstart"];
    evs.forEach((ev) => window.addEventListener(ev, reset, { passive: true }));
    reset();
    return () => { clearTimeout(t); evs.forEach((ev) => window.removeEventListener(ev, reset)); };
  }, [vault.locked, vault.id, lock]);

  const paletteActions = [
    { label: "New entry", icon: "plus", kbd: "⌘N", run: openNew },
    { label: "Copy password", icon: "key", kbd: "⌘C", run: () => copy(null, null, "password") },
    { label: "Lock vault", icon: "lock", kbd: "⌘L", run: lock },
    ...vaults.filter((v) => v.id !== activeId).map((v) => ({
      label: "Switch to " + v.name + (v.locked ? " (locked)" : ""), icon: "shield",
      kbd: "⌘" + (vaults.indexOf(v) + 1), run: () => switchVault(v.id),
    })),
    { label: "Open vault…", icon: "file", kbd: "⌘O", run: () => setOpenVault(true) },
    { label: theme === "dark" ? "Switch to light theme" : "Switch to dark theme", icon: theme === "dark" ? "sun" : "moon", kbd: "⌘J", run: toggleTheme },
    { label: "Change color theme…", icon: "droplet", run: () => setThemeMenu(true) },
    { label: "Keyboard shortcuts", icon: "command", kbd: "?", run: () => setHelp(true) },
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

      if (mod && e.key.toLowerCase() === "l") { e.preventDefault(); return lock(); }
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

  return (
    <div className="desk">
      <div className="window">
        {/* titlebar */}
        <div className="titlebar">
          <div className="traffic"><span className="tl r" /><span className="tl y" /><span className="tl g" /></div>
          <div className="win-title"><span className={"dot" + (locked ? " locked" : "")} /> Trove — {vault.file}</div>
          <div className="rgt" />
        </div>

        {/* toolbar */}
        <div className="toolbar">
          <div className="status-pill">
            <Icon name={locked ? "lock" : "unlock"} size={15} className={"lk" + (locked ? " amber" : "")} />
            <span>{locked ? "Locked" : "Unlocked"}</span>
            {!locked && <span className="sub">· auto‑lock 5m</span>}
          </div>
          {!locked ? (
            <div className="search" onClick={() => searchRef.current && searchRef.current.focus()}>
              <Icon name="search" size={16} className="si" />
              <input ref={searchRef} value={query} onChange={(e) => setQuery(e.target.value)} placeholder={"Search " + vault.name.toLowerCase() + "…"} spellCheck="false" />
              {query ? (
                <button className="icon-btn" style={{ width: 24, height: 24 }} onClick={(e) => { e.stopPropagation(); setQuery(""); }}><Icon name="x" size={14} /></button>
              ) : (
                <span className="kbd">/</span>
              )}
            </div>
          ) : (
            <div style={{ flex: 1 }} />
          )}
          <div className="tbar-actions">
            {!locked && <button className="btn-accent" onClick={openNew}><Icon name="plus" size={16} />New</button>}
            {!locked && <button className="icon-btn" onClick={() => setPalette(true)} title="Command palette (⌘K)"><Icon name="command" size={17} /></button>}
            <div className="divider-v" />
            <button className="icon-btn" onClick={toggleTheme} title="Toggle theme (⌘J)"><Icon name={theme === "dark" ? "sun" : "moon"} size={17} /></button>
            <button className={"icon-btn" + (themeMenu ? " active" : "")} onClick={() => setThemeMenu((m) => !m)} title="Appearance"><Icon name="droplet" size={17} /></button>
            <button className="icon-btn" onClick={() => setHelp(true)} title="Shortcuts (?)" style={{ fontWeight: 700, fontSize: 15 }}>?</button>
            {!locked && <button className="icon-btn" onClick={lock} title="Lock (⌘L)"><Icon name="lock" size={17} /></button>}
          </div>
        </div>

        {/* body */}
        {locked ? (
          <Unlock vault={vault} onUnlock={unlock} onChange={() => setSwitcher(true)} />
        ) : (
          <div className="body">
            <Sidebar tree={tree} total={entries.length} favCount={favCount} selectedGroup={group} onSelectGroup={setGroup} vault={vault} onSwitcher={() => setSwitcher(true)} />
            <EntryList
              entries={filtered} selectedId={selId} onSelect={setSelId}
              title={groupTitle} subtitle={groupSub} sort={sort} onCycleSort={cycleSort}
            />
            <Detail
              entry={selected} notes={detail.notes} fields={detail.fields} password={detail.password}
              onCopy={copy} copiedKey={copiedKey}
              onEdit={openEdit} onDelete={(e) => setDel(e)} onToggleFav={toggleFav}
              revealed={revealed} onToggleReveal={() => setRevealed((r) => !r)}
            />
          </div>
        )}

        {/* overlays */}
        {palette && <CommandPalette entries={entries} actions={paletteActions} onClose={() => setPalette(false)} onOpenEntry={(id) => patch({ selId: id, group: "__all" })} />}
        {form && <EntryForm entry={form.entry} detail={form.detail} onClose={() => setForm(null)} onSave={saveEntry} onDelete={(e) => { setForm(null); setDel(e); }} />}
        {del && <ConfirmDelete entry={del} onCancel={() => setDel(null)} onConfirm={doDelete} />}
        {help && <HelpModal onClose={() => setHelp(false)} />}
        {themeMenu && <ThemeMenu theme={theme} accent={accent} onTheme={setTheme} onAccent={setAccent} onClose={() => setThemeMenu(false)} />}
        {switcher && <VaultSwitcher vaults={vaults} activeId={activeId} onSwitch={switchVault} onOpenNew={() => setOpenVault(true)} onClose={() => setSwitcher(false)} />}
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
