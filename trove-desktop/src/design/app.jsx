import React from 'react';
import { Icon } from './icons.jsx';
import { buildTree, makeVault, INITIAL_VAULTS, OPENABLE_VAULTS } from './data.jsx';
import { Sidebar, EntryList, Detail } from './views.jsx';
import { Unlock, CommandPalette, EntryForm, ConfirmDelete, HelpModal, ThemeMenu, VaultSwitcher, OpenVaultModal, ClipboardToast, PlainToast } from './overlays.jsx';
// Trove — main app (multi-vault)

const { useState, useEffect, useRef, useCallback } = React;

function App() {
  // vaults: each carries its own entries + view state
  const [vaults, setVaults] = useState(() => INITIAL_VAULTS.map((v) => ({
    ...v, group: "__all", selId: v.entries[0] && v.entries[0].id, query: "", sort: "title",
  })));
  const [activeId, setActiveId] = useState(() => INITIAL_VAULTS[0].id);
  const vault = vaults.find((v) => v.id === activeId) || vaults[0];
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

  const [copiedKey, setCopiedKey] = useState(null);
  const [clip, setClip] = useState(null);
  const [plain, setPlain] = useState(null);
  const searchRef = useRef(null);
  const clipTimer = useRef(null);
  const copiedTimer = useRef(null);
  const plainTimer = useRef(null);

  useEffect(() => { document.documentElement.dataset.theme = theme; try { localStorage.setItem("trove.theme", theme); } catch (e) {} }, [theme]);
  useEffect(() => { document.documentElement.dataset.accent = accent; try { localStorage.setItem("trove.accent", accent); } catch (e) {} }, [accent]);

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
      if (sort === "modified") return new Date(b.modified) - new Date(a.modified);
      if (sort === "strength") return a.strength - b.strength;
      return 0;
    });
    return out;
  }, [entries, group, query, sort]);

  useEffect(() => {
    if (filtered.length && !filtered.some((e) => e.id === selId)) patch({ selId: filtered[0].id });
  }, [filtered, selId, patch]);

  useEffect(() => { setRevealed(false); }, [selId, activeId]);

  const selected = entries.find((e) => e.id === selId) || null;
  const anyOverlay = palette || form || del || help || openVault;

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
    clearInterval(clipTimer.current);
    setClip(null);
  }, []);
  const copy = useCallback((value, key, kind) => {
    try { navigator.clipboard && navigator.clipboard.writeText(value); } catch (e) {}
    if (key) { setCopiedKey(key); clearCopiedSoon(); }
    if (kind === "password") {
      const total = 12;
      clearInterval(clipTimer.current);
      setClip({ label: "Password", total, left: total });
      clipTimer.current = setInterval(() => {
        setClip((c) => {
          if (!c) return null;
          if (c.left <= 1) { clearInterval(clipTimer.current); return null; }
          return { ...c, left: c.left - 1 };
        });
      }, 1000);
    } else {
      const nice = kind === "url" ? "URL" : kind.charAt(0).toUpperCase() + kind.slice(1);
      flashPlain(nice + " copied");
    }
  }, []);

  // ---- vault actions ----
  const lock = () => { stopClip(); patch({ locked: true }); setPalette(false); setForm(null); setDel(null); };
  const unlock = () => patch({ locked: false });
  const switchVault = (id) => {
    setActiveId(id); setSwitcher(false);
    setPalette(false); setForm(null); setDel(null); setRevealed(false);
  };
  const doOpenVault = (f) => {
    setOpenVault(false);
    const existing = vaults.find((v) => v.file === f.file);
    if (existing) { switchVault(existing.id); return; }
    const nv = makeVault(f.name, f.file, f.raw, true);
    setVaults((vs) => [...vs, { ...nv, group: "__all", selId: nv.entries[0] && nv.entries[0].id, query: "", sort: "title" }]);
    setActiveId(nv.id);
    flashPlain("Opened " + f.file + " — locked");
  };
  const openableFiles = OPENABLE_VAULTS.filter((f) => !vaults.some((v) => v.file === f.file));

  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"));
  const cycleSort = () => patch((v) => ({ sort: v.sort === "title" ? "modified" : v.sort === "modified" ? "strength" : "title" }));
  const toggleFav = (id) => patch((v) => ({ entries: v.entries.map((e) => e.id === id ? { ...e, fav: !e.fav } : e) }));

  const openNew = () => setForm({ entry: null });
  const openEdit = (e) => setForm({ entry: e });
  const saveEntry = (f, orig) => {
    const segs = f.path.split("/").filter(Boolean);
    const title = segs[segs.length - 1] || "untitled";
    const gp = segs.slice(0, -1);
    if (orig) {
      patch((v) => ({ entries: v.entries.map((e) => e.id === orig.id ? {
        ...e, ...f, title, group: gp, groupPath: gp.join("/"), modified: new Date().toISOString(),
      } : e) }));
    } else {
      const id = vault.id + "-e" + Date.now();
      const ne = { id, ...f, title, group: gp, groupPath: gp.join("/"), type: f.type || "login",
        fields: [], strength: 80, modified: new Date().toISOString(), created: new Date().toISOString(), fav: false };
      patch((v) => ({ entries: [...v.entries, ne], selId: id, group: "__all" }));
    }
    setForm(null); flashPlain(orig ? "Entry saved" : "Entry added");
  };
  const doDelete = (e) => {
    patch((v) => ({ entries: v.entries.filter((x) => x.id !== e.id) }));
    setDel(null); setForm(null); flashPlain("Entry deleted");
  };

  const paletteActions = [
    { label: "New entry", icon: "plus", kbd: "⌘N", run: openNew },
    { label: "Copy password", icon: "key", kbd: "⌘C", run: () => selected && copy(selected.password, selected.id + ":pass", "password") },
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
      if (mod && e.key.toLowerCase() === "c") { e.preventDefault(); if (selected) copy(selected.password, selected.id + ":pass", "password"); return; }
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
              entry={selected} onCopy={copy} copiedKey={copiedKey}
              onEdit={openEdit} onDelete={(e) => setDel(e)} onToggleFav={toggleFav}
              revealed={revealed} onToggleReveal={() => setRevealed((r) => !r)}
            />
          </div>
        )}

        {/* overlays */}
        {palette && <CommandPalette entries={entries} actions={paletteActions} onClose={() => setPalette(false)} onOpenEntry={(id) => patch({ selId: id, group: "__all" })} />}
        {form && <EntryForm entry={form.entry} onClose={() => setForm(null)} onSave={saveEntry} onDelete={(e) => { setForm(null); setDel(e); }} />}
        {del && <ConfirmDelete entry={del} onCancel={() => setDel(null)} onConfirm={doDelete} />}
        {help && <HelpModal onClose={() => setHelp(false)} />}
        {themeMenu && <ThemeMenu theme={theme} accent={accent} onTheme={setTheme} onAccent={setAccent} onClose={() => setThemeMenu(false)} />}
        {switcher && <VaultSwitcher vaults={vaults} activeId={activeId} onSwitch={switchVault} onOpenNew={() => setOpenVault(true)} onClose={() => setSwitcher(false)} />}
        {openVault && <OpenVaultModal files={openableFiles} onPick={doOpenVault} onClose={() => setOpenVault(false)} />}

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
