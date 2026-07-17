// Trove — overlays: unlock, command palette, entry form, toast, help

/* ============ UNLOCK ============ */
function Unlock({ vault, onUnlock, onChange }) {
  const [pw, setPw] = React.useState("");
  const [show, setShow] = React.useState(false);
  const [err, setErr] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const ref = React.useRef(null);
  React.useEffect(() => { ref.current && ref.current.focus(); }, [vault.id]);

  const submit = (e) => {
    e && e.preventDefault();
    if (!pw) return;
    setBusy(true); setErr(false);
    setTimeout(() => {
      // demo: any non-"wrong" password unlocks
      if (pw.toLowerCase() === "wrong") { setErr(true); setBusy(false); setPw(""); return; }
      onUnlock();
    }, 420);
  };

  return (
    <div className="unlock-desk embed">
      <form className="unlock-card" onSubmit={submit}>
        <div className="ul-lock"><Icon name="lock" size={28} /></div>
        <div className="ul-h">Unlock {vault.name}</div>
        <div className="ul-sub">Enter your master password to decrypt the vault.</div>

        <div className="vault-chip">
          <div className="vc-ic"><Icon name="file" size={17} /></div>
          <div style={{ minWidth: 0 }}>
            <div className="vc-name">{vault.name}</div>
            <div className="vc-path">~/vaults/{vault.file}</div>
          </div>
          <button type="button" className="vc-change" onClick={onChange}>Change</button>
        </div>

        <div className="ul-field">
          <input
            ref={ref} type={show ? "text" : "password"} value={pw}
            onChange={(e) => { setPw(e.target.value); setErr(false); }}
            placeholder="Master password" autoComplete="off" spellCheck="false"
          />
          <button type="button" className="ul-reveal" onClick={() => setShow((s) => !s)} tabIndex={-1}>
            <Icon name={show ? "eyeOff" : "eye"} size={17} />
          </button>
        </div>
        <div className="ul-err">{err && (<><Icon name="x" size={13} /> Incorrect master password. Try again.</>)}</div>

        <button type="submit" className="ul-unlock" disabled={busy}>
          {busy ? <><Icon name="refresh" size={17} /> Decrypting…</> : <><Icon name="unlock" size={17} /> Unlock</>}
        </button>

        <div className="ul-foot"><Icon name="shield" size={13} /> Local‑only · never leaves this device</div>
      </form>
    </div>
  );
}

/* ============ COMMAND PALETTE ============ */
function CommandPalette({ entries, onClose, onOpenEntry, actions }) {
  const [q, setQ] = React.useState("");
  const [idx, setIdx] = React.useState(0);
  const ref = React.useRef(null);
  const listRef = React.useRef(null);
  React.useEffect(() => { ref.current && ref.current.focus(); }, []);

  const ql = q.trim().toLowerCase();
  const entryHits = entries.filter((e) =>
    !ql || e.path.toLowerCase().includes(ql) || e.username.toLowerCase().includes(ql)
  ).slice(0, 7);
  const actionHits = actions.filter((a) => !ql || a.label.toLowerCase().includes(ql));

  const flat = [
    ...entryHits.map((e) => ({ kind: "entry", e })),
    ...actionHits.map((a) => ({ kind: "action", a })),
  ];
  React.useEffect(() => { setIdx(0); }, [q]);
  React.useEffect(() => {
    const el = listRef.current && listRef.current.querySelector(".pal-item.active");
    if (el && listRef.current) {
      const c = listRef.current, r = el.getBoundingClientRect(), cr = c.getBoundingClientRect();
      if (r.top < cr.top) c.scrollTop -= (cr.top - r.top + 8);
      else if (r.bottom > cr.bottom) c.scrollTop += (r.bottom - cr.bottom + 8);
    }
  }, [idx]);

  const run = (item) => {
    if (!item) return;
    if (item.kind === "entry") onOpenEntry(item.e.id);
    else item.a.run();
    onClose();
  };
  const onKey = (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setIdx((i) => Math.min(flat.length - 1, i + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setIdx((i) => Math.max(0, i - 1)); }
    else if (e.key === "Enter") { e.preventDefault(); run(flat[idx]); }
    else if (e.key === "Escape") { e.preventDefault(); onClose(); }
  };

  let running = -1;
  return (
    <div className="scrim" onMouseDown={onClose}>
      <div className="palette" onMouseDown={(e) => e.stopPropagation()}>
        <div className="pal-input">
          <Icon name="search" size={19} />
          <input ref={ref} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey} placeholder="Search entries or run a command…" />
          <span className="kbd">esc</span>
        </div>
        <div className="pal-list" ref={listRef}>
          {entryHits.length > 0 && <div className="pal-grouplabel">Entries</div>}
          {entryHits.map((e) => {
            running++; const active = running === idx; const cur = running;
            return (
              <div key={e.id} className={"pal-item" + (active ? " active" : "")} onMouseEnter={() => setIdx(cur)} onClick={() => run({ kind: "entry", e })}>
                <span className="pic"><Icon name={TYPE_ICON[e.type] || "key"} size={16} /></span>
                <div className="ptxt">
                  <div className="pt">{e.title}</div>
                  <div className="ps">{e.groupPath} · {e.username}</div>
                </div>
                <Icon name="enter" size={15} className="pk" />
              </div>
            );
          })}
          {actionHits.length > 0 && <div className="pal-grouplabel">Commands</div>}
          {actionHits.map((a) => {
            running++; const active = running === idx; const cur = running;
            return (
              <div key={a.label} className={"pal-item" + (active ? " active" : "")} onMouseEnter={() => setIdx(cur)} onClick={() => run({ kind: "action", a })}>
                <span className="pic"><Icon name={a.icon} size={16} /></span>
                <div className="ptxt"><div className="pt">{a.label}</div></div>
                {a.kbd && <span className="kbd">{a.kbd}</span>}
              </div>
            );
          })}
          {flat.length === 0 && <div style={{ padding: "26px 14px", textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>No matches for “{q}”.</div>}
        </div>
        <div className="pal-foot">
          <span className="fh"><Icon name="updown" size={13} /> navigate</span>
          <span className="fh"><Icon name="enter" size={13} /> open</span>
          <span className="fh"><span className="kbd solo">esc</span> close</span>
        </div>
      </div>
    </div>
  );
}

/* ============ ENTRY FORM ============ */
function genPassword() {
  const sets = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*-_";
  let s = ""; for (let i = 0; i < 20; i++) s += sets[Math.floor(Math.random() * sets.length)];
  return s;
}
function EntryForm({ entry, onClose, onSave, onDelete }) {
  const editing = !!entry;
  const [f, setF] = React.useState(() => entry ? {
    path: entry.path, username: entry.username, password: entry.password, url: entry.url, notes: entry.notes || "", type: entry.type,
  } : { path: "", username: "", password: genPassword(), url: "", notes: "", type: "login" });
  const [show, setShow] = React.useState(false);
  const set = (k, v) => setF((o) => ({ ...o, [k]: v }));
  const ref = React.useRef(null);
  React.useEffect(() => { ref.current && ref.current.focus(); }, []);

  return (
    <div className="scrim center" onMouseDown={onClose}>
      <div className="modal" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="mh-badge"><Icon name={editing ? "edit" : "plus"} size={19} /></div>
          <div>
            <h2>{editing ? "Edit entry" : "New entry"}</h2>
            <p>{editing ? entry.path : "Add a credential to your vault"}</p>
          </div>
          <button className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose}><Icon name="x" size={18} /></button>
        </div>
        <div className="modal-body">
          <div className="fld">
            <label>Path <span style={{ color: "var(--text-ghost)", fontWeight: 400 }}>— group/subgroup/name</span></label>
            <input ref={ref} className="inp mono" value={f.path} onChange={(e) => set("path", e.target.value)} placeholder="inpace/00004.alex-clinic/ssh" />
          </div>
          <div className="fld">
            <label>Username</label>
            <input className="inp mono" value={f.username} onChange={(e) => set("username", e.target.value)} placeholder="root" />
          </div>
          <div className="fld">
            <label>Password</label>
            <div className="pw-row">
              <input className="inp mono" type={show ? "text" : "password"} value={f.password} onChange={(e) => set("password", e.target.value)} />
              <button className="pw-tool" title={show ? "Hide" : "Reveal"} onClick={() => setShow((s) => !s)}><Icon name={show ? "eyeOff" : "eye"} size={16} /></button>
              <button className="pw-tool" title="Generate" onClick={() => { set("password", genPassword()); setShow(true); }}><Icon name="refresh" size={16} /></button>
            </div>
          </div>
          <div className="fld">
            <label>URL</label>
            <input className="inp mono" value={f.url} onChange={(e) => set("url", e.target.value)} placeholder="https://" />
          </div>
          <div className="fld">
            <label>Notes</label>
            <textarea className="inp" rows={3} value={f.notes} onChange={(e) => set("notes", e.target.value)} placeholder="Anything else worth remembering…" />
          </div>
        </div>
        <div className="modal-foot">
          {editing && <button className="btn-danger" onClick={() => onDelete(entry)}><Icon name="trash" size={15} style={{ display: "inline", verticalAlign: "-2px", marginRight: 5 }} />Delete</button>}
          <div className="grow" />
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" onClick={() => onSave(f, entry)}>{editing ? "Save changes" : "Add entry"}</button>
        </div>
      </div>
    </div>
  );
}

/* ============ CONFIRM DELETE ============ */
function ConfirmDelete({ entry, onCancel, onConfirm }) {
  return (
    <div className="scrim center" onMouseDown={onCancel}>
      <div className="modal" style={{ width: "min(420px, 94%)" }} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="mh-badge" style={{ background: "var(--red-dim)", borderColor: "var(--red-dim)", color: "var(--red)" }}><Icon name="trash" size={18} /></div>
          <div><h2>Delete entry?</h2><p>This moves it to the recycle bin.</p></div>
        </div>
        <div className="modal-body"><div style={{ fontSize: 13.5, color: "var(--text-dim)", lineHeight: 1.6 }}>
          <span style={{ fontFamily: "var(--font-mono)", color: "var(--text)" }}>{entry.path}</span> will be removed from the vault. You can restore it later from the recycle bin.
        </div></div>
        <div className="modal-foot"><div className="grow" />
          <button className="btn-ghost" onClick={onCancel}>Cancel</button>
          <button className="btn-danger" onClick={() => onConfirm(entry)}>Delete entry</button>
        </div>
      </div>
    </div>
  );
}

/* ============ HELP ============ */
const SHORTCUTS = [
  { l: "Command palette", k: ["⌘", "K"] },
  { l: "Focus search", k: ["/"] },
  { l: "Navigate list", k: ["↑", "↓"] },
  { l: "Copy password", k: ["⌘", "C"] },
  { l: "Copy username", k: ["⌘", "B"] },
  { l: "Reveal password", k: ["R"] },
  { l: "New entry", k: ["⌘", "N"] },
  { l: "Edit entry", k: ["E"] },
  { l: "Switch vault", k: ["⌘", "1–9"] },
  { l: "Open vault", k: ["⌘", "O"] },
  { l: "Lock vault", k: ["⌘", "L"] },
  { l: "Toggle theme", k: ["⌘", "J"] },
  { l: "Shortcuts", k: ["?"] },
  { l: "Close / clear", k: ["esc"] },
];
function HelpModal({ onClose }) {
  return (
    <div className="scrim center" onMouseDown={onClose}>
      <div className="modal" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="mh-badge"><Icon name="command" size={18} /></div>
          <div><h2>Keyboard shortcuts</h2><p>Trove is built to run without the mouse.</p></div>
          <button className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose}><Icon name="x" size={18} /></button>
        </div>
        <div className="modal-body">
          <div className="help-grid">
            {SHORTCUTS.map((s) => (
              <div className="help-row" key={s.l}>
                <span className="hl">{s.l}</span>
                <span className="help-keys">{s.k.map((k, i) => <span className="kbd" key={i}>{k}</span>)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ============ TOAST ============ */
function ClipboardToast({ data, onClear }) {
  const pct = (data.left / data.total) * 100;
  const r = 12, circ = 2 * Math.PI * r;
  return (
    <div className="toast">
      <div className="ring">
        <svg width="30" height="30">
          <circle cx="15" cy="15" r={r} fill="none" stroke="var(--bg-3)" strokeWidth="2.5" />
          <circle cx="15" cy="15" r={r} fill="none" stroke="var(--teal)" strokeWidth="2.5" strokeLinecap="round"
            strokeDasharray={circ} strokeDashoffset={circ * (1 - pct / 100)} style={{ transition: "stroke-dashoffset 1s linear" }} />
        </svg>
        <span className="rt">{data.left}</span>
      </div>
      <div style={{ flex: 1 }}>
        <div className="tmsg">{data.label} copied</div>
        <div className="tsub">Clipboard clears in {data.left}s</div>
      </div>
      <button className="tclear" onClick={onClear}>Clear now</button>
    </div>
  );
}
function PlainToast({ text }) {
  return (
    <div className="toast plain">
      <div className="toast-check"><Icon name="check" size={15} /></div>
      <div className="tmsg">{text}</div>
    </div>
  );
}

/* ============ APPEARANCE MENU ============ */
const THEMES = [
  { id: "brass", name: "Brass", hue: 85 },
  { id: "coral", name: "Coral", hue: 25 },
  { id: "amethyst", name: "Violet", hue: 300 },
  { id: "azure", name: "Azure", hue: 258 },
  { id: "emerald", name: "Fern", hue: 152 },
];
function ThemeMenu({ theme, accent, onTheme, onAccent, onClose }) {
  const L = theme === "light" ? "0.56 0.14" : "0.80 0.11";
  return (
    <React.Fragment>
      <div className="pop-scrim" onMouseDown={onClose} />
      <div className="popover" onMouseDown={(e) => e.stopPropagation()}>
        <div className="pop-title"><Icon name="droplet" size={16} style={{ color: "var(--accent-strong)" }} />Appearance</div>
        <div className="seg">
          <button className={theme === "dark" ? "on" : ""} onClick={() => onTheme("dark")}><Icon name="moon" size={15} />Dark</button>
          <button className={theme === "light" ? "on" : ""} onClick={() => onTheme("light")}><Icon name="sun" size={15} />Light</button>
        </div>
        <div className="pop-sec">Color theme</div>
        <div className="swatch-grid">
          {THEMES.map((t) => (
            <button key={t.id} className={"swatch" + (accent === t.id ? " on" : "")} onClick={() => onAccent(t.id)} title={t.name}>
              <span className="dot" style={{ background: `oklch(${L} ${t.hue})` }} />
              <span className="sn">{t.name}</span>
            </button>
          ))}
        </div>
      </div>
    </React.Fragment>
  );
}

/* ============ VAULT SWITCHER ============ */
function VaultSwitcher({ vaults, activeId, onSwitch, onOpenNew, onClose }) {
  return (
    <React.Fragment>
      <div className="pop-scrim" onMouseDown={onClose} />
      <div className="popover vsw" onMouseDown={(e) => e.stopPropagation()}>
        <div className="pop-sec" style={{ marginTop: 2 }}>Open vaults</div>
        {vaults.map((v, i) => (
          <button key={v.id} className={"vrow" + (v.id === activeId ? " on" : "")} onClick={() => { onSwitch(v.id); onClose(); }}>
            <span className={"vdot " + (v.locked ? "locked" : "unlocked")} title={v.locked ? "Locked" : "Unlocked"} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="vrn">{v.name}</div>
              <div className="vrf">{v.file}{v.locked ? " · locked" : ""}</div>
            </div>
            <span className="kbd">⌘{i + 1}</span>
          </button>
        ))}
        <div className="pop-div" />
        <button className="vrow" onClick={() => { onClose(); onOpenNew(); }}>
          <span className="vdot add"><Icon name="plus" size={13} /></span>
          <div style={{ flex: 1 }}><div className="vrn" style={{ fontWeight: 500 }}>Open vault…</div></div>
          <span className="kbd">⌘O</span>
        </button>
      </div>
    </React.Fragment>
  );
}

/* ============ OPEN VAULT MODAL ============ */
function OpenVaultModal({ files, onPick, onClose }) {
  return (
    <div className="scrim center" onMouseDown={onClose}>
      <div className="modal" style={{ width: "min(440px, 94%)" }} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="mh-badge"><Icon name="file" size={18} /></div>
          <div><h2>Open vault</h2><p>~/vaults</p></div>
          <button className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose}><Icon name="x" size={18} /></button>
        </div>
        <div className="modal-body" style={{ gap: 4 }}>
          {files.length === 0 && (
            <div style={{ padding: "18px 6px", textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>
              All vaults in ~/vaults are already open.
            </div>
          )}
          {files.map((f) => (
            <button key={f.file} className="vrow" onClick={() => onPick(f)}>
              <span className="vdot add"><Icon name="file" size={13} /></span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="vrn">{f.name}</div>
                <div className="vrf">{f.file}</div>
              </div>
              <Icon name="chevron" size={14} style={{ color: "var(--text-ghost)" }} />
            </button>
          ))}
        </div>
        <div className="modal-foot" style={{ borderTop: "1px solid var(--border)" }}>
          <span style={{ fontSize: 11.5, color: "var(--text-ghost)", display: "flex", alignItems: "center", gap: 6 }}><Icon name="lock" size={12} />Vaults open locked — you'll be asked for their master password.</span>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { Unlock, CommandPalette, EntryForm, ConfirmDelete, HelpModal, ClipboardToast, PlainToast, genPassword, ThemeMenu, THEMES, VaultSwitcher, OpenVaultModal });
