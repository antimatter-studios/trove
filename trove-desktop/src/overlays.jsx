import React from 'react';
import { listen } from '@tauri-apps/api/event';
import { Icon, TYPE_ICON } from './icons.jsx';
// Trove — overlays: unlock, command palette, entry form, toast, help

/* ============ UNLOCK ============ */
// The steps an unlock goes through, in the order the backend reports them.
// Listed up front so the checklist appears complete from the first frame
// rather than growing as events arrive.
// Floor on how long each step stays visible. Below roughly this, a change
// isn't perceived as a change — the list just blinks.
const MIN_STEP_MS = 220;

const UNLOCK_STEPS = [
  { step: "open", label: "Decrypting the vault" },
  { step: "entries", label: "Reading entries" },
  { step: "agent", label: "Adding keys to the system agent" },
  { step: "files", label: "Writing materialized files" },
];

function UnlockProgress({ progress }) {
  return (
    <ul className="unlock-steps">
      {UNLOCK_STEPS.map(({ step, label }) => {
        const st = progress[step];
        const state = st ? st.state : "waiting";
        return (
          <li key={step} className={"ustep " + state}>
            <span className="umark">
              {state === "done" ? <Icon name="check" size={13} />
                : state === "failed" ? <Icon name="x" size={13} />
                : state === "skipped" ? <span className="udash" />
                : state === "pending" ? <span className="uspin" />
                : <span className="udot" />}
            </span>
            <span className="ulabel">{label}</span>
            {st && st.detail ? <span className="udetail">{st.detail}</span> : null}
          </li>
        );
      })}
    </ul>
  );
}

function Unlock({ vault, onUnlock, onReady, onChange }) {
  const [pw, setPw] = React.useState("");
  const [show, setShow] = React.useState(false);
  const [err, setErr] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  // step id → { state, detail }, filled in by `unlock-progress` events.
  const [progress, setProgress] = React.useState({});
  const ref = React.useRef(null);

  // Only listen while an unlock is actually running: the backend emits to the
  // whole window, and a stale listener would repaint a card nobody is looking
  // at. `listen` resolves to its own unlisten function.
  // Events are applied through a queue with a floor on how fast the list may
  // advance. Without it a fast unlock paints every step in one frame and reads
  // as "nothing happened, then it vanished" — which is exactly what it looked
  // like when the backend blocked and flushed all its events at once.
  const queue = React.useRef([]);
  const draining = React.useRef(false);
  // Registered on MOUNT, not when `busy` flips. `listen` is itself an async IPC
  // round trip, and unlock starts emitting immediately — registering at submit
  // time loses every step that fires before the registration lands, which
  // looked exactly like "nothing happens, then it vanishes".
  React.useEffect(() => {
    let stop = null, dead = false;

    const drain = () => {
      if (dead) return;
      const next = queue.current.shift();
      if (!next) { draining.current = false; return; }
      setProgress((p) => ({ ...p, [next.step]: { state: next.state, detail: next.detail } }));
      setTimeout(drain, MIN_STEP_MS);
    };

    listen("unlock-progress", (e) => {
      const { step, state, detail } = e.payload || {};
      if (!step) return;
      queue.current.push({ step, state, detail });
      if (!draining.current) { draining.current = true; drain(); }
    }).then((fn) => { if (dead) fn(); else stop = fn; }).catch(() => {});

    return () => { dead = true; stop && stop(); };
  }, []);

  // Resolves once every queued step has been applied, plus a beat so the last
  // tick is on screen rather than replaced in the same frame.
  const drained = React.useCallback(
    () =>
      new Promise((resolve) => {
        const check = () => {
          if (!queue.current.length && !draining.current) setTimeout(resolve, MIN_STEP_MS);
          else setTimeout(check, MIN_STEP_MS / 2);
        };
        check();
      }),
    []
  );
  React.useEffect(() => { ref.current && ref.current.focus(); }, [vault.id]);
  // Reset transient state when the target vault changes.
  React.useEffect(() => { setPw(""); setErr(false); setBusy(false); }, [vault.id]);

  const submit = async (e) => {
    e && e.preventDefault();
    if (!pw || busy) return;
    setBusy(true); setErr(false); setProgress({});
    queue.current = []; draining.current = false;
    try {
      // onUnlock decrypts the vault and RESOLVES WITH THE ENTRY LIST — it does
      // not flip the parent itself. Deliberate: the backend has finished by the
      // time it resolves, but the checklist may still be draining, and an
      // immediate unmount would bin the last few ticks.
      const list = await onUnlock(pw);
      await drained();
      onReady(list);
      return;
    } catch (e2) {
      setErr(e2 && typeof e2 === "string" ? e2 : (e2 && e2.message) || true);
      setBusy(false);
      setPw("");
      ref.current && ref.current.focus();
    }
  };

  // Split the path so the chip truncates the *directory* (ellipsis) while
  // always keeping the filename visible — right-truncating the whole path
  // would hide the .kdbx name, which is the part that identifies the vault.
  const fullPath = vault.path || vault.file || "";
  const lastSlash = fullPath.lastIndexOf("/");
  const pathDir = lastSlash > 0 ? fullPath.slice(0, lastSlash) : "";
  const pathFile = lastSlash >= 0 ? fullPath.slice(lastSlash) : fullPath;

  // Once the password is accepted the form has done its job, so the card
  // becomes the progress view outright rather than growing a list underneath a
  // dead password field. A rejected password is the only way back.
  if (busy) {
    return (
      <div className="unlock-desk embed">
        <div className="unlock-card">
          <div className="ul-lock working"><Icon name="unlock" size={28} /></div>
          <div className="ul-h">Unlocking {vault.name}</div>
          <div className="ul-sub">Decrypting and handing your keys to the machine.</div>
          <UnlockProgress progress={progress} />
        </div>
      </div>
    );
  }

  return (
    <div className="unlock-desk embed">
      <form className="unlock-card" onSubmit={submit}>
        <div className="ul-lock"><Icon name="lock" size={28} /></div>
        <div className="ul-h">Unlock {vault.name}</div>
        <div className="ul-sub">Enter your master password to decrypt the vault.</div>

        <div className="vault-chip">
          <div className="vc-ic"><Icon name="file" size={17} /></div>
          <div className="vc-meta">
            <div className="vc-name">{vault.name}</div>
            <div className="vc-path" title={fullPath}>
              {pathDir && <span className="vc-dir">{pathDir}</span>}
              <span className="vc-file">{pathFile}</span>
            </div>
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
        <div className="ul-err">{err && (<><Icon name="x" size={13} /> {typeof err === "string" ? err : "Incorrect master password. Try again."}</>)}</div>

        <button type="submit" className="ul-unlock">
          <Icon name="unlock" size={17} /> Unlock
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
function EntryForm({ entry, detail, onClose, onSave, onDelete }) {
  const editing = !!entry;
  // The list DTO carries no secrets; the current password + notes for an existing
  // entry are fetched (get_entry_detail) and handed in via `detail` to prefill.
  const [f, setF] = React.useState(() => entry ? {
    path: entry.path, username: entry.username,
    password: (detail && detail.password) || "", url: entry.url,
    notes: (detail && detail.notes) || "", type: entry.type,
  } : { path: "", username: "", password: genPassword(), url: "", notes: "", type: "login" });
  const [show, setShow] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const set = (k, v) => setF((o) => ({ ...o, [k]: v }));
  const ref = React.useRef(null);
  React.useEffect(() => { ref.current && ref.current.focus(); }, []);

  const save = async () => {
    if (busy) return;
    setBusy(true);
    try {
      // onSave persists via the backend and (on success) closes the form.
      await onSave(f, entry);
    } catch (e) {
      setBusy(false);
    }
  };

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
          <button className="btn-primary" onClick={save} disabled={busy}>{editing ? "Save changes" : "Add entry"}</button>
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

/* ============ NEW VAULT ============ */
// Second half of "create a vault": the file has been chosen, now set the master
// password. There is no recovery for a forgotten one, so it is confirmed.
function NewVaultModal({ path, onCreate, onClose }) {
  const [pw, setPw] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [show, setShow] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const ref = React.useRef(null);
  React.useEffect(() => { ref.current && ref.current.focus(); }, []);

  const file = String(path || "").split("/").pop();
  const submit = async (e) => {
    e && e.preventDefault();
    if (busy) return;
    if (!pw) { setErr("Choose a master password."); return; }
    if (pw !== confirm) { setErr("The two passwords don't match."); return; }
    setBusy(true); setErr("");
    try {
      await onCreate(path, pw);
    } catch (e2) {
      setBusy(false);
      setErr(String(e2 && e2.message ? e2.message : e2) || "Couldn't create the vault.");
    }
  };

  return (
    <div className="scrim center" onMouseDown={onClose}>
      <div className="modal" style={{ width: "min(460px, 94%)" }} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="mh-badge"><Icon name="plus" size={18} /></div>
          <div><h2>New vault</h2><p>{file}</p></div>
          <button className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose}><Icon name="x" size={18} /></button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body" style={{ gap: 12 }}>
            <div className="fld">
              <label>Master password</label>
              <input ref={ref} className="inp mono" type={show ? "text" : "password"} value={pw}
                     autoComplete="new-password"
                     onChange={(e) => { setPw(e.target.value); setErr(""); }} />
            </div>
            <div className="fld">
              <label>Confirm password</label>
              <input className="inp mono" type={show ? "text" : "password"} value={confirm}
                     autoComplete="new-password"
                     onChange={(e) => { setConfirm(e.target.value); setErr(""); }} />
            </div>
            <label className="set-row">
              <input type="checkbox" checked={show} onChange={(e) => setShow(e.target.checked)} />
              <span><b>Show passwords</b></span>
            </label>
            <p style={{ fontSize: 12.5, color: err ? "var(--red)" : "var(--text-dim)", lineHeight: 1.6, margin: 0 }}>
              {err || "There is no way to recover this password. Store it somewhere you won't lose it."}
            </p>
          </div>
          <div className="modal-foot">
            <div className="grow" />
            <button type="button" className="btn-ghost" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-primary" disabled={busy}>{busy ? "Creating…" : "Create vault"}</button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ============ SETTINGS ============ */
// Every switch here changes what unlocking does to the rest of the machine, so
// each row states the consequence rather than naming the mechanism. Rows that
// only apply while forwarding is on are nested under it and go inert instead of
// vanishing, so the panel never reflows under the pointer.
function Switch({ checked, onChange, disabled }) {
  return (
    <span className="switch">
      <input type="checkbox" checked={checked} disabled={disabled}
             onChange={(e) => onChange(e.target.checked)} />
      <span className="track" />
      <span className="knob" />
    </span>
  );
}

function SetRow({ title, desc, sub, off, children }) {
  return (
    <div className={"set-row" + (sub ? " set-sub" : "") + (off ? " off" : "")}>
      <div className="srb">
        <div className="srt">{title}</div>
        <div className="srd">{desc}</div>
      </div>
      {children}
    </div>
  );
}

function SettingsModal({ settings, onChange, onClose }) {
  const set = (patch) => onChange({ ...settings, ...patch });
  const agent = settings.systemAgent;
  return (
    <div className="scrim center" onMouseDown={onClose}>
      <div className="modal" style={{ width: "min(560px, 94%)" }} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="mh-badge"><Icon name="gear" size={18} /></div>
          <div><h2>Settings</h2><p>What unlocking a vault does to the rest of your machine.</p></div>
          <button className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose}><Icon name="x" size={18} /></button>
        </div>

        <div className="modal-body">
          {/* The one rule worth stating outright, because two different locks
              with two different scopes is exactly what confused this before. */}
          <p className="set-note" style={{ margin: "0 2px 4px" }}>
            <b>App lock</b> locks this window and forgets the decrypted vault.
            Your data stays where it is. <b>Data lock</b> is the padlock button:
            it removes the keys from the system agent and dematerializes the
            files.
          </p>

          <div className="set-group">
            <div className="set-group-head"><div className="sgt">SSH keys</div></div>

            <SetRow
              title="Add keys to the system agent on unlock"
              desc="Your terminal, your editor and anything launched from the Dock can then use them. A data lock takes them back out.">
              <Switch checked={agent} onChange={(v) => set({ systemAgent: v })} />
            </SetRow>

            <SetRow sub off={!agent}
              title="Expire keys after"
              desc="The agent drops them itself once this long has passed — the only protection left if Trove quits without locking. Keys whose entry states its own lifetime use that instead. 0 means never.">
              <span className="set-num">
                <input className="inp" type="number" min="0" step="60" disabled={!agent}
                       value={settings.systemAgentLifetime}
                       onChange={(e) => set({ systemAgentLifetime: Math.max(0, Number(e.target.value) || 0) })} />
                <span className="unit">sec</span>
              </span>
            </SetRow>
          </div>

          <div className="set-group">
            <div className="set-group-head"><div className="sgt">App lock</div></div>
            <SetRow
              title="Lock the app after"
              desc="Minutes of no interaction before the window locks and the decrypted vault is forgotten. Keys and materialized files are left alone — they expire on their own clocks. 0 never locks.">
              <span className="set-num">
                <input className="inp" type="number" min="0" step="1"
                       value={settings.idleLockMinutes ?? 5}
                       onChange={(e) => set({ idleLockMinutes: Math.max(0, Number(e.target.value) || 0) })} />
                <span className="unit">min</span>
              </span>
            </SetRow>
          </div>

          <div className="set-group">
            <div className="set-group-head"><div className="sgt">Files</div></div>
            <SetRow
              title="Write materialized files on unlock"
              desc="Entries carrying Materialize fields are written to their target paths, and wiped again on lock."
            >
              <Switch checked={settings.materialize} onChange={(v) => set({ materialize: v })} />
            </SetRow>
          </div>

          <p className="set-note">
            Which keys are eligible is decided per entry — open a key and use
            “Add this key to the system agent”. Changes here apply at the next
            unlock; keys already handed to the agent stay until a data lock.
          </p>
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
function VaultSwitcher({ vaults, activeId, onSwitch, onOpenNew, onNewVault, onClose }) {
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
          <span className="vdot add"><Icon name="folder" size={13} /></span>
          <div style={{ flex: 1 }}><div className="vrn" style={{ fontWeight: 500 }}>Open vault…</div></div>
          <span className="kbd">⌘O</span>
        </button>
        <button className="vrow" onClick={() => { onClose(); onNewVault(); }}>
          <span className="vdot add"><Icon name="plus" size={13} /></span>
          <div style={{ flex: 1 }}><div className="vrn" style={{ fontWeight: 500 }}>New vault…</div></div>
        </button>
      </div>
    </React.Fragment>
  );
}

/* ============ OPEN VAULT MODAL ============ */
// Lists the persisted "recent" vaults (from list_vaults) so one click switches
// to it; "Browse…" opens the native file dialog to register a new .kdbx.
function OpenVaultModal({ recents, activeId, onPick, onBrowse, onClose }) {
  const list = recents || [];
  return (
    <div className="scrim center" onMouseDown={onClose}>
      <div className="modal" style={{ width: "min(440px, 94%)" }} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="mh-badge"><Icon name="file" size={18} /></div>
          <div><h2>Open vault</h2><p>Recent vaults</p></div>
          <button className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose}><Icon name="x" size={18} /></button>
        </div>
        <div className="modal-body" style={{ gap: 4 }}>
          {list.length === 0 && (
            <div style={{ padding: "18px 6px", textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>
              No recent vaults yet — browse to open one.
            </div>
          )}
          {list.map((v) => (
            <button key={v.id} className={"vrow" + (v.id === activeId ? " on" : "")} onClick={() => onPick(v)}>
              <span className={"vdot " + (v.locked ? "locked" : "unlocked")} title={v.locked ? "Locked" : "Unlocked"} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="vrn">{v.name}</div>
                <div className="vrf">{v.file}{v.locked ? " · locked" : ""}</div>
              </div>
              <Icon name="chevron" size={14} style={{ color: "var(--text-ghost)" }} />
            </button>
          ))}
        </div>
        <div className="modal-foot" style={{ borderTop: "1px solid var(--border)" }}>
          <span style={{ fontSize: 11.5, color: "var(--text-ghost)", display: "flex", alignItems: "center", gap: 6 }}><Icon name="lock" size={12} />Opens locked — you'll enter its master password.</span>
          <div className="grow" />
          <button className="btn-primary" onClick={onBrowse}><Icon name="folder" size={15} style={{ display: "inline", verticalAlign: "-2px", marginRight: 5 }} />Browse…</button>
        </div>
      </div>
    </div>
  );
}

export { Unlock, CommandPalette, EntryForm, ConfirmDelete, HelpModal, ClipboardToast, PlainToast, genPassword, ThemeMenu, THEMES, VaultSwitcher, OpenVaultModal, SettingsModal, NewVaultModal, UnlockProgress, Switch };
