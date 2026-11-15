import React from 'react';
import { listen } from '@tauri-apps/api/event';
import { Icon, TYPE_ICON } from './icons.jsx';
import * as api from './api.js';
import { baseGroup, displayEntryPath, resolveEntryPath } from './tree.js';
// Trove — overlays: unlock, command palette, entry form, toast, help

/* ============ UNLOCK ============ */
// The steps an unlock goes through, in the order the backend reports them.
// Listed up front so the checklist appears complete from the first frame
// rather than growing as events arrive.
// Floor on how long each step stays visible. Below roughly this, a change
// isn't perceived as a change — the list just blinks.
const MIN_STEP_MS = 220;

const UNLOCK_STEPS = [
  { step: "open", label: "Decrypting the database" },
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

function Unlock({ database, onUnlock, onReady, onChange, onTouchId, onRemember }) {
  const [pw, setPw] = React.useState("");
  // { available, enrolled } — asked per database, and again whenever this screen
  // is shown, because both halves change without the app being told.
  const [bio, setBio] = React.useState({ available: false, enrolled: false });
  // Ticked before typing the password: enrolment needs a password that is
  // known to work, and the only moment we have one is a successful unlock.
  const [remember, setRemember] = React.useState(false);
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
  React.useEffect(() => {
    let dead = false;
    api.biometricStatus(database.id).then((b) => { if (!dead) setBio(b); });
    return () => { dead = true; };
  }, [database.id]);
  React.useEffect(() => { ref.current && ref.current.focus(); }, [database.id]);
  // Reset transient state when the target database changes.
  React.useEffect(() => { setPw(""); setErr(false); setBusy(false); }, [database.id]);

  const submit = async (e) => {
    e && e.preventDefault();
    // Read the field, not the state. `submit` closes over the render that made
    // it, so a submit arriving in the same tick as the last keystroke sees the
    // previous value — and the empty-password guard below then drops it
    // silently. The DOM always has what was actually typed.
    const password = (ref.current && ref.current.value) || pw;
    if (!password || busy) return;
    setBusy(true); setErr(false); setProgress({});
    queue.current = []; draining.current = false;
    try {
      // onUnlock decrypts the database and RESOLVES WITH THE ENTRY LIST — it does
      // not flip the parent itself. Deliberate: the backend has finished by the
      // time it resolves, but the checklist may still be draining, and an
      // immediate unmount would bin the last few ticks.
      const list = await onUnlock(password);
      // Enrol only now, with a password the database has just accepted. Failing
      // here must not fail the unlock — the database is open either way, and the
      // worst case is that the offer comes back next time.
      if (remember && bio.available && !bio.enrolled) {
        try {
          await onRemember(password);
        } catch (e3) {
          console.warn("could not remember this password for Touch ID", e3);
        }
      }
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

  // Touch ID: the fingerprint releases a password kept in the login keychain,
  // and from there this is an ordinary unlock. A cancelled prompt is not an
  // error — it returns null and leaves the password field exactly as it was.
  const touchId = async () => {
    if (busy) return;
    setBusy(true); setErr(false); setProgress({});
    queue.current = []; draining.current = false;
    try {
      const list = await onTouchId();
      if (!list) { setBusy(false); ref.current && ref.current.focus(); return; }
      await drained();
      onReady(list);
    } catch (e2) {
      setErr(e2 && typeof e2 === "string" ? e2 : (e2 && e2.message) || true);
      setBusy(false);
      ref.current && ref.current.focus();
    }
  };

  // Split the path so the chip truncates the *directory* (ellipsis) while
  // always keeping the filename visible — right-truncating the whole path
  // would hide the .kdbx name, which is the part that identifies the database.
  const fullPath = database.path || database.file || "";
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
          <div className="ul-h">Unlocking {database.name}</div>
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
        <div className="ul-h">Unlock {database.name}</div>
        <div className="ul-sub">Enter your master password to decrypt the database.</div>

        <div className="database-chip">
          <div className="vc-ic"><Icon name="file" size={17} /></div>
          <div className="vc-meta">
            <div className="vc-name">{database.name}</div>
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

        {bio.available && !bio.enrolled && (
          <label className="ul-remember">
            <input
              type="checkbox" checked={remember}
              onChange={(e) => setRemember(e.target.checked)}
            />
            <span><Icon name="fingerprint" size={14} /> Remember with Touch ID</span>
          </label>
        )}

        {bio.available && bio.enrolled && (
          <button type="button" className="ul-touchid" onClick={touchId}>
            <Icon name="fingerprint" size={17} /> Unlock with Touch ID
          </button>
        )}

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
function TagEditor({ tags, onChange, placeholder }) {
  const [value, setValue] = React.useState("");
  const add = () => {
    if (!value || tags.some((tag) => tag.toLowerCase() === value.toLowerCase())) return;
    onChange([...tags, value]);
    setValue("");
  };
  return (
    <div>
      <div className="tag-list tag-editor-list">
        {tags.map((tag, index) => <span className="tag-chip" key={`${tag}-${index}`}>{tag}<button type="button" aria-label={`Remove ${tag}`} onClick={() => onChange(tags.filter((_, i) => i !== index))}>×</button></span>)}
      </div>
      <div className="tag-add-row">
        <input className="inp" value={value} onChange={(e) => setValue(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(); } }} placeholder={placeholder || "Add a tag"} />
        <button type="button" className="btn-ghost" onClick={add} disabled={!value}>Add</button>
      </div>
    </div>
  );
}
function EntryForm({ entry, detail, group, onClose, onSave, onCreateFolder, onDelete }) {
  const editing = !!entry;
  const [itemType, setItemType] = React.useState("entry");
  // The list DTO carries no secrets; the current password + notes for an existing
  // entry are fetched (get_entry_detail) and handed in via `detail` to prefill.
  const [f, setF] = React.useState(() => entry ? {
    // Relative to the folder being browsed: saving it unchanged must be a
    // no-op, and the full path would be re-prefixed by the resolver.
    path: displayEntryPath(entry.path, group), username: entry.username,
    password: (detail && detail.password) || "", url: entry.url,
    notes: (detail && detail.notes) || "", type: entry.type,
    // Copied, not referenced: editing a row must not mutate the detail object
    // the read-only pane behind this modal is still rendering from.
    fields: ((detail && detail.fields) || []).map((x) => ({ k: x.k, v: x.v })),
    tags: (entry.tags || []).filter((tag) => tag.toLowerCase() !== "favorite"),
  } : { path: "", username: "", password: "", url: "", notes: "", type: "login", fields: [], tags: [] });
  // The password starts empty rather than pre-generated. Most new entries are
  // recording a credential that already exists somewhere, and a value nobody
  // asked for has to be noticed and cleared first — the generate button beside
  // the field covers the other case in one click.
  const [show, setShow] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");
  const set = (k, v) => setF((o) => ({ ...o, [k]: v }));
  const setField = (i, part, v) =>
    setF((o) => ({ ...o, fields: o.fields.map((x, j) => (j === i ? { ...x, [part]: v } : x)) }));
  const addField = () => setF((o) => ({ ...o, fields: [...o.fields, { k: "", v: "" }] }));
  const dropField = (i) => setF((o) => ({ ...o, fields: o.fields.filter((_, j) => j !== i) }));
  const ref = React.useRef(null);
  React.useEffect(() => { ref.current && ref.current.focus(); }, []);

  const save = async () => {
    if (busy) return;
    setBusy(true);
    try {
      if (itemType === "folder") {
        const path = resolveEntryPath(f.path, group).trim();
        if (!path) throw new Error("Folder name is required");
        await onCreateFolder(path);
      } else {
        await onSave(f, entry);
      }
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };

  return (
    <div className="scrim center" onMouseDown={onClose}>
      <div className="modal" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="mh-badge"><Icon name={editing ? "edit" : "plus"} size={19} /></div>
          <div>
            <h2>{editing ? "Edit entry" : itemType === "folder" ? "New folder" : "New entry"}</h2>
            <p>{editing ? entry.path : "Add an entry or an empty folder"}</p>
          </div>
          <button className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose}><Icon name="x" size={18} /></button>
        </div>
        <div className="modal-body">
          {!editing && (
            <div className="pw-row" role="group" aria-label="Item type" style={{ marginBottom: 14 }}>
              <button className={"btn-ghost" + (itemType === "entry" ? " active" : "")} onClick={() => { setItemType("entry"); setErr(""); }}>Entry</button>
              <button className={"btn-ghost" + (itemType === "folder" ? " active" : "")} onClick={() => { setItemType("folder"); setErr(""); }}>Folder</button>
            </div>
          )}
          {itemType === "folder" && !editing ? (
            <div className="fld">
              <label>Folder path <span style={{ color: "var(--text-ghost)", fontWeight: 400 }}>— create an empty folder</span></label>
              <input ref={ref} className="inp mono" value={f.path} onChange={(e) => { set("path", e.target.value); setErr(""); }} placeholder={baseGroup(group) ? `name or subgroup/name (inside ${baseGroup(group)})` : "group/subgroup"} />
              {f.path.trim() && <div style={{ marginTop: 4, fontSize: 12, color: "var(--text-ghost)", fontFamily: "var(--font-mono)" }}>→ {resolveEntryPath(f.path, group)}</div>}
              {err && <div className="att-err">{err}</div>}
            </div>
          ) : (
            <>
          <div className="fld">
            <label>
              Path{" "}
              <span style={{ color: "var(--text-ghost)", fontWeight: 400 }}>
                {baseGroup(group)
                  ? `— inside ${baseGroup(group)}, or /absolute`
                  : "— group/subgroup/name"}
              </span>
            </label>
            <input ref={ref} className="inp mono" value={f.path} onChange={(e) => set("path", e.target.value)} placeholder={baseGroup(group) ? `name, or subfolder/name (inside ${baseGroup(group)})` : "group/subgroup/name"} />
            {f.path.trim() !== "" && (
              <div style={{ marginTop: 4, fontSize: 12, color: "var(--text-ghost)", fontFamily: "var(--font-mono)" }}>
                → {resolveEntryPath(f.path, group)}
              </div>
            )}
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
            <label>KeePass tags</label>
            <TagEditor tags={f.tags} onChange={(tags) => set("tags", tags)} placeholder="Add an entry tag" />
          </div>
          <div className="fld">
            <label>Notes</label>
            <textarea className="inp" rows={3} value={f.notes} onChange={(e) => set("notes", e.target.value)} placeholder="Anything else worth remembering…" />
          </div>
          <div className="fld">
            <label>
              Attributes{" "}
              <span style={{ color: "var(--text-ghost)", fontWeight: 400 }}>
                — extra named values, e.g. git.token
              </span>
            </label>
            {f.fields.map((kv, i) => (
              <div className="pw-row" key={i} style={{ marginBottom: 6 }}>
                <input
                  className="inp mono"
                  style={{ flex: "0 0 38%" }}
                  value={kv.k}
                  onChange={(e) => setField(i, "k", e.target.value)}
                  placeholder="name"
                  aria-label={"Attribute name " + (i + 1)}
                />
                <input
                  className="inp mono"
                  value={kv.v}
                  onChange={(e) => setField(i, "v", e.target.value)}
                  placeholder="value"
                  aria-label={"Attribute value " + (i + 1)}
                />
                <button className="pw-tool" title="Remove attribute" onClick={() => dropField(i)}>
                  <Icon name="trash" size={15} />
                </button>
              </div>
            ))}
            <button className="btn-ghost" style={{ marginTop: 2 }} onClick={addField}>
              <Icon name="plus" size={14} style={{ display: "inline", verticalAlign: "-2px", marginRight: 5 }} />
              Add attribute
            </button>
          </div>
            </>
          )}
        </div>
        <div className="modal-foot">
          {editing && <button className="btn-danger" onClick={() => onDelete(entry)}><Icon name="trash" size={15} style={{ display: "inline", verticalAlign: "-2px", marginRight: 5 }} />Delete</button>}
          <div className="grow" />
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" onClick={save} disabled={busy}>{editing ? "Save changes" : itemType === "folder" ? "Create folder" : "Add entry"}</button>
        </div>
      </div>
    </div>
  );
}

/// What a folder (or, at Root, the whole database) gives the entries under it:
/// defaults only. A folder never turns a capability on for its entries — each
/// entry still needs its own — so these fill in what an entry leaves out, and a
/// constraint set here (Touch ID, a lifetime) cannot be loosened below it.
const FOLDER_DEFAULTS = [
  ["materialize", "dir", "Write files into", "text", "~/projects/app/secrets"],
  ["materialize", "mode", "File mode", "text", "0600"],
  ["env-agent", "export", "Export variables", "select", ["", "none", "shell"]],
  ["env-agent", "confirm", "Touch ID for variables", "bool"],
  ["env-agent", "lifetime", "Variable lifetime (sec)", "text", "no limit"],
  ["gpg-agent", "uses", "GPG keys may", "select", ["", "sign", "decrypt", "both"]],
  ["gpg-agent", "confirm", "Touch ID for GPG keys", "bool"],
];

function FolderDefaults({ databaseId, path }) {
  const [caps, setCaps] = React.useState(null);
  const [draft, setDraft] = React.useState({});
  const [err, setErr] = React.useState("");
  React.useEffect(() => {
    if (!databaseId) return;
    (async () => {
      try { setCaps((await api.groupCapabilities(databaseId, path)) || []); }
      catch (e) { setErr(String(e)); }
    })();
  }, [databaseId, path]);
  if (!databaseId) return null;
  const value = (cap, name) => {
    const k = cap + "." + name;
    if (k in draft) return draft[k];
    return caps?.find((c) => c.capability === cap)?.defaults?.[name] ?? "";
  };
  const write = async (cap, name, v) => {
    try {
      setCaps((await api.setGroupDefault(databaseId, path, cap, name, v)) || []);
      setErr("");
      setDraft((d) => { const n = { ...d }; delete n[cap + "." + name]; return n; });
    } catch (e) { setErr(String(e)); }
  };
  return (
    <div className="fld">
      <label>{path ? "Defaults for entries in this folder" : "Defaults for the whole database"}</label>
      <div className="folder-defaults">
        {FOLDER_DEFAULTS.map(([cap, name, label, kind, extra]) => (
          <div className="fd-row" key={cap + name}>
            <span className="fd-label">{label}</span>
            {kind === "bool" ? (
              <Switch checked={value(cap, name) === "true"} onChange={(on) => write(cap, name, on ? "true" : "")} />
            ) : kind === "select" ? (
              <select className="inp" value={value(cap, name)} onChange={(e) => write(cap, name, e.target.value)}>
                {extra.map((o) => <option key={o} value={o}>{o || "inherit"}</option>)}
              </select>
            ) : (
              <input className="inp mono" value={value(cap, name)} placeholder={extra} spellCheck="false"
                     onChange={(e) => setDraft((d) => ({ ...d, [cap + "." + name]: e.target.value }))}
                     onBlur={(e) => write(cap, name, e.target.value)} />
            )}
          </div>
        ))}
      </div>
      {err && <div className="att-err">{err}</div>}
    </div>
  );
}

function EditFolderModal({ group, entries, onClose, onSave, onDelete, databaseId }) {
  const [tags, setTags] = React.useState(group.tags || []);
  const [busy, setBusy] = React.useState(false);
  const [confirming, setConfirming] = React.useState(false);
  const path = group.groupPath.join("/");
  const label = path || "Root";
  const ownName = group.groupPath[group.groupPath.length - 1] || "";
  const [name, setName] = React.useState(ownName);
  const [nameErr, setNameErr] = React.useState("");
  // Everything the delete takes with it: entries here and in every subfolder.
  const doomed = path
    ? entries.filter((e) => e.groupPath === path || e.groupPath.startsWith(path + "/"))
    : [];
  const inBin = !!group.inRecycleBin;
  // The root has no name of its own, and the bin keeps the one KeePass gave it.
  const renamable = !!path && !inBin;
  const save = async () => {
    if (busy) return;
    setBusy(true);
    setNameErr("");
    // Not trimmed: a name that already ends in a space must survive a save
    // that never touched it. An unchanged name sends no rename at all.
    const rename = renamable && name !== ownName ? name : null;
    try { await onSave(group, tags, rename); } catch (e) { setNameErr(String(e?.message ?? e)); setBusy(false); }
  };
  const remove = async () => {
    if (busy) return;
    setBusy(true);
    try { await onDelete(group); } catch (e) { setBusy(false); }
  };
  // A tree with no entries in it holds nothing worth a second click.
  const askDelete = () => (doomed.length === 0 ? remove() : setConfirming(true));
  return (
    <div className="scrim center" onMouseDown={onClose}>
      <div className="modal" style={{ width: "min(480px, 94%)" }} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          {confirming
            ? <div className="mh-badge" style={{ background: "var(--red-dim)", borderColor: "var(--red-dim)", color: "var(--red)" }}><Icon name="trash" size={18} /></div>
            : <div className="mh-badge"><Icon name="folder" size={19} /></div>}
          <div><h2>{confirming ? "Delete folder?" : "Edit Folder"}</h2><p>{label}</p></div>
          <button className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose}><Icon name="x" size={18} /></button>
        </div>
        {confirming ? (
          <div className="modal-body">
            <div style={{ fontSize: 13.5, color: "var(--text-dim)", lineHeight: 1.6 }}>
              This deletes <strong style={{ color: "var(--text)" }}>{doomed.length} {doomed.length === 1 ? "entry" : "entries"}</strong> in
              this folder and its subfolders. {inBin ? "They are already in the recycle bin, so this is permanent." : "They move to the recycle bin."}
            </div>
            <div className="folder-doomed">
              {doomed.map((e) => <div key={e.id} className="folder-doomed-row">{e.path}</div>)}
            </div>
          </div>
        ) : (
          <div className="modal-body">
            {renamable && (
              <div className="fld">
                <label htmlFor="folder-name">Name</label>
                <input id="folder-name" className="inp" value={name} aria-invalid={nameErr ? "true" : undefined}
                  onChange={(e) => { setName(e.target.value); setNameErr(""); }}
                  onKeyDown={(e) => { if (e.key === "Enter") save(); }} />
                {nameErr && <div role="alert" className="att-err">{nameErr}</div>}
              </div>
            )}
            <div className="fld">
              <label>Tags on this folder</label>
              <TagEditor tags={tags} onChange={setTags} placeholder="Add a folder tag" />
            </div>
            {group.inheritedTags?.length > 0 && <div className="tag-inherited"><span>Inherited</span> {group.inheritedTags.join(", ")}</div>}
            {nameErr && !renamable && <div role="alert" className="att-err">{nameErr}</div>}
            {!inBin && <FolderDefaults databaseId={databaseId} path={path} />}
          </div>
        )}
        {confirming ? (
          <div className="modal-foot"><div className="grow" />
            <button className="btn-ghost" onClick={() => setConfirming(false)} disabled={busy}>Back</button>
            <button className="btn-danger" onClick={remove} disabled={busy}>Confirm Delete</button>
          </div>
        ) : (
          <div className="modal-foot">
            {path && <button className="btn-danger" onClick={askDelete} disabled={busy}><Icon name="trash" size={15} style={{ display: "inline", verticalAlign: "-2px", marginRight: 5 }} />Delete folder</button>}
            <div className="grow" />
            <button className="btn-ghost" onClick={onClose}>Cancel</button>
            <button className="btn-primary" onClick={save} disabled={busy}>Save</button>
          </div>
        )}
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
          <span style={{ fontFamily: "var(--font-mono)", color: "var(--text)" }}>{entry.path}</span> will be removed from the database. You can restore it later from the recycle bin.
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
  { l: "Switch database", k: ["⌘", "1–9"] },
  { l: "Open database", k: ["⌘", "O"] },
  { l: "Lock database", k: ["⌘", "L"] },
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

/* ============ NEW DATABASE ============ */
// Second half of "create a database": the file has been chosen, now set the master
// password. There is no recovery for a forgotten one, so it is confirmed.
function NewDatabaseModal({ path, onCreate, onClose }) {
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
      setErr(String(e2 && e2.message ? e2.message : e2) || "Couldn't create the database.");
    }
  };

  return (
    <div className="scrim center" onMouseDown={onClose}>
      <div className="modal" style={{ width: "min(460px, 94%)" }} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="mh-badge"><Icon name="plus" size={18} /></div>
          <div><h2>New database</h2><p>{file}</p></div>
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
            <button type="submit" className="btn-primary" disabled={busy}>{busy ? "Creating…" : "Create database"}</button>
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

// The one line Settings shows about the daemon behind `trove` commands and
// the agent sockets.
function daemonLine(status) {
  if (!status) return "Daemon: checking…";
  switch (status.mode) {
    case "hosted": return "Daemon: hosted by this app";
    case "client": return status.pid != null ? `Daemon: using troved (pid ${status.pid})` : "Daemon: using troved";
    case "failed": return `Daemon: ${status.error}`;
    default: return "Daemon: not running";
  }
}

function SettingsModal({ settings, onChange, onClose }) {
  const set = (patch) => onChange({ ...settings, ...patch });
  const agent = settings.systemAgent;
  const [daemon, setDaemon] = React.useState(null);
  React.useEffect(() => {
    let live = true;
    new Promise((resolve) => resolve(api.daemonStatus()))
      .then((status) => { if (live) setDaemon(status || { mode: "stopped" }); })
      .catch((e) => { if (live) setDaemon({ mode: "failed", error: String(e?.message ?? e) }); });
    return () => { live = false; };
  }, []);
  return (
    <div className="scrim center" onMouseDown={onClose}>
      <div className="modal" style={{ width: "min(560px, 94%)" }} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="mh-badge"><Icon name="gear" size={18} /></div>
          <div><h2>Settings</h2><p>What unlocking a database does to the rest of your machine.</p></div>
          <button className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose}><Icon name="x" size={18} /></button>
        </div>

        <div className="modal-body">
          {/* The one rule worth stating outright, because two different locks
              with two different scopes is exactly what confused this before. */}
          <p className="set-note" style={{ margin: "0 2px 4px" }}>
            <b>App lock</b> locks this window and forgets the decrypted database.
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
              desc="Minutes of no interaction before the window locks and the decrypted database is forgotten. Keys and materialized files are left alone — they expire on their own clocks. 0 never locks.">
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

          <p className="set-note" data-testid="daemon-status">{daemonLine(daemon)}</p>

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

function DatabaseMetadataModal({ databaseId, databaseName, onClose, onSaved }) {
  const [metadata, setMetadata] = React.useState(null);
  const [error, setError] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    let active = true;
    api.getDatabaseMetadata(databaseId)
      .then((value) => { if (active) setMetadata({
        name: value.name || "",
        description: value.description || "",
        defaultUsername: value.defaultUsername || "",
        troveUuid: value.troveUuid || "",
      }); })
      .catch((reason) => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [databaseId]);

  const update = (key, value) => setMetadata((current) => ({ ...current, [key]: value }));
  const saveMetadata = async (event) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const saved = await api.setDatabaseMetadata(databaseId, {
        name: metadata.name || null,
        description: metadata.description || null,
        defaultUsername: metadata.defaultUsername || null,
        troveUuid: metadata.troveUuid || null,
      });
      onSaved?.(saved);
      onClose();
    } catch (reason) {
      setError(String(reason));
      setSaving(false);
    }
  };

  return (
    <div className="scrim center" onMouseDown={onClose}>
      <form className="modal" style={{ width: "min(560px, 94%)" }} onMouseDown={(event) => event.stopPropagation()} onSubmit={saveMetadata}>
        <div className="modal-head">
          <div className="mh-badge"><Icon name="gear" size={18} /></div>
          <div><h2>Database metadata</h2><p>{databaseName}</p></div>
          <button type="button" className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose} aria-label="Close"><Icon name="x" size={18} /></button>
        </div>
        {!metadata ? (
          <div className="modal-body">{error || "Loading metadata…"}</div>
        ) : (
          <div className="modal-body">
            <div className="fld"><label htmlFor="database-name">Name</label><input id="database-name" className="inp" value={metadata.name} onChange={(event) => update("name", event.target.value)} /></div>
            <div className="fld"><label htmlFor="database-description">Description</label><textarea id="database-description" className="inp" rows="3" value={metadata.description} onChange={(event) => update("description", event.target.value)} /></div>
            <div className="fld"><label htmlFor="database-default-username">Default username</label><input id="database-default-username" className="inp" value={metadata.defaultUsername} onChange={(event) => update("defaultUsername", event.target.value)} /></div>
            <div className="fld"><label htmlFor="database-trove-uuid">Trove database UUID</label>
              <div className="pw-row"><input id="database-trove-uuid" className="inp mono" value={metadata.troveUuid} onChange={(event) => update("troveUuid", event.target.value)} placeholder="Not linked" spellCheck="false" />
                <button type="button" className="btn-ghost" onClick={() => update("troveUuid", crypto.randomUUID())}>Generate</button>
              </div>
              <small>Use the same UUID on database copies you want Trove to recognize as linked.</small>
            </div>
            {error && <div role="alert" className="form-error">{error}</div>}
          </div>
        )}
        <div className="modal-foot">
          <div className="grow" />
          <button type="button" className="btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn-primary" disabled={!metadata || saving}>{saving ? "Saving…" : "Save metadata"}</button>
        </div>
      </form>
    </div>
  );
}

/* ============ DATABASE SWITCHER ============ */
function DatabaseSwitcher({ databases, activeId, onSwitch, onSave, onRemove, onOpenNew, onNewDatabase, onClose }) {
  const [pending, setPending] = React.useState(null);
  const [error, setError] = React.useState("");
  const busy = React.useRef(false);
  const runAction = async (action, database) => {
    if (busy.current) return;
    busy.current = true;
    setPending({ action, id: database.id });
    setError("");
    try {
      await (action === "save" ? onSave : onRemove)(database.id);
    } catch (error) {
      setError(`${action === "save" ? "Save" : "Remove"} failed for ${database.path || database.file}: ${String(error)}`);
    } finally {
      busy.current = false;
      setPending(null);
    }
  };
  const linked = new Map();
  const unlinked = [];
  for (const database of databases) {
    const uuid = database.troveUuid?.trim().toLowerCase();
    if (!uuid) {
      unlinked.push(database);
      continue;
    }
    const copies = linked.get(uuid) || [];
    copies.push(database);
    linked.set(uuid, copies);
  }
  const compareDatabases = (left, right) =>
    left.name.localeCompare(right.name, undefined, { sensitivity: "base" }) ||
    (left.path || left.file).localeCompare(right.path || right.file, undefined, { sensitivity: "base" });
  const linkedGroups = [...linked.entries()].map(([uuid, copies]) => ({
    uuid,
    copies: copies.sort(compareDatabases),
  })).sort((left, right) => compareDatabases(left.copies[0], right.copies[0]));
  unlinked.sort(compareDatabases);
  const ordered = [...linkedGroups.flatMap((group) => group.copies), ...unlinked];
  const shortcutIndex = new Map(ordered.map((database, index) => [database.id, index + 1]));
  const renderDatabase = (database) => (
    <div key={database.id} role="group" aria-label={"Database " + (database.path || database.file)} className={"vrow database-option" + (database.id === activeId ? " on" : "")}>
      <button className="database-option-select" disabled={!!pending} onClick={() => { onSwitch(database.id); onClose(); }}>
        <span className={"vdot " + (database.readOnly ? "read-only" : database.locked ? "locked" : "unlocked")} title={database.readOnly ? "Read only" : database.locked ? "Locked" : "Unlocked"} />
        <span className="database-option-copy">
          <span className="vrn">{database.name}</span>
          <span className="vrf" title={database.path || database.file}>{database.path || database.file}</span>
        </span>
        <span className="kbd">⌘{shortcutIndex.get(database.id)}</span>
      </button>
      <div className="database-option-actions">
        <button className="icon-btn database-action-btn" aria-label={"Save database " + (database.path || database.file)} aria-busy={pending?.id === database.id && pending.action === "save"} disabled={!!pending || database.locked || database.readOnly} title={database.locked ? "Unlock this database to save" : database.readOnly ? "Read-only database" : "Save database to disk"} onClick={() => runAction("save", database)}><Icon name={pending?.id === database.id && pending.action === "save" ? "clock" : "save"} size={16} /></button>
        <button className="icon-btn database-action-btn" aria-label={"Remove database " + (database.path || database.file)} aria-busy={pending?.id === database.id && pending.action === "remove"} disabled={!!pending} title="Close and remove from Trove; the database file is kept" onClick={() => runAction("remove", database)}><Icon name={pending?.id === database.id && pending.action === "remove" ? "clock" : "x"} size={16} /></button>
      </div>
    </div>
  );

  return (
    <React.Fragment>
      <div className="pop-scrim" onMouseDown={onClose} />
      <div className="popover vsw" onMouseDown={(e) => e.stopPropagation()}>
        <div className="pop-sec" style={{ marginTop: 2 }}>Open databases</div>
        {error && <p role="alert" className="database-action-error">{error}</p>}
        {linkedGroups.map((group) => (
          <section className="database-link-group" key={group.uuid}>
            <div className="database-group-heading">
              <Icon name="link" size={13} />
              <span>Linked copies</span>
              <span className="database-group-count">{group.copies.length} open</span>
            </div>
            <div className="database-group-items">{group.copies.map(renderDatabase)}</div>
          </section>
        ))}
        {unlinked.length > 0 && (
          <>
            {linkedGroups.length > 0 && <div className="database-group-heading other-databases-heading">Other databases</div>}
            {unlinked.map(renderDatabase)}
          </>
        )}
        <div className="pop-div" />
        <button className="vrow" disabled={!!pending} onClick={() => { onClose(); onOpenNew(); }}>
          <span className="vdot add"><Icon name="folder" size={13} /></span>
          <div style={{ flex: 1 }}><div className="vrn" style={{ fontWeight: 500 }}>Open database…</div></div>
          <span className="kbd">⌘O</span>
        </button>
        <button className="vrow" disabled={!!pending} onClick={() => { onClose(); onNewDatabase(); }}>
          <span className="vdot add"><Icon name="plus" size={13} /></span>
          <div style={{ flex: 1 }}><div className="vrn" style={{ fontWeight: 500 }}>New database…</div></div>
        </button>
      </div>
    </React.Fragment>
  );
}

/* ============ OPEN DATABASE MODAL ============ */
// Lists the persisted "recent" databases (from list_databases) so one click switches
// to it; "Browse…" opens the native file dialog to register a new .kdbx.
function OpenDatabaseModal({ recents, activeId, onPick, onBrowse, onClose }) {
  const list = recents || [];
  return (
    <div className="scrim center" onMouseDown={onClose}>
      <div className="modal" style={{ width: "min(440px, 94%)" }} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="mh-badge"><Icon name="file" size={18} /></div>
          <div><h2>Open database</h2><p>Recent databases</p></div>
          <button className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose}><Icon name="x" size={18} /></button>
        </div>
        <div className="modal-body" style={{ gap: 4 }}>
          {list.length === 0 && (
            <div style={{ padding: "18px 6px", textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>
              No recent databases yet — browse to open one.
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

export { daemonLine, Unlock, CommandPalette, EntryForm, EditFolderModal, FolderDefaults, ConfirmDelete, HelpModal, ClipboardToast, PlainToast, genPassword, ThemeMenu, THEMES, DatabaseSwitcher, DatabaseMetadataModal, OpenDatabaseModal, SettingsModal, NewDatabaseModal, UnlockProgress, Switch };
