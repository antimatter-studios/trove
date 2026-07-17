// Trove — helpers + three-pane views

function relTime(iso) {
  const d = new Date(iso), now = new Date("2026-07-04T12:00:00Z");
  const s = Math.floor((now - d) / 1000);
  const day = 86400;
  if (s < 3600) return Math.max(1, Math.floor(s / 60)) + "m ago";
  if (s < day) return Math.floor(s / 3600) + "h ago";
  if (s < day * 30) return Math.floor(s / day) + "d ago";
  if (s < day * 365) return Math.floor(s / (day * 30)) + "mo ago";
  return Math.floor(s / (day * 365)) + "y ago";
}
function fullDate(iso) {
  return new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}
function strengthInfo(v) {
  if (v >= 85) return { label: "Excellent", color: "var(--green)" };
  if (v >= 70) return { label: "Strong", color: "var(--accent)" };
  if (v >= 45) return { label: "Fair", color: "var(--amber)" };
  return { label: "Weak", color: "var(--red)" };
}

/* ============ SIDEBAR ============ */
function TreeNode({ node, depth, open, setOpen, selected, onSelect }) {
  const hasKids = node.children && node.children.length > 0;
  const isOpen = open[node.path];
  const sel = selected === node.path;
  return (
    <React.Fragment>
      <div
        className={"tree-row" + (sel ? " sel" : "")}
        style={{ paddingLeft: 6 + depth * 14 }}
        onClick={() => onSelect(node.path)}
      >
        <span
          className={"tw" + (isOpen ? " open" : "")}
          onClick={(e) => { e.stopPropagation(); if (hasKids) setOpen(node.path); }}
          style={{ visibility: hasKids ? "visible" : "hidden" }}
        >
          <Icon name="chevron" size={13} />
        </span>
        <Icon name="folder" size={15} className="tfic" />
        <span className="tr-name">{node.name}</span>
        <span className="tr-count">{node.count}</span>
      </div>
      {hasKids && isOpen && node.children.map((c) => (
        <TreeNode key={c.path} node={c} depth={depth + 1} open={open} setOpen={setOpen} selected={selected} onSelect={onSelect} />
      ))}
    </React.Fragment>
  );
}

function Sidebar({ tree, total, selectedGroup, onSelectGroup, favCount, vault, onSwitcher }) {
  const [open, setOpenState] = React.useState({ inpace: true, personal: true, infra: false });
  const setOpen = (p) => setOpenState((o) => ({ ...o, [p]: !o[p] }));
  return (
    <div className="pane sidebar">
      <div className="sb-scroll">
        <button className="sb-vault" onClick={onSwitcher} title="Switch vault">
          <div className="vbadge"><Icon name="shield" size={17} /></div>
          <div style={{ minWidth: 0, flex: 1, textAlign: "left" }}>
            <div className="vname">{vault.name}</div>
            <div className="vmeta">{vault.file}</div>
          </div>
          <Icon name="chevronDown" size={15} className="vchev" />
        </button>

        <div className="sb-label">Library</div>
        <div className={"tree-row" + (selectedGroup === "__all" ? " sel" : "")} onClick={() => onSelectGroup("__all")} style={{ paddingLeft: 6 }}>
          <span className="tw" style={{ visibility: "hidden" }} />
          <Icon name="hash" size={15} className="tfic" />
          <span className="tr-name" style={{ fontFamily: "var(--font-sans)", fontWeight: 500 }}>All entries</span>
          <span className="tr-count">{total}</span>
        </div>
        <div className={"tree-row" + (selectedGroup === "__fav" ? " sel" : "")} onClick={() => onSelectGroup("__fav")} style={{ paddingLeft: 6 }}>
          <span className="tw" style={{ visibility: "hidden" }} />
          <Icon name="star" size={15} className="tfic" />
          <span className="tr-name" style={{ fontFamily: "var(--font-sans)", fontWeight: 500 }}>Favorites</span>
          <span className="tr-count">{favCount}</span>
        </div>

        <div className="sb-label">Groups</div>
        {tree.map((n) => (
          <TreeNode key={n.path} node={n} depth={0} open={open} setOpen={setOpen} selected={selectedGroup} onSelect={onSelectGroup} />
        ))}
      </div>
      <div className="sb-foot">
        <Icon name="lock" size={13} />
        <span>AES‑256 · Argon2id</span>
      </div>
    </div>
  );
}

/* ============ ENTRY LIST ============ */
function EntryList({ entries, selectedId, onSelect, title, subtitle, sort, onCycleSort }) {
  const listRef = React.useRef(null);
  React.useEffect(() => {
    const el = listRef.current && listRef.current.querySelector(".erow.sel");
    if (el) el.scrollIntoView ? null : null; // avoid scrollIntoView; rely on manual below
  }, [selectedId]);
  React.useEffect(() => {
    if (!listRef.current) return;
    const el = listRef.current.querySelector(".erow.sel");
    if (!el) return;
    const c = listRef.current, r = el.getBoundingClientRect(), cr = c.getBoundingClientRect();
    if (r.top < cr.top + 40) c.scrollTop -= (cr.top + 40 - r.top);
    else if (r.bottom > cr.bottom) c.scrollTop += (r.bottom - cr.bottom + 8);
  }, [selectedId]);

  const sortLabel = { title: "Title", modified: "Recently modified", strength: "Weakest first" }[sort];
  return (
    <div className="pane list">
      <div className="list-head">
        <div>
          <div className="lh-title">{title}</div>
          <div className="lh-sub">{subtitle}</div>
        </div>
        <button className="sort-chip" onClick={onCycleSort} title="Cycle sort">
          <Icon name="updown" size={13} />{sortLabel}
        </button>
      </div>
      <div className="col-head">
        <span>Entry</span><span style={{ textAlign: "right" }}>Modified</span>
      </div>
      <div className="list-scroll" ref={listRef}>
        {entries.length === 0 && (
          <div style={{ padding: "50px 20px", textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>No entries match.</div>
        )}
        {entries.map((e) => (
          <div key={e.id} className={"erow" + (e.id === selectedId ? " sel" : "")} onClick={() => onSelect(e.id)}>
            <div className="cell-title">
              <span className="etype"><Icon name={TYPE_ICON[e.type] || "key"} size={16} /></span>
              <div className="etitle-wrap">
                <div className="etitle">
                  <span className="etitle-txt">{e.title}</span>
                  {e.fav && <Icon name="star" size={12} className="fav" />}
                  {e.strength < 45 && <span className="weakdot" title="Weak password" />}
                </div>
                <div className="egroup"><span>{e.username}</span><span className="eg-path">{"  ·  " + e.groupPath}</span></div>
              </div>
            </div>
            <div className="cell-mod">{relTime(e.modified)}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ============ DETAIL ============ */
function Field({ k, value, secret, revealed, onReveal, link, onCopy, copiedKey, copyId }) {
  const isCopied = copiedKey === copyId;
  return (
    <div className="field">
      <span className="fk">{k}</span>
      <span
        className={"fv" + (secret && !revealed ? " secret" : "") + (link ? " link" : "")}
        onClick={link ? () => onCopy(value, copyId, "url") : undefined}
        title={link ? value : undefined}
      >
        {secret && !revealed ? "•".repeat(Math.min(18, value.length)) : value}
      </span>
      <div className="facts">
        {secret && (
          <button className="fact" onClick={onReveal} title={revealed ? "Hide" : "Reveal"}>
            <Icon name={revealed ? "eyeOff" : "eye"} size={16} />
          </button>
        )}
        {link && (
          <button className="fact" onClick={() => window.open(value, "_blank")} title="Open URL">
            <Icon name="external" size={16} />
          </button>
        )}
        <button className={"fact" + (isCopied ? " copied" : "")} onClick={() => onCopy(value, copyId, secret ? "password" : k.toLowerCase())} title="Copy">
          <Icon name={isCopied ? "check" : "copy"} size={16} />
        </button>
      </div>
    </div>
  );
}

function Detail({ entry, onCopy, copiedKey, onEdit, onDelete, onToggleFav, revealed, onToggleReveal }) {
  if (!entry) {
    return (
      <div className="pane detail">
        <div className="empty">
          <div className="eglyph"><Icon name="key" size={30} /></div>
          <h3>No entry selected</h3>
          <p>Pick an entry from the list, or press <span className="kbd">⌘K</span> to search your whole vault.</p>
        </div>
      </div>
    );
  }
  const si = strengthInfo(entry.strength);
  return (
    <div className="pane detail">
      <div className="detail-scroll">
        <div className="dt-hero">
          <div className="dt-crumb">
            {entry.group.map((g, i) => (
              <React.Fragment key={i}>
                <span className="seg">{g}</span><span className="sl"><Icon name="chevron" size={11} /></span>
              </React.Fragment>
            ))}
            <span style={{ color: "var(--text-dim)" }}>{entry.title}</span>
          </div>
          <div className="dt-titlerow">
            <div className="dt-badge"><Icon name={TYPE_ICON[entry.type] || "key"} size={24} /></div>
            <div style={{ minWidth: 0 }}>
              <div className="dt-title">{entry.title}</div>
              <div className="dt-type"><Icon name="hash" size={12} />{entry.type}</div>
            </div>
            <div className="dt-actions">
              <button className={"icon-btn" + (entry.fav ? " active" : "")} onClick={() => onToggleFav(entry.id)} title="Favorite"><Icon name="star" size={17} /></button>
              <button className="icon-btn" onClick={() => onEdit(entry)} title="Edit (E)"><Icon name="edit" size={17} /></button>
              <button className="icon-btn" onClick={() => onDelete(entry)} title="Delete"><Icon name="trash" size={17} /></button>
            </div>
          </div>
        </div>

        <div className="dt-section">
          <div className="dt-sec-label">Credentials</div>
          <Field k="Username" value={entry.username} onCopy={onCopy} copiedKey={copiedKey} copyId={entry.id + ":user"} />
          <Field k="Password" value={entry.password} secret revealed={revealed} onReveal={onToggleReveal} onCopy={onCopy} copiedKey={copiedKey} copyId={entry.id + ":pass"} />
          <div className="strength">
            <div className="strength-bar"><i style={{ width: entry.strength + "%", background: si.color }} /></div>
            <div className="strength-meta">
              <span style={{ color: si.color, fontWeight: 600, fontSize: 11.5 }}>{si.label}</span>
              <span style={{ color: "var(--text-faint)", fontFamily: "var(--font-mono)", fontSize: 11 }}>{entry.strength}/100 · {entry.password.length} chars</span>
            </div>
          </div>
          {entry.url && <div style={{ height: 8 }} />}
          {entry.url && <Field k="URL" value={entry.url} link onCopy={onCopy} copiedKey={copiedKey} copyId={entry.id + ":url"} />}
        </div>

        {entry.fields && entry.fields.length > 0 && (
          <div className="dt-section">
            <div className="dt-sec-label">Attributes</div>
            {entry.fields.map((f, i) => (
              <Field key={i} k={f.k} value={f.v} onCopy={onCopy} copiedKey={copiedKey} copyId={entry.id + ":attr" + i} />
            ))}
          </div>
        )}

        {entry.notes && (
          <div className="dt-section">
            <div className="dt-sec-label">Notes</div>
            <div className="notes">{entry.notes}</div>
          </div>
        )}

        <div className="dt-section" style={{ borderBottom: "none" }}>
          <div className="dt-sec-label">Metadata</div>
          <div className="meta-grid">
            <div className="meta-item"><div className="ml">Modified</div><div className="mv">{fullDate(entry.modified)} · {relTime(entry.modified)}</div></div>
            <div className="meta-item"><div className="ml">Created</div><div className="mv">{fullDate(entry.created)}</div></div>
            <div className="meta-item"><div className="ml">Group</div><div className="mv">{entry.groupPath}</div></div>
            <div className="meta-item"><div className="ml">UUID</div><div className="mv">{"trv-" + entry.id.padStart(4, "0") + "-a91f"}</div></div>
          </div>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { relTime, fullDate, strengthInfo, Sidebar, EntryList, Detail });
