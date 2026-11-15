import React from 'react';
import * as api from './api.js';
import { Icon } from './icons.jsx';
import { compareEntries, linkedDatabases, revisionDiff } from './revisions.js';
import './revisions.css';

function versionLabel(version) {
  const date = version.modified ? new Date(version.modified).toLocaleString() : 'Unknown date';
  return `${version.index == null ? 'Current' : 'History ' + (version.index + 1)} · ${date}`;
}

export function RevisionComparison({ database, otherDatabase = database, entryId, leftExists = true, rightExists = true, onSaved }) {
  const [versions, setVersions] = React.useState(null);
  const [leftIndex, setLeftIndex] = React.useState(0);
  const [rightIndex, setRightIndex] = React.useState(0);
  const [revealed, setRevealed] = React.useState(false);
  const [onlyChanges, setOnlyChanges] = React.useState(true);
  const [pending, setPending] = React.useState(null);
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState('');
  const [reload, setReload] = React.useState(0);
  const sameDatabase = database.id === otherDatabase.id;

  React.useEffect(() => {
    let active = true;
    setVersions(null); setError(''); setPending(null); setRevealed(false);
    Promise.all([
      leftExists ? api.getEntryRevisions(database.id, entryId) : Promise.resolve([]),
      rightExists ? api.getEntryRevisions(otherDatabase.id, entryId) : Promise.resolve([]),
    ]).then(([left, right]) => {
      if (!active) return;
      setLeftIndex(0); setRightIndex(sameDatabase && right.length > 1 ? 1 : 0);
      setVersions({ left, right });
    }).catch((reason) => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [database.id, otherDatabase.id, entryId, leftExists, rightExists, sameDatabase, reload]);

  const left = versions?.left[leftIndex];
  const right = versions?.right[rightIndex];
  const rows = revisionDiff(left, right);
  const changedCount = rows.filter((row) => row.changed).length;
  const visibleRows = onlyChanges ? rows.filter((row) => row.changed) : rows;
  const targetDatabase = pending === 'left' ? otherDatabase : database;
  const apply = async () => {
    setSaving(true); setError('');
    try {
      const chosen = pending === 'left' ? left : right;
      const source = pending === 'left' ? database : otherDatabase;
      const targetVersions = pending === 'left' ? versions.right : versions.left;
      await api.applyEntryRevision(targetDatabase.id, source.id, entryId, chosen.index, chosen.token, targetVersions[0]?.token || null);
      setPending(null);
      try { await onSaved?.(targetDatabase.id); }
      catch (reason) { setError('Version saved, but refreshing the view failed: ' + String(reason)); return; }
      setReload((value) => value + 1);
    } catch (reason) { setError(String(reason)); }
    finally { setSaving(false); }
  };
  const renderValue = (value, protectedValue) => value == null ? <span className="revision-missing">Not present</span> : protectedValue && !revealed ? <span aria-label="Hidden value">••••••••</span> : value === '' ? <span className="revision-missing">Empty</span> : value;
  const versionSelect = (side, list, index, change) => (
    <select className="inp" aria-label={`${side} version`} value={index} disabled={saving || !list.length} onChange={(event) => { change(Number(event.target.value)); setPending(null); setRevealed(false); }}>
      {!list.length && <option value="0">Entry not present</option>}
      {list.map((version, position) => <option key={position} value={position}>{versionLabel(version)}</option>)}
    </select>
  );
  return (
    <section className="revision-comparison" aria-label="Entry version comparison">
      {error && <div role="alert" className="revision-error">{error} <button className="btn-ghost" disabled={saving} onClick={() => setReload((value) => value + 1)}>Reload comparison</button></div>}
      {!versions && !error && <p role="status">Loading entry history…</p>}
      {versions && <>
        <div className="revision-controls">
          <span>{changedCount} {changedCount === 1 ? 'difference' : 'differences'}</span>
          <label><input type="checkbox" checked={onlyChanges} onChange={(event) => setOnlyChanges(event.target.checked)} /> Differences only</label>
          <button className="btn-ghost" onClick={() => setRevealed((value) => !value)}>{revealed ? 'Hide protected values' : 'Reveal protected values'}</button>
        </div>
        <div className="revision-sides">
          <div><strong>This database</strong><div className="revision-path" title={database.path}>{database.path}</div>{versionSelect('Left', versions.left, leftIndex, setLeftIndex)}</div>
          <div><strong>{sameDatabase ? 'Entry history' : 'Linked database'}</strong><div className="revision-path" title={otherDatabase.path}>{otherDatabase.path}</div>{versionSelect('Right', versions.right, rightIndex, setRightIndex)}</div>
        </div>
        <div className="revision-fields">
          {!visibleRows.length && <p className="revision-empty">{sameDatabase && versions.right.length === 1 ? 'No saved history for this entry yet.' : 'Selected versions have the same content.'}</p>}
          {visibleRows.map((row) => <div className={'revision-field' + (row.changed ? ' changed' : '')} key={row.key}>
            <div className="revision-label">{row.label}{row.changed && <span>Different</span>}</div>
            <div className="revision-sides"><pre>{renderValue(row.left, row.protected)}</pre><pre>{renderValue(row.right, row.protected)}</pre></div>
          </div>)}
        </div>
        <div className="revision-actions">
          <button className="btn-ghost" disabled={saving || !left || otherDatabase.readOnly || left.token === versions.right[0]?.token} onClick={() => setPending('left')}>Use left version</button>
          <button className="btn-accent" disabled={saving || !right || database.readOnly || right.token === versions.left[0]?.token} onClick={() => setPending('right')}>Use right version</button>
        </div>
        <p className="revision-note">Whole entry: fields, attachments and settings. Existing active entries stay in their folder. The previous version stays in history, subject to the target database’s history limits. {sameDatabase ? 'Restores the selected version as a new edit.' : 'Writes the chosen version to the opposite database; the source is not changed. An active source restores a recycled target into the source folder. Deletions are never propagated.'}</p>
        {database.readOnly && <p role="status">This database is read only. Its versions can still be copied to a writable linked database.</p>}
        {pending && <div role="alertdialog" aria-label="Confirm version choice" className="revision-confirm">
          <strong>Apply the {pending} version to {sameDatabase ? 'this database' : 'the opposite database'}?</strong><div className="revision-path">{targetDatabase.path}</div>
          <button className="btn-ghost" disabled={saving} onClick={() => setPending(null)}>Cancel</button>
          <button className="btn-accent" disabled={saving} onClick={apply}>{saving ? 'Saving…' : 'Apply version'}</button>
        </div>}
      </>}
    </section>
  );
}

export function EntryHistoryModal({ database, entry, onClose, onSaved }) {
  return <div className="scrim center" onMouseDown={onClose}>
    <div role="dialog" aria-modal="true" aria-label="Entry history" className="modal revision-modal" onMouseDown={(event) => event.stopPropagation()}>
      <div className="modal-head"><Icon name="clock" size={20} /><div><h2>Entry history</h2><p>{entry.title}</p></div><button className="icon-btn" aria-label="Close history" onClick={onClose}><Icon name="x" size={18} /></button></div>
      <RevisionComparison database={database} entryId={entry.id} onSaved={onSaved} />
    </div>
  </div>;
}

export function DatabaseSync({ database, databases, onSaved, onRefreshed, appActions }) {
  const refreshedRef = React.useRef(onRefreshed);
  refreshedRef.current = onRefreshed;
  const peers = linkedDatabases(database, databases);
  const [peerId, setPeerId] = React.useState(null);
  const peer = peers.find((candidate) => candidate.id === peerId) || peers[0];
  const [entries, setEntries] = React.useState(null);
  const [selectedId, setSelectedId] = React.useState(null);
  const [showMatching, setShowMatching] = React.useState(false);
  const [error, setError] = React.useState('');
  const [reload, setReload] = React.useState(0);
  React.useEffect(() => {
    let active = true;
    let loading = false;
    setEntries(null); setError('');
    if (!peer) return;
    const readSide = async (id) => {
      await api.reloadDatabase(id);
      await refreshedRef.current?.(id);
      return api.listRevisionEntries(id);
    };
    const refresh = async () => {
      if (!active || loading) return;
      loading = true;
      try {
        const [left, right] = await Promise.all([readSide(database.id), readSide(peer.id)]);
        if (active) { setEntries({ left, right }); setError(''); }
      } catch (reason) {
        if (active) { setEntries(null); setError(String(reason)); }
      } finally {
        loading = false;
      }
    };
    const refreshVisible = () => { if (!document.hidden) refresh(); };
    refresh();
    const timer = setInterval(refreshVisible, 3000);
    window.addEventListener('focus', refreshVisible);
    document.addEventListener('visibilitychange', refreshVisible);
    return () => {
      active = false;
      clearInterval(timer);
      window.removeEventListener('focus', refreshVisible);
      document.removeEventListener('visibilitychange', refreshVisible);
    };
  }, [database.id, peer?.id, reload]);
  const rows = entries ? compareEntries(entries.left, entries.right, showMatching) : [];
  const selected = rows.find((row) => row.id === selectedId) || rows[0];
  return <div className="pane database-sync">
    <div className="detail-bar">{appActions}</div>
    <header className="sync-header"><h2>Database Sync</h2><p>Compare linked copies. Choose the whole entry version you want; nothing changes until you apply it.</p>
      {peer && <label>Compare with<select className="inp" aria-label="Linked database" value={peer.id} onChange={(event) => { setPeerId(event.target.value); setSelectedId(null); }}>
        {peers.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.path}</option>)}
      </select></label>}
      <label><input type="checkbox" checked={showMatching} onChange={(event) => setShowMatching(event.target.checked)} /> Show matching entries and their history</label>
      <button className="btn-ghost" onClick={() => setReload((value) => value + 1)}>Refresh comparison</button>
    </header>
    {!peer && <p className="revision-empty">Unlock another database with the same Trove database UUID to compare copies.</p>}
    {error && <p role="alert" className="revision-error">{error}</p>}
    {peer && !entries && !error && <p role="status" className="revision-empty">Comparing entries…</p>}
    {entries && <div className="sync-body">
      <nav className="sync-entries" aria-label="Entry differences"><p>{rows.length} {showMatching ? 'entries' : 'different entries'}</p>
        {!rows.length && <p>No entry content differences.</p>}
        {rows.map((row) => <button key={row.id} className={'sync-entry' + (selected?.id === row.id ? ' selected' : '')} onClick={() => setSelectedId(row.id)}><strong>{row.title}</strong><span>{row.status}</span><span title={(row.left || row.right).path}>{(row.left || row.right).path}</span></button>)}
      </nav>
      {selected && <div className="sync-review"><h3>{selected.title}</h3><RevisionComparison key={`${database.id}:${peer.id}:${selected.id}:${selected.left?.token}:${selected.right?.token}:${reload}`} database={database} otherDatabase={peer} entryId={selected.id} leftExists={!!selected.left} rightExists={!!selected.right} onSaved={async (id) => { await onSaved?.(id); setReload((value) => value + 1); }} /></div>}
    </div>}
  </div>;
}
