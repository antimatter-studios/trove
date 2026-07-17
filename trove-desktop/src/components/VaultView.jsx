// The unlocked three-pane vault view: group-tree sidebar, filtered entry
// list, and a detail pane that reveals/copies secrets on demand. Ported from
// the Claude Design reference (design/) onto the real Tauri command surface —
// mock data replaced by the `useVault` store, secrets fetched via `reveal`
// (get_field) rather than held in the entry list.

import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useVault } from '../store/vault';
import { buildTree, filterEntries, groupPath } from '../store/tree';

function Sidebar({ tree, total, group, onSelectGroup }) {
  const { t } = useTranslation();
  return (
    <nav className="pane sidebar" aria-label={t('vault.library')}>
      <div className="sb-label">{t('vault.library')}</div>
      <button
        type="button"
        className={`tree-row${group === '__all' ? ' sel' : ''}`}
        onClick={() => onSelectGroup('__all')}
      >
        <span className="tr-name">{t('vault.allEntries')}</span>
        <span className="tr-count">{total}</span>
      </button>
      <div className="sb-label">{t('vault.groups')}</div>
      {tree.map((node) => (
        <TreeNode key={node.path} node={node} depth={0} group={group} onSelectGroup={onSelectGroup} />
      ))}
    </nav>
  );
}

function TreeNode({ node, depth, group, onSelectGroup }) {
  return (
    <>
      <button
        type="button"
        className={`tree-row${group === node.path ? ' sel' : ''}`}
        style={{ paddingLeft: 10 + depth * 14 }}
        onClick={() => onSelectGroup(node.path)}
      >
        <span className="tr-name">{node.name}</span>
        <span className="tr-count">{node.count}</span>
      </button>
      {node.children.map((child) => (
        <TreeNode
          key={child.path}
          node={child}
          depth={depth + 1}
          group={group}
          onSelectGroup={onSelectGroup}
        />
      ))}
    </>
  );
}

function EntryList({ entries, selectedId, onSelect }) {
  const { t } = useTranslation();
  if (entries.length === 0) {
    return (
      <div className="pane list">
        <p className="empty">{t('vault.noMatches')}</p>
      </div>
    );
  }
  return (
    <div className="pane list">
      <ul className="entries-list" role="listbox" aria-label={t('entries.heading')}>
        {entries.map((e) => (
          <li key={e.id}>
            <button
              type="button"
              className={`erow${e.id === selectedId ? ' sel' : ''}`}
              aria-selected={e.id === selectedId}
              onClick={() => onSelect(e.id)}
            >
              <span className="etitle">{e.title}</span>
              <span className="egroup">
                {e.username || t('entries.noUsername')}
                {groupPath(e).length > 0 ? ` · ${groupPath(e).join('/')}` : ''}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

// A single revealable/copyable field. Value is fetched lazily via `reveal`
// and held only in this component's state — never in the store.
function SecretField({ label, entryId, field, secret }) {
  const { t } = useTranslation();
  const reveal = useVault((s) => s.reveal);
  const [value, setValue] = useState(null);
  const [shown, setShown] = useState(false);
  const [copied, setCopied] = useState(false);

  async function ensure() {
    if (value === null) {
      const v = await reveal(entryId, field);
      setValue(v ?? '');
      return v ?? '';
    }
    return value;
  }

  async function toggle() {
    await ensure();
    setShown((s) => !s);
  }

  async function copy() {
    const v = await ensure();
    try {
      await navigator.clipboard?.writeText(v);
    } catch {
      // Clipboard may be unavailable (e.g. tests); swallow.
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1100);
  }

  const display = !secret || shown ? (value ?? '') : '•'.repeat(10);
  return (
    <div className="field">
      <span className="fk">{label}</span>
      <span className={`fv${secret && !shown ? ' secret' : ''}`}>{display}</span>
      <div className="facts">
        {secret && (
          <button type="button" className="fact" onClick={toggle}>
            {shown ? t('vault.hide') : t('vault.reveal')}
          </button>
        )}
        <button type="button" className="fact" onClick={copy}>
          {copied ? t('vault.copied') : t('vault.copy')}
        </button>
      </div>
    </div>
  );
}

function Detail({ entry }) {
  const { t } = useTranslation();
  if (!entry) {
    return (
      <div className="pane detail">
        <div className="empty-detail">
          <h3>{t('vault.noSelection')}</h3>
          <p>{t('vault.noSelectionHint')}</p>
        </div>
      </div>
    );
  }
  return (
    <div className="pane detail">
      <div className="dt-hero">
        <div className="dt-crumb">{entry.display_path}</div>
        <h2 className="dt-title">{entry.title}</h2>
      </div>
      <section className="dt-section">
        <div className="dt-sec-label">{t('vault.credentials')}</div>
        {/* Key each field by entry id so React remounts them when the selected
            entry changes — otherwise the reused component keeps the previously
            revealed value in local state and can show/copy another entry's
            secret. */}
        {entry.username != null && (
          <SecretField key={`${entry.id}:UserName`} label={t('vault.username')} entryId={entry.id} field="UserName" secret={false} />
        )}
        <SecretField key={`${entry.id}:Password`} label={t('vault.password')} entryId={entry.id} field="Password" secret />
        {entry.url && (
          <SecretField key={`${entry.id}:URL`} label={t('vault.url')} entryId={entry.id} field="URL" secret={false} />
        )}
      </section>
      {entry.attachment_names.length > 0 && (
        <section className="dt-section">
          <div className="dt-sec-label">{t('vault.attachments')}</div>
          <ul className="attach-list">
            {entry.attachment_names.map((name) => (
              <li key={name}>{name}</li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

export default function VaultView() {
  const { t } = useTranslation();
  const entries = useVault((s) => s.entries);
  const group = useVault((s) => s.group);
  const query = useVault((s) => s.query);
  const selectedId = useVault((s) => s.selectedId);
  const setGroup = useVault((s) => s.setGroup);
  const setQuery = useVault((s) => s.setQuery);
  const select = useVault((s) => s.select);
  const lock = useVault((s) => s.lock);

  const tree = useMemo(() => buildTree(entries), [entries]);
  const filtered = useMemo(() => filterEntries(entries, group, query), [entries, group, query]);
  const selected = filtered.find((e) => e.id === selectedId) ?? entries.find((e) => e.id === selectedId) ?? null;

  return (
    <div className="vault">
      <header className="toolbar">
        <span className="brand">{t('app.title')}</span>
        <input
          className="search"
          type="search"
          value={query}
          placeholder={t('vault.search')}
          aria-label={t('vault.search')}
          onChange={(e) => setQuery(e.currentTarget.value)}
        />
        <button type="button" className="ghost" onClick={lock}>
          {t('entries.lock')}
        </button>
      </header>
      <div className="body">
        <Sidebar tree={tree} total={entries.length} group={group} onSelectGroup={setGroup} />
        <EntryList entries={filtered} selectedId={selectedId} onSelect={select} />
        <Detail entry={selected} />
      </div>
    </div>
  );
}
