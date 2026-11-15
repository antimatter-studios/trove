import React from 'react';
import * as api from './api.js';
import './health.css';

function plural(n, one, many) {
  return n === 1 ? one : many;
}

function Section({ title, count, children }) {
  return <section className="health-section" aria-label={title}>
    <h3>{title} <span className="health-count">{count}</span></h3>
    {children}
  </section>;
}

function Row({ entry, detail, onSelect }) {
  return <button className="health-row" onClick={() => onSelect(entry.id)} title={entry.path}>
    <span className="health-path">{entry.path}</span>
    {detail && <span className="health-detail">{detail}</span>}
  </button>;
}

function formatDate(when) {
  const date = new Date(when);
  return Number.isNaN(date.getTime()) ? when : date.toLocaleDateString();
}

/// Password health for the open database: reused, weak, old and expired
/// entries. Reloads whenever the entry list changes (a save, a reload from
/// disk) or another database is opened, so a fixed password drops out.
export function HealthView({ database, appActions, onSelectEntry }) {
  const [report, setReport] = React.useState(null);
  const [error, setError] = React.useState('');
  React.useEffect(() => {
    let active = true;
    setError('');
    api.databaseHealth(database.id)
      .then((next) => { if (active) setReport(next); })
      .catch((reason) => { if (active) { setReport(null); setError(String(reason)); } });
    return () => { active = false; };
  }, [database.id, database.entries]);

  const reusedCount = report ? report.reused.reduce((n, group) => n + group.entries.length, 0) : 0;
  const clean = report && !reusedCount && !report.weak.length && !report.stale.length && !report.expired.length;
  return <div className="pane health-view">
    <div className="detail-bar">{appActions}</div>
    <header className="health-header">
      <h2>Password Health</h2>
      <p>Entries in {database.name} that need attention. Nothing here leaves this computer.</p>
    </header>
    {error && <p role="alert" className="health-error">{error}</p>}
    {!report && !error && <p role="status" className="health-empty">Checking passwords…</p>}
    {clean && <p role="status" className="health-empty">No problems found</p>}
    {report && !clean && <div className="health-body">
      <Section title="Reused" count={reusedCount}>
        {report.reused.map((group, index) => <div className="health-group" key={index}>
          <p className="health-note">Same password in {group.entries.length} entries</p>
          {group.entries.map((entry) => <Row key={entry.id} entry={entry} onSelect={onSelectEntry} />)}
        </div>)}
      </Section>
      <Section title="Weak" count={report.weak.length}>
        {report.weak.map((entry) => <Row key={entry.id} entry={entry} detail={`Score ${entry.score} of 4`} onSelect={onSelectEntry} />)}
      </Section>
      <Section title="Old" count={report.stale.length}>
        {report.stale.map((entry) => <Row key={entry.id} entry={entry} detail={`Unchanged for ${entry.ageDays} ${plural(entry.ageDays, 'day', 'days')}`} onSelect={onSelectEntry} />)}
      </Section>
      <Section title="Expired" count={report.expired.length}>
        {report.expired.map((entry) => <Row key={entry.id} entry={entry} detail={`Expired ${formatDate(entry.expiredAt)}`} onSelect={onSelectEntry} />)}
      </Section>
    </div>}
  </div>;
}
