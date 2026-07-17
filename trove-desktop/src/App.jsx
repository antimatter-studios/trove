import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { open as openDialog } from '@tauri-apps/plugin-dialog';
import { useVault } from './store/vault';
import VaultView from './components/VaultView';

function UnlockScreen() {
  const { t } = useTranslation();
  const { unlock, busy, error } = useVault();
  const [path, setPath] = useState('');
  const [password, setPassword] = useState('');

  async function browse() {
    const picked = await openDialog({
      multiple: false,
      filters: [{ name: 'KeePass vault', extensions: ['kdbx'] }],
    });
    if (typeof picked === 'string') setPath(picked);
  }

  function submit(e) {
    e.preventDefault();
    unlock(path, password);
  }

  return (
    <main className="screen unlock">
      <form className="card" onSubmit={submit}>
        <h1 className="brand">{t('app.title')}</h1>
        <p style={{ margin: '2px 0 10px', font: '600 11px/1 ui-monospace, monospace', letterSpacing: '0.12em', textTransform: 'uppercase', color: '#d8b25e' }}>
          v0.5.0 · new three-pane build
        </p>
        <h2>{t('unlock.heading')}</h2>

        <label className="field">
          <span>{t('unlock.vaultFile')}</span>
          <div className="file-row">
            <input
              type="text"
              value={path}
              placeholder={t('unlock.pathPlaceholder')}
              onChange={(e) => setPath(e.currentTarget.value)}
            />
            <button type="button" className="ghost" onClick={browse}>
              {t('unlock.browse')}
            </button>
          </div>
        </label>

        <label className="field">
          <span>{t('unlock.password')}</span>
          <input
            type="password"
            value={password}
            autoFocus
            onChange={(e) => setPassword(e.currentTarget.value)}
          />
        </label>

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}

        <button className="primary" type="submit" disabled={busy}>
          {busy ? t('unlock.unlocking') : t('unlock.submit')}
        </button>
      </form>
    </main>
  );
}

export default function App() {
  const locked = useVault((s) => s.locked);
  return locked ? <UnlockScreen /> : <VaultView />;
}
