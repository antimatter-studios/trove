// A passkey made in KeePassXC shows in the detail pane as where it signs in and
// as whom, and the entry list marks the entry. No key material is ever in the
// page: the backend does not send it, and nothing here asks for it.

import { describe, it, expect, vi } from 'vitest';
import { render, waitFor } from '@testing-library/react';

vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(() => Promise.resolve()) }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(() => Promise.resolve(() => {})) }));
vi.mock('../src/api.js', () => ({
  entryCapabilities: vi.fn(() => Promise.resolve([])),
  listAttachments: vi.fn(() => Promise.resolve([])),
}));

import { Detail, EntryList } from '../src/views.jsx';

const ENTRY = {
  id: 'e1',
  title: 'webauthn',
  group: ['Web'],
  groupPath: 'Web',
  username: 'alice',
  url: 'https://webauthn.io',
  type: 'login',
  strength: 80,
  pwLen: 0,
  fav: false,
  tags: ['Passkey'],
  inheritedTags: [],
  modified: '2026-11-01T10:00:00+00:00',
  created: '2026-11-01T10:00:00+00:00',
  attachmentNames: [],
  passkey: true,
};

function renderDetail(passkey) {
  return render(
    <Detail
      databaseId="db1"
      entry={ENTRY}
      notes=""
      fields={[]}
      password=""
      passkey={passkey}
      onCopy={() => {}}
      copiedKey={null}
      onEdit={() => {}}
      onDelete={() => {}}
      onToggleFav={() => {}}
      revealed={false}
      onToggleReveal={() => {}}
    />,
  );
}

describe('passkeys', () => {
  it('shows the relying party and username and no key material', async () => {
    const { getByLabelText, container } = renderDetail({ relyingParty: 'webauthn.io', username: 'alice' });
    const section = getByLabelText('Passkey');
    expect(section.textContent).toContain('Passkey');
    expect(section.textContent).toContain('webauthn.io');
    expect(section.textContent).toContain('alice');
    await waitFor(() => expect(container.textContent).not.toContain('PRIVATE KEY'));
    expect(container.textContent).not.toContain('KPEX_PASSKEY');
  });

  it('has no passkey section for an entry without one', () => {
    const { queryByLabelText } = renderDetail(null);
    expect(queryByLabelText('Passkey')).toBeNull();
  });

  it('marks passkey entries in the list', () => {
    const plain = { ...ENTRY, id: 'e2', title: 'plain', passkey: false };
    const { container } = render(
      <EntryList
        entries={[ENTRY, plain]}
        selectedId={null}
        onSelect={() => {}}
        title="All"
        subtitle=""
        sort="title"
        onCycleSort={() => {}}
        query=""
        onQuery={() => {}}
        databaseName="db"
      />,
    );
    const rows = [...container.querySelectorAll('.erow')];
    expect(rows).toHaveLength(2);
    expect(rows[0].querySelector('[aria-label="Passkey"]')).not.toBeNull();
    expect(rows[1].querySelector('[aria-label="Passkey"]')).toBeNull();
  });
});
