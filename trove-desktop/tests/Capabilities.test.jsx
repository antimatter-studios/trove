// The settings sections write capability documents through the backend and
// redraw from what it returns. These prove the panels send the calls they
// should, show inherited values as inherited, and offer to add a capability
// only while it is off.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/react';

vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(() => Promise.resolve()) }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(() => Promise.resolve(() => {})) }));
vi.mock('../src/api.js', () => ({
  entryCapabilities: vi.fn(),
  setCapabilityItem: vi.fn(),
  removeCapabilityItem: vi.fn(),
  setCapabilityOn: vi.fn(),
  groupCapabilities: vi.fn(),
  setGroupDefault: vi.fn(),
}));

import * as api from '../src/api.js';
import { CapabilitySections } from '../src/views.jsx';
import { FolderDefaults } from '../src/overlays.jsx';

const ENTRY = { id: 'e1' };

function caps({ envOn = false, gpgOn = false, envItems = [] } = {}) {
  return [
    { capability: 'env-agent', on: envOn, legacy: false, items: envItems, fields: ['Password', 'UserName', 'gitea-token'], attachments: ['gitea_ed25519'] },
    { capability: 'materialize', on: false, legacy: false, items: [], fields: [], attachments: ['gitea_ed25519'] },
    { capability: 'gpg-agent', on: gpgOn, legacy: false, items: [], fields: [], attachments: ['gitea_ed25519'] },
  ];
}

const TOKEN = {
  key: 'GITEA_TOKEN',
  own: { name: 'GITEA_TOKEN', field: 'gitea-token' },
  effective: {
    name: { value: 'GITEA_TOKEN', from: '' },
    field: { value: 'gitea-token', from: '' },
    confirm: { value: 'true', from: 'group antimatter-studios' },
  },
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe('CapabilitySections', () => {
  it('offers to add a capability only while it is off', async () => {
    api.entryCapabilities.mockResolvedValue(caps());
    api.setCapabilityOn.mockResolvedValue(caps({ envOn: true }));
    const { findByText, queryByText } = render(<CapabilitySections vaultId="v1" entry={ENTRY} />);
    fireEvent.click(await findByText(/Export variables to trove exec/));
    await waitFor(() => expect(api.setCapabilityOn).toHaveBeenCalledWith('v1', 'e1', 'env-agent', true));
    await findByText(/Environment · 0/);
    expect(queryByText(/Export variables to trove exec/)).toBeNull();
    expect(await findByText(/Serve a GPG key/)).toBeTruthy();
  });

  it('adds a variable from a field and shows an inherited constraint as inherited', async () => {
    api.entryCapabilities.mockResolvedValue(caps({ envOn: true }));
    api.setCapabilityItem.mockResolvedValue(caps({ envOn: true, envItems: [TOKEN] }));
    const { container, findByText } = render(<CapabilitySections vaultId="v1" entry={ENTRY} />);
    await findByText(/Environment · 0/);
    const name = container.querySelector('.cap-add input');
    fireEvent.change(name, { target: { value: 'gitea_token' } });
    const source = container.querySelector('.cap-add select');
    fireEvent.change(source, { target: { value: 'field:gitea-token' } });
    fireEvent.click(await findByText('Add'));
    await waitFor(() =>
      expect(api.setCapabilityItem).toHaveBeenCalledWith('v1', 'e1', 'env-agent', { name: 'GITEA_TOKEN', field: 'gitea-token' })
    );
    expect(await findByText('GITEA_TOKEN')).toBeTruthy();
    expect(await findByText(/group antimatter-studios/)).toBeTruthy();
    const touch = container.querySelector('.cap-row .cap-check input');
    expect(touch.checked).toBe(true);
    expect(touch.disabled).toBe(true);
  });

  it('turns a capability off and removes an item', async () => {
    api.entryCapabilities.mockResolvedValue(caps({ envOn: true, envItems: [TOKEN] }));
    api.removeCapabilityItem.mockResolvedValue(caps({ envOn: true }));
    api.setCapabilityOn.mockResolvedValue(caps());
    const { container, findByText } = render(<CapabilitySections vaultId="v1" entry={ENTRY} />);
    await findByText('GITEA_TOKEN');
    fireEvent.click(container.querySelector('.cap-row .icon-btn'));
    await waitFor(() => expect(api.removeCapabilityItem).toHaveBeenCalledWith('v1', 'e1', 'env-agent', 'GITEA_TOKEN'));
    fireEvent.click(await findByText('turn off'));
    await waitFor(() => expect(api.setCapabilityOn).toHaveBeenCalledWith('v1', 'e1', 'env-agent', false));
  });

  it('shows a backend refusal instead of crashing', async () => {
    api.entryCapabilities.mockRejectedValue('EnvAgent.settings is not well-formed XML');
    const { findByText } = render(<CapabilitySections vaultId="v1" entry={ENTRY} />);
    expect(await findByText(/not well-formed/)).toBeTruthy();
  });
});

describe('FolderDefaults', () => {
  it('writes a default when a box loses focus and a toggle at once', async () => {
    api.groupCapabilities.mockResolvedValue([
      { capability: 'env-agent', defaults: {}, allowed: ['export', 'confirm', 'lifetime'] },
      { capability: 'materialize', defaults: { mode: '0600' }, allowed: ['dir', 'mode', 'ttl', 'allowDiskBacked'] },
      { capability: 'gpg-agent', defaults: {}, allowed: ['uses', 'confirm', 'lifetime'] },
    ]);
    api.setGroupDefault.mockResolvedValue([]);
    const { container, findByDisplayValue } = render(<FolderDefaults vaultId="v1" path="Apple/Apps/rest-mail" />);
    await findByDisplayValue('0600');
    const dir = container.querySelector('input[placeholder="~/projects/app/secrets"]');
    fireEvent.change(dir, { target: { value: '~/rest-mail/secrets' } });
    fireEvent.blur(dir);
    await waitFor(() =>
      expect(api.setGroupDefault).toHaveBeenCalledWith('v1', 'Apple/Apps/rest-mail', 'materialize', 'dir', '~/rest-mail/secrets')
    );
  });

  it('says it applies to the whole vault at the root', async () => {
    api.groupCapabilities.mockResolvedValue([]);
    const { findByText } = render(<FolderDefaults vaultId="v1" path="" />);
    expect(await findByText(/whole vault/)).toBeTruthy();
  });
});
