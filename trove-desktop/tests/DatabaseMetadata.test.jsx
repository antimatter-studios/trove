import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('../src/api.js', () => ({
  getDatabaseMetadata: vi.fn(),
  setDatabaseMetadata: vi.fn(),
}));

import * as api from '../src/api.js';
import { DatabaseMetadataModal } from '../src/overlays.jsx';

describe('database metadata editor', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getDatabaseMetadata.mockResolvedValue({
      name: 'Personal',
      description: 'Private records',
      defaultUsername: 'chris',
      troveUuid: null,
    });
    api.setDatabaseMetadata.mockResolvedValue({});
  });

  it('loads, edits, and saves database metadata', async () => {
    const onClose = vi.fn();
    const onSaved = vi.fn();
    render(<DatabaseMetadataModal databaseId="db-1" databaseName="personal.kdbx" onClose={onClose} onSaved={onSaved} />);

    const name = await screen.findByLabelText('Name');
    expect(name).toHaveValue('Personal');
    fireEvent.change(name, { target: { value: 'Shared records' } });
    fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Shared copy' } });
    fireEvent.change(screen.getByLabelText('Default username'), { target: { value: 'admin' } });
    fireEvent.change(screen.getByLabelText('Trove database UUID'), { target: { value: '3c7e4e44-5fca-4e2f-bb19-0912ebf2ab09' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save metadata' }));

    await waitFor(() => expect(api.setDatabaseMetadata).toHaveBeenCalledWith('db-1', {
      name: 'Shared records',
      description: 'Shared copy',
      defaultUsername: 'admin',
      troveUuid: '3c7e4e44-5fca-4e2f-bb19-0912ebf2ab09',
    }));
    expect(onSaved).toHaveBeenCalledOnce();
    expect(onClose).toHaveBeenCalledOnce();
  });
});
