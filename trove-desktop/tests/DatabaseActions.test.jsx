import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { DatabaseSwitcher } from '../src/overlays.jsx';

const databases = [
  { id: 'local', name: 'same.kdbx', path: '/local/same.kdbx', locked: false },
  { id: 'remote', name: 'same.kdbx', path: '/remote/same.kdbx', locked: true },
  { id: 'readonly', name: 'same.kdbx', path: '/readonly/same.kdbx', locked: false, readOnly: true },
];
let callbacks;

beforeEach(() => {
  callbacks = {
    onSave: vi.fn().mockResolvedValue(undefined),
    onRemove: vi.fn().mockResolvedValue(undefined),
    onSwitch: vi.fn(),
    onClose: vi.fn(),
    onOpenNew: vi.fn(),
    onNewDatabase: vi.fn(),
  };
});

function showSwitcher() {
  return render(<DatabaseSwitcher databases={databases} activeId="local" {...callbacks} />);
}

describe('database dropdown actions', () => {
  it('saves the exact database without switching or closing the menu', async () => {
    showSwitcher();
    fireEvent.click(screen.getByRole('button', { name: 'Save database /local/same.kdbx' }));

    await waitFor(() => expect(callbacks.onSave).toHaveBeenCalledWith('local'));
    expect(callbacks.onSwitch).not.toHaveBeenCalled();
    expect(callbacks.onClose).not.toHaveBeenCalled();
    expect(callbacks.onRemove).not.toHaveBeenCalled();
  });

  it('allows removal of locked and read-only databases but disables their save buttons', async () => {
    showSwitcher();
    expect(screen.getByRole('button', { name: 'Save database /remote/same.kdbx' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Save database /readonly/same.kdbx' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Remove database /remote/same.kdbx' }));
    await waitFor(() => expect(callbacks.onRemove).toHaveBeenCalledWith('remote'));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Remove database /readonly/same.kdbx' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Remove database /readonly/same.kdbx' }));
    await waitFor(() => expect(callbacks.onRemove).toHaveBeenCalledWith('readonly'));
    expect(callbacks.onSwitch).not.toHaveBeenCalled();
  });

  it('prevents repeated or competing actions while a save is pending', async () => {
    let finish;
    callbacks.onSave.mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    showSwitcher();
    fireEvent.click(screen.getByRole('button', { name: 'Save database /local/same.kdbx' }));
    expect(screen.getByRole('button', { name: 'Save database /local/same.kdbx' })).toHaveAttribute('aria-busy', 'true');
    fireEvent.click(screen.getByRole('button', { name: 'Save database /local/same.kdbx' }));
    fireEvent.click(screen.getByRole('button', { name: 'Remove database /remote/same.kdbx' }));
    expect(callbacks.onSave).toHaveBeenCalledTimes(1);
    expect(callbacks.onRemove).not.toHaveBeenCalled();
    await act(async () => finish());
    expect(screen.getByRole('button', { name: 'Save database /local/same.kdbx' })).toBeEnabled();
  });

  it.each(['save', 'remove'])('shows %s errors with the target path and allows retry', async (action) => {
    const callback = action === 'save' ? callbacks.onSave : callbacks.onRemove;
    callback.mockRejectedValueOnce(new Error('permission denied'));
    showSwitcher();
    const button = screen.getByRole('button', { name: `${action === 'save' ? 'Save' : 'Remove'} database /local/same.kdbx` });
    fireEvent.click(button);
    expect(await screen.findByRole('alert')).toHaveTextContent('/local/same.kdbx');
    expect(screen.getByRole('alert')).toHaveTextContent('permission denied');
    expect(button).toBeEnabled();
    fireEvent.click(button);
    await waitFor(() => expect(callback).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('still switches through the filename/path button', () => {
    const { container } = showSwitcher();
    fireEvent.click(screen.getByText('/remote/same.kdbx').closest('button'));
    expect(callbacks.onSwitch).toHaveBeenCalledWith('remote');
    expect(callbacks.onClose).toHaveBeenCalledOnce();
    expect(container.querySelector('button button')).toBeNull();
  });

  it('uses icons and tooltips rather than visible action labels', () => {
    showSwitcher();
    for (const name of ['Save database /local/same.kdbx', 'Remove database /local/same.kdbx']) {
      const button = screen.getByRole('button', { name });
      expect(button).toHaveTextContent('');
      expect(button.textContent).toBe('');
      expect(button.querySelector('svg')).not.toBeNull();
      expect(button).toHaveAttribute('title');
    }
  });
});
