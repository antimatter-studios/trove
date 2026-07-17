// Vault session state. Holds only the lock flag, the non-secret entry list,
// selection/filter UI state, and transient status. Secrets are never cached
// here — `reveal` fetches a single field from the Rust side on demand and the
// caller is responsible for not persisting it.

import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';

export const useVault = create((set, get) => ({
  locked: true,
  vaultPath: null,
  entries: [],
  selectedId: null,
  group: '__all',
  query: '',
  error: null,
  busy: false,

  async unlock(path, password) {
    set({ busy: true, error: null });
    try {
      const entries = await invoke('open_vault', { path, password });
      set({
        locked: false,
        vaultPath: path,
        entries,
        selectedId: entries[0]?.id ?? null,
        busy: false,
      });
    } catch (e) {
      set({ error: String(e), busy: false });
    }
  },

  async lock() {
    try {
      await invoke('lock_vault');
    } catch {
      // Best-effort from the UI's perspective; clear state regardless.
    }
    set({
      locked: true,
      vaultPath: null,
      entries: [],
      selectedId: null,
      group: '__all',
      query: '',
      error: null,
    });
  },

  select(id) {
    set({ selectedId: id });
  },
  setGroup(group) {
    set({ group });
  },
  setQuery(query) {
    set({ query });
  },

  // Fetch one protected/plain field for an entry. Returns the value (or null).
  // Never written into the store — the component holds it transiently.
  async reveal(id, field) {
    return invoke('get_field', { id, field });
  },

  // The currently-selected entry summary, or null.
  selected() {
    const { entries, selectedId } = get();
    return entries.find((e) => e.id === selectedId) ?? null;
  },
}));
