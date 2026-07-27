// Trove — the ONE module that talks to the Tauri backend.
// Every other frontend module imports from here; this is what vitest mocks.
// One thin async wrapper per Tauri command in the contract. Argument keys are
// camelCase exactly as the backend's serialized (serde rename_all = camelCase)
// names — Tauri maps them onto the snake_case Rust parameters.
import { invoke } from '@tauri-apps/api/core';

// The design's views read `e.type` (icon lookup). The backend DTO carries
// `entryType`. Normalise here so every consumer keeps reading `e.type` while the
// raw `entryType` stays available too. No secrets live on the list DTO.
function normEntry(e) {
  return { ...e, type: e.entryType };
}
function normEntries(list) {
  return (list || []).map(normEntry);
}

/* ---- Vault lifecycle ---- */

// list_vaults() -> Vec<VaultDto>  { id, name, file, path, locked }
export function listVaults() {
  return invoke('list_vaults');
}

// register_vault(path) -> VaultDto  (adds an existing .kdbx as locked; idempotent)
export function registerVault(path) {
  return invoke('register_vault', { path });
}

// create_vault(path, password) -> VaultDto  (new .kdbx, registered unlocked)
export function createVault(path, password) {
  return invoke('create_vault', { path, password });
}

// unlock_vault(id, password) -> Vec<EntryDto>  (wrong password rejects)
export function unlockVault(id, password) {
  return invoke('unlock_vault', { id, password }).then(normEntries);
}

// lock_vault(id) -> ()
export function lockVault(id) {
  return invoke('lock_vault', { id });
}

// list_entries(id) -> Vec<EntryDto>  (re-read an already-unlocked vault)
export function listEntries(id) {
  return invoke('list_entries', { id }).then(normEntries);
}

/* ---- Reading one entry (secrets, on demand) ---- */

// get_field(id, entryId, field) -> Option<String>
export function getField(id, entryId, field) {
  return invoke('get_field', { id, entryId, field });
}

// get_entry_detail(id, entryId) -> { notes, fields: [{k,v}], password }
export function getEntryDetail(id, entryId) {
  return invoke('get_entry_detail', { id, entryId });
}

/* ---- Mutations (backend saves, then returns the fresh list) ---- */

// save_entry(id, input) -> { entries: Vec<EntryDto>, id }
// input = { entryId, path, username, password, url, notes, entryType }
export function saveEntry(id, input) {
  return invoke('save_entry', { id, input }).then((res) => ({
    id: res.id,
    entries: normEntries(res.entries),
  }));
}

// delete_entry(id, entryId) -> Vec<EntryDto>  (moves to recycle bin)
export function deleteEntry(id, entryId) {
  return invoke('delete_entry', { id, entryId }).then(normEntries);
}

// set_favorite(id, entryId, fav) -> Vec<EntryDto>
export function setFavorite(id, entryId, fav) {
  return invoke('set_favorite', { id, entryId, fav }).then(normEntries);
}
