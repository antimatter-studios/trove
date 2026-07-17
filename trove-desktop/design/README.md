# Trove Desktop — UI design reference

Pulled from the "Trove Desktop" Claude Design project (claude.ai/design,
project `9a23cd98-1872-4d20-ab6c-d37ca308dfa7`). This is the approved visual
+ interaction reference for the real app; `Trove.html` opens standalone in a
browser (UMD React + babel-standalone + mock data in `data.jsx`).

Contents:

- `Trove.html` — tokens (OKLCH, dark/light, 5 accent themes), full stylesheet,
  standalone harness
- `icons.jsx` — 1.5px-stroke icon set + `TYPE_ICON` mapping
- `data.jsx` — mock vaults/entries, `buildTree` group-tree builder
- `views.jsx` — `Sidebar`, `EntryList`, `Detail` (three-pane layout)
- `overlays.jsx` — `Unlock`, `CommandPalette`, `EntryForm`, `ConfirmDelete`,
  `HelpModal`, toasts, `ThemeMenu`, `VaultSwitcher`, `OpenVaultModal`
- `app.jsx` — multi-vault app shell: keyboard map, clipboard auto-clear
  countdown, palette actions

Integration into `src/` replaces the mock layer (`data.jsx`,
`INITIAL_VAULTS`, the fake unlock timeout) with Tauri commands backed by
`trove-core`; the components and stylesheet port over as-is (Vite ESM
imports instead of `Object.assign(window, …)` globals, real `@fontsource`
packages instead of the Google Fonts CDN, pinned React instead of unpkg).
