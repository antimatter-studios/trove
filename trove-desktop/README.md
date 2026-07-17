# trove-desktop

A desktop vault manager — the GUI front-end for [`trove-core`](https://github.com/antimatter-studios/trove).

Built with Tauri 2 (Rust backend) and React + Vite (frontend). The Rust side links
`trove-core` directly and exposes a small command surface; the unlocked vault lives
in backend memory and the UI only ever sees non-secret entry summaries until it asks
for a specific field.

## Status

Early scaffold. Working vertical slice: open a `.kdbx` vault with a master password
and browse its entries. Creating entries, editing fields, and copy-to-clipboard are
not built yet.

## Install

macOS (via Homebrew) — installs the app **and** the `trove`/`troved` runtime it
depends on:

```sh
brew install --cask antimatter-studios/tap/trove-desktop
```

Linux and Windows: download the `.deb` / `.AppImage` (Linux) or `.exe` (Windows)
from [Releases](https://github.com/antimatter-studios/trove/releases).
Homebrew casks are macOS-only, so there is no `brew` path on those platforms.

## Develop

```sh
npm install
npm run tauri dev      # run the desktop app
npm test               # frontend unit tests (Vitest)
npm run test:rust      # backend tests (cargo)
```

`trove-core` is linked directly from the workspace
(`trove-core = { path = "../../crates/trove-core" }`), so a change to the core
crate is picked up immediately — no crates.io publish or version bump needed while
co-developing. The crate is still published to crates.io for external consumers.

## License

MIT — see [LICENSE](LICENSE).
