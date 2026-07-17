// PROOF #1 — the app ships the *exact* Claude design, not a reimplementation.
//
// For each design module, strip the ESM wrapper we added (prepended imports +
// the Object.assign(window,…) → export swap) and assert what remains is
// byte-for-byte identical to the reference file pulled from the Claude Design
// project into design/. Also assert the app stylesheet is the verbatim <style>
// block from design/Trove.html. If anyone edits the design's component bodies
// or CSS, this fails.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ref = (p) => readFileSync(join(root, 'design', p), 'utf8');
const app = (p) => readFileSync(join(root, 'src/design', p), 'utf8');

// Reduce an app module to just the design's own code: drop leading `import …`
// lines we prepended, and rewrite our `export { … }` back to the design's
// original `Object.assign(window, { … })` trailer.
function stripWrapper(src, exportedNames) {
  let s = src;
  // Remove every leading import line (the wrapper we added).
  s = s.replace(/^(?:import[^\n]*\n)+/, '');
  // Rewrite our export back to the original global assignment.
  s = s.replace(
    new RegExp(`export \\{ ${exportedNames.map((n) => n).join(', ')} \\};\\s*$`),
    `Object.assign(window, { ${exportedNames.join(', ')} });\n`,
  );
  return s;
}

const MODULES = {
  'icons.jsx': ['Icon', 'TYPE_ICON'],
  'data.jsx': ['buildEntries', 'buildTree', 'makeVault', 'INITIAL_VAULTS', 'OPENABLE_VAULTS'],
  'views.jsx': ['relTime', 'fullDate', 'strengthInfo', 'Sidebar', 'EntryList', 'Detail'],
  'overlays.jsx': [
    'Unlock', 'CommandPalette', 'EntryForm', 'ConfirmDelete', 'HelpModal',
    'ClipboardToast', 'PlainToast', 'genPassword', 'ThemeMenu', 'THEMES',
    'VaultSwitcher', 'OpenVaultModal',
  ],
};

describe('design source parity', () => {
  for (const [file, names] of Object.entries(MODULES)) {
    it(`${file} is the design's code verbatim (only the ESM wrapper differs)`, () => {
      expect(stripWrapper(app(file), names)).toBe(ref(file));
    });
  }

  it('app.jsx is the design app verbatim (imports + default-export swap only)', () => {
    let s = app('app.jsx').replace(/^(?:import[^\n]*\n)+/, '');
    s = s.replace(
      /export default App;\s*$/,
      'ReactDOM.createRoot(document.getElementById("root")).render(<App />);\n',
    );
    expect(s).toBe(ref('app.jsx'));
  });

  it('design.css contains the verbatim <style> block from Trove.html', () => {
    const style = ref('Trove.html').match(/<style>([\s\S]*?)<\/style>/)[1].trim();
    // The app stylesheet is that block plus a documented desktop-fill override.
    expect(app('design.css')).toContain(style);
    expect(app('design.css')).toContain('desktop-app overrides');
  });
});

describe('design tokens are intact (the identity of the look)', () => {
  const css = app('design.css');
  it('dark theme + brass accent hue', () => {
    expect(css).toContain('[data-accent="brass"]    { --ah: 85; }');
    expect(css).toContain('--accent: oklch(0.80 0.11 var(--ah));');
  });
  it('IBM Plex type system', () => {
    expect(css).toContain('"IBM Plex Sans"');
    expect(css).toContain('"IBM Plex Mono"');
  });
  it('the three-pane grid and window chrome exist', () => {
    expect(css).toMatch(/\.body\s*\{[^}]*grid-template-columns:\s*230px/);
    expect(css).toContain('.titlebar');
    expect(css).toContain('.status-pill');
  });
});
