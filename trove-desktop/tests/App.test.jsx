// PROOF #2 — the design actually mounts, with its real chrome, theme, and
// three-pane structure (not a stand-in). Asserts the specific class hooks and
// tokens from the Claude design are present in the live DOM.

import { describe, it, expect, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import App from '../src/design/app.jsx';

function mount() {
  return render(<App />).container;
}

describe('design renders with its real identity', () => {
  beforeEach(() => {
    document.documentElement.removeAttribute('data-theme');
    document.documentElement.removeAttribute('data-accent');
    try {
      localStorage.clear();
    } catch {
      /* happy-dom always has it */
    }
  });

  it('applies the dark theme + brass accent to <html>', () => {
    mount();
    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(document.documentElement.dataset.accent).toBe('brass');
  });

  it('renders the windowed chrome: titlebar with three traffic lights + toolbar', () => {
    const c = mount();
    expect(c.querySelector('.window')).toBeTruthy();
    expect(c.querySelector('.titlebar')).toBeTruthy();
    expect(c.querySelectorAll('.titlebar .traffic .tl')).toHaveLength(3);
    expect(c.querySelector('.toolbar .status-pill')).toBeTruthy();
    expect(c.querySelector('.toolbar .search input')).toBeTruthy();
  });

  it('renders the three-pane body: sidebar · list · detail', () => {
    const c = mount();
    expect(c.querySelector('.body .pane.sidebar')).toBeTruthy();
    expect(c.querySelector('.body .pane.list')).toBeTruthy();
    expect(c.querySelector('.body .pane.detail')).toBeTruthy();
    expect(c.textContent).toContain('All entries');
    expect(c.querySelectorAll('.list .erow').length).toBeGreaterThan(0);
  });

  it('the detail pane masks the password behind a reveal control + strength meter', () => {
    const c = mount();
    const secret = c.querySelector('.detail .field .fv.secret');
    expect(secret).toBeTruthy();
    expect(secret.textContent).toMatch(/^•+$/);
    expect(c.querySelector('.detail .strength-bar')).toBeTruthy();
  });
});
