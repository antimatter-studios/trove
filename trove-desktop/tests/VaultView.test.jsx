// PROOF #3 — the design's interactions work: selecting an entry drives the
// detail pane, revealing unmasks the password, and the command palette opens.
// These are behaviors of the real Claude design, exercised in the live DOM.

import { describe, it, expect, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/react';
import App from '../src/design/app.jsx';

function mount() {
  return render(<App />).container;
}

describe('design interactions', () => {
  beforeEach(() => {
    try {
      localStorage.clear();
    } catch {
      /* ignore */
    }
  });

  it('selecting a different entry updates the detail title', () => {
    const c = mount();
    const rows = [...c.querySelectorAll('.list .erow')];
    expect(rows.length).toBeGreaterThan(1);
    const before = c.querySelector('.detail .dt-title')?.textContent;
    // Click a row whose title differs from the current selection.
    const other = rows.find(
      (r) => r.querySelector('.etitle-txt')?.textContent !== before,
    );
    fireEvent.click(other);
    const after = c.querySelector('.detail .dt-title')?.textContent;
    expect(after).toBeTruthy();
    expect(after).not.toBe(before);
  });

  it('revealing unmasks the password field', () => {
    const c = mount();
    const field = c.querySelector('.detail .field'); // first credential field w/ secret
    // Find the secret field specifically.
    const secretField = [...c.querySelectorAll('.detail .field')].find((f) =>
      f.querySelector('.fv.secret'),
    );
    expect(secretField).toBeTruthy();
    expect(secretField.querySelector('.fv.secret')).toBeTruthy();
    // The reveal control is the first .fact button in that field.
    const revealBtn = secretField.querySelector('.facts .fact');
    fireEvent.click(revealBtn);
    // After reveal, the value is no longer masked as a secret.
    expect(secretField.querySelector('.fv.secret')).toBeFalsy();
    expect(field).toBeTruthy();
  });

  it('the command palette opens from the toolbar', () => {
    const c = mount();
    // The command-palette button carries the ⌘K title.
    const palBtn = c.querySelector('button[title*="Command palette"]');
    expect(palBtn).toBeTruthy();
    fireEvent.click(palBtn);
    expect(document.querySelector('.palette')).toBeTruthy();
    expect(document.querySelector('.pal-input input')).toBeTruthy();
  });
});
