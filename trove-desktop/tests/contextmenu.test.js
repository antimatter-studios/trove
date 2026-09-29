// Right click: the webview's page menu is suppressed except where the system
// menu is useful — text fields, and text that is selected.

import { describe, it, expect, afterEach } from 'vitest';
import { suppressContextMenu, wantsNativeMenu } from '../src/contextmenu.js';

const noSelection = { isCollapsed: true, toString: () => '' };

describe('context menu', () => {
  let stop;
  afterEach(() => { stop && stop(); document.body.innerHTML = ''; window.getSelection().removeAllRanges(); });

  it('keeps the menu in text fields only', () => {
    document.body.innerHTML = '<div class="erow"><span>mail</span></div><input /><textarea></textarea>';
    expect(wantsNativeMenu(document.querySelector('span'), noSelection)).toBe(false);
    expect(wantsNativeMenu(document.querySelector('input'), noSelection)).toBe(true);
    expect(wantsNativeMenu(document.querySelector('textarea'), noSelection)).toBe(true);
  });

  it('keeps the menu over selected text, so Copy is there', () => {
    const sel = { isCollapsed: false, toString: () => 'db.prod' };
    expect(wantsNativeMenu(document.body, sel)).toBe(true);
  });

  it('cancels the page menu everywhere else', () => {
    document.body.innerHTML = '<div class="tree-row">Work</div><input />';
    stop = suppressContextMenu();
    const fire = (el) => {
      const ev = new MouseEvent('contextmenu', { bubbles: true, cancelable: true });
      el.dispatchEvent(ev);
      return ev.defaultPrevented;
    };
    expect(fire(document.querySelector('.tree-row'))).toBe(true);
    expect(fire(document.querySelector('input'))).toBe(false);
  });
});
