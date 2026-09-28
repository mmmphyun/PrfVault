import { describe, it, expect } from 'vitest';
import {
  detectForms,
  detectSecurityModules,
  isElementVisible,
  SECURITY_MODULE_SELECTORS,
} from '../src/content/detector';

/**
 * Node.js 환경에서 DOM 트리를 흉내 내기 위한 경량 Mock Node 헬퍼
 */
class MockElement {
  public tagName: string;
  public id: string = '';
  public name: string = '';
  public type: string = 'text';
  public placeholder: string = '';
  public value: string = '';
  public attributes: Record<string, string> = {};
  public style: Record<string, string> = {};
  public children: MockElement[] = [];
  public parentElement: MockElement | null = null;
  public offsetParent: MockElement | null = null;

  constructor(tagName: string) {
    this.tagName = tagName.toUpperCase();
  }

  getAttribute(name: string): string | null {
    return this.attributes[name.toLowerCase()] ?? null;
  }

  setAttribute(name: string, value: string): void {
    this.attributes[name.toLowerCase()] = value;
    if (name.toLowerCase() === 'id') this.id = value;
    if (name.toLowerCase() === 'name') this.name = value;
    if (name.toLowerCase() === 'type') this.type = value;
    if (name.toLowerCase() === 'placeholder') this.placeholder = value;
  }

  appendChild(child: MockElement): MockElement {
    child.parentElement = this;
    this.children.push(child);
    return child;
  }

  closest(selector: string): MockElement | null {
    const targetTag = selector.toUpperCase();
    let current: MockElement | null = this;
    while (current) {
      if (current.tagName === targetTag) return current;
      current = current.parentElement;
    }
    return null;
  }

  querySelectorAll(selector: string): MockElement[] {
    const results: MockElement[] = [];

    const matches = (el: MockElement): boolean => {
      // 1. Tag match (e.g. "input", "form")
      if (selector === 'input') return el.tagName === 'INPUT';
      if (selector === 'form') return el.tagName === 'FORM';

      // 2. ID match (e.g. "#TouchEnKey_tk_input", "div#AnySign4PC")
      if (selector.startsWith('#') && el.id === selector.slice(1)) return true;
      if (selector.startsWith('div#') && el.tagName === 'DIV' && el.id === selector.slice(4)) return true;

      // 3. Attribute existence (e.g. "input[tk_type]", "input[astx]", "input[npk]")
      const attrExistMatch = selector.match(/^(\w+)?\[([\w-]+)\]$/);
      if (attrExistMatch) {
        const [, tag, attr] = attrExistMatch;
        if (tag && el.tagName !== tag.toUpperCase()) return false;
        return el.getAttribute(attr) !== null;
      }

      // 4. Attribute exact/partial match (e.g. input[data-enc="on"], img[src*="keypad" i], div[class*="keypad" i])
      const attrValMatch = selector.match(/^(\w+)?\[([\w-]+)([\*\^~]?=)"([^"]+)"(?:\s*i)?\]$/);
      if (attrValMatch) {
        const [, tag, attr, op, val] = attrValMatch;
        if (tag && el.tagName !== tag.toUpperCase()) return false;
        const attrVal = el.getAttribute(attr);
        if (attrVal === null) return false;
        if (op === '=') return attrVal === val;
        if (op === '*=') return attrVal.toLowerCase().includes(val.toLowerCase());
      }

      return false;
    };

    const traverse = (node: MockElement) => {
      for (const child of node.children) {
        if (matches(child)) {
          results.push(child);
        }
        traverse(child);
      }
    };

    traverse(this);
    return results;
  }

  querySelector(selector: string): MockElement | null {
    const list = this.querySelectorAll(selector);
    return list.length > 0 ? list[0] : null;
  }
}

describe('Content Script DOM 탐지기 단위 테스트 (detector.ts)', () => {
  it('가시적 요소 판별 로직(isElementVisible)이 hidden 및 display:none 필드를 정확히 제외해야 한다', () => {
    const visibleInput = new MockElement('input');
    visibleInput.type = 'text';
    expect(isElementVisible(visibleInput as unknown as HTMLElement)).toBe(true);

    const hiddenTypeInput = new MockElement('input');
    hiddenTypeInput.type = 'hidden';
    expect(isElementVisible(hiddenTypeInput as unknown as HTMLElement)).toBe(false);

    const displayNoneInput = new MockElement('input');
    displayNoneInput.style.display = 'none';
    expect(isElementVisible(displayNoneInput as unknown as HTMLElement)).toBe(false);

    const ariaHiddenInput = new MockElement('input');
    ariaHiddenInput.setAttribute('aria-hidden', 'true');
    expect(isElementVisible(ariaHiddenInput as unknown as HTMLElement)).toBe(false);
  });

  it('일반 로그인 폼에서 사용자명 필드와 비밀번호 필드를 정확히 탐지해야 한다', () => {
    const root = new MockElement('div');
    const form = new MockElement('form');
    root.appendChild(form);

    const usernameInput = new MockElement('input');
    usernameInput.type = 'text';
    usernameInput.name = 'user_id';
    usernameInput.setAttribute('autocomplete', 'username');
    form.appendChild(usernameInput);

    const passwordInput = new MockElement('input');
    passwordInput.type = 'password';
    passwordInput.name = 'password';
    form.appendChild(passwordInput);

    const result = detectForms(root as unknown as Document);

    expect(result.forms.length).toBe(1);
    const detected = result.forms[0];
    expect(detected.isRegistration).toBe(false);
    expect(detected.usernameField).toBe(usernameInput);
    expect(detected.passwordFields.length).toBe(1);
    expect(detected.passwordFields[0]).toBe(passwordInput);
    expect(result.hasSecurityModule).toBe(false);
  });

  it('회원가입 폼(비밀번호 2개 필드 존재 시)을 정확히 isRegistration=true로 식별해야 한다', () => {
    const root = new MockElement('div');
    const form = new MockElement('form');
    root.appendChild(form);

    const emailInput = new MockElement('input');
    emailInput.type = 'email';
    emailInput.id = 'member_email';
    form.appendChild(emailInput);

    const newPwInput = new MockElement('input');
    newPwInput.type = 'password';
    newPwInput.setAttribute('autocomplete', 'new-password');
    form.appendChild(newPwInput);

    const confirmPwInput = new MockElement('input');
    confirmPwInput.type = 'password';
    form.appendChild(confirmPwInput);

    const result = detectForms(root as unknown as Document);

    expect(result.forms.length).toBe(1);
    const detected = result.forms[0];
    expect(detected.isRegistration).toBe(true);
    expect(detected.usernameField).toBe(emailInput);
    expect(detected.passwordFields.length).toBe(2);
  });

  it('TouchEn Key 보안 모듈 시그니처가 존재할 때 이를 정확히 감지해야 한다', () => {
    const root = new MockElement('div');
    const securityInput = new MockElement('input');
    securityInput.setAttribute('data-enc', 'on');
    root.appendChild(securityInput);

    const result = detectSecurityModules(root as unknown as ParentNode);
    expect(result.hasSecurityModule).toBe(true);
    expect(result.hasE2EKeyboardModule).toBe(true);
    expect(result.detectedSelectors).toContain('input[data-enc="on"]');
  });

  it('가상 키패드 시그니처(Transkey, mTk 등)가 존재할 때 이를 감지해야 한다', () => {
    const root = new MockElement('div');
    const keypadDiv = new MockElement('div');
    keypadDiv.setAttribute('class', 'transkey_div_keypad');
    root.appendChild(keypadDiv);

    const result = detectSecurityModules(root as unknown as ParentNode);
    expect(result.hasSecurityModule).toBe(true);
    expect(result.hasVirtualKeypad).toBe(true);
    expect(result.detectedSelectors).toContain('div[class*="transkey" i]');
  });
});
