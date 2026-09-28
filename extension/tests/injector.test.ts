import { describe, it, expect, vi } from 'vitest';
import { injectCredentials, setNativeInputValue } from '../src/content/injector';

class MockInput {
  public tagName = 'INPUT';
  public type: string = 'text';
  public value: string = '';
  public form: any = null;
  public parentElement: any = null;
  public attributes: Record<string, string> = {};
  public eventListeners: Record<string, Function[]> = {};

  getAttribute(name: string): string | null {
    return this.attributes[name.toLowerCase()] ?? null;
  }

  setAttribute(name: string, value: string): void {
    this.attributes[name.toLowerCase()] = value;
  }

  addEventListener(type: string, listener: Function): void {
    if (!this.eventListeners[type]) {
      this.eventListeners[type] = [];
    }
    this.eventListeners[type].push(listener);
  }

  dispatchEvent(event: { type: string }): boolean {
    const listeners = this.eventListeners[event.type] || [];
    for (const listener of listeners) {
      listener(event);
    }
    return true;
  }

  focus(): void {}
}

class MockForm {
  public tagName = 'FORM';
  public children: any[] = [];
  public attributes: Record<string, string> = {};

  getAttribute(name: string): string | null {
    return this.attributes[name.toLowerCase()] ?? null;
  }

  setAttribute(name: string, value: string): void {
    this.attributes[name.toLowerCase()] = value;
  }

  querySelector(selector: string): any {
    for (const child of this.children) {
      if (selector === 'input[data-enc="on"]' && child.getAttribute('data-enc') === 'on') {
        return child;
      }
      if (selector.includes('transkey') && child.getAttribute('class')?.includes('transkey')) {
        return child;
      }
    }
    return null;
  }
}

describe('프레임워크 호환 폼 제어 및 자동 입력 엔진 단위 테스트 (injector.ts)', () => {
  it('setNativeInputValue는 input과 change 이벤트를 순차적으로 발화시켜야 한다', () => {
    const input = new MockInput();
    const eventLog: string[] = [];

    input.addEventListener('input', () => eventLog.push('input'));
    input.addEventListener('change', () => eventLog.push('change'));

    setNativeInputValue(input as unknown as HTMLInputElement, 'my_test_password');

    expect(input.value).toBe('my_test_password');
    expect(eventLog).toEqual(['input', 'change']);
  });

  it('일반 폼에 아이디와 비밀번호를 성공적으로 주입하고 SUCCESS 상태를 반환해야 한다', () => {
    const form = new MockForm();
    const userInput = new MockInput();
    userInput.type = 'text';
    userInput.form = form;
    form.children.push(userInput);

    const passInput = new MockInput();
    passInput.type = 'password';
    passInput.form = form;
    form.children.push(passInput);

    const result = injectCredentials(
      userInput as unknown as HTMLInputElement,
      passInput as unknown as HTMLInputElement,
      { username: 'testuser', password: 'secretPassword123!' }
    );

    expect(result.status).toBe('SUCCESS');
    expect(result.usernameInjected).toBe(true);
    expect(result.passwordInjected).toBe(true);
    expect(userInput.value).toBe('testuser');
    expect(passInput.value).toBe('secretPassword123!');
  });

  it('보안 프로그램(TouchEn Key) 시그니처가 폼 내에 존재하면 주입을 거부하고 BLOCKED_BY_KEYPAD를 반환해야 한다', () => {
    const form = new MockForm();
    const userInput = new MockInput();
    userInput.form = form;
    form.children.push(userInput);

    const passInput = new MockInput();
    passInput.type = 'password';
    passInput.setAttribute('data-enc', 'on');
    passInput.form = form;
    form.children.push(passInput);

    const result = injectCredentials(
      userInput as unknown as HTMLInputElement,
      passInput as unknown as HTMLInputElement,
      { username: 'testuser', password: 'secretPassword123!' }
    );

    expect(result.status).toBe('BLOCKED_BY_KEYPAD');
    expect(result.usernameInjected).toBe(false);
    expect(result.passwordInjected).toBe(false);
    expect(userInput.value).toBe('');
    expect(passInput.value).toBe('');
    expect(result.errorMessage).toContain('보안 모듈 또는 가상 키패드가 감지되어 주입이 차단되었습니다');
  });

  it('forceInjectEvenIfKeypad 옵션 사용 시 보안 모듈 감지 상태여도 강제 주입되어야 한다', () => {
    const form = new MockForm();
    const userInput = new MockInput();
    userInput.form = form;
    form.children.push(userInput);

    const passInput = new MockInput();
    passInput.type = 'password';
    passInput.setAttribute('data-enc', 'on');
    passInput.form = form;
    form.children.push(passInput);

    const result = injectCredentials(
      userInput as unknown as HTMLInputElement,
      passInput as unknown as HTMLInputElement,
      { username: 'testuser', password: 'secretPassword123!' },
      { forceInjectEvenIfKeypad: true }
    );

    expect(result.status).toBe('SUCCESS');
    expect(result.usernameInjected).toBe(true);
    expect(result.passwordInjected).toBe(true);
    expect(userInput.value).toBe('testuser');
    expect(passInput.value).toBe('secretPassword123!');
  });

  it('주입할 필드가 없거나 비어있는 경우 DOM_INPUT_REJECTED를 반환해야 한다', () => {
    const result = injectCredentials(null, null, { username: 'testuser' });
    expect(result.status).toBe('DOM_INPUT_REJECTED');
  });
});
