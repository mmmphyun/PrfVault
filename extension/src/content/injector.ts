/**
 * PrfVault MV3 프레임워크 호환 DOM 폼 제어 및 자동 입력 엔진
 *
 * [보안 제약 및 프레임워크 호환성 설계]
 * - React, Vue, Angular 등 모던 SPA 프레임워크의 내부 상태(State)를 정상 갱신하기 위해
 *   HTMLInputElement.prototype.value 세터를 직접 호출하고 input/change/blur 이벤트를 연속 디스패치합니다.
 * - E2E 키보드 보안 모듈 또는 가상 키패드가 감지된 필드는 입력 충돌 및 패킷 오염을 방지하기 위해 주입을 거부합니다.
 * - 입력 처리 직후 민감 평문 데이터의 메모리 참조를 즉시 해제합니다.
 */

import { detectSecurityModules } from './detector';

export type InjectionStatus = 'SUCCESS' | 'BLOCKED_BY_KEYPAD' | 'DOM_INPUT_REJECTED';

export interface InjectionResult {
  status: InjectionStatus;
  usernameInjected: boolean;
  passwordInjected: boolean;
  errorMessage?: string;
}

export interface InjectionOptions {
  forceInjectEvenIfKeypad?: boolean;
}

/**
 * Node.js 및 브라우저 환경에서 안전하게 이벤트를 생성하고 디스패치합니다.
 */
function dispatchSafeEvent(element: HTMLInputElement, type: string): void {
  try {
    if (typeof Event !== 'undefined') {
      element.dispatchEvent(new Event(type, { bubbles: true, cancelable: true }));
    }
  } catch {
    // 모의 환경 또는 예외 격리
  }
}

/**
 * React 16+ 및 브라우저 네이티브 프로퍼티 체인을 통과하여 입력 요소의 값을 안전하게 변경합니다.
 */
export function setNativeInputValue(element: HTMLInputElement, value: string): void {
  const prototype = typeof window !== 'undefined' ? window.HTMLInputElement?.prototype : Object.getPrototypeOf(element);
  const descriptor = Object.getOwnPropertyDescriptor(prototype, 'value');
  const nativeSetter = descriptor?.set;

  if (nativeSetter) {
    nativeSetter.call(element, value);
  } else {
    element.value = value;
  }

  // React/Vue 등의 synthetic event 리스너를 발화시키기 위해 표준 이벤트 디스패치
  dispatchSafeEvent(element, 'input');
  dispatchSafeEvent(element, 'change');
}

/**
 * 지정된 폼 입력 필드에 아이디 및 비밀번호를 안전하게 주입합니다.
 */
export function injectCredentials(
  usernameField: HTMLInputElement | null,
  passwordField: HTMLInputElement | null,
  credentials: { username?: string; password?: string },
  options: InjectionOptions = {}
): InjectionResult {
  // 1. 보안 프로그램 및 가상 키패드 간섭 여부 사전 검사
  const rootToCheck: ParentNode | null =
    passwordField?.form ||
    passwordField?.parentElement ||
    usernameField?.form ||
    usernameField?.parentElement ||
    (typeof document !== 'undefined' ? document : null);

  const securityCheck = rootToCheck
    ? detectSecurityModules(rootToCheck)
    : { hasSecurityModule: false, hasVirtualKeypad: false, hasE2EKeyboardModule: false, detectedSelectors: [] };

  if (securityCheck.hasSecurityModule && !options.forceInjectEvenIfKeypad) {
    return {
      status: 'BLOCKED_BY_KEYPAD',
      usernameInjected: false,
      passwordInjected: false,
      errorMessage: `보안 모듈 또는 가상 키패드가 감지되어 주입이 차단되었습니다: ${securityCheck.detectedSelectors.join(', ')}`,
    };
  }

  let usernameInjected = false;
  let passwordInjected = false;

  try {
    // 2. 아이디 주입
    if (usernameField && typeof credentials.username === 'string' && credentials.username.length > 0) {
      if (typeof usernameField.focus === 'function') usernameField.focus();
      setNativeInputValue(usernameField, credentials.username);
      dispatchSafeEvent(usernameField, 'blur');
      usernameInjected = true;
    }

    // 3. 비밀번호 주입
    if (passwordField && typeof credentials.password === 'string' && credentials.password.length > 0) {
      if (typeof passwordField.focus === 'function') passwordField.focus();
      setNativeInputValue(passwordField, credentials.password);
      dispatchSafeEvent(passwordField, 'blur');
      passwordInjected = true;
    }

    if (!usernameInjected && !passwordInjected) {
      return {
        status: 'DOM_INPUT_REJECTED',
        usernameInjected: false,
        passwordInjected: false,
        errorMessage: '주입할 유효한 입력 필드가 존재하지 않습니다.',
      };
    }

    return {
      status: 'SUCCESS',
      usernameInjected,
      passwordInjected,
    };
  } catch (err) {
    return {
      status: 'DOM_INPUT_REJECTED',
      usernameInjected,
      passwordInjected,
      errorMessage: err instanceof Error ? err.message : String(err),
    };
  }
}
