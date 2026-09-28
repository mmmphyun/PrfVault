/**
 * PrfVault MV3 Content Script 엔트리포인트
 *
 * [보안 제약 및 격리 원칙]
 * - 웹페이지 DOM에 직접 접근하는 Isolated World 컨텍스트입니다.
 * - 볼트 스토리지 및 Wasm 메모리에 직접 접근할 수 없으며, 모든 처리는 Service Worker와의 IPC로만 수행합니다.
 * - E2E 키보드 보안 모듈 또는 가상 키패드 탐지 시 사전 리포트하고, 사용자 동의 없는 위험 주입을 차단합니다.
 */

import { detectForms, detectSecurityModules } from './detector';
import { injectCredentials } from './injector';
import type { IpcResponse } from '../ipc/messages';

/**
 * 범용 UUID v4 생성기 (Web Crypto API 기반)
 */
function generateUuid(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * 백그라운드 Service Worker로 보안 모듈 감지 리포트를 발송합니다.
 */
export async function reportSecurityModuleStatus(): Promise<void> {
  if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
    return;
  }

  try {
    const security = detectSecurityModules(document);
    if (!security.hasSecurityModule) {
      return;
    }

    const payload = {
      domain: window.location.hostname,
      hasVirtualKeypad: security.hasVirtualKeypad,
      hasE2EKeyboardModule: security.hasE2EKeyboardModule,
      detectedSelectors: security.detectedSelectors.slice(0, 32),
    };

    await chrome.runtime.sendMessage({
      id: generateUuid(),
      action: 'CS_DETECT_SECURITY_MODULE',
      payload,
      timestamp: Date.now(),
    });
  } catch (err) {
    console.debug('[PrfVault] 보안 모듈 리포트 전송 생략:', err);
  }
}

/**
 * 수신된 자격증명으로 첫 번째 감지된 로그인 폼을 채우고 결과를 백그라운드로 보고합니다.
 */
export async function handleAutoFillRequest(credentials: {
  accountId: string;
  username: string;
  password?: string;
  forceInjectEvenIfKeypad?: boolean;
}): Promise<IpcResponse> {
  const detection = detectForms(document);

  if (detection.forms.length === 0) {
    return {
      id: generateUuid(),
      success: false,
      error: {
        code: 'NO_CREDENTIALS_FOUND',
        message: '자동 입력 가능한 로그인 폼이 페이지 내에 존재하지 않습니다.',
      },
    };
  }

  const targetForm = detection.forms[0];
  const startTime = Date.now();

  const injectionResult = injectCredentials(
    targetForm.usernameField,
    targetForm.passwordFields[0] ?? null,
    { username: credentials.username, password: credentials.password },
    { forceInjectEvenIfKeypad: credentials.forceInjectEvenIfKeypad }
  );

  const durationMs = Date.now() - startTime;

  // 백그라운드에 주입 결과 리포트
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    try {
      await chrome.runtime.sendMessage({
        id: generateUuid(),
        action: 'CS_REPORT_INJECTION_RESULT',
        payload: {
          domain: window.location.hostname,
          accountId: credentials.accountId,
          status: injectionResult.status,
          interKeystrokeMs: durationMs,
        },
        timestamp: Date.now(),
      });
    } catch (err) {
      console.debug('[PrfVault] 주입 결과 리포트 실패:', err);
    }
  }

  if (injectionResult.status !== 'SUCCESS') {
    return {
      id: generateUuid(),
      success: false,
      error: {
        code: injectionResult.status === 'BLOCKED_BY_KEYPAD' ? 'SECURITY_MODULE_BLOCKED' : 'DOM_INPUT_REJECTED',
        message: injectionResult.errorMessage || '자동 입력에 실패했습니다.',
      },
    };
  }

  return {
    id: generateUuid(),
    success: true,
    data: {
      usernameInjected: injectionResult.usernameInjected,
      passwordInjected: injectionResult.passwordInjected,
    },
  };
}

/**
 * Content Script 진입 시 초기화 및 리스너 등록
 */
export function initializeContentScript(): void {
  // DOM 로드 후 보안 모듈 시그니처 정찰
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      reportSecurityModuleStatus();
    });
  } else {
    reportSecurityModuleStatus();
  }

  // 백그라운드 및 팝업 메시지 수신
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (message && message.action === 'TRIGGER_FORM_AUTOFILL') {
        handleAutoFillRequest(message.payload).then(sendResponse);
        return true; // 비동기 응답 대기
      }

      if (message && message.action === 'SCAN_PAGE_DOM') {
        const detection = detectForms(document);
        sendResponse({
          formsCount: detection.forms.length,
          hasSecurityModule: detection.hasSecurityModule,
          hasVirtualKeypad: detection.hasVirtualKeypad,
          hasE2EKeyboardModule: detection.hasE2EKeyboardModule,
          detectedSelectors: detection.detectedSelectors,
        });
        return false;
      }
    });
  }
}

// 브라우저 런타임 자동 초기화
if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  initializeContentScript();
}
