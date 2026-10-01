/**
 * PrfVault MV3 Popup UI 엔트리포인트
 *
 * [보안 아키텍처 및 신뢰 경계]
 * - Extension Page(Popup)는 사용자의 물리적 인터랙션(User Gesture) 하에서 동작합니다.
 * - Windows Hello CNG / TPM 기반 Chrome Native Messaging Host와의 실시간 통신 상태(Liveness) 모니터링
 *   및 하드웨어 PRF 대칭키 도출 테스트 인터페이스를 제공합니다.
 */

import { pingNativeHost, derivePrfViaHost, NativeMessagingError } from '../background/native-ipc';

/**
 * 네이티브 호스트 생존 여부(Liveness)를 조회하고 UI 배지를 갱신한다.
 */
export async function checkNativeHostLiveness(): Promise<boolean> {
  const badge = document.getElementById('native-host-badge');
  const btnPing = document.getElementById('btn-native-ping') as HTMLButtonElement | null;

  if (badge) {
    badge.className = 'badge badge-pending';
    badge.textContent = '확인 중...';
  }
  if (btnPing) {
    btnPing.disabled = true;
  }

  try {
    // 1차: 백그라운드 Service Worker IPC 경유 시도
    let isAlive = false;
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      try {
        const response = await chrome.runtime.sendMessage({
          id: crypto.randomUUID(),
          action: 'EP_NATIVE_PING',
          payload: {},
          timestamp: Date.now(),
        });
        if (response && response.pong === true) {
          isAlive = true;
        }
      } catch {
        // Service Worker 응답 실패 시 직접 Native Messaging 호출 폴백
      }
    }

    if (!isAlive) {
      const res = await pingNativeHost();
      isAlive = res.pong === true;
    }

    if (badge) {
      badge.className = 'badge badge-ok';
      badge.textContent = 'Connected (Active)';
    }
    return true;
  } catch (err) {
    if (badge) {
      badge.className = 'badge badge-error';
      const msg = err instanceof NativeMessagingError ? err.code : 'Disconnected';
      badge.textContent = `Disconnected (${msg})`;
    }
    return false;
  } finally {
    if (btnPing) {
      btnPing.disabled = false;
    }
  }
}

/**
 * 사용자 입력 도메인과 챌린지를 기반으로 Windows Hello CNG 하드웨어 PRF 키 도출을 요청한다.
 */
export async function triggerHardwarePrfDerivation(): Promise<void> {
  const domainInput = document.getElementById('input-prf-domain') as HTMLInputElement | null;
  const challengeInput = document.getElementById('input-prf-challenge') as HTMLInputElement | null;
  const resultBox = document.getElementById('prf-result-box');
  const btnDerive = document.getElementById('btn-prf-derive') as HTMLButtonElement | null;

  const domain = domainInput ? domainInput.value.trim() : '';
  const challenge = challengeInput ? challengeInput.value.trim() : '';

  if (!domain) {
    if (resultBox) resultBox.textContent = '[오류] 도메인을 입력하십시오.';
    return;
  }

  if (btnDerive) {
    btnDerive.disabled = true;
    btnDerive.textContent = '도출 진행 중 (Windows Hello 대기)...';
  }
  if (resultBox) {
    resultBox.textContent = `[요청 전송]\n도메인: ${domain}\n인증 대기 중...`;
  }

  try {
    let result: { domain: string; challenge?: string; derived: boolean; key?: string };

    // 1차: 백그라운드 Service Worker IPC 경유 시도
    let handledBySw = false;
    let swResponse: any = null;

    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      try {
        swResponse = await chrome.runtime.sendMessage({
          id: crypto.randomUUID(),
          action: 'EP_NATIVE_PRF_DERIVE',
          payload: {
            domain,
            challenge,
          },
          timestamp: Date.now(),
        });
        handledBySw = swResponse && swResponse.derived !== undefined;
      } catch {
        // Service Worker 실패 시 폴백
      }
    }

    if (handledBySw) {
      result = swResponse;
    } else {
      result = await derivePrfViaHost(domain, challenge);
    }

    if (resultBox) {
      const keySummary = result.key ? `${result.key.slice(0, 16)}...${result.key.slice(-16)} (32 Bytes)` : '성공 (키 반환됨)';
      resultBox.textContent = `[도출 성공]\n상태: derived=true\n도메인: ${result.domain}\nPRF 대칭키: ${keySummary}`;
    }
  } catch (err: any) {
    if (resultBox) {
      const code = err instanceof NativeMessagingError ? err.code : (err.code || 'UNKNOWN_ERROR');
      const message = err.message || String(err);
      resultBox.textContent = `[도출 실패]\n에러 코드: ${code}\n상세 메시지: ${message}`;
    }
  } finally {
    if (btnDerive) {
      btnDerive.disabled = false;
      btnDerive.textContent = '하드웨어 PRF 키 도출';
    }
  }
}

/**
 * 현재 브라우저 활성 탭의 도메인을 조회하여 도메인 입력 필드를 자동 설정한다.
 */
async function autoDetectActiveTabDomain(): Promise<void> {
  const domainInput = document.getElementById('input-prf-domain') as HTMLInputElement | null;
  if (!domainInput) return;

  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url) {
        const url = new URL(tab.url);
        if (url.hostname && !url.hostname.startsWith('chrome') && !url.hostname.startsWith('about')) {
          domainInput.value = url.hostname;
        }
      }
    } catch {
      // 탭 접근 불가 시 기본값 유지
    }
  }
}

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    // 1. 활성 탭 도메인 감지
    autoDetectActiveTabDomain();

    // 2. 초기 Liveness 체크
    checkNativeHostLiveness();

    // 3. 버튼 이벤트 리스너 바인딩
    const btnPing = document.getElementById('btn-native-ping');
    if (btnPing) {
      btnPing.addEventListener('click', () => {
        checkNativeHostLiveness();
      });
    }

    const btnDerive = document.getElementById('btn-prf-derive');
    if (btnDerive) {
      btnDerive.addEventListener('click', () => {
        triggerHardwarePrfDerivation();
      });
    }
  });
}
