/**
 * PrfVault MV3 Popup UI 엔트리포인트
 *
 * [보안 아키텍처 및 신뢰 경계]
 * - Extension Page(Popup)는 사용자의 물리적 인터랙션(User Gesture) 하에서 동작합니다.
 * - Windows Hello CNG / TPM 기반 Chrome Native Messaging Host와의 실시간 통신 상태(Liveness) 모니터링
 *   및 하드웨어 PRF 대칭키 도출 테스트 인터페이스를 제공합니다.
 */

import { pingNativeHost, derivePrfViaHost, NativeMessagingError } from '../background/native-ipc';
import { deriveMasterKeyWithFallback } from '../auth/webauthn-prf';
import { loadEncryptedVault, saveEncryptedVault } from '../storage/vault-store';
import { parseWireFormat, buildAad } from '../vault/wire-format';
import { deserializeVault, serializeVault, type VaultData } from '../vault/model';
import { getOrCreateCryptoCore, CryptoCore } from '../crypto/wasm-core';

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
 * 볼트 잠금 해제 파이프라인 (WebAuthn PRF 및 Windows Hello Native Host 하이브리드 폴백)
 */
export async function handleUnlockVault(customCore?: CryptoCore): Promise<boolean> {
  const domainInput = document.getElementById('input-vault-domain') as HTMLInputElement | null;
  const resultBox = document.getElementById('unlock-result-box');
  const btnUnlock = document.getElementById('btn-unlock-vault') as HTMLButtonElement | null;
  const vaultBadge = document.getElementById('vault-badge');
  const providerBadge = document.getElementById('unlock-provider-badge');

  const domain = (domainInput ? domainInput.value.trim() : '') || 'localhost';

  if (btnUnlock) {
    btnUnlock.disabled = true;
    btnUnlock.textContent = '잠금 해제 진행 중...';
  }
  if (resultBox) {
    resultBox.textContent = `[인증 요청] 도메인: ${domain}\n하드웨어/생체 인증 대기 중...`;
  }

  try {
    const core = await getOrCreateCryptoCore(customCore);

    // 1. 로컬 스토리지에서 암호화된 볼트 조회
    let stored = await loadEncryptedVault();

    // 저장된 볼트가 없는 경우 초기 샘플 볼트 생성
    if (!stored) {
      const initialSalt = crypto.getRandomValues(new Uint8Array(32));
      const { masterKey: initKey } = await deriveMasterKeyWithFallback(domain, initialSalt, undefined, core);

      const demoVault: VaultData = {
        version: 1,
        credentialId: 'initial-credential',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        entries: [
          {
            id: crypto.randomUUID(),
            domain,
            username: `admin@${domain}`,
            password: 'InitialSecurePassword123!',
            notes: '초기 생성된 볼트 계정',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          },
        ],
      };

      const extId = (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id)
        ? chrome.runtime.id
        : 'prfvault-default-extension-id';
      const aad = buildAad(extId);
      const encBlob = core.encryptVault(initKey, serializeVault(demoVault), aad);
      encBlob.set(initialSalt, 2);
      await saveEncryptedVault(encBlob, demoVault.credentialId);
      stored = await loadEncryptedVault();
    }

    if (!stored) {
      throw new Error('암호화된 볼트를 불러오거나 생성할 수 없습니다.');
    }

    // 2. 와이어 포맷에서 Salt 추출
    const parsed = parseWireFormat(stored.blob);
    const salt = parsed.salt;
    const credentialId = stored.metadata.credentialId;

    // 3. WebAuthn 1차 시도 및 Native Host 2차 자동 폴백을 통한 마스터키 도출
    const { masterKey, provider } = await deriveMasterKeyWithFallback(
      domain,
      salt,
      credentialId,
      core
    );

    // 4. AES-256-GCM 복호화
    const extId = (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id)
      ? chrome.runtime.id
      : 'prfvault-default-extension-id';
    const aad = buildAad(extId);

    let decryptedPt: Uint8Array;
    try {
      decryptedPt = core.decryptVault(masterKey, stored.blob, aad);
    } catch {
      decryptedPt = core.decryptVault(masterKey, stored.blob);
    }

    // 5. 볼트 데이터 역직렬화
    const vaultData = deserializeVault(decryptedPt);

    // 6. 백그라운드 Service Worker 세션 등록 (EP_UNLOCK_VAULT)
    const accountsSummary = vaultData.entries.map((e) => ({
      id: e.id,
      domain: e.domain,
      username: e.username,
    }));

    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      try {
        await chrome.runtime.sendMessage({
          id: crypto.randomUUID(),
          action: 'EP_UNLOCK_VAULT',
          payload: {
            decryptedAccountsSummary: accountsSummary,
          },
          timestamp: Date.now(),
        });
      } catch (swErr) {
        console.warn('Service Worker 세션 등록 경고:', swErr);
      }
    }

    // 7. UI 상태 및 배지 갱신
    if (vaultBadge) {
      vaultBadge.className = 'badge badge-ok';
      vaultBadge.textContent = 'Unlocked';
    }

    if (providerBadge) {
      providerBadge.style.display = 'inline-block';
      providerBadge.className = 'badge badge-provider';
      providerBadge.textContent = provider === 'webauthn' ? 'WebAuthn PRF' : 'Windows Hello';
    }

    if (resultBox) {
      const providerLabel = provider === 'webauthn' ? 'WebAuthn Level 3 PRF' : 'Windows Hello (Native Host)';
      const listStr = accountsSummary.length > 0
        ? accountsSummary.map((acc) => `• [${acc.domain}] ${acc.username}`).join('\n')
        : '(계정 없음)';
      resultBox.textContent = `[잠금 해제 성공]\n인증 프로바이더: ${providerLabel}\n복호화 계정: ${accountsSummary.length}개\n${listStr}`;
    }

    return true;
  } catch (err: any) {
    if (vaultBadge) {
      vaultBadge.className = 'badge badge-locked';
      vaultBadge.textContent = 'Locked';
    }
    if (providerBadge) {
      providerBadge.style.display = 'none';
    }
    if (resultBox) {
      const code = err instanceof NativeMessagingError ? err.code : (err.code || 'UNLOCK_FAILED');
      const message = err.message || String(err);
      resultBox.textContent = `[잠금 해제 실패]\n에러 코드: ${code}\n상세 메시지: ${message}\n안내: 하드웨어 보안키 또는 Windows Hello 등록 상태를 확인하십시오.`;
    }
    return false;
  } finally {
    if (btnUnlock) {
      btnUnlock.disabled = false;
      btnUnlock.textContent = '볼트 잠금 해제';
    }
  }
}

/**
 * 현재 브라우저 활성 탭의 도메인을 조회하여 도메인 입력 필드를 자동 설정한다.
 */
async function autoDetectActiveTabDomain(): Promise<void> {
  const domainInput = document.getElementById('input-prf-domain') as HTMLInputElement | null;
  const vaultDomainInput = document.getElementById('input-vault-domain') as HTMLInputElement | null;

  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url) {
        const url = new URL(tab.url);
        if (url.hostname && !url.hostname.startsWith('chrome') && !url.hostname.startsWith('about')) {
          if (domainInput) domainInput.value = url.hostname;
          if (vaultDomainInput) vaultDomainInput.value = url.hostname;
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

    const btnUnlock = document.getElementById('btn-unlock-vault');
    if (btnUnlock) {
      btnUnlock.addEventListener('click', () => {
        handleUnlockVault();
      });
    }
  });
}

