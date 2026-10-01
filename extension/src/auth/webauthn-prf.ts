/**
 * WebAuthn Level 3 PRF (Pseudo-Random Function) 하드웨어 키 유도 클라이언트
 *
 * [보안 설계 및 실행 컨텍스트 제약]
 * - 본 모듈은 Extension Page(Popup / Options)와 같은 Window 컨텍스트에서만 실행되어야 합니다.
 * - Service Worker에는 Window 객체가 없어 navigator.credentials API 호출 시 즉시 런타임 오류가 발생합니다.
 * - FIDO2 CTAP 2.1 호환성을 위해 prf 확장과 hmacGetSecret(구버전 폴백)을 동시 요청합니다.
 * - 도출된 PRF 32B 비밀값은 메모리에 영구 보관하지 않고, HKDF 마스터키 도출 직후 참조를 해제해야 합니다.
 */

import { derivePrfViaHost } from '../background/native-ipc';
import { getOrCreateCryptoCore, CryptoCore } from '../crypto/wasm-core';

export interface PrfCapabilities {
  hasWebAuthn: boolean;
  hasPlatformAuthenticator: boolean;
  prfSupported: boolean | 'unknown';
}

export interface RegisterCredentialResult {
  credentialId: string; // Base64URL 인코딩
  prfEnabled: boolean;
  rawId: Uint8Array;
}

/**
 * 브라우저 및 호스트 OS의 WebAuthn PRF 지원 역량을 진단합니다.
 */
export async function checkWebAuthnPrfSupport(): Promise<PrfCapabilities> {
  const hasWebAuthn = typeof window !== 'undefined' && 'PublicKeyCredential' in window;
  if (!hasWebAuthn) {
    return {
      hasWebAuthn: false,
      hasPlatformAuthenticator: false,
      prfSupported: false,
    };
  }

  let hasPlatformAuthenticator = false;
  try {
    hasPlatformAuthenticator = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    hasPlatformAuthenticator = false;
  }

  let prfSupported: boolean | 'unknown' = 'unknown';
  if (typeof (PublicKeyCredential as any).getClientCapabilities === 'function') {
    try {
      const caps = await (PublicKeyCredential as any).getClientCapabilities();
      prfSupported = !!caps['extension:prf'];
    } catch {
      prfSupported = 'unknown';
    }
  }

  return {
    hasWebAuthn,
    hasPlatformAuthenticator,
    prfSupported,
  };
}

/**
 * 새 WebAuthn 자격 증명을 등록하고 PRF 확장을 활성화합니다.
 */
export async function registerPrfCredential(
  rpId: string = 'localhost',
  userName: string = 'prfvault-user',
  userDisplayName: string = 'PrfVault User'
): Promise<RegisterCredentialResult> {
  if (typeof navigator === 'undefined' || !navigator.credentials) {
    throw new Error('navigator.credentials API를 사용할 수 없는 컨텍스트입니다.');
  }

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = new TextEncoder().encode(userName);

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: {
        id: rpId,
        name: 'PrfVault',
      },
      user: {
        id: userId,
        name: userName,
        displayName: userDisplayName,
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },  // ES256
        { alg: -257, type: 'public-key' }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'preferred',
      },
      timeout: 60000,
      extensions: {
        prf: {},
      } as any,
    },
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error('자격 증명 생성이 취소되었거나 실패했습니다.');
  }

  const extResults = credential.getClientExtensionResults() as any;
  const prfEnabled = extResults.prf?.enabled ?? false;
  const rawId = new Uint8Array(credential.rawId);
  const credentialId = base64UrlEncode(rawId);

  return {
    credentialId,
    prfEnabled,
    rawId,
  };
}

/**
 * 등록된 자격 증명과 Salt를 사용해 TPM/인증자로부터 32바이트 PRF 대칭키를 유도합니다.
 */
export async function derivePrfSecret(
  credentialIdBase64?: string,
  salt: Uint8Array = new Uint8Array(32),
  rpId: string = 'localhost'
): Promise<Uint8Array> {
  if (salt.length !== 32) {
    throw new Error(`Salt는 32바이트여야 합니다. (현재: ${salt.length})`);
  }
  if (typeof navigator === 'undefined' || !navigator.credentials) {
    throw new Error('navigator.credentials API를 사용할 수 없는 컨텍스트입니다.');
  }

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const credIdBytes = credentialIdBase64 ? base64UrlDecode(credentialIdBase64) : null;

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge,
    rpId,
    ...(credIdBytes
      ? {
          allowCredentials: [
            {
              id: credIdBytes.buffer as ArrayBuffer,
              type: 'public-key',
            },
          ],
        }
      : {}),
    userVerification: 'required',
    timeout: 60000,
    extensions: {
      prf: {
        eval: {
          first: salt,
        },
      },
      hmacGetSecret: {
        salt1: salt,
      },
    } as any,
  };

  const assertion = (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential | null;

  if (!assertion) {
    throw new Error('하드웨어 인증 요청이 취소되었거나 실패했습니다.');
  }

  const extResults = assertion.getClientExtensionResults() as any;
  let derivedBuffer: ArrayBuffer | null = null;

  if (extResults.prf?.results?.first) {
    derivedBuffer = extResults.prf.results.first;
  } else if (extResults.hmacGetSecret?.output1) {
    derivedBuffer = extResults.hmacGetSecret.output1;
  }

  if (!derivedBuffer) {
    throw new Error(
      '인증자로부터 PRF 대칭키가 반환되지 않았습니다. (TPM 미지원 또는 OS 권한 제한)'
    );
  }

  return new Uint8Array(derivedBuffer);
}

export interface HybridKeyDerivationResult {
  masterKey: Uint8Array;
  provider: 'webauthn' | 'native_host';
}

/**
 * WebAuthn Level 3 PRF 1차 시도 및 Chrome Native Messaging Host(Windows Hello/TPM) 2차 자동 폴백을 통한
 * 일관된 AES-256-GCM 볼트 마스터 키 도출 파이프라인.
 *
 * 1차: 브라우저 표준 navigator.credentials.get({ extensions: { prf: ... } }) 호출
 * 2차: PRF 확장 미지원 또는 실패 시 Native Host(derivePrfViaHost(domain, toHex(salt)))로 투명하게 전환
 * 획득한 32바이트 바이너리 PRF 키를 Rust Wasm derive_master_key에 전달하여 일관된 볼트 마스터 키 생성
 *
 * @param domain 바인딩 대상 도메인 (Relying Party ID)
 * @param salt 볼트 와이어 포맷 32바이트 Salt
 * @param credentialId WebAuthn 자격 증명 식별자 (선택적)
 * @param cryptoCore Wasm CryptoCore 인스턴스 (선택적)
 */
export async function deriveMasterKeyWithFallback(
  domain: string,
  salt: Uint8Array,
  credentialId?: string,
  cryptoCore?: CryptoCore
): Promise<HybridKeyDerivationResult> {
  if (salt.length !== 32) {
    throw new Error(`Salt는 32바이트여야 합니다. (현재: ${salt.length})`);
  }

  const core = await getOrCreateCryptoCore(cryptoCore);
  let prfSecret: Uint8Array | null = null;
  let provider: 'webauthn' | 'native_host' = 'webauthn';

  // 1차 시도: 브라우저 표준 WebAuthn Level 3 PRF
  try {
    if (typeof navigator === 'undefined' || !navigator.credentials) {
      throw new Error('navigator.credentials API를 사용할 수 없는 환경입니다.');
    }
    prfSecret = await derivePrfSecret(credentialId, salt, domain);
    provider = 'webauthn';
  } catch (webauthnErr) {
    // 2차 폴백: Native Messaging Host (Windows Hello CNG / TPM)
    provider = 'native_host';
    const challengeHex = toHex(salt);

    let hostResult: { domain: string; challenge?: string; derived: boolean; key?: string } | null = null;

    // Service Worker IPC 경유 시도 후 직접 Native Messaging 호출 폴백
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      try {
        const swResponse = await chrome.runtime.sendMessage({
          id: crypto.randomUUID(),
          action: 'EP_NATIVE_PRF_DERIVE',
          payload: {
            domain,
            challenge: challengeHex,
          },
          timestamp: Date.now(),
        });
        if (swResponse && swResponse.derived && swResponse.key) {
          hostResult = swResponse;
        }
      } catch {
        // SW IPC 실패 시 아래의 직접 sendNativeMessage 호출로 폴백
      }
    }

    if (!hostResult) {
      hostResult = await derivePrfViaHost(domain, challengeHex);
    }

    if (!hostResult || !hostResult.derived || !hostResult.key) {
      throw new Error(
        `하이브리드 키 도출 실패: WebAuthn(${webauthnErr instanceof Error ? webauthnErr.message : String(webauthnErr)}) 및 Native Host 폴백 모두 실패했습니다.`
      );
    }

    prfSecret = fromHex(hostResult.key);
  }

  if (!prfSecret || prfSecret.length !== 32) {
    throw new Error(`도출된 PRF 비밀값 크기가 올바르지 않습니다. (길이: ${prfSecret?.length ?? 0}B)`);
  }

  const masterKey = core.deriveMasterKey(prfSecret, salt);
  return { masterKey, provider };
}


// Base64URL & Hex 인코딩 유틸리티
export function base64UrlEncode(buf: Uint8Array | ArrayBuffer): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function toHex(buf: Uint8Array | ArrayBuffer): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Hex 문자열 길이가 짝수가 아닙니다.');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}
