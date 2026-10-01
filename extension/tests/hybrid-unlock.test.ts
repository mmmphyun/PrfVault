import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { createCryptoCore, CryptoCore } from '../src/crypto/wasm-core';
import { deriveMasterKeyWithFallback, toHex, fromHex } from '../src/auth/webauthn-prf';
import { serializeVault, deserializeVault, type VaultData } from '../src/vault/model';
import { buildAad, parseWireFormat } from '../src/vault/wire-format';
import { saveEncryptedVault, loadEncryptedVault } from '../src/storage/vault-store';
import { handleUnlockVault } from '../src/ui/popup';

class MockElement {
  public id: string;
  public className: string = '';
  public textContent: string = '';
  public value: string = '';
  public disabled: boolean = false;
  public listeners: Record<string, Function[]> = {};
  public style: Record<string, string> = {};

  constructor(id: string) {
    this.id = id;
  }

  addEventListener(type: string, fn: Function) {
    if (!this.listeners[type]) this.listeners[type] = [];
    this.listeners[type].push(fn);
  }
}

describe('WebAuthn PRF 및 Native Host 하이브리드 볼트 언락 파이프라인 E2E 통합 테스트', () => {
  let core: CryptoCore;
  let elements: Record<string, MockElement>;
  let storageData: Record<string, any>;
  const originalChrome = (globalThis as any).chrome;
  const originalDoc = (globalThis as any).document;

  beforeEach(async () => {
    const wasmPath = path.resolve(__dirname, '../src/crypto/wasm/crypto_core_bg.wasm');
    const wasmBuffer = fs.readFileSync(wasmPath);
    core = await createCryptoCore(wasmBuffer);

    storageData = {};
    elements = {
      'native-host-badge': new MockElement('native-host-badge'),
      'btn-native-ping': new MockElement('btn-native-ping'),
      'input-prf-domain': new MockElement('input-prf-domain'),
      'input-prf-challenge': new MockElement('input-prf-challenge'),
      'btn-prf-derive': new MockElement('btn-prf-derive'),
      'prf-result-box': new MockElement('prf-result-box'),
      'vault-badge': new MockElement('vault-badge'),
      'unlock-provider-badge': new MockElement('unlock-provider-badge'),
      'input-vault-domain': new MockElement('input-vault-domain'),
      'btn-unlock-vault': new MockElement('btn-unlock-vault'),
      'unlock-result-box': new MockElement('unlock-result-box'),
    };

    (globalThis as any).document = {
      getElementById: (id: string) => elements[id] || null,
      addEventListener: vi.fn(),
    };

    const mockStorage = {
      get: vi.fn((keys: string | string[], cb: (res: Record<string, any>) => void) => {
        const result: Record<string, any> = {};
        const keyList = Array.isArray(keys) ? keys : [keys];
        for (const k of keyList) {
          if (storageData[k] !== undefined) result[k] = storageData[k];
        }
        cb(result);
      }),
      set: vi.fn((items: Record<string, any>, cb?: () => void) => {
        Object.assign(storageData, items);
        if (cb) cb();
      }),
    };

    (globalThis as any).chrome = {
      runtime: {
        id: 'prfvault-e2e-extension-id',
        sendMessage: vi.fn().mockResolvedValue({ success: true }),
      },
      storage: {
        local: mockStorage,
      },
    };
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    (globalThis as any).chrome = originalChrome;
    (globalThis as any).document = originalDoc;
  });

  it('WebAuthn PRF 미지원 환경에서 Native Host(Windows Hello) 폴백을 통해 볼트가 정상 복호화되어야 한다', async () => {
    // 1. 테스트용 원본 볼트 데이터 구성
    const targetDomain = 'financial.kbstar.com';
    const testVault: VaultData = {
      version: 1,
      credentialId: 'cred-windows-hello-tpm',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      entries: [
        {
          id: 'kb-acc-001',
          domain: targetDomain,
          username: 'sec_officer',
          password: 'UltraSecurePassword999!@#',
          notes: '금융 메인 계정',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      ],
    };

    // 2. Native Host가 반환할 32바이트 PRF 대칭키 및 임의의 Salt 준비
    const nativePrfSecret = new Uint8Array(32).fill(0x7c);
    const salt = new Uint8Array(32).fill(0x3a);

    // 3. 해당 PRF 키와 Salt로 암호화된 볼트 블롭 생성 및 스토리지 사전 저장
    const masterKey = core.deriveMasterKey(nativePrfSecret, salt);
    const extId = 'prfvault-e2e-extension-id';
    const aad = buildAad(extId);
    const encryptedBlob = core.encryptVault(masterKey, serializeVault(testVault), aad);
    encryptedBlob.set(salt, 2); // salt 동기화
    await saveEncryptedVault(encryptedBlob, testVault.credentialId);

    // 4. 브라우저 WebAuthn 미지원 모킹 (ExtensionNotSupported 에러 발생)
    vi.stubGlobal('navigator', {
      credentials: {
        get: vi.fn().mockRejectedValue(new Error('ExtensionNotSupported: navigator.credentials.get prf unsupported')),
      },
    });

    // 5. Chrome Native Messaging Host 응답 모킹 (Windows Hello CNG 성공)
    const nativeHexKey = toHex(nativePrfSecret);
    (globalThis as any).chrome.runtime.sendNativeMessage = vi.fn((_host: string, _msg: unknown, cb: (res: unknown) => void) => {
      cb({
        status: 'OK',
        data: {
          domain: targetDomain,
          challenge: toHex(salt),
          derived: true,
          key: nativeHexKey,
        },
      });
    });

    elements['input-vault-domain'].value = targetDomain;

    // 6. 팝업 UI 언락 트리거 실행
    const unlockSuccess = await handleUnlockVault(core);

    // 7. 검증
    expect(unlockSuccess).toBe(true);
    expect(elements['vault-badge'].className).toBe('badge badge-ok');
    expect(elements['vault-badge'].textContent).toBe('Unlocked');
    expect(elements['unlock-provider-badge'].textContent).toBe('Windows Hello');
    expect(elements['unlock-result-box'].textContent).toContain('[잠금 해제 성공]');
    expect(elements['unlock-result-box'].textContent).toContain('Windows Hello');
    expect(elements['unlock-result-box'].textContent).toContain('sec_officer');

    // 8. Service Worker에 EP_UNLOCK_VAULT IPC가 정상 등록되었는지 검증
    expect((globalThis as any).chrome.runtime.sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'EP_UNLOCK_VAULT',
        payload: {
          decryptedAccountsSummary: [
            {
              id: 'kb-acc-001',
              domain: targetDomain,
              username: 'sec_officer',
            },
          ],
        },
      })
    );
  });

  it('WebAuthn PRF 지원 환경에서는 Native Host를 호출하지 않고 WebAuthn으로 즉시 잠금 해제되어야 한다', async () => {
    const targetDomain = 'github.com';
    const testVault: VaultData = {
      version: 1,
      credentialId: 'cred-webauthn-fido2',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      entries: [
        {
          id: 'gh-acc-002',
          domain: targetDomain,
          username: 'octocat',
          password: 'Fido2ProtectedPass456$$$',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      ],
    };

    const webauthnPrfSecret = new Uint8Array(32).fill(0x5a);
    const salt = new Uint8Array(32).fill(0x2f);

    const masterKey = core.deriveMasterKey(webauthnPrfSecret, salt);
    const aad = buildAad('prfvault-e2e-extension-id');
    const encryptedBlob = core.encryptVault(masterKey, serializeVault(testVault), aad);
    encryptedBlob.set(salt, 2);
    await saveEncryptedVault(encryptedBlob, testVault.credentialId);

    // WebAuthn 정상 동작 모킹
    vi.stubGlobal('navigator', {
      credentials: {
        get: vi.fn().mockResolvedValue({
          getClientExtensionResults: () => ({
            prf: {
              results: {
                first: webauthnPrfSecret.buffer,
              },
            },
          }),
        }),
      },
    });

    const mockSendNative = vi.fn();
    (globalThis as any).chrome.runtime.sendNativeMessage = mockSendNative;

    elements['input-vault-domain'].value = targetDomain;

    const unlockSuccess = await handleUnlockVault(core);

    expect(unlockSuccess).toBe(true);
    expect(elements['vault-badge'].textContent).toBe('Unlocked');
    expect(elements['unlock-provider-badge'].textContent).toBe('WebAuthn PRF');
    expect(elements['unlock-result-box'].textContent).toContain('WebAuthn Level 3 PRF');
    expect(elements['unlock-result-box'].textContent).toContain('octocat');
    // Native Host는 호출되지 않아야 함
    expect(mockSendNative).not.toHaveBeenCalled();
  });

  it('하드웨어 키 도출 후 암호문이 변조된 경우 복호화 실패 및 Locked 상태를 유지해야 한다', async () => {
    const targetDomain = 'tampered-vault.com';
    const testVault: VaultData = {
      version: 1,
      credentialId: 'cred-tampered',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      entries: [
        {
          id: 'acc-tampered',
          domain: targetDomain,
          username: 'victim',
          password: 'OriginalPassword',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      ],
    };

    const prfSecret = new Uint8Array(32).fill(0x1a);
    const salt = new Uint8Array(32).fill(0x2b);

    const masterKey = core.deriveMasterKey(prfSecret, salt);
    const aad = buildAad('prfvault-e2e-extension-id');
    const encryptedBlob = core.encryptVault(masterKey, serializeVault(testVault), aad);
    encryptedBlob.set(salt, 2);

    // 암호문 1바이트 변조 (무결성 훼손)
    encryptedBlob[encryptedBlob.length - 1] ^= 0xff;
    await saveEncryptedVault(encryptedBlob, testVault.credentialId);

    vi.stubGlobal('navigator', {
      credentials: {
        get: vi.fn().mockResolvedValue({
          getClientExtensionResults: () => ({
            prf: { results: { first: prfSecret.buffer } },
          }),
        }),
      },
    });

    elements['input-vault-domain'].value = targetDomain;

    const unlockSuccess = await handleUnlockVault(core);

    expect(unlockSuccess).toBe(false);
    expect(elements['vault-badge'].className).toBe('badge badge-locked');
    expect(elements['vault-badge'].textContent).toBe('Locked');
    expect(elements['unlock-result-box'].textContent).toContain('[잠금 해제 실패]');
  });
});
