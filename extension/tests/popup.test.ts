import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { checkNativeHostLiveness, triggerHardwarePrfDerivation, handleUnlockVault } from '../src/ui/popup';
import { createCryptoCore, CryptoCore } from '../src/crypto/wasm-core';

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

describe('팝업 UI 엔트리포인트 (popup.ts) 모듈 테스트', () => {
  let elements: Record<string, MockElement>;
  let core: CryptoCore;
  const originalChrome = (globalThis as any).chrome;
  const originalDoc = (globalThis as any).document;

  beforeEach(async () => {
    const wasmPath = path.resolve(__dirname, '../src/crypto/wasm/crypto_core_bg.wasm');
    const wasmBuffer = fs.readFileSync(wasmPath);
    core = await createCryptoCore(wasmBuffer);

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
  });

  afterEach(() => {
    (globalThis as any).chrome = originalChrome;
    (globalThis as any).document = originalDoc;
  });

  it('네이티브 호스트 Ping 성공 시 배지가 Connected로 업데이트되어야 한다', async () => {
    (globalThis as any).chrome = {
      runtime: {
        sendMessage: vi.fn().mockResolvedValue({ pong: true }),
      },
    };

    const isAlive = await checkNativeHostLiveness();

    expect(isAlive).toBe(true);
    expect(elements['native-host-badge'].className).toBe('badge badge-ok');
    expect(elements['native-host-badge'].textContent).toBe('Connected (Active)');
    expect(elements['btn-native-ping'].disabled).toBe(false);
  });

  it('네이티브 호스트 Ping 실패 시 배지가 Disconnected로 업데이트되어야 한다', async () => {
    (globalThis as any).chrome = {
      runtime: {
        sendMessage: vi.fn().mockRejectedValue(new Error('Host not found')),
        sendNativeMessage: vi.fn((_host, _msg, cb) => {
          (globalThis as any).chrome.runtime.lastError = { message: 'Host not found' };
          cb(null);
        }),
      },
    };

    const isAlive = await checkNativeHostLiveness();

    expect(isAlive).toBe(false);
    expect(elements['native-host-badge'].className).toBe('badge badge-error');
    expect(elements['native-host-badge'].textContent).toContain('Disconnected');
    expect(elements['btn-native-ping'].disabled).toBe(false);
  });

  it('도메인이 누락되었을 때 검증 에러를 표시하고 요청을 중단해야 한다', async () => {
    elements['input-prf-domain'].value = '';

    await triggerHardwarePrfDerivation();

    expect(elements['prf-result-box'].textContent).toContain('도메인을 입력하십시오');
  });

  it('하드웨어 PRF 도출 성공 시 결과 박스에 대칭키 요약이 출력되어야 한다', async () => {
    elements['input-prf-domain'].value = 'test.service.com';
    elements['input-prf-challenge'].value = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    (globalThis as any).chrome = {
      runtime: {
        sendMessage: vi.fn().mockResolvedValue({
          domain: 'test.service.com',
          derived: true,
          key: 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
        }),
      },
    };

    await triggerHardwarePrfDerivation();

    expect(elements['prf-result-box'].textContent).toContain('[도출 성공]');
    expect(elements['prf-result-box'].textContent).toContain('test.service.com');
    expect(elements['prf-result-box'].textContent).toContain('aabbccddeeff0011');
    expect(elements['btn-prf-derive'].disabled).toBe(false);
  });

  it('하드웨어 PRF 도출 실패 시 에러 코드와 상세 메시지가 노출되어야 한다', async () => {
    elements['input-prf-domain'].value = 'test.service.com';
    elements['input-prf-challenge'].value = 'seed123';

    (globalThis as any).chrome = {
      runtime: {
        sendMessage: vi.fn().mockRejectedValue({
          code: 'HARDWARE_UNAVAILABLE',
          message: 'TPM 2.0 미지원 환경입니다.',
        }),
        sendNativeMessage: vi.fn((_host, _msg, cb) => {
          cb({
            status: 'ERROR',
            code: 'HARDWARE_UNAVAILABLE',
            message: 'TPM 2.0 미지원 환경입니다.',
          });
        }),
      },
    };

    await triggerHardwarePrfDerivation();

    expect(elements['prf-result-box'].textContent).toContain('[도출 실패]');
    expect(elements['prf-result-box'].textContent).toContain('HARDWARE_UNAVAILABLE');
    expect(elements['btn-prf-derive'].disabled).toBe(false);
  });

  describe('볼트 잠금 해제 UX (handleUnlockVault) 테스트', () => {
    let storageData: Record<string, any>;

    beforeEach(() => {
      storageData = {};
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
          id: 'test-ext-id',
          sendMessage: vi.fn().mockResolvedValue({ success: true }),
        },
        storage: {
          local: mockStorage,
        },
      };
    });

    it('WebAuthn PRF 성공 시 Unlocked 배지와 WebAuthn 프로바이더가 표시되어야 한다', async () => {
      const mockPrfSecret = new Uint8Array(32).fill(0x11);
      vi.stubGlobal('navigator', {
        credentials: {
          get: vi.fn().mockResolvedValue({
            getClientExtensionResults: () => ({
              prf: { results: { first: mockPrfSecret.buffer } },
            }),
          }),
        },
      });

      elements['input-vault-domain'].value = 'test.domain.com';

      const success = await handleUnlockVault(core);

      expect(success).toBe(true);
      expect(elements['vault-badge'].className).toBe('badge badge-ok');
      expect(elements['vault-badge'].textContent).toBe('Unlocked');
      expect(elements['unlock-provider-badge'].textContent).toBe('WebAuthn PRF');
      expect(elements['unlock-result-box'].textContent).toContain('[잠금 해제 성공]');
      expect(elements['btn-unlock-vault'].disabled).toBe(false);

      vi.unstubAllGlobals();
    });

    it('WebAuthn 실패 시 Native Host로 폴백하여 Windows Hello 프로바이더로 언락되어야 한다', async () => {
      // WebAuthn 실패 시뮬레이션
      vi.stubGlobal('navigator', {
        credentials: {
          get: vi.fn().mockRejectedValue(new Error('ExtensionNotSupported')),
        },
      });

      const mockNativeKey = '22'.repeat(32);
      (globalThis as any).chrome.runtime.sendNativeMessage = vi.fn((_host: string, _msg: unknown, cb: (res: unknown) => void) => {
        cb({
          status: 'OK',
          data: {
            domain: 'test.domain.com',
            challenge: 'toHexSalt',
            derived: true,
            key: mockNativeKey,
          },
        });
      });

      elements['input-vault-domain'].value = 'test.domain.com';

      const success = await handleUnlockVault(core);

      expect(success).toBe(true);
      expect(elements['vault-badge'].className).toBe('badge badge-ok');
      expect(elements['vault-badge'].textContent).toBe('Unlocked');
      expect(elements['unlock-provider-badge'].textContent).toBe('Windows Hello');
      expect(elements['unlock-result-box'].textContent).toContain('[잠금 해제 성공]');
      expect(elements['btn-unlock-vault'].disabled).toBe(false);

      vi.unstubAllGlobals();
    });

    it('인증 실패 시 Locked 상태 유지 및 에러 메시지가 표시되어야 한다', async () => {
      vi.stubGlobal('navigator', {
        credentials: {
          get: vi.fn().mockRejectedValue(new Error('NotSupportedError')),
        },
      });

      (globalThis as any).chrome.runtime.sendNativeMessage = vi.fn((_host: string, _msg: unknown, cb: (res: unknown) => void) => {
        cb({
          status: 'ERROR',
          code: 'USER_CANCELLED',
          message: '사용자가 인증을 취소했습니다.',
        });
      });

      elements['input-vault-domain'].value = 'test.domain.com';

      const success = await handleUnlockVault(core);

      expect(success).toBe(false);
      expect(elements['vault-badge'].className).toBe('badge badge-locked');
      expect(elements['vault-badge'].textContent).toBe('Locked');
      expect(elements['unlock-provider-badge'].style.display).toBe('none');
      expect(elements['unlock-result-box'].textContent).toContain('[잠금 해제 실패]');
      expect(elements['unlock-result-box'].textContent).toContain('USER_CANCELLED');
      expect(elements['btn-unlock-vault'].disabled).toBe(false);

      vi.unstubAllGlobals();
    });
  });
});

