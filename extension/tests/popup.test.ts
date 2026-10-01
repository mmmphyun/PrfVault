import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { checkNativeHostLiveness, triggerHardwarePrfDerivation } from '../src/ui/popup';

class MockElement {
  public id: string;
  public className: string = '';
  public textContent: string = '';
  public value: string = '';
  public disabled: boolean = false;
  public listeners: Record<string, Function[]> = {};

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
  const originalChrome = (globalThis as any).chrome;
  const originalDoc = (globalThis as any).document;

  beforeEach(() => {
    elements = {
      'native-host-badge': new MockElement('native-host-badge'),
      'btn-native-ping': new MockElement('btn-native-ping'),
      'input-prf-domain': new MockElement('input-prf-domain'),
      'input-prf-challenge': new MockElement('input-prf-challenge'),
      'btn-prf-derive': new MockElement('btn-prf-derive'),
      'prf-result-box': new MockElement('prf-result-box'),
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
});
