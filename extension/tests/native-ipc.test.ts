import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  sendNativeMessage,
  pingNativeHost,
  derivePrfViaHost,
  NativeMessagingError,
  DEFAULT_NATIVE_HOST_NAME,
} from '../src/background/native-ipc';
import {
  EpNativePingSchema,
  EpNativePrfDeriveSchema,
  validateIpcPayload,
} from '../src/ipc/messages';

describe('Chrome Native Messaging 클라이언트 통신 모듈 (native-ipc.ts) 테스트', () => {
  const originalChrome = (globalThis as unknown as { chrome?: unknown }).chrome;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    (globalThis as unknown as { chrome?: unknown }).chrome = originalChrome;
  });

  it('chrome.runtime.sendNativeMessage API가 부재할 경우 NATIVE_API_UNAVAILABLE 에러를 반환해야 한다', async () => {
    (globalThis as unknown as { chrome?: unknown }).chrome = undefined;

    await expect(sendNativeMessage({ type: 'PING' })).rejects.toThrow(
      new NativeMessagingError(
        'NATIVE_API_UNAVAILABLE',
        'Chrome Native Messaging API를 사용할 수 없는 환경입니다.'
      )
    );
  });

  it('네이티브 호스트로부터 정상 OK 응답 수신 시 데이터를 반환해야 한다', async () => {
    const mockSend = vi.fn((_host: string, _msg: unknown, cb: (res: unknown) => void) => {
      cb({ status: 'OK', data: { pong: true } });
    });

    (globalThis as unknown as { chrome?: unknown }).chrome = {
      runtime: {
        sendNativeMessage: mockSend,
      },
    };

    const result = await pingNativeHost();
    expect(mockSend).toHaveBeenCalledWith(
      DEFAULT_NATIVE_HOST_NAME,
      { type: 'PING' },
      expect.any(Function)
    );
    expect(result).toEqual({ pong: true });
  });

  it('chrome.runtime.lastError 발생 시 HOST_COMMUNICATION_FAILED 에러를 반환해야 한다', async () => {
    const mockSend = vi.fn((_host: string, _msg: unknown, cb: (res: unknown) => void) => {
      (globalThis as unknown as { chrome: { runtime: { lastError?: { message: string } } } }).chrome.runtime.lastError = {
        message: 'Specified native messaging host not found.',
      };
      cb(null);
    });

    (globalThis as unknown as { chrome?: unknown }).chrome = {
      runtime: {
        sendNativeMessage: mockSend,
        lastError: undefined,
      },
    };

    await expect(pingNativeHost()).rejects.toThrow(
      new NativeMessagingError(
        'HOST_COMMUNICATION_FAILED',
        'Specified native messaging host not found.'
      )
    );
  });

  it('호스트가 ERROR 상태 코드를 반환하면 지정된 에러 코드로 reject해야 한다', async () => {
    const mockSend = vi.fn((_host: string, _msg: unknown, cb: (res: unknown) => void) => {
      cb({ status: 'ERROR', code: 'INVALID_PAYLOAD', message: 'Malformed JSON' });
    });

    (globalThis as unknown as { chrome?: unknown }).chrome = {
      runtime: {
        sendNativeMessage: mockSend,
      },
    };

    await expect(derivePrfViaHost('example.com', 'chal123')).rejects.toThrow(
      new NativeMessagingError('INVALID_PAYLOAD', 'Malformed JSON')
    );
  });

  it('호스트 응답 제한 시간(timeoutMs)을 초과하면 HOST_TIMEOUT 에러를 반환해야 한다', async () => {
    const mockSend = vi.fn((_host: string, _msg: unknown, _cb: (res: unknown) => void) => {
      // 의도적으로 콜백을 호출하지 않고 침묵 (Hanging Host 시뮬레이션)
    });

    (globalThis as unknown as { chrome?: unknown }).chrome = {
      runtime: {
        sendNativeMessage: mockSend,
      },
    };

    const promise = pingNativeHost(DEFAULT_NATIVE_HOST_NAME, 1000);
    vi.advanceTimersByTime(1001);

    await expect(promise).rejects.toThrow(
      new NativeMessagingError(
        'HOST_TIMEOUT',
        `네이티브 호스트(${DEFAULT_NATIVE_HOST_NAME}) 응답 제한시간(1000ms)이 초과되었습니다.`
      )
    );
  });

  it('derivePrfViaHost 호출 시 PRF_DERIVE 규격 메시지를 올바르게 전송해야 한다', async () => {
    const mockSend = vi.fn((_host: string, msg: unknown, cb: (res: unknown) => void) => {
      const typed = msg as { type: string; domain: string; challenge: string };
      cb({
        status: 'OK',
        data: {
          domain: typed.domain,
          challenge: typed.challenge,
          derived: true,
        },
      });
    });

    (globalThis as unknown as { chrome?: unknown }).chrome = {
      runtime: {
        sendNativeMessage: mockSend,
      },
    };

    const result = await derivePrfViaHost('kbstar.com', 'test_challenge_seed');
    expect(result).toEqual({
      domain: 'kbstar.com',
      challenge: 'test_challenge_seed',
      derived: true,
    });
  });

  describe('네이티브 IPC Zod 런타임 스키마 무결성 검증', () => {
    it('EpNativePingSchema 유효성 검증 성공', () => {
      const valid = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        action: 'EP_NATIVE_PING',
        payload: {
          hostName: 'com.prfvault.native_host',
          timeoutMs: 5000,
        },
        timestamp: Date.now(),
      };
      const parsed = validateIpcPayload(EpNativePingSchema, valid);
      expect(parsed.action).toBe('EP_NATIVE_PING');
    });

    it('EpNativePrfDeriveSchema 유효성 검증 성공 및 미등록 키 거부', () => {
      const valid = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        action: 'EP_NATIVE_PRF_DERIVE',
        payload: {
          domain: 'naver.com',
          challenge: 'random_seed_123',
        },
        timestamp: Date.now(),
      };
      const parsed = validateIpcPayload(EpNativePrfDeriveSchema, valid);
      expect(parsed.payload.domain).toBe('naver.com');

      const polluted = {
        ...valid,
        payload: {
          ...valid.payload,
          evil: true,
        },
      };
      // strict()에 의해 미정의 속성 또는 오염 시도시 Unrecognized key 에러 발생 확인
      expect(() => validateIpcPayload(EpNativePrfDeriveSchema, polluted)).toThrow(/Unrecognized key/);
    });
  });
});
