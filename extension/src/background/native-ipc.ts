/**
 * Chrome Native Messaging Host 클라이언트 통신 모듈
 *
 * [보안 설계 및 책임 한계]
 * - Chrome 확장 프로그램 MV3 Service Worker와 Rust 네이티브 호스트(crates/native-host) 간의
 *   표준 입출력 4바이트 uint32 LE 통신 파이프라인을 비동기 Promise 인터페이스로 추상화한다.
 * - 타임아웃 및 프로세스 크래시 시 누수(Hanging Promise)를 방지하기 위해 엄격한 타이머 가드레일을 적용한다.
 */

export const DEFAULT_NATIVE_HOST_NAME = 'com.prfvault.native_host';

export interface NativePingRequest {
  type: 'PING';
}

export interface NativePrfDeriveRequest {
  type: 'PRF_DERIVE';
  domain: string;
  challenge: string;
}

export type NativeHostRequest = NativePingRequest | NativePrfDeriveRequest;

export interface NativeSuccessResponse<T = unknown> {
  status: 'OK';
  data: T;
}

export interface NativeErrorResponse {
  status: 'ERROR';
  code: string;
  message?: string;
}

export type NativeHostResponse<T = unknown> = NativeSuccessResponse<T> | NativeErrorResponse;

export class NativeMessagingError extends Error {
  constructor(
    public readonly code: string,
    message: string
  ) {
    super(message);
    this.name = 'NativeMessagingError';
  }
}

/**
 * 네이티브 호스트 프로세스로 단일 메시지를 전송하고 응답을 수신한다.
 *
 * # 제약 사항
 * - Windows 환경에서 네이티브 호스트 레지스트리가 미등록된 경우 chrome.runtime.lastError가 발생한다.
 * - 지정된 timeoutMs 초과 시 프로세스 응답 대기를 중단하고 타임아웃 예외를 던진다.
 *
 * # 부작용
 * - Chrome 브라우저가 백그라운드에서 네이티브 호스트 프로세스를 스폰(spawn)하며,
 *   단일 메시지 완료 후 호스트 수명 주기는 브라우저 정책 및 호스트 구현에 종속된다.
 */
export async function sendNativeMessage<TReq extends object = NativeHostRequest, TRes = unknown>(
  message: TReq,
  hostName: string = DEFAULT_NATIVE_HOST_NAME,
  timeoutMs: number = 5000
): Promise<TRes> {
  if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendNativeMessage) {
    throw new NativeMessagingError(
      'NATIVE_API_UNAVAILABLE',
      'Chrome Native Messaging API를 사용할 수 없는 환경입니다.'
    );
  }

  return new Promise<TRes>((resolve, reject) => {
    let hasResolved = false;

    const timer = setTimeout(() => {
      if (!hasResolved) {
        hasResolved = true;
        reject(
          new NativeMessagingError(
            'HOST_TIMEOUT',
            `네이티브 호스트(${hostName}) 응답 제한시간(${timeoutMs}ms)이 초과되었습니다.`
          )
        );
      }
    }, timeoutMs);

    try {
      chrome.runtime.sendNativeMessage(hostName, message, (response: unknown) => {
        if (hasResolved) return;
        hasResolved = true;
        clearTimeout(timer);

        if (chrome.runtime.lastError) {
          reject(
            new NativeMessagingError(
              'HOST_COMMUNICATION_FAILED',
              chrome.runtime.lastError.message ?? '네이티브 호스트 통신 실패'
            )
          );
          return;
        }

        if (!response || typeof response !== 'object') {
          reject(
            new NativeMessagingError(
              'INVALID_RESPONSE',
              '네이티브 호스트로부터 유효하지 않은 응답을 수신했습니다.'
            )
          );
          return;
        }

        const hostResp = response as NativeHostResponse<TRes>;
        if (hostResp.status === 'ERROR') {
          reject(
            new NativeMessagingError(
              hostResp.code || 'HOST_ERROR',
              hostResp.message || '네이티브 호스트 처리 실패'
            )
          );
          return;
        }

        if (hostResp.status === 'OK') {
          resolve(hostResp.data as TRes);
          return;
        }

        resolve(response as TRes);
      });
    } catch (err) {
      if (!hasResolved) {
        hasResolved = true;
        clearTimeout(timer);
        reject(
          new NativeMessagingError(
            'SEND_FAILED',
            err instanceof Error ? err.message : String(err)
          )
        );
      }
    }
  });
}

/**
 * 네이티브 호스트의 liveness(생존 여부)를 검증하기 위한 헬스체크 핑을 전송한다.
 */
export async function pingNativeHost(
  hostName: string = DEFAULT_NATIVE_HOST_NAME,
  timeoutMs: number = 3000
): Promise<{ pong: boolean }> {
  return sendNativeMessage<{ type: 'PING' }, { pong: boolean }>(
    { type: 'PING' },
    hostName,
    timeoutMs
  );
}

/**
 * 네이티브 호스트(Windows Hello / OS Authenticator PRF)를 통해 도메인별 바운드 키 도출을 요청한다.
 */
export async function derivePrfViaHost(
  domain: string,
  challenge: string,
  hostName: string = DEFAULT_NATIVE_HOST_NAME,
  timeoutMs: number = 10000
): Promise<{ domain: string; challenge: string; derived: boolean }> {
  return sendNativeMessage<
    NativePrfDeriveRequest,
    { domain: string; challenge: string; derived: boolean }
  >(
    {
      type: 'PRF_DERIVE',
      domain,
      challenge,
    },
    hostName,
    timeoutMs
  );
}
