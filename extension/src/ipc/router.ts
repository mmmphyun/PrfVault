/**
 * MV3 컨텍스트 간 내부 IPC 라우터 및 발신지 위조 방지 엔진
 *
 * [보안 아키텍처 및 위협 모델 대응]
 * 1. 악성 확장프로그램 침투 방어: sender.id와 chrome.runtime.id 일치 여부 엄격 검증.
 * 2. 도메인 스푸핑(Domain Spoofing) 원천 차단:
 *    - 비신뢰 영역인 Content Script가 임의로 전송한 domain 파라미터를 불신합니다.
 *    - 브라우저 커널이 서명/보증한 sender.tab.url로부터 Public Suffix List(PSL - tldts) 기반
 *      eTLD+1을 직접 산출하여 볼트 조회 및 권한 격리 키로 강제 바인딩합니다.
 * 3. 프로토콜 격리: chrome://, file://, javascript: 등 비웹 컨텍스트의 요청을 즉시 드롭합니다.
 */

import { getDomain } from 'tldts';
import type { IpcErrorCode, IpcRequest, IpcResponse } from './messages';

export interface MessageContext {
  sender: chrome.runtime.MessageSender;
  verifiedDomain: string | null;
}

export type IpcHandler<TReq = any, TRes = any> = (
  request: TReq,
  context: MessageContext
) => Promise<TRes> | TRes;

export class IpcRouter {
  private handlers = new Map<string, IpcHandler>();

  /**
   * 특정 IPC 액션에 대한 핸들러를 등록합니다.
   */
  public register<TReq = any, TRes = any>(action: string, handler: IpcHandler<TReq, TRes>): this {
    this.handlers.set(action, handler);
    return this;
  }

  /**
   * 인입된 메시지의 발신자 및 도메인을 검증하고 적절한 핸들러로 라우팅합니다.
   */
  public async dispatch(
    message: unknown,
    sender: chrome.runtime.MessageSender,
    expectedRuntimeId?: string
  ): Promise<IpcResponse> {
    const effectiveRuntimeId = expectedRuntimeId ?? (typeof chrome !== 'undefined' && chrome.runtime ? chrome.runtime.id : '');

    // 1. 기본 메시지 구조 검증
    if (!message || typeof message !== 'object' || !('id' in message) || !('action' in message)) {
      return {
        id: (message as any)?.id ?? 'unknown',
        success: false,
        error: {
          code: 'INVALID_REQUEST_PAYLOAD',
          message: '메시지 규격(id, action)이 누락되었습니다.',
        },
      };
    }

    const req = message as IpcRequest;

    // 2. 발신자 확장프로그램 런타임 ID 검증
    if (sender.id !== effectiveRuntimeId) {
      return {
        id: req.id,
        success: false,
        error: {
          code: 'UNAUTHORIZED_SENDER',
          message: `런타임 ID가 일치하지 않습니다. (발신: ${sender.id}, 기대: ${effectiveRuntimeId})`,
        },
      };
    }

    // 3. Content Script 발신 요청에 대한 브라우저 탭 URL 및 eTLD+1 도메인 추출
    let verifiedDomain: string | null = null;
    if (sender.tab && sender.tab.url) {
      try {
        const parsedUrl = new URL(sender.tab.url);

        // 보안상 HTTP/HTTPS 오리진만 허용 (chrome://, file://, javascript: 배제)
        if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
          return {
            id: req.id,
            success: false,
            error: {
              code: 'UNAUTHORIZED_SENDER',
              message: `허용되지 않은 프로토콜 오리진입니다: ${parsedUrl.protocol}`,
            },
          };
        }

        // Public Suffix List 기반 eTLD+1 추출 (예: sub.naver.com -> naver.com, a.co.kr -> a.co.kr)
        const domain = getDomain(parsedUrl.hostname);
        if (!domain) {
          return {
            id: req.id,
            success: false,
            error: {
              code: 'UNAUTHORIZED_SENDER',
              message: `탭 URL에서 유효한 eTLD+1 도메인을 도출할 수 없습니다: ${parsedUrl.hostname}`,
            },
          };
        }
        verifiedDomain = domain;
      } catch (e: any) {
        return {
          id: req.id,
          success: false,
          error: {
            code: 'UNAUTHORIZED_SENDER',
            message: `탭 URL 파싱 실패: ${e.message}`,
          },
        };
      }
    }

    // 4. 핸들러 디스패치
    const handler = this.handlers.get(req.action);
    if (!handler) {
      return {
        id: req.id,
        success: false,
        error: {
          code: 'INVALID_REQUEST_PAYLOAD',
          message: `지원되지 않는 IPC 액션입니다: ${req.action}`,
        },
      };
    }

    try {
      const data = await handler(req, { sender, verifiedDomain });
      return {
        id: req.id,
        success: true,
        data,
      };
    } catch (err: any) {
      const errorCode: IpcErrorCode = err.code ?? (
        err.message?.startsWith('INVALID_REQUEST_PAYLOAD') ? 'INVALID_REQUEST_PAYLOAD' : 'STORAGE_ERROR'
      );
      return {
        id: req.id,
        success: false,
        error: {
          code: errorCode,
          message: err.message || '알 수 없는 내부 핸들러 오류',
          details: err.details,
        },
      };
    }
  }

  /**
   * Chrome Runtime 리스너에 바인딩할 핸들러 함수를 반환합니다.
   */
  public createListener(): (
    message: any,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: any) => void
  ) => boolean {
    return (message, sender, sendResponse) => {
      this.dispatch(message, sender)
        .then(sendResponse)
        .catch((err) => {
          sendResponse({
            id: message?.id ?? 'unknown',
            success: false,
            error: { code: 'STORAGE_ERROR', message: err.message },
          });
        });
      // 비동기 응답(sendResponse) 유지를 위해 true 반환
      return true;
    };
  }
}
