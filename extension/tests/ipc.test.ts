import { describe, it, expect } from 'vitest';
import { IpcRouter } from '../src/ipc/router';
import {
  CsRequestCredentialsSchema,
  validateIpcPayload,
  type CsRequestCredentialsRequest,
} from '../src/ipc/messages';

describe('MV3 IPC 라우터 및 발신지 검증 엔진 테스트', () => {
  const mockExtensionId = 'abcdefghijklmnopqrstuvwxyz123456';
  const validUuid = '123e4567-e89b-12d3-a456-426614174000';

  it('발신자 runtime ID가 일치하지 않으면 UNAUTHORIZED_SENDER로 거부해야 한다', async () => {
    const router = new IpcRouter();
    router.register('TEST_ACTION', () => ({ ok: true }));

    const response = await router.dispatch(
      { id: validUuid, action: 'TEST_ACTION', payload: {}, timestamp: Date.now() },
      { id: 'malicious-extension-id' },
      mockExtensionId
    );

    expect(response.success).toBe(false);
    if (!response.success) {
      expect(response.error.code).toBe('UNAUTHORIZED_SENDER');
    }
  });

  it('Content Script의 서브도메인 URL로부터 정확한 eTLD+1 도메인을 추출해야 한다', async () => {
    const router = new IpcRouter();
    let capturedDomain: string | null = null;

    router.register('CS_REQUEST_CREDENTIALS', (req, ctx) => {
      capturedDomain = ctx.verifiedDomain;
      return { candidates: [] };
    });

    const mockSender: chrome.runtime.MessageSender = {
      id: mockExtensionId,
      tab: {
        id: 1,
        index: 0,
        pinned: false,
        highlighted: false,
        windowId: 1,
        active: true,
        incognito: false,
        selected: true,
        discarded: false,
        autoDiscardable: true,
        frozen: false,
        groupId: -1,
        url: 'https://login.finance.naver.com/user/signin',
      },
    };

    const response = await router.dispatch(
      {
        id: validUuid,
        action: 'CS_REQUEST_CREDENTIALS',
        payload: { isPasswordChangeForm: false },
        timestamp: Date.now(),
      },
      mockSender,
      mockExtensionId
    );

    expect(response.success).toBe(true);
    expect(capturedDomain).toBe('naver.com');
  });

  it('file://, chrome:// 등 비허용 프로토콜의 탭 요청은 거부해야 한다', async () => {
    const router = new IpcRouter();
    router.register('CS_REQUEST_CREDENTIALS', () => ({ ok: true }));

    const invalidSender: chrome.runtime.MessageSender = {
      id: mockExtensionId,
      tab: {
        id: 1,
        index: 0,
        pinned: false,
        highlighted: false,
        windowId: 1,
        active: true,
        incognito: false,
        selected: true,
        discarded: false,
        autoDiscardable: true,
        frozen: false,
        groupId: -1,
        url: 'chrome://settings',
      },
    };

    const response = await router.dispatch(
      {
        id: validUuid,
        action: 'CS_REQUEST_CREDENTIALS',
        payload: { isPasswordChangeForm: false },
        timestamp: Date.now(),
      },
      invalidSender,
      mockExtensionId
    );

    expect(response.success).toBe(false);
    if (!response.success) {
      expect(response.error.code).toBe('UNAUTHORIZED_SENDER');
    }
  });

  it('정의되지 않은 필드(Prototype Pollution 공격) 주입 시 Zod strict 검증이 실패해야 한다', () => {
    const maliciousPayload = {
      id: validUuid,
      action: 'CS_REQUEST_CREDENTIALS',
      payload: {
        isPasswordChangeForm: false,
        __proto__: { isAdmin: true },
        injectedField: 'malicious',
      },
      timestamp: Date.now(),
    };

    expect(() => {
      validateIpcPayload(CsRequestCredentialsSchema, maliciousPayload);
    }).toThrow(/INVALID_REQUEST_PAYLOAD/);
  });
});
