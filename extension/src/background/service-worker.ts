/**
 * PrfVault MV3 Background Service Worker
 *
 * [보안 설계 및 책임 한계]
 * - 본 서비스 워커는 암호화 블롭의 I/O 브로커이자 컨텍스트 간 IPC 라우터로만 기능합니다.
 * - 마스터 키나 평문 비밀번호를 직접 다루지 않으며, 복호화는 Extension Page(Popup)에서만 수행됩니다.
 * - Content Script의 요청은 브라우저 커널이 인증한 verifiedDomain(eTLD+1)을 기준으로만 자격증명을 필터링합니다.
 */

import { IpcRouter } from '../ipc/router';
import {
  type EpGetVaultStatusRequest,
  type EpGetVaultStatusData,
  type EpSaveEncryptedVaultRequest,
  type EpUnlockVaultRequest,
  type CsRequestCredentialsRequest,
  type CredentialCandidate,
  validateIpcPayload,
  EpGetVaultStatusSchema,
  EpSaveEncryptedVaultSchema,
  EpUnlockVaultSchema,
  CsRequestCredentialsSchema,
} from '../ipc/messages';
import { loadEncryptedVault, saveEncryptedVault } from '../storage/vault-store';
import { fromHex } from '../auth/webauthn-prf';

// 세션 캐시 (SW 수명 주기 내에서만 유지되며 브라우저 유휴 시 자동 소멸)
interface CachedSession {
  unlockedAt: number;
  accounts: Array<{ id: string; domain: string; username: string }>;
}

let activeSession: CachedSession | null = null;

export const router = new IpcRouter();

// 1. EP_GET_VAULT_STATUS 핸들러
router.register('EP_GET_VAULT_STATUS', async (req: EpGetVaultStatusRequest): Promise<EpGetVaultStatusData> => {
  validateIpcPayload(EpGetVaultStatusSchema, req);
  const stored = await loadEncryptedVault();

  if (!stored) {
    return {
      isInitialized: false,
      isLocked: true,
      accountCount: 0,
    };
  }

  return {
    isInitialized: true,
    isLocked: activeSession === null,
    credentialId: stored.metadata.credentialId,
    salt: stored.metadata.saltHex,
    accountCount: activeSession ? activeSession.accounts.length : 0,
  };
});

// 2. EP_SAVE_ENCRYPTED_VAULT 핸들러
router.register('EP_SAVE_ENCRYPTED_VAULT', async (req: EpSaveEncryptedVaultRequest) => {
  validateIpcPayload(EpSaveEncryptedVaultSchema, req);
  const blob = fromHex(req.payload.encryptedBlobHex);

  const stored = await loadEncryptedVault();
  const credId = stored ? stored.metadata.credentialId : 'initial-credential';
  const meta = await saveEncryptedVault(blob, credId);

  return {
    bytesWritten: meta.byteLength,
    updatedAt: meta.updatedAt,
  };
});

// 3. EP_UNLOCK_VAULT 핸들러
router.register('EP_UNLOCK_VAULT', async (req: EpUnlockVaultRequest) => {
  validateIpcPayload(EpUnlockVaultSchema, req);

  activeSession = {
    unlockedAt: Date.now(),
    accounts: req.payload.decryptedAccountsSummary,
  };

  return {
    unlockedAt: activeSession.unlockedAt,
    sessionTtlMs: 30000,
  };
});

// 4. CS_REQUEST_CREDENTIALS 핸들러
router.register('CS_REQUEST_CREDENTIALS', async (req: CsRequestCredentialsRequest, ctx) => {
  validateIpcPayload(CsRequestCredentialsSchema, req);

  const targetDomain = ctx.verifiedDomain;
  if (!targetDomain) {
    throw new Error('검증된 도메인이 존재하지 않습니다.');
  }

  const isVaultLocked = activeSession === null;
  const candidates: CredentialCandidate[] = [];

  if (activeSession) {
    const matched = activeSession.accounts.filter((acc) => acc.domain === targetDomain);
    for (const acc of matched) {
      candidates.push({
        accountId: acc.id,
        username: acc.username,
      });
    }
  }

  return {
    domain: targetDomain,
    isVaultLocked,
    candidates,
  };
});

// 크롬 런타임 메시지 리스너 바인딩
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener(router.createListener());
}
