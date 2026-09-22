import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import {
  saveEncryptedVault,
  loadEncryptedVault,
  clearVaultStorage,
  STORAGE_KEY_BLOB,
  STORAGE_KEY_META,
} from '../src/storage/vault-store';
import { createCryptoCore, CryptoCore } from '../src/crypto/wasm-core';
import { serializeVault, deserializeVault, type VaultData } from '../src/vault/model';
import { buildAad } from '../src/vault/wire-format';
import { fromHex } from '../src/auth/webauthn-prf';

describe('chrome.storage.local 볼트 스토리지 및 전체 E2E 파이프라인 통합 테스트', () => {
  let core: CryptoCore;
  let mockStorage: Record<string, any> = {};

  beforeAll(async () => {
    const wasmPath = path.resolve(__dirname, '../src/crypto/wasm/crypto_core_bg.wasm');
    const wasmBuffer = fs.readFileSync(wasmPath);
    core = await createCryptoCore(wasmBuffer);
  });

  beforeEach(() => {
    mockStorage = {};
    (global as any).chrome = {
      runtime: {
        id: 'extension-id-123456789012345678',
        lastError: null,
      },
      storage: {
        local: {
          set: (items: Record<string, any>, callback?: () => void) => {
            Object.assign(mockStorage, items);
            if (callback) callback();
          },
          get: (keys: string[], callback: (items: Record<string, any>) => void) => {
            const result: Record<string, any> = {};
            for (const k of keys) {
              if (k in mockStorage) result[k] = mockStorage[k];
            }
            callback(result);
          },
          remove: (keys: string[], callback?: () => void) => {
            for (const k of keys) {
              delete mockStorage[k];
            }
            if (callback) callback();
          },
        },
      },
    };
  });

  it('볼트 블롭 저장 및 메타데이터 조회가 정상 동작해야 한다', async () => {
    const dummyKey = new Uint8Array(32).fill(0x11);
    const dummyPt = new TextEncoder().encode('Test Payload');
    const blob = core.encryptVault(dummyKey, dummyPt);

    const meta = await saveEncryptedVault(blob, 'cred-1234');
    expect(meta.credentialId).toBe('cred-1234');
    expect(meta.byteLength).toBe(blob.length);

    const loaded = await loadEncryptedVault();
    expect(loaded).not.toBeNull();
    expect(loaded!.blob).toEqual(blob);
    expect(loaded!.metadata.credentialId).toBe('cred-1234');
  });

  it('clearVaultStorage 실행 시 스토리지 데이터가 비워져야 한다', async () => {
    const dummyKey = new Uint8Array(32).fill(0x11);
    const blob = core.encryptVault(dummyKey, new Uint8Array([1, 2, 3]));

    await saveEncryptedVault(blob, 'cred-1234');
    expect(await loadEncryptedVault()).not.toBeNull();

    await clearVaultStorage();
    expect(await loadEncryptedVault()).toBeNull();
  });

  it('볼트 직렬화 -> 암호화 -> 스토리지 I/O -> 복호화 -> 역직렬화 E2E 파이프라인이 100% 무결성을 유지해야 한다', async () => {
    // 1. 볼트 데이터 생성
    const originalVault: VaultData = {
      version: 1,
      credentialId: 'webauthn-cred-id-abc',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      entries: [
        {
          id: 'acc-uuid-001',
          domain: 'naver.com',
          username: 'security-admin',
          password: 'UltraSecurePassword123!@#',
          notes: '메인 관리자 계정',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
        {
          id: 'acc-uuid-002',
          domain: 'github.com',
          username: 'prfvault-developer',
          password: 'PasskeySupported456$%^',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      ],
    };

    // 2. 직렬화
    const plaintext = serializeVault(originalVault);

    // 3. WebAuthn PRF 출력 (가상 32B) & Salt 기반 HKDF 마스터 키 도출
    const virtualPrfSecret = new Uint8Array(32).fill(0x7a);
    const salt = new Uint8Array(32).fill(0x9b);
    const masterKey = core.deriveMasterKey(virtualPrfSecret, salt);

    // 4. AES-256-GCM 암호화 (와이어 포맷 패킹)
    const extId = 'abcdefghijklmnopqrstuvwxyz123456';
    const aad = new TextEncoder().encode(extId);
    const encryptedBlob = core.encryptVault(masterKey, plaintext, aad);

    // 5. chrome.storage.local에 저장
    const savedMeta = await saveEncryptedVault(encryptedBlob, originalVault.credentialId);
    expect(savedMeta.byteLength).toBe(encryptedBlob.length);

    // 6. 스토리지에서 다시 읽기
    const storedRecord = await loadEncryptedVault();
    expect(storedRecord).not.toBeNull();
    expect(storedRecord!.blob).toEqual(encryptedBlob);

    // 7. 복호화
    const decryptedPt = core.decryptVault(masterKey, storedRecord!.blob, aad);

    // 8. 볼트 데이터 역직렬화 및 검증
    const restoredVault = deserializeVault(decryptedPt);
    expect(restoredVault).toEqual(originalVault);
    expect(restoredVault.entries.length).toBe(2);
    expect(restoredVault.entries[0].username).toBe('security-admin');
    expect(restoredVault.entries[0].password).toBe('UltraSecurePassword123!@#');
  });
});
