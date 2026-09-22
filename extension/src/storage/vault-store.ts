/**
 * chrome.storage.local 기반 암호화 볼트 및 메타데이터 영구 저장소
 *
 * [보안 설계 및 스토리지 불변성 원칙]
 * - 평문 비밀번호 및 도출된 대칭키는 영구 스토리지에 절대 기록하지 않습니다.
 * - 오직 와이어 포맷으로 패킹된 암호문 블롭(Base64URL 직렬화) 및 인증 메타데이터(Salt, Credential ID)만 보관합니다.
 * - 스토리지 읽기/쓰기 시 chrome.storage.local API 오류를 엄격히 감지하여 트랜잭션 롤백 및 에러를 전파합니다.
 */

import { parseWireFormat } from '../vault/wire-format';
import { base64UrlEncode, base64UrlDecode, toHex } from '../auth/webauthn-prf';

export const STORAGE_KEY_BLOB = 'prfvault_encrypted_blob';
export const STORAGE_KEY_META = 'prfvault_metadata';

export interface VaultMetadata {
  credentialId: string;
  saltHex: string;
  schemaVersion: number;
  updatedAt: string;
  byteLength: number;
}

export interface StoredVaultRecord {
  blob: Uint8Array;
  metadata: VaultMetadata;
}

/**
 * 암호화된 볼트 블롭과 자격 증명 식별자를 chrome.storage.local에 원자적으로 저장합니다.
 */
export async function saveEncryptedVault(
  blob: Uint8Array,
  credentialId: string
): Promise<VaultMetadata> {
  // 저장 전 와이어 포맷 무결성 사전 검증 (손상된 블롭 저장 원천 차단)
  const parsed = parseWireFormat(blob);

  const metadata: VaultMetadata = {
    credentialId,
    saltHex: toHex(parsed.salt),
    schemaVersion: parsed.schemaVersion,
    updatedAt: new Date().toISOString(),
    byteLength: blob.length,
  };

  const encodedBlob = base64UrlEncode(blob);

  await new Promise<void>((resolve, reject) => {
    chrome.storage.local.set(
      {
        [STORAGE_KEY_BLOB]: encodedBlob,
        [STORAGE_KEY_META]: metadata,
      },
      () => {
        if (chrome.runtime.lastError) {
          reject(new Error(`스토리지 저장 실패: ${chrome.runtime.lastError.message}`));
        } else {
          resolve();
        }
      }
    );
  });

  return metadata;
}

/**
 * 로컬 스토리지에서 암호화된 볼트 블롭과 메타데이터를 조회합니다.
 */
export async function loadEncryptedVault(): Promise<StoredVaultRecord | null> {
  const result = await new Promise<Record<string, any>>((resolve, reject) => {
    chrome.storage.local.get([STORAGE_KEY_BLOB, STORAGE_KEY_META], (items) => {
      if (chrome.runtime.lastError) {
        reject(new Error(`스토리지 조회 실패: ${chrome.runtime.lastError.message}`));
      } else {
        resolve(items);
      }
    });
  });

  const rawBlob = result[STORAGE_KEY_BLOB];
  const metadata = result[STORAGE_KEY_META] as VaultMetadata | undefined;

  if (!rawBlob || !metadata) {
    return null;
  }

  const blob = base64UrlDecode(rawBlob);
  return {
    blob,
    metadata,
  };
}

/**
 * 저장된 볼트 데이터 전체를 완전히 초기화(삭제)합니다.
 */
export async function clearVaultStorage(): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    chrome.storage.local.remove([STORAGE_KEY_BLOB, STORAGE_KEY_META], () => {
      if (chrome.runtime.lastError) {
        reject(new Error(`스토리지 초기화 실패: ${chrome.runtime.lastError.message}`));
      } else {
        resolve();
      }
    });
  });
}
