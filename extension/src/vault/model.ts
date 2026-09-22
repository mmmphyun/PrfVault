/**
 * PrfVault 평문 볼트 데이터 모델 및 직렬화/역직렬화 엔진
 *
 * [보안 제약]
 * - 평문 볼트 데이터 모델 객체는 메모리 내에만 머물며, 영구 스토리지에 직접 기록되어서는 안 됩니다.
 * - AES-256-GCM 암호화 직전 UTF-8 JSON 바이트로 직렬화되고, 복호화 직후 파싱됩니다.
 */

export interface VaultEntry {
  id: string;
  domain: string;
  username: string;
  password: string;
  notes?: string;
  createdAt: string;
  updatedAt: string;
}

export interface VaultData {
  version: number;
  credentialId: string;
  createdAt: string;
  updatedAt: string;
  entries: VaultEntry[];
}

/**
 * 볼트 데이터 객체를 정규화된 UTF-8 JSON 바이트열로 직렬화합니다.
 */
export function serializeVault(vault: VaultData): Uint8Array {
  const json = JSON.stringify(vault);
  return new TextEncoder().encode(json);
}

/**
 * 복호화된 평문 바이트열을 볼트 데이터 객체로 파싱하고 유효성을 검증합니다.
 */
export function deserializeVault(bytes: Uint8Array): VaultData {
  const json = new TextDecoder().decode(bytes);
  const data = JSON.parse(json);

  if (!data || typeof data !== 'object' || typeof data.version !== 'number' || !Array.isArray(data.entries)) {
    throw new Error('올바르지 않은 볼트 데이터 포맷입니다.');
  }

  return data as VaultData;
}
