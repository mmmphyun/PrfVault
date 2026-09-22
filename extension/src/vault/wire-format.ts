/**
 * PrfVault 바이너리 와이어 포맷(Binary Wire Format) 및 AAD 빌더
 *
 * [보안 설계 및 와이어 레이아웃 규격 (docs/01-architecture-spec.md)]
 * 1. Binary Wire Format (Big-Endian):
 *    - Schema Ver (2B) + Salt (32B) + Nonce (12B) + Ciphertext Length (4B) + Ciphertext (Var) + Tag (16B)
 *    - 최소 페이로드 길이: 66바이트
 * 2. AAD (Additional Authenticated Data):
 *    - Schema Ver (2B, BE) + Ext ID Length (2B, BE) + chrome.runtime.id (ASCII 32B) = 36바이트
 *    - 런타임 Extension ID를 암호화 무결성에 수학적으로 바인딩하여 타 확장프로그램 주입/탈취 원천 차단
 */

export const SCHEMA_VERSION = 0x0001;
export const SALT_LEN = 32;
export const NONCE_LEN = 12;
export const TAG_LEN = 16;
export const MIN_PAYLOAD_LEN = 2 + SALT_LEN + NONCE_LEN + 4 + TAG_LEN; // 66 바이트

export interface ParsedWireFormat {
  schemaVersion: number;
  salt: Uint8Array;
  nonce: Uint8Array;
  ciphertextLength: number;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

/**
 * 런타임 Extension ID 기반 36바이트 AAD 바이너리 버퍼를 생성합니다.
 */
export function buildAad(extensionId: string, schemaVersion: number = SCHEMA_VERSION): Uint8Array {
  const extIdBytes = new TextEncoder().encode(extensionId);
  const extIdLen = extIdBytes.length;

  const totalLen = 2 + 2 + extIdLen;
  const buffer = new Uint8Array(totalLen);
  const view = new DataView(buffer.buffer);

  // 1. Schema Version (2B, Big-Endian)
  view.setUint16(0, schemaVersion, false);
  // 2. Extension ID Length (2B, Big-Endian)
  view.setUint16(2, extIdLen, false);
  // 3. Extension ID (ASCII)
  buffer.set(extIdBytes, 4);

  return buffer;
}

/**
 * 바이너리 와이어 포맷 블롭을 파싱하고 오프셋 및 무결성을 검증합니다.
 */
export function parseWireFormat(blob: Uint8Array): ParsedWireFormat {
  if (blob.length < MIN_PAYLOAD_LEN) {
    throw new Error(
      `와이어 포맷 최소 길이(${MIN_PAYLOAD_LEN}바이트)에 미달합니다. (현재: ${blob.length})`
    );
  }

  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);

  // 1. Schema Version (2B, Big-Endian)
  const schemaVersion = view.getUint16(0, false);
  if (schemaVersion !== SCHEMA_VERSION) {
    throw new Error(`지원되지 않는 스키마 버전입니다: 0x${schemaVersion.toString(16).padStart(4, '0')}`);
  }

  // 2. Salt (32B)
  const salt = blob.slice(2, 2 + SALT_LEN);

  // 3. Nonce (12B)
  const nonce = blob.slice(2 + SALT_LEN, 2 + SALT_LEN + NONCE_LEN);

  // 4. Ciphertext Length (4B, Big-Endian)
  const ctLenOffset = 2 + SALT_LEN + NONCE_LEN;
  const ciphertextLength = view.getUint32(ctLenOffset, false);

  const expectedTotalLen = MIN_PAYLOAD_LEN + ciphertextLength;
  if (blob.length !== expectedTotalLen) {
    throw new Error(
      `암호문 길이 필드(${ciphertextLength})와 실제 블롭 전체 크기(${blob.length})가 일치하지 않습니다.`
    );
  }

  // 5. Ciphertext (Var)
  const ctOffset = ctLenOffset + 4;
  const ciphertext = blob.slice(ctOffset, ctOffset + ciphertextLength);

  // 6. Tag (16B)
  const tagOffset = ctOffset + ciphertextLength;
  const tag = blob.slice(tagOffset, tagOffset + TAG_LEN);

  return {
    schemaVersion,
    salt,
    nonce,
    ciphertextLength,
    ciphertext,
    tag,
  };
}
