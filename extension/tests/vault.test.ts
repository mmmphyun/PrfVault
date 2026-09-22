import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { buildAad, parseWireFormat, SCHEMA_VERSION, MIN_PAYLOAD_LEN } from '../src/vault/wire-format';
import { serializeVault, deserializeVault, type VaultData } from '../src/vault/model';
import { createCryptoCore, CryptoCore } from '../src/crypto/wasm-core';

describe('볼트 데이터 모델 및 바이너리 와이어 포맷 테스트', () => {
  let core: CryptoCore;

  beforeAll(async () => {
    const wasmPath = path.resolve(__dirname, '../src/crypto/wasm/crypto_core_bg.wasm');
    const wasmBuffer = fs.readFileSync(wasmPath);
    core = await createCryptoCore(wasmBuffer);
  });

  it('buildAad가 36바이트의 올바른 Big-Endian 레이아웃을 생성해야 한다', () => {
    const extId = 'abcdefghijklmnopqrstuvwxyz123456'; // 32자
    const aad = buildAad(extId);

    expect(aad.length).toBe(36);
    const view = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);

    expect(view.getUint16(0, false)).toBe(SCHEMA_VERSION); // 0x0001
    expect(view.getUint16(2, false)).toBe(32); // 0x0020
    const extractedId = new TextDecoder().decode(aad.slice(4));
    expect(extractedId).toBe(extId);
  });

  it('Rust Wasm 암호화 블롭을 parseWireFormat으로 정상 파싱해야 한다', () => {
    const key = new Uint8Array(32).fill(0x55);
    const plaintext = new TextEncoder().encode('Sensitive Payload');
    const blob = core.encryptVault(key, plaintext);

    const parsed = parseWireFormat(blob);
    expect(parsed.schemaVersion).toBe(SCHEMA_VERSION);
    expect(parsed.salt.length).toBe(32);
    expect(parsed.nonce.length).toBe(12);
    expect(parsed.ciphertextLength).toBe(plaintext.length);
    expect(parsed.ciphertext.length).toBe(plaintext.length);
    expect(parsed.tag.length).toBe(16);
  });

  it('와이어 포맷 크기가 66바이트 미만이면 예외를 던져야 한다', () => {
    const shortBlob = new Uint8Array(65);
    expect(() => parseWireFormat(shortBlob)).toThrow(/최소 길이.*미달/);
  });

  it('지원되지 않는 스키마 버전이면 예외를 던져야 한다', () => {
    const blob = new Uint8Array(MIN_PAYLOAD_LEN);
    new DataView(blob.buffer).setUint16(0, 0x0099, false); // 잘못된 버전

    expect(() => parseWireFormat(blob)).toThrow(/지원되지 않는 스키마 버전/);
  });

  it('볼트 데이터 모델 직렬화 및 역직렬화가 완벽하게 일치해야 한다', () => {
    const originalVault: VaultData = {
      version: 1,
      credentialId: 'mock-cred-id-base64',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      entries: [
        {
          id: '123e4567-e89b-12d3-a456-426614174000',
          domain: 'github.com',
          username: 'user@example.com',
          password: 'SecretPassword123!',
          notes: '개인용 계정',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      ],
    };

    const serialized = serializeVault(originalVault);
    expect(serialized).toBeInstanceOf(Uint8Array);

    const restored = deserializeVault(serialized);
    expect(restored).toEqual(originalVault);
  });
});
