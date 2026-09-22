import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { createCryptoCore, CryptoCore } from '../src/crypto/wasm-core';

describe('Rust Wasm CryptoCore C-ABI 테스트', () => {
  let core: CryptoCore;

  beforeAll(async () => {
    const wasmPath = path.resolve(__dirname, '../src/crypto/wasm/crypto_core_bg.wasm');
    const wasmBuffer = fs.readFileSync(wasmPath);
    core = await createCryptoCore(wasmBuffer);
  });

  it('WebAuthn PRF 출력과 Salt로부터 32바이트 마스터 키를 도출해야 한다', () => {
    const prfSecret = new Uint8Array(32).fill(0x42);
    const salt = new Uint8Array(32).fill(0x11);

    const masterKey = core.deriveMasterKey(prfSecret, salt);
    expect(masterKey).toBeInstanceOf(Uint8Array);
    expect(masterKey.length).toBe(32);
    expect(masterKey).not.toEqual(new Uint8Array(32)); // 비어있지 않음
  });

  it('AES-256-GCM 암호화 및 복호화 라운드트립이 일치해야 한다', () => {
    const key = new Uint8Array(32).fill(0x77);
    const aad = new TextEncoder().encode('test-extension-id');
    const plaintext = new TextEncoder().encode(
      JSON.stringify({ site: 'github.com', password: 'P@ssw0rdSecure!' })
    );

    const blob = core.encryptVault(key, plaintext, aad);
    // 와이어 포맷 최소 길이: 66 + 본문 길이
    expect(blob.length).toBeGreaterThanOrEqual(66 + plaintext.length);

    const decrypted = core.decryptVault(key, blob, aad);
    expect(decrypted).toEqual(plaintext);
    expect(new TextDecoder().decode(decrypted)).toBe(
      JSON.stringify({ site: 'github.com', password: 'P@ssw0rdSecure!' })
    );
  });

  it('AAD가 일치하지 않으면 복호화가 실패해야 한다', () => {
    const key = new Uint8Array(32).fill(0x77);
    const originAad = new TextEncoder().encode('valid-extension-id');
    const forgedAad = new TextEncoder().encode('malicious-extension-id');
    const plaintext = new TextEncoder().encode('Sensitive Payload');

    const blob = core.encryptVault(key, plaintext, originAad);

    expect(() => {
      core.decryptVault(key, blob, forgedAad);
    }).toThrow(/복호화 검증 실패/);
  });

  it('암호문이 변조되거나 잘린 경우 복호화가 실패해야 한다', () => {
    const key = new Uint8Array(32).fill(0x77);
    const plaintext = new TextEncoder().encode('Sensitive Payload');
    const blob = core.encryptVault(key, plaintext);

    // 1바이트 변조
    const tampered = new Uint8Array(blob);
    tampered[tampered.length - 1] ^= 0xff;

    expect(() => {
      core.decryptVault(key, tampered);
    }).toThrow();
  });
});
