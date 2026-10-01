/**
 * Rust Wasm Crypto Core FFI 래퍼 및 선형 메모리 수명 관리자
 *
 * [보안 설계 및 제약사항]
 * - Wasm 선형 메모리 내에 잔류하는 마스터 키, 평문, PRF 비밀값은 가비지 컬렉터의 관리 대상이 아닙니다.
 * - 따라서 모든 암복호화 및 키 유도 연산은 try-finally 블록 내에서 prf_vault_dealloc_zeroize를
 *   강제 호출하여 예외 발생 여부와 무관하게 0x00 휘발성 소거(Volatile zeroize)를 보장합니다.
 */

import { CryptoErrorCode, type CryptoCoreWasmExports } from './types';
import initWasm, { initSync } from './wasm/crypto_core.js';

export class CryptoCore {
  private exports: CryptoCoreWasmExports;

  constructor(exports: CryptoCoreWasmExports) {
    this.exports = exports;
  }

  /**
   * WebAuthn PRF 출력(32B)과 볼트 Salt(32B)로부터 HKDF-SHA-256 마스터 키를 도출합니다.
   */
  public deriveMasterKey(prfSecret: Uint8Array, salt: Uint8Array): Uint8Array {
    if (prfSecret.length !== 32) {
      throw new Error(`PRF Secret은 정확히 32바이트여야 합니다. (현재: ${prfSecret.length})`);
    }
    if (salt.length !== 32) {
      throw new Error(`Salt는 정확히 32바이트여야 합니다. (현재: ${salt.length})`);
    }

    const { prf_vault_alloc, prf_vault_dealloc_zeroize, prf_vault_derive_master_key, memory } = this.exports;

    const prfPtr = prf_vault_alloc(32);
    const saltPtr = prf_vault_alloc(32);
    const outKeyPtr = prf_vault_alloc(32);

    if (!prfPtr || !saltPtr || !outKeyPtr) {
      throw new Error('Wasm 선형 메모리 할당에 실패했습니다.');
    }

    try {
      new Uint8Array(memory.buffer, prfPtr, 32).set(prfSecret);
      new Uint8Array(memory.buffer, saltPtr, 32).set(salt);

      const code = prf_vault_derive_master_key(prfPtr, saltPtr, outKeyPtr);
      if (code !== CryptoErrorCode.SUCCESS) {
        throw new Error(`HKDF 마스터 키 도출 실패 (에러 코드: ${code})`);
      }

      // 결과 키 복사 (32바이트)
      const masterKey = new Uint8Array(memory.buffer, outKeyPtr, 32).slice();
      return masterKey;
    } finally {
      prf_vault_dealloc_zeroize(prfPtr, 32);
      prf_vault_dealloc_zeroize(saltPtr, 32);
      prf_vault_dealloc_zeroize(outKeyPtr, 32);
    }
  }

  /**
   * 마스터 키로 평문을 AES-256-GCM 암호화하고 바이너리 와이어 포맷 패킷을 생성합니다.
   * 반환 규격: Schema(2B) + Salt(32B) + Nonce(12B) + Length(4B) + Ciphertext(Var) + Tag(16B)
   */
  public encryptVault(masterKey: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Uint8Array {
    if (masterKey.length !== 32) {
      throw new Error(`마스터 키는 32바이트여야 합니다. (현재: ${masterKey.length})`);
    }

    const { prf_vault_alloc, prf_vault_dealloc_zeroize, prf_vault_encrypt, memory } = this.exports;

    const keyPtr = prf_vault_alloc(32);
    const ptLen = plaintext.length;
    const ptPtr = ptLen > 0 ? prf_vault_alloc(ptLen) : 0;
    const aadLen = aad ? aad.length : 0;
    const aadPtr = aadLen > 0 ? prf_vault_alloc(aadLen) : 0;

    // 포인터 포인터 및 길이 버퍼 (각 4바이트)
    const outBlobPtrPtr = prf_vault_alloc(4);
    const outBlobLenPtr = prf_vault_alloc(4);

    let allocatedBlobPtr = 0;
    let allocatedBlobLen = 0;

    try {
      new Uint8Array(memory.buffer, keyPtr, 32).set(masterKey);
      if (ptPtr && ptLen > 0) {
        new Uint8Array(memory.buffer, ptPtr, ptLen).set(plaintext);
      }
      if (aadPtr && aadLen > 0 && aad) {
        new Uint8Array(memory.buffer, aadPtr, aadLen).set(aad);
      }

      const code = prf_vault_encrypt(
        keyPtr,
        aadPtr,
        aadLen,
        ptPtr,
        ptLen,
        outBlobPtrPtr,
        outBlobLenPtr
      );

      if (code !== CryptoErrorCode.SUCCESS) {
        throw new Error(`AES-256-GCM 암호화 실패 (에러 코드: ${code})`);
      }

      allocatedBlobPtr = new DataView(memory.buffer).getUint32(outBlobPtrPtr, true);
      allocatedBlobLen = new DataView(memory.buffer).getUint32(outBlobLenPtr, true);

      const resultBlob = new Uint8Array(memory.buffer, allocatedBlobPtr, allocatedBlobLen).slice();
      return resultBlob;
    } finally {
      prf_vault_dealloc_zeroize(keyPtr, 32);
      if (ptPtr && ptLen > 0) prf_vault_dealloc_zeroize(ptPtr, ptLen);
      if (aadPtr && aadLen > 0) prf_vault_dealloc_zeroize(aadPtr, aadLen);
      prf_vault_dealloc_zeroize(outBlobPtrPtr, 4);
      prf_vault_dealloc_zeroize(outBlobLenPtr, 4);
      if (allocatedBlobPtr && allocatedBlobLen > 0) {
        prf_vault_dealloc_zeroize(allocatedBlobPtr, allocatedBlobLen);
      }
    }
  }

  /**
   * 바이너리 와이어 포맷 패킷을 검증하고 복호화하여 평문 버퍼를 반환합니다.
   */
  public decryptVault(masterKey: Uint8Array, blob: Uint8Array, aad?: Uint8Array): Uint8Array {
    if (masterKey.length !== 32) {
      throw new Error(`마스터 키는 32바이트여야 합니다. (현재: ${masterKey.length})`);
    }

    const { prf_vault_alloc, prf_vault_dealloc_zeroize, prf_vault_decrypt, memory } = this.exports;

    const keyPtr = prf_vault_alloc(32);
    const blobLen = blob.length;
    const blobPtr = prf_vault_alloc(blobLen);
    const aadLen = aad ? aad.length : 0;
    const aadPtr = aadLen > 0 ? prf_vault_alloc(aadLen) : 0;

    const outPtPtrPtr = prf_vault_alloc(4);
    const outPtLenPtr = prf_vault_alloc(4);

    let allocatedPtPtr = 0;
    let allocatedPtLen = 0;

    try {
      new Uint8Array(memory.buffer, keyPtr, 32).set(masterKey);
      new Uint8Array(memory.buffer, blobPtr, blobLen).set(blob);
      if (aadPtr && aadLen > 0 && aad) {
        new Uint8Array(memory.buffer, aadPtr, aadLen).set(aad);
      }

      const code = prf_vault_decrypt(
        keyPtr,
        aadPtr,
        aadLen,
        blobPtr,
        blobLen,
        outPtPtrPtr,
        outPtLenPtr
      );

      if (code !== CryptoErrorCode.SUCCESS) {
        throw new Error(`AES-256-GCM 복호화 검증 실패 (에러 코드: ${code})`);
      }

      allocatedPtPtr = new DataView(memory.buffer).getUint32(outPtPtrPtr, true);
      allocatedPtLen = new DataView(memory.buffer).getUint32(outPtLenPtr, true);

      const plaintext = new Uint8Array(memory.buffer, allocatedPtPtr, allocatedPtLen).slice();
      return plaintext;
    } finally {
      prf_vault_dealloc_zeroize(keyPtr, 32);
      prf_vault_dealloc_zeroize(blobPtr, blobLen);
      if (aadPtr && aadLen > 0) prf_vault_dealloc_zeroize(aadPtr, aadLen);
      prf_vault_dealloc_zeroize(outPtPtrPtr, 4);
      prf_vault_dealloc_zeroize(outPtLenPtr, 4);
      if (allocatedPtPtr && allocatedPtLen > 0) {
        prf_vault_dealloc_zeroize(allocatedPtPtr, allocatedPtLen);
      }
    }
  }
}

/**
 * Wasm 모듈을 초기화하여 CryptoCore 인스턴스를 반환합니다.
 * @param source Wasm 바이트 버퍼 또는 URL/경로 (생략 시 기본 경로 사용)
 */
export async function createCryptoCore(
  source?: BufferSource | WebAssembly.Module | string | URL
): Promise<CryptoCore> {
  let exports: CryptoCoreWasmExports;

  if (source && (source instanceof ArrayBuffer || ArrayBuffer.isView(source) || source instanceof WebAssembly.Module)) {
    exports = initSync({ module: source as any }) as unknown as CryptoCoreWasmExports;
  } else {
    exports = (await initWasm(source as any)) as unknown as CryptoCoreWasmExports;
  }

  return new CryptoCore(exports);
}

let cachedCryptoCore: CryptoCore | null = null;

export async function getOrCreateCryptoCore(customCore?: CryptoCore): Promise<CryptoCore> {
  if (customCore) return customCore;
  if (!cachedCryptoCore) {
    cachedCryptoCore = await createCryptoCore();
  }
  return cachedCryptoCore;
}

export function setGlobalCryptoCore(core: CryptoCore | null): void {
  cachedCryptoCore = core;
}

