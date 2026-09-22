/**
 * Rust Wasm Crypto Core C-ABI FFI 정의 및 에러 코드
 *
 * [보안 제약]
 * - FFI 경계를 넘나드는 모든 민감 버퍼(PRF 출력, Salt, MasterKey, Plaintext)는
 *   작업 직후 prf_vault_dealloc_zeroize를 통해 물리적 0x00으로 소거되어야 합니다.
 */

export const CryptoErrorCode = {
  SUCCESS: 0,
  ERR_NULL_POINTER: -1,
  ERR_INVALID_PAYLOAD_LEN: -2,
  ERR_UNSUPPORTED_VERSION: -3,
  ERR_TAG_VERIFICATION: -4,
  ERR_HKDF_FAILED: -5,
  ERR_ALLOCATION_FAILED: -6,
} as const;

export type CryptoErrorCode = typeof CryptoErrorCode[keyof typeof CryptoErrorCode];

export interface CryptoCoreWasmExports {
  memory: WebAssembly.Memory;
  prf_vault_alloc: (size: number) => number;
  prf_vault_dealloc_zeroize: (ptr: number, size: number) => void;
  prf_vault_derive_master_key: (prfOutputPtr: number, saltPtr: number, outKeyPtr: number) => number;
  prf_vault_encrypt: (
    keyPtr: number,
    aadPtr: number,
    aadLen: number,
    plaintextPtr: number,
    plaintextLen: number,
    outBlobPtrPtr: number,
    outBlobLenPtr: number
  ) => number;
  prf_vault_decrypt: (
    keyPtr: number,
    aadPtr: number,
    aadLen: number,
    blobPtr: number,
    blobLen: number,
    outPtPtrPtr: number,
    outPtLenPtr: number
  ) => number;
}
