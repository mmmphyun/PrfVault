/**
 * @file prfvault_crypto.h
 * @brief PrfVault Rust Crypto Core C-ABI 공식 인터페이스 헤더
 *
 * [아키텍처 및 메모리 안전성 규칙]
 * 1. WebAssembly 선형 메모리는 V8 가비지 컬렉터의 관리 대상이 아닙니다.
 * 2. 본 인터페이스를 통해 할당된 모든 버퍼는 사용 직후 반드시 prf_vault_dealloc_zeroize()를
 *    호출하여 0x00 휘발성 물리 소거(volatile zeroize) 후 해제되어야 합니다.
 * 3. 모든 다중 바이트 정수(Schema, Length)는 Big-Endian(Network Byte Order)을 준수합니다.
 */

#ifndef PRFVAULT_CRYPTO_H
#define PRFVAULT_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/* 에러 코드 상수 (docs/01-architecture-spec.md 준수)                           */
/* ========================================================================== */

#define PRFVAULT_SUCCESS                     0  /**< 정상 처리 완료 */
#define PRFVAULT_ERR_NULL_POINTER          -1  /**< 필수 포인터 인자가 NULL임 */
#define PRFVAULT_ERR_INVALID_PAYLOAD_LEN   -2  /**< 암호문 또는 블롭 길이가 최소 규격(66B) 미만임 */
#define PRFVAULT_ERR_UNSUPPORTED_VERSION   -3  /**< 지원하지 않는 스키마 버전임 (현재 0x0001만 지원) */
#define PRFVAULT_ERR_TAG_VERIFICATION      -4  /**< AES-GCM 무결성 인증 태그 검증 실패 또는 AAD 불일치 */
#define PRFVAULT_ERR_HKDF_FAILED           -5  /**< HKDF-SHA-256 키 유도 연산 실패 */
#define PRFVAULT_ERR_ALLOCATION_FAILED     -6  /**< CSPRNG 난수 생성 또는 메모리 할당 실패 */

/* ========================================================================== */
/* 프로토콜 바이너리 와이어 포맷 상수                                            */
/* ========================================================================== */

#define PRFVAULT_SCHEMA_VERSION        0x0001  /**< 스키마 버전 1 */
#define PRFVAULT_SALT_LEN                  32  /**< PRF 및 HKDF용 솔트 바이트 길이 */
#define PRFVAULT_NONCE_LEN                 12  /**< AES-256-GCM 96비트 IV 길이 */
#define PRFVAULT_TAG_LEN                   16  /**< 128비트 GCM 인증 태그 길이 */
#define PRFVAULT_MIN_PAYLOAD_LEN           66  /**< 최소 유효 블롭 크기 (2+32+12+4+0+16) */
#define PRFVAULT_MASTER_KEY_LEN            32  /**< AES-256 마스터 암호화 키 길이 */

/* ========================================================================== */
/* C-ABI FFI 함수 원형 (Functions)                                            */
/* ========================================================================== */

/**
 * @brief Wasm 선형 메모리에 지정된 바이트 크기만큼의 연속 힙 버퍼를 할당합니다.
 *
 * @param size 할당할 바이트 크기 (0일 경우 NULL 반환)
 * @return uint8_t* 할당된 메모리의 시작 주소 (Wasm 선형 메모리 내 오프셋). 실패 시 NULL.
 *
 * @warning 반환된 포인터는 수명 종료 시 반드시 prf_vault_dealloc_zeroize()로 해제해야 합니다.
 */
uint8_t* prf_vault_alloc(size_t size);

/**
 * @brief Wasm 선형 메모리의 버퍼를 0x00으로 물리 소거(volatile write)한 후 힙에 반환합니다.
 *
 * @note 컴파일러 최적화(Dead Code Elimination)로 소거 명령이 제거되지 않도록 보장합니다.
 *
 * @param ptr prf_vault_alloc으로 할당되었거나 모듈 내부에서 동적 할당된 메모리 주소
 * @param size 할당 당시의 정확한 바이트 크기
 */
void prf_vault_dealloc_zeroize(uint8_t* ptr, size_t size);

/**
 * @brief WebAuthn PRF 출력(32B)과 볼트 Salt(32B)로부터 HKDF-SHA-256 마스터 키를 도출합니다.
 *
 * Info 문자열은 b"PrfVault/v1/MasterEncryptionKey"로 고정 적용됩니다.
 *
 * @param prf_output_ptr 32바이트 PRF Secret 버퍼 (const)
 * @param salt_ptr       32바이트 볼트 Salt 버퍼 (const)
 * @param out_key_ptr    도출된 32바이트 마스터 키가 기록될 출력 버퍼 (out)
 * @return int32_t       성공 시 PRFVAULT_SUCCESS(0), 실패 시 음수 에러 코드
 */
int32_t prf_vault_derive_master_key(
    const uint8_t* prf_output_ptr,
    const uint8_t* salt_ptr,
    uint8_t* out_key_ptr
);

/**
 * @brief 평문 데이터를 AES-256-GCM으로 암호화하고 바이너리 와이어 포맷으로 패킹합니다.
 *
 * 내부적으로 32B Salt와 12B Nonce를 CSPRNG로 독립 생성하여 패킷 헤더에 결합합니다.
 *
 * @param key_ptr       32바이트 AES-256 마스터 키 (const)
 * @param aad_ptr       추가 인증 데이터 버퍼 (const, 없을 경우 NULL)
 * @param aad_len       추가 인증 데이터 바이트 길이
 * @param plaintext_ptr 암호화할 평문 데이터 버퍼 (const)
 * @param plaintext_len 평문 데이터 바이트 길이
 * @param out_blob_ptr  패킹된 바이너리 와이어 포맷 블롭 포인터가 저장될 이중 포인터 (out)
 * @param out_blob_len  패킹된 블롭의 총 바이트 길이가 저장될 포인터 (out)
 * @return int32_t      성공 시 PRFVAULT_SUCCESS(0), 실패 시 음수 에러 코드
 *
 * @note *out_blob_ptr에 할당된 메모리는 호출자가 prf_vault_dealloc_zeroize()로 해제해야 합니다.
 */
int32_t prf_vault_encrypt(
    const uint8_t* key_ptr,
    const uint8_t* aad_ptr,
    size_t aad_len,
    const uint8_t* plaintext_ptr,
    size_t plaintext_len,
    uint8_t** out_blob_ptr,
    size_t* out_blob_len
);

/**
 * @brief 바이너리 와이어 포맷 패킷을 검증하고 AES-256-GCM으로 복호화합니다.
 *
 * 스키마 버전 검증, 길이 일치성 검사, AAD 및 GCM Tag 무결성 검증을 일괄 수행합니다.
 *
 * @param key_ptr       32바이트 AES-256 마스터 키 (const)
 * @param aad_ptr       암호화 당시 바인딩된 추가 인증 데이터 버퍼 (const, 없을 경우 NULL)
 * @param aad_len       추가 인증 데이터 바이트 길이
 * @param blob_ptr      와이어 포맷 암호문 블롭 버퍼 (const)
 * @param blob_len      블롭 바이트 길이 (최소 66바이트 이상)
 * @param out_pt_ptr    복호화된 평문 데이터 포인터가 저장될 이중 포인터 (out)
 * @param out_pt_len    복호화된 평문 바이트 길이가 저장될 포인터 (out)
 * @return int32_t      성공 시 PRFVAULT_SUCCESS(0), 실패 시 음수 에러 코드
 *
 * @note *out_pt_ptr에 할당된 메모리는 호출자가 prf_vault_dealloc_zeroize()로 해제해야 합니다.
 */
int32_t prf_vault_decrypt(
    const uint8_t* key_ptr,
    const uint8_t* aad_ptr,
    size_t aad_len,
    const uint8_t* blob_ptr,
    size_t blob_len,
    uint8_t** out_pt_ptr,
    size_t* out_pt_len
);

#ifdef __cplusplus
}
#endif

#endif /* PRFVAULT_CRYPTO_H */
