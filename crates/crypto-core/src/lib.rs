use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

// FFI 상태 및 에러 코드 상수 (docs/01-architecture-spec.md 준수)
pub const SUCCESS: i32 = 0;
pub const ERR_NULL_POINTER: i32 = -1;
pub const ERR_INVALID_PAYLOAD_LEN: i32 = -2;
pub const ERR_UNSUPPORTED_VERSION: i32 = -3;
pub const ERR_TAG_VERIFICATION: i32 = -4;
pub const ERR_HKDF_FAILED: i32 = -5;
pub const ERR_ALLOCATION_FAILED: i32 = -6;

// 프로토콜 바이너리 레이아웃 상수
pub const SCHEMA_VERSION: u16 = 0x0001;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const MIN_PAYLOAD_LEN: usize = 2 + SALT_LEN + NONCE_LEN + 4 + TAG_LEN; // 66 바이트
pub const HKDF_INFO: &[u8] = b"PrfVault/v1/MasterEncryptionKey";

/// Wasm 선형 메모리에 지정 바이트 크기의 연속 버퍼를 할당하고 포인터를 반환합니다.
///
/// # Safety
/// 반환된 포인터는 반드시 `prf_vault_dealloc_zeroize`를 통해 수명 해제되어야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prf_vault_alloc(size: usize) -> *mut u8 {
    if size == 0 {
        return std::ptr::null_mut();
    }
    let mut buffer = vec![0u8; size].into_boxed_slice();
    let ptr = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    ptr
}

/// Wasm 선형 메모리의 버퍼를 0x00으로 물리 소거(volatile write)한 후 할당 해제합니다.
///
/// # Safety
/// - `ptr`는 `prf_vault_alloc` 또는 내부에서 Box로 할당된 유효 포인터여야 합니다.
/// - `size`는 할당 당시의 정확한 바이트 크기여야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prf_vault_dealloc_zeroize(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, size);
        slice.zeroize();
        let boxed = Box::from_raw(slice as *mut [u8]);
        drop(boxed);
    }
}

/// WebAuthn PRF 출력과 볼트 Salt로부터 HKDF-SHA-256을 통해 마스터 키(32바이트)를 도출합니다.
///
/// # Safety
/// - `prf_output_ptr`: 최소 32바이트 유효 버퍼 포인터
/// - `salt_ptr`: 최소 32바이트 유효 버퍼 포인터
/// - `out_key_ptr`: 32바이트 쓰기 가능한 버퍼 포인터
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prf_vault_derive_master_key(
    prf_output_ptr: *const u8,
    salt_ptr: *const u8,
    out_key_ptr: *mut u8,
) -> i32 {
    if prf_output_ptr.is_null() || salt_ptr.is_null() || out_key_ptr.is_null() {
        return ERR_NULL_POINTER;
    }

    let (prf_output, salt) = unsafe {
        (
            std::slice::from_raw_parts(prf_output_ptr, 32),
            std::slice::from_raw_parts(salt_ptr, 32),
        )
    };

    let hk = Hkdf::<Sha256>::new(Some(salt), prf_output);
    let mut okm = [0u8; 32];
    if hk.expand(HKDF_INFO, &mut okm).is_err() {
        return ERR_HKDF_FAILED;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(okm.as_ptr(), out_key_ptr, 32);
    }
    okm.zeroize();

    SUCCESS
}

/// 평문 데이터를 AES-256-GCM 및 AAD로 암호화하고 바이너리 와이어 포맷으로 패킹합니다.
///
/// # Safety
/// - 포인터 인자들은 유효한 메모리 범위를 가리켜야 합니다.
/// - 반환된 `*out_blob_ptr`는 `prf_vault_dealloc_zeroize`로 해제해야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prf_vault_encrypt(
    key_ptr: *const u8,
    aad_ptr: *const u8,
    aad_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    out_blob_ptr: *mut *mut u8,
    out_blob_len: *mut usize,
) -> i32 {
    if key_ptr.is_null() || out_blob_ptr.is_null() || out_blob_len.is_null() {
        return ERR_NULL_POINTER;
    }
    if aad_len > 0 && aad_ptr.is_null() {
        return ERR_NULL_POINTER;
    }
    if plaintext_len > 0 && plaintext_ptr.is_null() {
        return ERR_NULL_POINTER;
    }

    let key_slice = unsafe { std::slice::from_raw_parts(key_ptr, 32) };
    let aad_slice = if aad_len > 0 {
        unsafe { std::slice::from_raw_parts(aad_ptr, aad_len) }
    } else {
        &[]
    };
    let pt_slice = if plaintext_len > 0 {
        unsafe { std::slice::from_raw_parts(plaintext_ptr, plaintext_len) }
    } else {
        &[]
    };

    // 1. Salt (32B) 생성
    let mut salt = [0u8; SALT_LEN];
    if getrandom::getrandom(&mut salt).is_err() {
        return ERR_ALLOCATION_FAILED;
    }

    // 2. Nonce (12B) 생성
    let mut nonce_bytes = [0u8; NONCE_LEN];
    if getrandom::getrandom(&mut nonce_bytes).is_err() {
        return ERR_ALLOCATION_FAILED;
    }

    // 3. AES-256-GCM 암호화
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_slice));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = Payload {
        msg: pt_slice,
        aad: aad_slice,
    };

    let ciphertext_and_tag = match cipher.encrypt(nonce, payload) {
        Ok(ct) => ct,
        Err(_) => return ERR_TAG_VERIFICATION,
    };

    if ciphertext_and_tag.len() < TAG_LEN {
        return ERR_TAG_VERIFICATION;
    }

    let ct_len = ciphertext_and_tag.len() - TAG_LEN;
    let ct = &ciphertext_and_tag[..ct_len];
    let tag = &ciphertext_and_tag[ct_len..];

    // 4. Binary Wire Format 패킹
    // Schema(2B) + Salt(32B) + Nonce(12B) + CiphertextLength(4B) + Ciphertext(Var) + Tag(16B)
    let total_len = MIN_PAYLOAD_LEN + ct_len;
    let mut blob = Vec::with_capacity(total_len);

    blob.extend_from_slice(&SCHEMA_VERSION.to_be_bytes());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&(ct_len as u32).to_be_bytes());
    blob.extend_from_slice(ct);
    blob.extend_from_slice(tag);

    let mut boxed = blob.into_boxed_slice();
    unsafe {
        *out_blob_len = boxed.len();
        *out_blob_ptr = boxed.as_mut_ptr();
    }
    std::mem::forget(boxed);

    SUCCESS
}

/// 바이너리 와이어 포맷 볼트를 파싱하고 AAD 및 태그를 검증하여 복호화된 평문을 반환합니다.
///
/// # Safety
/// - 포인터 인자들은 유효한 메모리 범위를 가리켜야 합니다.
/// - 반환된 `*out_pt_ptr`는 `prf_vault_dealloc_zeroize`로 해제해야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prf_vault_decrypt(
    key_ptr: *const u8,
    aad_ptr: *const u8,
    aad_len: usize,
    blob_ptr: *const u8,
    blob_len: usize,
    out_pt_ptr: *mut *mut u8,
    out_pt_len: *mut usize,
) -> i32 {
    if key_ptr.is_null() || blob_ptr.is_null() || out_pt_ptr.is_null() || out_pt_len.is_null() {
        return ERR_NULL_POINTER;
    }
    if aad_len > 0 && aad_ptr.is_null() {
        return ERR_NULL_POINTER;
    }

    if blob_len < MIN_PAYLOAD_LEN {
        return ERR_INVALID_PAYLOAD_LEN;
    }

    let blob = unsafe { std::slice::from_raw_parts(blob_ptr, blob_len) };
    let key_slice = unsafe { std::slice::from_raw_parts(key_ptr, 32) };
    let aad_slice = if aad_len > 0 {
        unsafe { std::slice::from_raw_parts(aad_ptr, aad_len) }
    } else {
        &[]
    };

    // 1. Schema Version 검증
    let schema_ver = u16::from_be_bytes([blob[0], blob[1]]);
    if schema_ver != SCHEMA_VERSION {
        return ERR_UNSUPPORTED_VERSION;
    }

    // 2. 오프셋 파싱
    // [0..2]: Schema Ver
    // [2..34]: Salt (32B)
    // [34..46]: Nonce (12B)
    // [46..50]: Ciphertext Length (4B, BE)
    let nonce_bytes = &blob[34..46];
    let ct_len = u32::from_be_bytes([blob[46], blob[47], blob[48], blob[49]]) as usize;

    if blob_len != MIN_PAYLOAD_LEN + ct_len {
        return ERR_INVALID_PAYLOAD_LEN;
    }

    let ct = &blob[50..50 + ct_len];
    let tag = &blob[50 + ct_len..50 + ct_len + TAG_LEN];

    // 3. 복호화 페이로드 재구성 (aes-gcm은 ct || tag 포맷 기대)
    let mut ct_with_tag = Vec::with_capacity(ct_len + TAG_LEN);
    ct_with_tag.extend_from_slice(ct);
    ct_with_tag.extend_from_slice(tag);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_slice));
    let nonce = Nonce::from_slice(nonce_bytes);
    let payload = Payload {
        msg: &ct_with_tag,
        aad: aad_slice,
    };

    let pt = match cipher.decrypt(nonce, payload) {
        Ok(plain) => plain,
        Err(_) => return ERR_TAG_VERIFICATION,
    };

    let mut boxed = pt.into_boxed_slice();
    unsafe {
        *out_pt_len = boxed.len();
        *out_pt_ptr = boxed.as_mut_ptr();
    }
    std::mem::forget(boxed);

    SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_alloc_and_zeroize() {
        unsafe {
            let size = 64;
            let ptr = prf_vault_alloc(size);
            assert!(!ptr.is_null());

            // 버퍼에 더미 값 기록
            for i in 0..size {
                *ptr.add(i) = 0xAA;
            }

            prf_vault_dealloc_zeroize(ptr, size);
        }
    }

    #[test]
    fn test_hkdf_derive_master_key() {
        unsafe {
            let prf_output = [0x42u8; 32];
            let salt = [0x11u8; 32];
            let mut derived_key = [0u8; 32];

            let res = prf_vault_derive_master_key(
                prf_output.as_ptr(),
                salt.as_ptr(),
                derived_key.as_mut_ptr(),
            );
            assert_eq!(res, SUCCESS);
            assert_ne!(derived_key, [0u8; 32]);
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_and_aad_binding() {
        unsafe {
            let key = [0x33u8; 32];
            let aad = b"test-extension-id-12345678901234";
            let plaintext = b"{\"site\":\"github.com\",\"password\":\"SuperSecret123!\"}";

            let mut blob_ptr: *mut u8 = std::ptr::null_mut();
            let mut blob_len: usize = 0;

            // 1. 암호화
            let enc_res = prf_vault_encrypt(
                key.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                &mut blob_ptr,
                &mut blob_len,
            );
            assert_eq!(enc_res, SUCCESS);
            assert!(blob_len >= MIN_PAYLOAD_LEN + plaintext.len());
            assert!(!blob_ptr.is_null());

            // 2. 정상 복호화
            let mut pt_ptr: *mut u8 = std::ptr::null_mut();
            let mut pt_len: usize = 0;

            let dec_res = prf_vault_decrypt(
                key.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                blob_ptr,
                blob_len,
                &mut pt_ptr,
                &mut pt_len,
            );
            assert_eq!(dec_res, SUCCESS);
            assert_eq!(pt_len, plaintext.len());

            let recovered_slice = std::slice::from_raw_parts(pt_ptr, pt_len);
            assert_eq!(recovered_slice, plaintext);

            prf_vault_dealloc_zeroize(pt_ptr, pt_len);

            // 3. AAD 변조 탐지 테스트 (다른 extension_id 주입)
            let forged_aad = b"forged-malicious-extension-id-99";
            let mut bad_pt_ptr: *mut u8 = std::ptr::null_mut();
            let mut bad_pt_len: usize = 0;

            let forged_dec_res = prf_vault_decrypt(
                key.as_ptr(),
                forged_aad.as_ptr(),
                forged_aad.len(),
                blob_ptr,
                blob_len,
                &mut bad_pt_ptr,
                &mut bad_pt_len,
            );
            assert_eq!(forged_dec_res, ERR_TAG_VERIFICATION);

            // 4. 비정상 크기 주입 차단 테스트
            let mut invalid_pt_ptr: *mut u8 = std::ptr::null_mut();
            let mut invalid_pt_len: usize = 0;
            let invalid_len_res = prf_vault_decrypt(
                key.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                blob_ptr,
                MIN_PAYLOAD_LEN - 1,
                &mut invalid_pt_ptr,
                &mut invalid_pt_len,
            );
            assert_eq!(invalid_len_res, ERR_INVALID_PAYLOAD_LEN);

            // 메모리 소거 해제
            prf_vault_dealloc_zeroize(blob_ptr, blob_len);
        }
    }
}
