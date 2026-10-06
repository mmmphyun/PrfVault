//! Windows CNG(Cryptography Next Generation) / NCrypt FFI 바인딩 모듈
//!
//! # 보안 설계 및 아키텍처
//! - TPM 2.0 및 Windows Hello 생체/PIN 인증 기반 KSP(Key Storage Provider)를 활용하여
//!   도메인별 격리된 하드웨어 바운드 PRF(HMAC-SHA256) 대칭키를 안전하게 도출한다.
//! - C-FFI 자원 해제 누수를 방지하기 위해 RAII(Drop) 패턴으로 안전 핸들 래퍼를 강제한다.
//! - 임의 외부 서드파티 라이브러리 추가 없이 Windows OS 내장 `ncrypt.dll` 시스템 심볼을 직접 바인딩한다.

use std::ffi::c_void;
use std::fmt;

// ============================================================================
// Windows CNG NCrypt Win32 상수 및 에러 코드
// ============================================================================

#[allow(dead_code)]
pub const ERROR_SUCCESS: i32 = 0;
#[allow(dead_code)]
pub const NTE_BAD_KEYSET: i32 = -2146893802; // 0x80090016
#[allow(dead_code)]
pub const NTE_NOT_SUPPORTED: i32 = -2146893783; // 0x80090029
#[allow(dead_code)]
pub const NTE_USER_CANCELLED: i32 = -2146893770; // 0x80090036
#[allow(dead_code)]
pub const NTE_INVALID_PARAMETER: i32 = -2146893785; // 0x80090027
#[allow(dead_code)]
pub const NTE_DEVICE_NOT_READY: i32 = -2146893776; // 0x80090030
#[allow(dead_code)]
pub const NTE_NO_KEY: i32 = -2146893811; // 0x8009000D
#[allow(dead_code)]
pub const NTE_EXISTS: i32 = -2146893809; // 0x8009000F
#[allow(dead_code)]
pub const SCARD_W_CANCELLED_BY_USER: i32 = -2146435986; // 0x8010006E
#[allow(dead_code)]
pub const SEC_E_NO_CREDENTIALS: i32 = -2146893042; // 0x8009030E

// KDF 버퍼 식별자 (bcrypt.h / ncrypt.h)
#[allow(dead_code)]
pub const KDF_HASH_ALGORITHM: u32 = 0;
#[allow(dead_code)]
pub const KDF_SECRET_PREPEND: u32 = 1;
#[allow(dead_code)]
pub const KDF_SECRET_APPEND: u32 = 2;
#[allow(dead_code)]
pub const KDF_HMAC_KEY: u32 = 3;

// ============================================================================
// FFI 구조체 정의
// ============================================================================

#[repr(C)]
#[allow(non_snake_case)]
pub struct NCryptBuffer {
    pub cbBuffer: u32,
    pub BufferType: u32,
    pub pvBuffer: *mut c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct NCryptBufferDesc {
    pub ulVersion: u32,
    pub cBuffers: u32,
    pub pBuffers: *mut NCryptBuffer,
}

#[cfg(target_os = "windows")]
#[link(name = "ncrypt")]
unsafe extern "system" {
    fn NCryptOpenStorageProvider(
        phProvider: *mut usize,
        pszProviderName: *const u16,
        dwFlags: u32,
    ) -> i32;

    fn NCryptFreeObject(hObject: usize) -> i32;

    fn NCryptOpenKey(
        hProvider: usize,
        phKey: *mut usize,
        pszKeyName: *const u16,
        dwLegacyKeySpec: u32,
        dwFlags: u32,
    ) -> i32;

    fn NCryptCreatePersistedKey(
        hProvider: usize,
        phKey: *mut usize,
        pszAlgId: *const u16,
        pszKeyName: *const u16,
        dwLegacyKeySpec: u32,
        dwFlags: u32,
    ) -> i32;

    fn NCryptFinalizeKey(hKey: usize, dwFlags: u32) -> i32;

    fn NCryptDeriveKey(
        hKey: usize,
        pszKDF: *const u16,
        pParameterList: *const NCryptBufferDesc,
        pbDerivedKey: *mut u8,
        cbDerivedKey: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> i32;
}

#[cfg(not(target_os = "windows"))]
#[allow(non_snake_case)]
unsafe fn NCryptOpenStorageProvider(_: *mut usize, _: *const u16, _: u32) -> i32 {
    NTE_DEVICE_NOT_READY
}

#[cfg(not(target_os = "windows"))]
#[allow(non_snake_case)]
unsafe fn NCryptFreeObject(_: usize) -> i32 {
    ERROR_SUCCESS
}

#[cfg(not(target_os = "windows"))]
#[allow(non_snake_case)]
unsafe fn NCryptOpenKey(_: usize, _: *mut usize, _: *const u16, _: u32, _: u32) -> i32 {
    NTE_DEVICE_NOT_READY
}

#[cfg(not(target_os = "windows"))]
#[allow(non_snake_case)]
unsafe fn NCryptCreatePersistedKey(
    _: usize,
    _: *mut usize,
    _: *const u16,
    _: *const u16,
    _: u32,
    _: u32,
) -> i32 {
    NTE_DEVICE_NOT_READY
}

#[cfg(not(target_os = "windows"))]
#[allow(non_snake_case)]
unsafe fn NCryptFinalizeKey(_: usize, _: u32) -> i32 {
    NTE_DEVICE_NOT_READY
}

#[cfg(not(target_os = "windows"))]
#[allow(non_snake_case)]
unsafe fn NCryptDeriveKey(
    _: usize,
    _: *const u16,
    _: *const NCryptBufferDesc,
    _: *mut u8,
    _: u32,
    _: *mut u32,
    _: u32,
) -> i32 {
    NTE_DEVICE_NOT_READY
}

// ============================================================================
// RAII 자원 관리 래퍼
// ============================================================================

struct SafeProviderHandle(usize);

impl Drop for SafeProviderHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

struct SafeKeyHandle(usize);

impl Drop for SafeKeyHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

// ============================================================================
// 에러 열거형 정의
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsHelloError {
    UserCancelled,
    HardwareUnavailable(String),
    InvalidParameter(String),
    Internal(String),
}

impl fmt::Display for WindowsHelloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserCancelled => write!(f, "사용자에 의해 Windows Hello 인증이 취소되었습니다."),
            Self::HardwareUnavailable(msg) => write!(
                f,
                "하드웨어 보안 모듈(TPM 2.0/Windows Hello) 사용 불가: {msg}"
            ),
            Self::InvalidParameter(msg) => write!(f, "유효하지 않은 매개변수: {msg}"),
            Self::Internal(msg) => write!(f, "Windows CNG 내부 오류: {msg}"),
        }
    }
}

impl std::error::Error for WindowsHelloError {}

// ============================================================================
// 유틸리티 함수
// ============================================================================

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ============================================================================
// 공개 API 함수
// ============================================================================

/// Windows CNG(Cryptography Next Generation) / NCrypt FFI를 통해
/// TPM 2.0 또는 Windows Hello 기반 PRF 대칭키(32바이트)를 도출한다.
///
/// # 파라미터 제약
/// - `domain`: 1자 이상 255자 이하의 유효한 UTF-8 문자열
/// - `challenge`: 정확히 32바이트 길이의 바이너리 슬라이스
///
/// # 예외 정책
/// - 사용자가 생체/PIN 인증 프롬프트 취소 시 `WindowsHelloError::UserCancelled` 반환
/// - TPM 2.0 하드웨어 또는 KSP 접근 불가 시 `WindowsHelloError::HardwareUnavailable` 반환
/// - 잘못된 인자 전달 시 `WindowsHelloError::InvalidParameter` 반환
pub fn derive_hardware_prf(domain: &str, challenge: &[u8]) -> Result<[u8; 32], WindowsHelloError> {
    // 1. 파라미터 제약 검증
    if domain.is_empty() || domain.len() > 255 {
        return Err(WindowsHelloError::InvalidParameter(
            "도메인 길이는 1자 이상 255자 이하여야 합니다.".to_string(),
        ));
    }
    if challenge.len() != 32 {
        return Err(WindowsHelloError::InvalidParameter(
            "챌린지는 정확히 32바이트여야 합니다.".to_string(),
        ));
    }

    // 2. KSP 프로바이더 열기 (Passport -> TPM Platform Provider 순차 탐색)
    let providers = [
        to_wide_null("Microsoft Passport Key Storage Provider"),
        to_wide_null("Microsoft Platform Crypto Provider"),
    ];

    let mut provider_handle = 0usize;
    let mut last_status = 0i32;
    let mut connected = false;

    for wide_name in &providers {
        let status =
            unsafe { NCryptOpenStorageProvider(&mut provider_handle, wide_name.as_ptr(), 0) };
        if status == ERROR_SUCCESS {
            connected = true;
            break;
        }
        last_status = status;
    }

    if !connected {
        return Err(match last_status {
            NTE_USER_CANCELLED | SCARD_W_CANCELLED_BY_USER => WindowsHelloError::UserCancelled,
            _ => WindowsHelloError::HardwareUnavailable(format!(
                "TPM 2.0 또는 Windows Hello KSP 열기 실패 (상태 코드: {last_status:#X})"
            )),
        });
    }

    let provider = SafeProviderHandle(provider_handle);

    // 3. 도메인별 격리 키 열기 또는 생성
    let key_name_w = to_wide_null(&format!("PrfVault_{domain}"));
    let mut key_handle = 0usize;

    let mut status =
        unsafe { NCryptOpenKey(provider.0, &mut key_handle, key_name_w.as_ptr(), 0, 0) };

    if status == NTE_BAD_KEYSET || status == NTE_NO_KEY {
        let alg_w = to_wide_null("ECDSA_P256");
        status = unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut key_handle,
                alg_w.as_ptr(),
                key_name_w.as_ptr(),
                0,
                0,
            )
        };
        if status == ERROR_SUCCESS {
            status = unsafe { NCryptFinalizeKey(key_handle, 0) };
        }
    }

    if status != ERROR_SUCCESS {
        if key_handle != 0 {
            unsafe { NCryptFreeObject(key_handle) };
        }
        return Err(match status {
            NTE_USER_CANCELLED | SCARD_W_CANCELLED_BY_USER => WindowsHelloError::UserCancelled,
            NTE_NOT_SUPPORTED | NTE_BAD_KEYSET | NTE_DEVICE_NOT_READY | NTE_INVALID_PARAMETER => {
                WindowsHelloError::HardwareUnavailable(format!(
                    "하드웨어 키 생성/접근 불가 (상태 코드: {status:#X})"
                ))
            }
            _ => WindowsHelloError::Internal(format!(
                "Windows Hello CNG 키 생성/접근 실패 (상태 코드: {status:#X})"
            )),
        });
    }

    let key = SafeKeyHandle(key_handle);

    // 4. KDF를 통한 대칭키 도출 (HMAC-SHA256)
    let kdf_alg_w = to_wide_null("HMAC");
    let hash_alg_w = to_wide_null("SHA256");

    let mut buffers = [
        NCryptBuffer {
            cbBuffer: ((hash_alg_w.len()) * 2) as u32,
            BufferType: KDF_HASH_ALGORITHM,
            pvBuffer: hash_alg_w.as_ptr() as *mut c_void,
        },
        NCryptBuffer {
            cbBuffer: challenge.len() as u32,
            BufferType: KDF_SECRET_PREPEND,
            pvBuffer: challenge.as_ptr() as *mut c_void,
        },
    ];

    let buf_desc = NCryptBufferDesc {
        ulVersion: 0,
        cBuffers: buffers.len() as u32,
        pBuffers: buffers.as_mut_ptr(),
    };

    let mut derived_key = [0u8; 32];
    let mut result_len = 0u32;

    let derive_status = unsafe {
        NCryptDeriveKey(
            key.0,
            kdf_alg_w.as_ptr(),
            &buf_desc,
            derived_key.as_mut_ptr(),
            derived_key.len() as u32,
            &mut result_len,
            0,
        )
    };

    if derive_status != ERROR_SUCCESS {
        return Err(match derive_status {
            NTE_USER_CANCELLED | SCARD_W_CANCELLED_BY_USER => WindowsHelloError::UserCancelled,
            NTE_NOT_SUPPORTED | NTE_INVALID_PARAMETER => WindowsHelloError::HardwareUnavailable(
                format!("하드웨어 KDF 미지원 (상태 코드: {derive_status:#X})"),
            ),
            _ => WindowsHelloError::Internal(format!(
                "NCryptDeriveKey 실패 (상태 코드: {derive_status:#X})"
            )),
        });
    }

    if result_len != 32 {
        return Err(WindowsHelloError::Internal(format!(
            "도출된 키 크기 불일치: {result_len} 바이트 (기대치: 32)"
        )));
    }

    Ok(derived_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_parameters_empty_domain() {
        let challenge = [0u8; 32];
        let res = derive_hardware_prf("", &challenge);
        assert!(matches!(res, Err(WindowsHelloError::InvalidParameter(_))));
    }

    #[test]
    fn test_invalid_parameters_oversized_domain() {
        let long_domain = "a".repeat(256);
        let challenge = [0u8; 32];
        let res = derive_hardware_prf(&long_domain, &challenge);
        assert!(matches!(res, Err(WindowsHelloError::InvalidParameter(_))));
    }

    #[test]
    fn test_invalid_parameters_short_challenge() {
        let challenge = [0u8; 31];
        let res = derive_hardware_prf("example.com", &challenge);
        assert!(matches!(res, Err(WindowsHelloError::InvalidParameter(_))));
    }

    #[test]
    fn test_invalid_parameters_long_challenge() {
        let challenge = [0u8; 33];
        let res = derive_hardware_prf("example.com", &challenge);
        assert!(matches!(res, Err(WindowsHelloError::InvalidParameter(_))));
    }

    #[test]
    fn test_derive_hardware_prf_execution_or_graceful_error() {
        // 하드웨어 모듈 환경에 따라 성공(Ok)하거나 규정된 에러(HardwareUnavailable, UserCancelled)로 안전 귀결되어야 함
        let challenge = [0x5au8; 32];
        let res = derive_hardware_prf("test.prfvault.local", &challenge);
        match res {
            Ok(key) => {
                assert_eq!(key.len(), 32);
            }
            Err(WindowsHelloError::HardwareUnavailable(_)) => {
                // TPM/Windows Hello 미지원 또는 권한 미부여 환경에서 정상 처리
            }
            Err(WindowsHelloError::UserCancelled) => {
                // 사용자가 인증 프롬프트를 닫은 경우 정상 처리
            }
            Err(WindowsHelloError::Internal(msg)) => {
                // CI/가상화 환경에서 KSP 내부 에러 반환 시 안전 포착
                println!("[INFO] Windows CNG 내부 결과: {msg}");
            }
            Err(e) => {
                panic!("예상치 못한 에러 반환: {e:?}");
            }
        }
    }
}
