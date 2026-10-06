use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Chrome Native Messaging 사양에 따른 단일 메시지 최대 허용 바이트 크기 (1MB).
/// 임의의 악의적 페이로드로 인한 힙 메모리 고갈(OOM DoS)을 원천 차단하기 위한 상한선.
pub const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

/// 네이티브 호스트로 수신되는 요청 메시지 정의
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HostRequest {
    #[serde(rename = "PING")]
    Ping,
    #[serde(rename = "PRF_DERIVE")]
    PrfDerive { domain: String, challenge: String },
}

/// 공통 실패 응답 구조체
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// 공통 성공 응답 구조체
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SuccessResponse<T> {
    pub status: String,
    pub data: T,
}

/// 표준 입력 스트림으로부터 4바이트 uint32 Little-Endian 길이 접두사를 읽고 본문 버퍼를 추출한다.
///
/// # 제약 사항
/// - 스트림이 완전히 비어있는 정상 EOF인 경우 `Ok(None)`을 반환하여 루프를 안전하게 종료한다.
/// - 길이 접두사 이후 페이로드 중간에 스트림이 조기 종료되면 `io::ErrorKind::UnexpectedEof`를 발생시킨다.
/// - 선언된 길이가 `MAX_MESSAGE_SIZE`(1MB)를 초과하는 경우 파싱을 거부하고 `io::ErrorKind::InvalidData`를 반환한다.
pub fn read_message<R: Read>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let length = u32::from_le_bytes(len_bytes);
    if length > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("메시지 크기 초과: {length} bytes (최대 {MAX_MESSAGE_SIZE} bytes 허용)"),
        ));
    }

    let mut buffer = vec![0u8; length as usize];
    reader.read_exact(&mut buffer)?;
    Ok(Some(buffer))
}

/// 표준 출력 스트림으로 4바이트 uint32 Little-Endian 길이 접두사와 함께 직렬화된 바이트 슬라이스를 전송한다.
///
/// # 부작용
/// - 쓰기 완료 즉시 `flush()`를 호출하여 브라우저 클라이언트가 버퍼링 대기 없이 즉시 프레임을 수신하도록 강제한다.
pub fn write_message<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let length = payload.len() as u32;
    if length > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("전송 페이로드 크기 초과: {length} bytes"),
        ));
    }

    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

/// 수신된 바이트 슬라이스를 파싱하여 적절한 응답을 생성하고 루프 종료 여부를 반환한다.
///
/// # 에러 정책 및 페일세이프 (Fail-Safe)
/// - 유효하지 않은 JSON 수신 시 `{"status":"ERROR","code":"INVALID_PAYLOAD"}`를 반환하고 즉시 프로세스를 안전하게 종료하도록 `should_exit = true`를 반환한다.
/// - 프로토콜 명세에 어긋나는 비인가/변조 페이로드가 진입할 경우 호스트 상태를 보존하지 않고 즉각 종료하여 메모리 오염을 차단한다.
pub fn handle_message(raw_bytes: &[u8]) -> (Vec<u8>, bool) {
    let parse_result: Result<HostRequest, _> = serde_json::from_slice(raw_bytes);

    match parse_result {
        Ok(HostRequest::Ping) => {
            #[derive(Serialize)]
            struct PongData {
                pong: bool,
            }
            let resp = SuccessResponse {
                status: "OK".to_string(),
                data: PongData { pong: true },
            };
            let body = serde_json::to_vec(&resp).unwrap_or_default();
            (body, false)
        }
        Ok(HostRequest::PrfDerive { domain, challenge }) => {
            // 도메인 유효성 제약 검증 (1자 이상 255자 이하)
            if domain.is_empty() || domain.len() > 255 {
                let resp = ErrorResponse {
                    status: "ERROR".to_string(),
                    code: "INVALID_PARAMETER".to_string(),
                    message: Some("도메인 길이는 1자 이상 255자 이하여야 합니다.".to_string()),
                };
                let body = serde_json::to_vec(&resp).unwrap_or_default();
                return (body, false);
            }

            let challenge_seed = parse_or_normalize_challenge(&challenge);

            match crate::windows_hello::derive_hardware_prf(&domain, &challenge_seed) {
                Ok(key) => {
                    let hex_key = to_hex_string(&key);
                    #[derive(Serialize)]
                    struct PrfData {
                        domain: String,
                        challenge: String,
                        derived: bool,
                        key: String,
                    }
                    let resp = SuccessResponse {
                        status: "OK".to_string(),
                        data: PrfData {
                            domain,
                            challenge,
                            derived: true,
                            key: hex_key,
                        },
                    };
                    let body = serde_json::to_vec(&resp).unwrap_or_default();
                    (body, false)
                }
                Err(crate::windows_hello::WindowsHelloError::UserCancelled) => {
                    let resp = ErrorResponse {
                        status: "ERROR".to_string(),
                        code: "USER_CANCELLED".to_string(),
                        message: Some(
                            "사용자에 의해 Windows Hello 인증이 취소되었습니다.".to_string(),
                        ),
                    };
                    let body = serde_json::to_vec(&resp).unwrap_or_default();
                    (body, false)
                }
                Err(crate::windows_hello::WindowsHelloError::HardwareUnavailable(msg)) => {
                    let resp = ErrorResponse {
                        status: "ERROR".to_string(),
                        code: "HARDWARE_UNAVAILABLE".to_string(),
                        message: Some(msg),
                    };
                    let body = serde_json::to_vec(&resp).unwrap_or_default();
                    (body, false)
                }
                Err(crate::windows_hello::WindowsHelloError::InvalidParameter(msg)) => {
                    let resp = ErrorResponse {
                        status: "ERROR".to_string(),
                        code: "INVALID_PARAMETER".to_string(),
                        message: Some(msg),
                    };
                    let body = serde_json::to_vec(&resp).unwrap_or_default();
                    (body, false)
                }
                Err(crate::windows_hello::WindowsHelloError::Internal(msg)) => {
                    let resp = ErrorResponse {
                        status: "ERROR".to_string(),
                        code: "INTERNAL_ERROR".to_string(),
                        message: Some(msg),
                    };
                    let body = serde_json::to_vec(&resp).unwrap_or_default();
                    (body, false)
                }
            }
        }
        Err(_) => {
            let resp = ErrorResponse {
                status: "ERROR".to_string(),
                code: "INVALID_PAYLOAD".to_string(),
                message: Some("Invalid JSON payload or unsupported message type".to_string()),
            };
            let body = serde_json::to_vec(&resp).unwrap_or_default();
            // 스펙상 비정상 페이로드 진입 시 Fail-safe 종료 트리거
            (body, true)
        }
    }
}

/// 챌린지 문자열을 파싱하여 정확히 32바이트 바이너리 시드로 정규화한다.
/// - 64자리 16진수 hex 문자열인 경우 바이트 디코딩.
/// - 32바이트 길이 문자열인 경우 바이트 배열 직접 추출.
/// - 그 외 문자열인 경우 32바이트 제로 패딩/슬라이싱 적용.
fn parse_or_normalize_challenge(s: &str) -> [u8; 32] {
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        let mut valid = true;
        for i in 0..32 {
            if let Ok(b) = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16) {
                out[i] = b;
            } else {
                valid = false;
                break;
            }
        }
        if valid {
            return out;
        }
    }

    let bytes = s.as_bytes();
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        return out;
    }

    let mut out = [0u8; 32];
    let copy_len = bytes.len().min(32);
    out[..copy_len].copy_from_slice(&bytes[..copy_len]);
    out
}

/// 바이트 슬라이스를 소문자 16진수 hex 문자열로 인코딩한다.
fn to_hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_message_success() {
        let msg = b"{\"type\":\"PING\"}";
        let len = (msg.len() as u32).to_le_bytes();
        let mut stream = Vec::new();
        stream.extend_from_slice(&len);
        stream.extend_from_slice(msg);

        let mut cursor = Cursor::new(stream);
        let result = read_message(&mut cursor).expect("정상 수신 실패");
        assert_eq!(result, Some(msg.to_vec()));
    }

    #[test]
    fn test_read_message_eof() {
        let mut cursor = Cursor::new(Vec::new());
        let result = read_message(&mut cursor).expect("EOF 처리 실패");
        assert_eq!(result, None);
    }

    #[test]
    fn test_read_message_exceeds_max_size() {
        let invalid_len = (MAX_MESSAGE_SIZE + 1).to_le_bytes();
        let mut cursor = Cursor::new(invalid_len.to_vec());
        let result = read_message(&mut cursor);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_write_message_format() {
        let payload = b"{\"status\":\"OK\"}";
        let mut output = Vec::new();
        write_message(&mut output, payload).expect("전송 실패");

        let expected_len = (payload.len() as u32).to_le_bytes();
        assert_eq!(&output[0..4], &expected_len);
        assert_eq!(&output[4..], payload);
    }

    #[test]
    fn test_handle_message_ping() {
        let ping_msg = b"{\"type\":\"PING\"}";
        let (resp_bytes, should_exit) = handle_message(ping_msg);
        assert!(!should_exit);

        let v: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(v["status"], "OK");
        assert_eq!(v["data"]["pong"], true);
    }

    #[test]
    fn test_handle_message_prf_derive_hardware_or_graceful_error() {
        let prf_msg = br#"{"type":"PRF_DERIVE","domain":"example.com","challenge":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#;
        let (resp_bytes, should_exit) = handle_message(prf_msg);
        assert!(!should_exit);

        let v: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
        if v["status"] == "OK" {
            assert_eq!(v["data"]["domain"], "example.com");
            assert_eq!(v["data"]["derived"], true);
            assert!(v["data"]["key"].is_string());
        } else {
            assert_eq!(v["status"], "ERROR");
            assert!(
                v["code"] == "HARDWARE_UNAVAILABLE"
                    || v["code"] == "USER_CANCELLED"
                    || v["code"] == "INTERNAL_ERROR"
            );
        }
    }

    #[test]
    fn test_handle_message_prf_derive_invalid_domain() {
        let empty_domain_msg = br#"{"type":"PRF_DERIVE","domain":"","challenge":"seed"}"#;
        let (resp_bytes, should_exit) = handle_message(empty_domain_msg);
        assert!(!should_exit);

        let v: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(v["status"], "ERROR");
        assert_eq!(v["code"], "INVALID_PARAMETER");
    }

    #[test]
    fn test_handle_message_invalid_payload_failsafe() {
        let invalid_msg = b"malformed json payload";
        let (resp_bytes, should_exit) = handle_message(invalid_msg);
        assert!(
            should_exit,
            "유효하지 않은 페이로드는 Fail-safe 종료를 유발해야 함"
        );

        let v: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(v["status"], "ERROR");
        assert_eq!(v["code"], "INVALID_PAYLOAD");
    }

    #[test]
    fn test_parse_or_normalize_challenge_hex() {
        let hex_chal = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let parsed = parse_or_normalize_challenge(hex_chal);
        assert_eq!(parsed[0], 0x01);
        assert_eq!(parsed[1], 0x23);
        assert_eq!(parsed[31], 0xef);
    }
}
