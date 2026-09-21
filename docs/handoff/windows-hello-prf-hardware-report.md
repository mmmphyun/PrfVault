# Windows Hello WebAuthn PRF 실기 검증 및 플랫폼 제약 실증 보고서

본 문서는 데스크톱 실기 환경에서 수행한 **WebAuthn Level 3 PRF(Pseudo-Random Function) 하드웨어 키 유도 실증 테스트** 과정과 도출된 기술적 사실(Fact) 및 OS 레벨 제약 사항을 기록한다.

---

## 1. 테스트 환경 제원

* **OS**: Windows 11 Home (Version 25H2, OS Build 26200.0)
* **WebAuthn 인터페이스**: `C:\Windows\System32\webauthn.dll` (FileVersion 10.0.26100.9278)
* **CPU / TPM**: Intel Core i5-10400 (Comet Lake, Intel PTT TPM 2.0 활성화)
* **테스트 브라우저**:
  * Microsoft Edge 153.0.4234.48 (Official Build, 64-bit)
  * Google Chrome 153.0.8010.48 (Official Build, 64-bit)
* **도구 체인**: Node.js v24.15.0, Rust 1.98.1, wasm-pack 0.15.0

---

## 2. 점진적 파라미터 변천 및 테스트 로그

### 2.1 1차 테스트: 브라우저 기본 인터셉트 및 비상주 키
* **조건**: `residentKey: "preferred"`, `extensions: { prf: {} }`
* **현상**: Chrome/Edge 브라우저가 플랫폼 인증자 요청 시 OS Windows Hello 대신 **Google 비밀번호 관리자(GPM)** 팝업(신규 6자리 PIN 생성 요구)을 우선 가로챔.
* **결과**: GPM은 PRF 미지원이므로 자격 증명 등록 후 키 유도(`get`) 시 빈 객체 `{"prf": {}}` 반환.

### 2.2 2차 테스트: Windows Hello 직접 지정 (4자리 OS PIN)
* **조건**: Windows Hello 명시 선택, 4자리 시스템 PIN 통과.
* **결과**: 등록(`create`) 반환값에서 PRF가 명시적으로 거부됨:
  ```json
  WebAuthn 확장 반환 결과: {"prf": {"enabled": false}}
  ```

### 2.3 3차 테스트: 상주 키 강제 및 등록 시점 Salt 바인딩
* **조건**: 
  * `residentKey: "required"` (FIDO2 CTAP 2.1 상주 키 슬롯 강제)
  * `userId`: 고정값(`prfvault-spike-user`)으로 지정 (Windows 패스키 누적 방지)
  * `extensions: { prf: { eval: { first: <32B Salt> } } }` (등록과 동시에 연산 강제)
* **결과**: 여전히 `{"prf": {"enabled": false}}` 반환.

### 2.4 4차 테스트: 구형 TPM/PTT 친화 알고리즘 재배열 및 CTAP 2.0 병행
* **조건**:
  * `pubKeyCredParams`: `RS256 (-257)` 1순위 지정, `ES256 (-7)`, `PS256 (-37)`, `Ed25519 (-8)` 포괄 선언.
  * `extensions`: `hmacCreateSecret: true` (CTAP 2.0 레거시 플래그) 병행 주입.
* **결과**: 브라우저 Capabilities는 지원(`true`)을 선언했으나, OS 인증자가 두 대칭키 인터페이스를 모두 최종 거부:
  ```json
  [클라이언트 Capabilities]
  "extension:hmacCreateSecret": true,
  "extension:prf": true

  [최종 WebAuthn 확장 반환 결과]
  {"hmacCreateSecret": false, "prf": {"enabled": false}}
  ```

---

## 3. 계층별 원인 규명 (Root Cause Analysis)

```mermaid
flowchart TD
    Browser["브라우저 계층 (Edge / Chrome 153)<br/>extension:prf = true<br/>extension:hmacCreateSecret = true"]
    OS["OS 인증자 계층 (Windows Hello / webauthn.dll)<br/>플랫폼 TPM 연동 시 PRF/hmac-secret 차단"]
    TPM["하드웨어 계층 (Intel 10세대 PTT / TPM 2.0)<br/>TCG 표준 TPM2_HMAC 명령 보유"]

    Browser -->|"PRF 확장 요청"| OS
    OS --x|"{"prf": {"enabled": false}}" 반환| Browser
    OS -.->|"대칭키 파이프라인 미노출"| TPM

    style Browser fill:#1e293b,stroke:#38bdf8,color:#fff
    style OS fill:#7f1d1d,stroke:#f87171,color:#fff
    style TPM fill:#1e293b,stroke:#4ade80,color:#fff
```

1. **하드웨어(Intel PTT) 결함 아님**:
   * TCG(Trusted Computing Group) TPM 2.0 표준 라이브러리 명세에 따라 `TPM2_HMAC` 및 시퀀스 연산은 필수 명령으로 하드웨어 수준에서 탑재되어 있음.
2. **브라우저 결함 아님**:
   * Chromium 153 계열 브라우저는 W3C WebAuthn Level 3 PRF 인터페이스를 정상 활성화하고 있음.
3. **병목 지점: Windows Hello OS 플랫폼 구현 한계**:
   * Windows의 `webauthn.dll`은 **외장 FIDO2 보안키(YubiKey 등 Roaming Authenticator)**에 대해서는 `hmac-secret`을 처리할 수 있으나,
   * **내장 TPM을 사용하는 플랫폼 인증자(Windows Hello PIN/지문)**에 대해서는 웹 브라우저 API 레벨에서 대칭키 유도 확장을 개방하지 않고 강제로 비활성화(`enabled: false`)함.
4. **업계 선행 사례와 일치**:
   * 글로벌 패스워드 관리자인 **Bitwarden 공식 기술 문서 및 GitHub Issue #19858**에서도 동일한 현상 보고:
   * *"Windows Hello 플랫폼 인증자는 최신 Windows 11에서도 PRF 확장에 대해 일관되게 `Encryption not supported`를 반환하는 OS 레벨 제약이 존재하며, 이로 인해 패스키 기반 자동 볼트 잠금 해제를 지원하지 못하고 마스터 패스워드 입력으로 Fallback 처리 중임."*

---

## 4. 본 프로젝트(PrfVault)의 기술적 함의 및 개발 방향

### 4.1 실증 연구 데이터로서의 가치
* 본 결과는 PrfVault의 연구 과제인 **"WebAuthn PRF 기반 Zero-Server 하드웨어 바인딩 로컬 볼트가 국내 데스크톱 웹 생태계에서 성립 가능한가?"**에 대한 결정적인 실증 데이터다.
* 이론적으로 완벽한 TPM 2.0 보안 모듈이 존재하더라도, OS 공급자(Microsoft)의 플랫폼 API 정책 및 인터페이스 폐쇄로 인해 상용 웹 볼트가 순수 PRF에 100% 의존할 수 없음을 입증한다.

### 4.2 개발 및 테스트 파이프라인 전략 (DoD)
* **Phase 2 (Chrome MV3 확장프로그램 및 Wasm 볼트)** 개발 시:
  * 물리 하드웨어의 미지원에 구애받지 않고, 표준 테스팅 규격인 **Chromium DevTools WebAuthn 가상 인증자(`Supports PRF: true`)** 환경에서 Rust Wasm 암복호화, zeroize 메모리 소거 및 단일 JSON 볼트 CRUD 파이프라인을 구축한다.
* **예외 처리 명세 준수**:
  * [`docs/06-webauthn-prf-exception-flow.md`](../06-webauthn-prf-exception-flow.md)의 **Step 4 -> `ERR_HARDWARE_PRF_REJECTED`** 상태 머신에 따라, 실기 Windows Hello 사용자에게는 안전한 에러 안내(Fail-Closed) 및 외장 토큰 권장을 제공하도록 UI를 설계한다.
