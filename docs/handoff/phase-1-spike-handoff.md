# Phase 1 Spike 완료 보고 및 Phase 2~4 구현 로드맵

본 문서는 **'Phase 1: Rust Wasm 암호화 코어 및 WebAuthn PRF Spike'** 검증 완료 결과를 공식 기록하고, Phase 2 이후의 확장프로그램 개발을 원활하게 이어가기 위한 가이드다.

---

## 1. Phase 1 완료 및 검증 내역 (Status: COMPLETED)

### 1.1 Rust Wasm Crypto Core (`crates/crypto-core/`)
- **C-ABI 메모리 관리**:
  - `prf_vault_alloc(size: usize) -> *mut u8`: Wasm 선형 메모리 힙 할당
  - `prf_vault_dealloc_zeroize(ptr: *mut u8, size: usize)`: `zeroize` 기반 물리적 `0x00` 소거(volatile write) 후 해제
- **마스터 키 도출**:
  - `prf_vault_derive_master_key`: HKDF-SHA-256 (IKM: 32B PRF Key, Salt: 32B Salt, Info: `b"PrfVault/v1/MasterEncryptionKey"`)
- **암복호화 및 바이너리 와이어 포맷**:
  - `prf_vault_encrypt` / `prf_vault_decrypt`: AES-256-GCM + CSPRNG Nonce(12B) + AAD 무결성 바인딩
  - Big-Endian 규격: `Schema(2B) + Salt(32B) + Nonce(12B) + Length(4B) + Ciphertext(Var) + Tag(16B)` (최소 66B)
- **단위 테스트 통과**:
  - Rust 네이티브 단위 테스트 3건 100% 통과 (`cargo test`)
  - Wasm 컴파일 및 번들링 성공 (`wasm-pack build crates/crypto-core --target web`)
  - 산출물: `crates/crypto-core/pkg/crypto_core_bg.wasm` (약 55KB)

### 1.2 WebAuthn PRF 엔드투엔드 파이프라인 무결성 검증
- **검증 도구**: `tests/spike/run-virtual-test.js` (CDP 기반 무인 자동화 테스트)
- **검증 환경**: Chromium DevTools Protocol의 W3C Level 3 PRF 가상 인증자 (`hasPrf: true`, `ctap2`, `internal`)
- **검증 결과 (100% 통과)**:
  1. 가상 TPM 자격 증명 등록 (`navigator.credentials.create` with `prf`) $\rightarrow$ `prf.enabled: true`
  2. 32바이트 하드웨어 대칭키 유도 (`navigator.credentials.get` with `prf.eval`) $\rightarrow$ 32B PRF Secret 정상 도출
  3. Rust Wasm C-ABI 마스터 키 파생 $\rightarrow$ AES-256-GCM 볼트 암호화 패킹 (173B) $\rightarrow$ 완벽 복호화 일치
  4. 민감 포인터 선형 메모리 물리 소거 (`zeroize` 0x00) 완료

---

## 2. 물리 하드웨어 실기 검증 및 OS 제약 분석 요약

* **실측 환경**: Windows 11 Home 25H2 (Build 26200), Intel Core i5-10400 (Intel PTT TPM 2.0), Edge/Chrome 153.
* **실측 결과**:
  * 브라우저와 Intel PTT 칩셋은 TCG TPM 2.0 및 WebAuthn PRF 확장을 정상 지원함.
  * 그러나 **Windows Hello OS 플랫폼 계층(`webauthn.dll`)이 내장 TPM 자격 증명에 대해 PRF/`hmac-secret` 웹 인터페이스를 개방하지 않아 `{"hmacCreateSecret": false, "prf": {"enabled": false}}`를 반환**하는 OS 레벨 제약이 확인됨.
  * 이는 비교군인 Bitwarden(GitHub Issue #19858)에서도 동일하게 겪고 있는 글로벌 공통 OS 제약 사항임.
* **상세 보고서**: [`docs/handoff/windows-hello-prf-hardware-report.md`](windows-hello-prf-hardware-report.md) 참조.

---

## 3. 전체 구현 로드맵 및 단계별 완료 기준 (DoD)

```
[Phase 1] 암호화 코어 & 하드웨어 유도 Spike (완료)
   │   ├─ Rust C-ABI 코어 & 네이티브 단위 테스트 100% 통과
   │   ├─ CDP 가상 인증자 기반 E2E 파이프라인 무결성 검증 완료
   │   └─ Windows Hello OS 플랫폼 제약 실태 보고서 작성
   ▼
[Phase 2] Chrome MV3 셸 & 볼트 스토리지 파이프라인 (다음 단계)
   │   ├─ 2.1: Vite + TypeScript + CRXJS 기반 MV3 확장프로그램 스켈레톤
   │   ├─ 2.2: Wasm 모듈 번들링 & Service Worker ↔ Popup IPC 메시징
   │   └─ 2.3: 단일 JSON 볼트 생성 / 로컬 스토리지(`chrome.storage.local`) 저장
   ▼
[Phase 3] Content Script & 폼 자동 입력 엔진
   │   ├─ 3.1: DOM 패스워드/아이디 필드 휴리스틱 탐지기
   │   ├─ 3.2: CSPRNG 기반 고엔트로피 비밀번호 생성기
   │   └─ 3.3: 폼 주입 및 메모리 즉시 소거 (가상키패드/E2E 간섭 감지)
   ▼
[Phase 4] 50대 사이트 벤치마크 & 실태 조사 자동화
       ├─ 4.1: Playwright 기반 국내 50대 웹사이트 DOM 스캐너
       └─ 4.2: 섀넌 엔트로피(Shannon Entropy) 손실률 정량 데이터 리포트 도출
```

### Phase 2 상세 작업 단위
- **Phase 2.1**: Chrome MV3 기본 프로젝트 세팅 (`manifest.json`, `package.json`, Vite 번들러, TypeScript, CRXJS).
- **Phase 2.2**: Extension Page(Popup/Options)에서 WebAuthn PRF 호출 컨텍스트 분리 및 Service Worker IPC 메시지 라우터 구축 ([`docs/05-ipc-and-manifest-spec.md`](../05-ipc-and-manifest-spec.md) 준수).
- **Phase 2.3**: 단일 JSON 볼트 스키마 파싱/직렬화 및 `chrome.storage.local` 암호문 저장/조회 파이프라인 완성.

---

## 4. Phase 2 세션 시작 가이드

Phase 2 작업을 시작할 때 다음 프롬프트를 입력하면 즉시 이어서 진행할 수 있습니다:

> `docs/handoff/phase-1-spike-handoff.md 확인해. Phase 1 검증이 완료되었으니, 로드맵에 따라 Phase 2.1인 Chrome Extension MV3 스켈레톤(Vite + TypeScript + CRXJS) 구축부터 진행하자.`
