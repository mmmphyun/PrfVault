# Phase 1 Spike 인수인계 및 Phase 2~4 구현 로드맵

본 문서는 학원 개발 환경에서 완료된 **'Phase 1: Rust Wasm 암호화 코어 및 WebAuthn PRF Spike'** 작업 상태를 기록하고, 집 데스크톱 환경에서 실제 하드웨어 검증을 거쳐 Phase 2 이후의 개발을 원활하게 이어가기 위한 가이드다.

---

## 1. 현재 완료된 구현 내역

### 1.1 Rust Wasm Crypto Core (`crates/crypto-core/`)
- **C-ABI 메모리 관리**:
  - `prf_vault_alloc(size: usize) -> *mut u8`: Wasm 선형 메모리 힙 할당
  - `prf_vault_dealloc_zeroize(ptr: *mut u8, size: usize)`: `zeroize` 기반 물리적 `0x00` 소거(volatile write) 후 해제
- **마스터 키 도출**:
  - `prf_vault_derive_master_key`: HKDF-SHA-256 (IKM: 32B PRF Key, Salt: 32B Salt, Info: `b"PrfVault/v1/MasterEncryptionKey"`)
- **암복호화 및 바이너리 와이어 포맷**:
  - `prf_vault_encrypt` / `prf_vault_decrypt`: AES-256-GCM + CSPRNG Nonce(12B) + AAD 무결성 바인딩
  - Big-Endian 규격: `Schema(2B) + Salt(32B) + Nonce(12B) + Length(4B) + Ciphertext(Var) + Tag(16B)` (최소 66B)
- **검증 완료 상태**:
  - Rust 네이티브 단위 테스트 3건 통과 (`cargo test`)
  - Wasm 컴파일 및 번들링 성공 (`wasm-pack build crates/crypto-core --target web`)
  - 산출물: `crates/crypto-core/pkg/crypto_core_bg.wasm` (약 55KB)

### 1.2 WebAuthn PRF 테스트 하네스 (`tests/spike/`)
- `tests/spike/serve.js`: 외부 의존성 없는 Node.js 내장 HTTP 정적 파일 서버 (`application/wasm` MIME 및 보안 헤더 처리)
- `tests/spike/index.html`:
  - Step 1~3 사전 진단 (WebAuthn 지원, 플랫폼 TPM 감지, PRF 기능 확인)
  - Step 4 Windows Hello 등록 (`navigator.credentials.create` with `prf: {}`)
  - Step 5 PRF 키 유도 (`navigator.credentials.get` with `prf: { eval: { first: salt } }`)
  - Step 6 Wasm C-ABI 엔드투엔드 연동 (HKDF 키 유도 -> 암호화 -> 복호화 -> zeroize)

---

## 2. 집 데스크톱 재개 프로토콜

### 2.1 필수 툴체인 점검
- Node.js LTS (v20 이상)
- Rustup (`rustc`, `cargo`)
- Wasm 타깃: `rustup target add wasm32-unknown-unknown`
- wasm-pack: `wasm-pack --version` (없을 경우 GitHub release 또는 `cargo install wasm-pack`)

### 2.2 원터치 실행 및 실기 검증 절차
```powershell
# 1. 저장소 최신 커밋 반영
git pull origin main

# 2. 로컬 정적 테스트 서버 구동
node tests/spike/serve.js
```

1. Chrome/Edge 브라우저에서 `http://localhost:3000` 접속.
2. **사전 진단 확인**: Step 1~2가 모두 `[OK]`인지 확인.
3. **1) Windows Hello 자격 증명 등록**: 실제 Windows 생체(지문/얼굴) 또는 PIN 팝업 확인 및 통과.
4. **2) PRF 32바이트 키 유도**: 재인증 팝업 통과 후 `[SUCCESS] 32바이트 하드웨어 PRF 키 유도 성공!` 및 64자리 Hex 키 출력 확인.
5. **3) Wasm 볼트 암복호화 파이프라인 검증**: Wasm 모듈 연동 및 `[SUCCESS] 복호화 완벽 일치!`, `[Zeroize]` 소거 완료 로그 확인.

---

## 3. 전체 구현 로드맵 및 단계별 완료 기준 (DoD)

```
[Phase 1] 암호화 코어 & 하드웨어 유도 Spike (현재 단계)
   │   └─ 집 데스크톱: Windows Hello 실기 1회 확인으로 최종 종결
   ▼
[Phase 2] Chrome MV3 셸 & 볼트 스토리지 파이프라인
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
- **Phase 2.1**: Chrome MV3 기본 프로젝트 세팅 (`manifest.json`, `package.json`, Vite 번들러, TypeScript).
- **Phase 2.2**: Extension Page(Popup/Options)에서 WebAuthn PRF 호출 컨텍스트 분리 및 Service Worker IPC 메시지 라우터 구축 (`docs/05-ipc-and-manifest-spec.md` 준수).
- **Phase 2.3**: 단일 JSON 볼트 스키마(`docs/03-single-json-vault-spec.md`) 파싱/직렬화 및 `chrome.storage.local` 암호문 저장/조회 파이프라인 완성.

---

## 4. 집 세션 시작 프롬프트

집 PC에서 AI 에이전트를 시작할 때 다음 프롬프트를 입력하면 컨텍스트 손실 없이 즉시 이어갈 수 있습니다:

> `docs/handoff/phase-1-spike-handoff.md 확인해. 집 데스크톱에서 Windows Hello PRF 실기 검증을 성공했어. 로드맵에 따라 Phase 2.1인 Chrome Extension MV3 스켈레톤 구축부터 티키타카 방식으로 한 단계씩 진행하자.`
