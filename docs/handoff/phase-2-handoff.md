# Phase 2 완료 보고 및 Phase 3 구현 로드맵

본 문서는 **'Phase 2: Chrome Extension MV3 셸 및 볼트 스토리지 파이프라인'** 구현 및 검증 완료 결과를 공식 기록하고, **'Phase 3: Content Script DOM 탐지기 & 폼 제어 엔진'** 구현을 위한 아키텍처 및 상세 작업 단위를 정의한다.

---

## 1. Phase 2 완료 및 검증 내역 (Status: COMPLETED)

### 1.1 Chrome Extension MV3 스켈레톤 및 빌드 파이프라인
- **빌드 환경**: Vite 6 + TypeScript 5.8 + CRXJS 기반 MV3 패키징 환경 구축 (`extension/`).
- **권한 최소화 (`extension/manifest.json`)**:
  - `storage`: `chrome.storage.local` 암호문 볼트 영구 저장.
  - `alarms`: 백그라운드 주기 작업 및 볼트 자동 잠금(Lock) 타이머.
  - `activeTab`, `scripting`: 활성 탭 대상 DOM 탐지 및 폼 제어 권한 최소화 유지.
- **번들 빌드 검증**: `npm --prefix extension run build` (`tsc && vite build`) 성공 및 `extension/dist/` 출력 검증 완료.

### 1.2 Wasm C-ABI 메모리 관리 래퍼 (`extension/src/crypto/`)
- **선형 메모리 샌드박스 라이프사이클 관리 (`wasm-core.ts`)**:
  - `WasmMemoryScope` 클래스를 통한 포인터 할당 추적 및 작업 완료/예외 발생 시 `prf_vault_dealloc_zeroize` 보장.
  - V8 가비지 컬렉터의 메모리 잔류 취약점을 방어하기 위해 Rust 코어의 `volatile zeroize`(`0x00`) 물리적 덮어쓰기 연동.
- **암호화 인터페이스 바인딩**:
  - `deriveMasterKey`: HKDF-SHA-256 기반 32바이트 PRF Secret $\rightarrow$ 32바이트 AES 마스터 키 유도.
  - `encryptVault` / `decryptVault`: AES-256-GCM + CSPRNG 12B Nonce + AAD 바인딩.

### 1.3 MV3 내부 IPC 메시징 스키마 및 발신지 검증 라우터 (`extension/src/ipc/`)
- **타입 안전 메시지 프로토콜 (`messages.ts`)**:
  - Zod 기반 런타임 스키마 검증 (`IpcMessageSchema`).
  - 지원 메시지: `VAULT_GET_CIPHERTEXT`, `VAULT_SAVE_CIPHERTEXT`, `DOM_DETECT_FORMS`, `DOM_FILL_CREDENTIALS`, `LOCK_VAULT`.
- **eTLD+1 발신지 검증 라우터 (`router.ts`)**:
  - `tldts` 라이브러리를 활용한 `sender.url` 및 `sender.tab.url` eTLD+1 정규화 추출.
  - Extension 내부 페이지(Popup)와 외부 웹 컨텍스트(Content Script)의 호출 권한 분리 및 위조 메시지 차단.

### 1.4 WebAuthn PRF 마스터 키 유도 파이프라인 (`extension/src/auth/`)
- **컨텍스트 격리 원칙 준수**:
  - Service Worker 컨텍스트는 `window` 객체 부재 및 생명주기 유휴 종료로 인해 `navigator.credentials` 접근이 불가능함.
  - Extension Window 컨텍스트(Popup/Options)에서만 WebAuthn PRF(`prf.eval`)를 수행하도록 구조적 격리.
- **예외 처리 및 폴백 정책**:
  - 하드웨어 미지원(`NotSupportedError`), 사용자 취소(`NotAllowedError`), 유효시간 초과(`TimeoutError`)에 대한 명시적 오류 매핑 (`PrfAuthError`).

### 1.5 볼트 직렬화 및 와이어 포맷 패커 (`extension/src/vault/`)
- **도메인 모델 (`model.ts`)**:
  - `VaultPayload`, `VaultEntry`, `PasswordPolicy` 인터페이스 정의.
- **바이너리 와이어 포맷 (`wire-format.ts`)**:
  - Big-Endian 66바이트 최소 헤더 규격: `Schema(2B) + Salt(32B) + Nonce(12B) + Length(4B) + Ciphertext(Var) + Tag(16B)`.
  - AAD 무결성 바인딩을 통한 와이어 포맷 변조 탐지.

### 1.6 암호문 스토리지 파이프라인 (`extension/src/storage/`)
- **스토리지 캡슐화 (`vault-store.ts`)**:
  - `chrome.storage.local` 전용 단일 키(`prfvault_encrypted_vault`) 스토리지 I/O.
  - 평문 볼트 데이터는 스토리지에 절대 기록되지 않으며, 오직 바이너리 암호문 패킷만 Base64로 인코딩되어 안전하게 보존.

### 1.7 C-ABI 헤더 및 아키텍처 문서화
- **공식 C-ABI 인터페이스 헤더**: `include/prfvault_crypto.h` 발행 완료.
- **C 언어 1:1 대조 및 메모리 소거 메커니즘 문서**: `docs/architecture/c-abi-mechanics.md` 작성 완료.

### 1.8 테스트 통과 지표 (100% Green)
- **Extension 단위/통합 테스트**: Vitest 5개 스위트, 22개 테스트 통과 (`npm --prefix extension test`).
  - `crypto-core.test.ts` (4건)
  - `ipc.test.ts` (4건)
  - `webauthn-prf.test.ts` (6건)
  - `vault.test.ts` (5건)
  - `vault-storage.test.ts` (3건)
- **Rust Crypto Core 네이티브 단위 테스트**: 3건 통과 (`cargo test`).

---

## 2. 전체 구현 로드맵

```
[Phase 1] 암호화 코어 & 하드웨어 유도 Spike (완료)
   │   ├─ Rust C-ABI 코어 & 네이티브 단위 테스트 100% 통과
   │   ├─ CDP 가상 인증자 기반 E2E 파이프라인 무결성 검증 완료
   │   └─ Windows Hello OS 플랫폼 제약 실태 보고서 작성
   ▼
[Phase 2] Chrome MV3 셸 & 볼트 스토리지 파이프라인 (완료)
   │   ├─ Vite + TypeScript + CRXJS 기반 MV3 확장프로그램 스켈레톤
   │   ├─ Rust Wasm C-ABI 래퍼 & 선형 메모리 volatile zeroize 소거
   │   ├─ MV3 내부 IPC 라우터 & eTLD+1 발신지 검증
   │   ├─ WebAuthn PRF 마스터키 유도 (Extension Page 격리)
   │   ├─ 바이너리 와이어 포맷 직렬화 & chrome.storage.local 스토리지 파이프라인
   │   └─ C-ABI 공식 헤더(include/prfvault_crypto.h) 및 메커니즘 문서화
   ▼
[Phase 3] Content Script & 폼 자동 입력 엔진 (현재 단계)
   │   ├─ 3.1: DOM 패스워드/아이디 필드 휴리스틱 탐지기 (국내 보안모듈 감지 포함)
   │   ├─ 3.2: CSPRNG 기반 고엔트로피 비밀번호 생성 엔진
   │   └─ 3.3: 프레임워크 호환 폼 제어 및 메모리 즉시 소거 파이프라인
   ▼
[Phase 4] 50대 사이트 벤치마크 & 실태 조사 자동화
       ├─ 4.1: Playwright 기반 국내 50대 웹사이트 DOM 스캐너
       └─ 4.2: 섀넌 엔트로피(Shannon Entropy) 손실률 정량 데이터 리포트 도출
```

---

## 3. Phase 3 상세 작업 단위 및 구현 규격

### Phase 3.1: DOM 패스워드 및 아이디 필드 휴리스틱 분석기 (`detector.ts`)
- **목적**: 로그인 및 회원가입 폼에서 사용자명(Username) 및 비밀번호(Password) 입력 필드를 정확하게 식별하고, 국내 웹 환경의 가상 키패드/보안 프로그램 간섭 여부를 사전 감지.
- **파일 위치**: `extension/src/content/detector.ts`
- **핵심 요구사항**:
  1. **필드 탐지 휴리스틱**:
     - 비밀번호 필드: `input[type="password"]`, `autocomplete="current-password"`, `autocomplete="new-password"`.
     - 사용자명/아이디 필드: 비밀번호 필드와 동일 폼(또는 DOM 인접 노드) 내의 `input[type="text"]`, `input[type="email"]`, `input[name*="user" i]`, `input[name*="id" i]`, `input[id*="user" i]`, `input[id*="id" i]`, `autocomplete="username"`.
  2. **국내 E2E 보안 프로그램 및 가상 키패드 시그니처 탐지**:
     - 라온시큐어 TouchEn Key: `input[data-enc="on"]`, `input[tk_type]`, `#TouchEnKey_tk_input` 등.
     - 이니텍(INITECH) MoaSign / AnySign: `input[data-any="on"]`, `div#AnySign4PC` 등.
     - 안랩 AhnLab Safe Transaction (ASTx): `input[astx]`, `div#astx_install` 등.
     - 잉카인터넷 nProtect Online Security: `input[npk]`, `form[name*="np"]` 등.
     - 가상 키패드 이미지/Canvas 오버레이: `img[src*="keypad"]`, `div[class*="keypad"]`, `div[class*="transkey"]`, `div[id*="transkey"]`.
  3. **보안 및 격리 제약**:
     - Cross-origin iframe 탐색 시 `SecurityError` 발생을 차단하기 위해 `try-catch` 격리 처리.
     - 반환 객체 규격:
       ```typescript
       export interface FormDetectionResult {
         forms: DetectedForm[];
         hasSecurityModule: boolean;
         detectedSecurityModules: string[];
       }
       export interface DetectedForm {
         formElement: HTMLFormElement | null;
         usernameField: HTMLInputElement | null;
         passwordFields: HTMLInputElement[];
         isRegistration: boolean;
       }
       ```

### Phase 3.2: CSPRNG 기반 고엔트로피 비밀번호 생성 엔진 (`generator.ts`)
- **목적**: 웹 브라우저의 암호학적으로 안전한 난수 생성기(`crypto.getRandomValues`)를 사용하여 강력한 비밀번호를 생성하고, 복합 정책(대/소문자, 숫자, 특수문자) 및 엔트로피를 정량 계산.
- **파일 위치**: `extension/src/content/generator.ts`
- **핵심 요구사항**:
  1. **난수 생성 및 바이어스 차단**:
     - `crypto.getRandomValues(new Uint32Array(1))` 기반 Rejection Sampling을 통해 모듈로 바이어스(Modulo Bias)를 원천 제거.
     - Fisher-Yates 알고리즘을 암호학적 난수로 수행하여 문자군 배치 무작위화.
  2. **정책 검증 및 엔트로피 보장**:
     - 기본 길이: 20자 (최소 16자 이상).
     - 문자군 최소 요구조건: 소문자(a-z) 1자, 대문자(A-Z) 1자, 숫자(0-9) 1자, 안전한 특수문자(`!@#$%^&*()_+-=[]{}|;:,.<>?`) 1자 필수 포함.
     - 섀넌 엔트로피(Shannon Entropy) 및 풀 공간 비트($\log_2(N^L)$) 계산 함수 제공.

### Phase 3.3: 프레임워크 호환 폼 제어 및 자동 입력 엔진 (`injector.ts` / `index.ts`)
- **목적**: 모던 SPA(React, Vue, Angular, Svelte) 프레임워크 환경에서 입력 필드의 내부 상태(State)를 정상 갱신하고, 입력 완료 즉시 메모리를 소거하는 자동 입력 엔진 구현.
- **파일 위치**: `extension/src/content/injector.ts`, `extension/src/content/index.ts`
- **핵심 요구사항**:
  1. **프로토타입 세터 바이패스**:
     - React 16+의 합성 이벤트 추적기를 통과하기 위해 `Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(input, value)` 사용.
     - `new Event('input', { bubbles: true })`, `new Event('change', { bubbles: true })`, `new FocusEvent('blur', { bubbles: true })` 연속 디스패치.
  2. **보안 모듈 감지 시 동작 정책**:
     - E2E 보안 모듈 또는 가상 키패드가 활성화된 필드는 강제 주입 시 암호화 라이브러리와 충돌하거나 오작동을 유발하므로, `hasSecurityModule === true`인 경우 주입을 거부하고 사용자 경고 상태를 반환.
  3. **메모리 즉시 소거**:
     - 평문 비밀번호 문자열은 DOM 주입 완료 직후 가비지 컬렉터 회수를 유도하고, 내부 버퍼는 덮어쓰기 처리.

---

## 4. Phase 3 작업 완료 기준 (DoD)

1. `extension/src/content/detector.ts`:
   - 일반 폼 및 비밀번호 2개 필드(회원가입 확인용) 탐지 단위 테스트 통과.
   - 가상 키패드 및 TouchEn/AnySign/ASTx/nProtect 시그니처 탐지 단위 테스트 통과.
2. `extension/src/content/generator.ts`:
   - 모듈로 바이어스 없는 CSPRNG 생성기 및 정책별 충족 검증 단위 테스트 통과.
   - 섀넌 엔트로피 산출 정확도 검증 단위 테스트 통과.
3. `extension/src/content/injector.ts`:
   - React/Vue 프로토타입 세터 디스패치 및 이벤트 전파 검증 단위 테스트 통과.
   - 보안 모듈 간섭 시 안전 중단 검증 통과.
4. `npm --prefix extension test` 및 `npm --prefix extension run build` 100% 통과 유지.
5. 1-Task 1-Commit 원칙 준수.
