# Phase 3 완료 보고 및 Phase 4 구현 로드맵

본 문서는 **'Phase 3: Content Script DOM 탐지기 & 폼 제어 엔진'** 구현 및 검증 완료 결과를 공식 기록하고, **'Phase 4: 50대 사이트 벤치마크 & 실태 조사 자동화'** 진입을 위한 아키텍처 및 상세 작업 단위를 정의한다.

---

## 1. Phase 3 완료 및 검증 내역 (Status: COMPLETED)

### 1.1 DOM 패스워드 및 아이디 필드 휴리스틱 분석기 (`extension/src/content/detector.ts`)
- **폼 및 입력 필드 휴리스틱 식별**:
  - 비밀번호 필드: `input[type="password"]`, `autocomplete="current-password"`, `autocomplete="new-password"` 가시적(visible) 요소 식별.
  - 회원가입 폼 판별: 비밀번호 필드가 2개 이상이거나 `new-password` 속성 보유 시 `isRegistration: true` 판정.
  - 사용자명 필드 탐색: `autocomplete="username"`, `type="email"`, 키워드(user, id, login, email, member) 정규식 매칭, 비밀번호 직전 인접 텍스트 필드 우선순위 기반 자동 매칭.
  - 가시성 검사 (`isElementVisible`): `type="hidden"`, `style.display="none"`, `style.visibility="hidden"`, `aria-hidden="true"`, `offsetParent === null` 복합 필터링.
- **국내 50대 사이트 E2E 보안 프로그램 및 가상 키패드 시그니처 감지**:
  - 라온시큐어 TouchEn Key: `input[data-enc="on"]`, `input[tk_type]`, `#TouchEnKey_tk_input` 등.
  - 이니텍 AnySign / MoaSign: `input[data-any="on"]`, `div#AnySign4PC`, `div#AnySign4PC_Frame` 등.
  - 안랩 AhnLab Safe Transaction (ASTx): `input[astx]`, `div#astx_install`, `object[id*="astx"]` 등.
  - 잉카인터넷 nProtect Online Security: `input[npk]`, `input[data-npk]`, `form[name*="np"]`, `div#nProtect` 등.
  - 가상 키패드: `img[src*="keypad" i]`, `div[class*="keypad" i]`, `div[class*="transkey" i]`, `div[id*="transkey" i]`, `div[class*="mtk" i]`, `input[data-mode="virtual"]` 등.
- **예외 격리**: DOM 쿼리 실패 및 Cross-Origin iframe 탐색 시 `SecurityError`를 안전하게 try-catch 격리.

### 1.2 CSPRNG 기반 고엔트로피 비밀번호 생성 엔진 (`extension/src/content/generator.ts`)
- **암호학적 난수 및 모듈로 바이어스(Modulo Bias) 배제**:
  - `crypto.getRandomValues(new Uint32Array(1))` 기반 Rejection Sampling 구현: $2^{32} - (2^{32} \pmod N)$ 상한을 적용하여 특정 문자 편향을 수학적으로 원천 제거.
  - 암호학적 난수 기반 Fisher-Yates 셔플 알고리즘(`secureShuffle`)으로 생성된 문자 위치 완전 무작위화.
- **정책 보장 및 엔트로피 분석 엔진**:
  - 4대 필수 문자군(소문자, 대문자, 숫자, 안전 특수문자) 최소 1자 포함 보장.
  - 혼동 문자('l', '1', 'I', 'o', '0', 'O' 등) 배제 옵션 지원 (`excludeAmbiguous: true`).
  - 섀넌 엔트로피(Shannon Entropy) 계산: $H = -\sum p_i \log_2(p_i)$.
  - 키 공간 엔트로피(Key Space Entropy) 계산: $E = L \times \log_2(N)$ (16자 기준 105비트 이상, 20자 기준 131비트 이상).

### 1.3 React 호환 폼 제어 및 자동 입력 엔진 (`extension/src/content/injector.ts`, `index.ts`)
- **React 16+ 프로토타입 세터 바이패스**:
  - `Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set`을 호출하여 모던 SPA 프레임워크(React, Vue, Angular)의 내부 State 추적기 통과.
  - `input`, `change`, `blur` 합성 이벤트를 순차적으로 버블링 발화시켜 프레임워크 폼 유효성 검사기 정상 동작 보장.
- **보안 모듈 충돌 방지 및 안전 중단**:
  - 가상 키패드 또는 E2E 보안 프로그램이 바인딩된 입력 필드는 주입 시 패킷 오염 및 계정 잠금을 방지하기 위해 입력을 거부하고 `BLOCKED_BY_KEYPAD` 상태 반환.
  - 사용자 명시적 강제 주입 옵션(`forceInjectEvenIfKeypad: true`) 지원.
- **Content Script 엔트리포인트 및 Service Worker IPC 연동**:
  - 페이지 진입 시 DOM 내 보안 모듈 존재 여부를 백그라운드로 자동 보고 (`CS_DETECT_SECURITY_MODULE`).
  - 폼 자동완성 트리거 수신(`TRIGGER_FORM_AUTOFILL`) 및 주입 결과 로깅 보고(`CS_REPORT_INJECTION_RESULT`).
  - Service Worker 라우터(`service-worker.ts`)에 신규 IPC 핸들러 등록 완료.

### 1.4 검증 지표 (100% Green)
- **Extension 단위/통합 테스트 (Vitest)**: 8개 테스트 스위트, 41개 단위 테스트 통과 (`npm --prefix extension test`).
  - `webauthn-prf.test.ts` (6건)
  - `injector.test.ts` (5건)
  - `detector.test.ts` (5건)
  - `generator.test.ts` (8건)
  - `vault.test.ts` (5건)
  - `crypto-core.test.ts` (4건)
  - `vault-storage.test.ts` (3건)
  - `ipc.test.ts` (5건)
- **Rust Crypto Core 네이티브 단위 테스트**: 3건 통과 (`cargo test --lib`).
- **Extension 번들 빌드**: `npm --prefix extension run build` (`tsc && vite build`) 정상 완료 (`extension/dist/` 출력).

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
[Phase 3] Content Script & 폼 자동 입력 엔진 (완료)
   │   ├─ 3.1: DOM 패스워드/아이디 필드 휴리스틱 탐지기 (국내 보안모듈 감지)
   │   ├─ 3.2: CSPRNG 기반 고엔트로피 비밀번호 생성 엔진 (Rejection Sampling)
   │   └─ 3.3: React 호환 프로토타입 세터 기반 폼 자동 입력 엔진 및 IPC 연동
   ▼
[Phase 4] 50대 사이트 벤치마크 & 실태 조사 자동화 (다음 단계)
       ├─ 4.1: Playwright 기반 국내 주요 50대 웹사이트 DOM 스캐너
       ├─ 4.2: E2E 보안 프로그램 / 가상 키패드 적용 실태 정량 데이터 수집
       └─ 4.3: 섀넌 엔트로피(Shannon Entropy) 손실률 및 차단율 벤치마크 리포트 도출
```

---

## 3. Phase 4 상세 작업 단위 및 구현 규격

### Phase 4.1: 국내 주요 50대 사이트 타깃 목록 및 Playwright 스캐너 구축
- **목적**: 국내 주요 웹사이트 50개(금융, 증권, 공공, 포털, e커머스)를 대상으로 헤드리스 브라우저를 구동하여 로그인 페이지의 DOM 구조와 보안 모듈을 자동 수집.
- **대상 위치**: `scripts/benchmark/targets.ts`, `scripts/benchmark/scanner.ts`
- **구현 내용**:
  1. 50대 타깃 도메인 및 로그인 URL 목록 정립 (네이버, 카카오, 토스, 국민은행, 신한은행, 정부24, 홈택스, 쿠팡 등).
  2. Playwright를 통한 순차/병렬 페이지 방문 및 `networkidle` 대기.
  3. Phase 3의 `detector.ts` 로직을 페이지 컨텍스트에 주입하여 폼 필드 구조 및 보안 모듈 시그니처 스캔.
  4. 원시 수집 결과 `results/raw-scans.json` 저장.

### Phase 4.2: 실태 조사 데이터 가공 및 섀넌 엔트로피 손실 분석기
- **목적**: 수집된 폼 제약(최대 글자 수 제한, 허용 특수문자 제한, 가상 키패드 마우스 클릭 강제)에 따른 보안성 저하를 정량화.
- **대상 위치**: `scripts/benchmark/analyzer.ts`
- **분석 지표**:
  - 비밀번호 정책별 키 공간(Key Space) 크기 및 엔트로피 비트수($L \times \log_2(N)$).
  - 8자/12자 제한 사이트에서의 섀넌 엔트로피 손실률.
  - 가상 키패드로 인한 패스워드 매니저 자동 완성 차단율(Blocking Rate).

### Phase 4.3: 포트폴리오용 공식 정량 벤치마크 리포트 도출
- **산출물**: `docs/benchmark/korea-50-sites-security-report.md`
- **구성**:
  - 50대 사이트 보안 모듈(TouchEn/AnySign/ASTx/nProtect/가상키패드) 점유율 차트/테이블.
  - WebAuthn PRF 패스키 도입 시 제거 가능한 레거시 보안 모듈 분석.
  - 글로벌 표준(FIDO2/W3C) vs 국내 웹 환경 괴리 분석 및 개선 권고안.

---

## 4. Phase 4 세션 시작 가이드

새 세션을 시작할 때 다음 명령어로 인수인계 상태를 복원하고 작업을 개시합니다:

```powershell
# 1. 직전 세션 맥락 복원
session-sync fetch --latest --out HANDOVER.md --verify

# 2. 다음 프롬프트로 Phase 4 개시
# "docs/handoff/phase-3-handoff.md 확인해. Phase 3 폼 자동 입력 엔진이 완료되었으니, 로드맵에 따라 Phase 4.1인 국내 50대 웹사이트 대상 벤치마크 타깃 목록 및 Playwright 스캐너 파이프라인 구축부터 진행하자."
```
