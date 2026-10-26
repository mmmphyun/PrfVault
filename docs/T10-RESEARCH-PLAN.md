# 과제 10: AI와 함께 쓰는 첫 논문 — 가설에서 결론까지
## 연구 계획서 및 완주 체크리스트 (T10-C01 - T10-C51)

- **연구 제목**: 국내 50대 웹사이트의 비표준 인증 보안 인터페이스가 브라우저 패스워드 매니저 및 암호 엔트로피에 미치는 영향 실증
- **작성자**: mmmphyun
- **작성일**: 2026-10-21
- **주요 근거 자료 및 기술 블로그**:
  - [PrfVault 1편: W3C WebAuthn PRF와 Rust Wasm 코어 암호 엔진 설계](https://mmmphyun.github.io/security-agent-toolkit/blog/proj-prfvault-01-wasm-core-and-webauthn-prf/) (공개 URL, 익명 접근 검증 완료)
  - Florêncio, D., & Herley, C. (2007). *A Large-Scale Study of Web Password Habits*. Proceedings of the 16th International Conference on World Wide Web (WWW '07), ACM, 657-666.
  - Grassi, P. A. et al. (2017). *NIST Special Publication 800-63B: Digital Identity Guidelines - Authentication and Lifecycle Management*. National Institute of Standards and Technology.
  - W3C Web Authentication Working Group (2023). *Web Authentication: An API for accessing Public Key Credentials Level 3 (PRF Extension)*.
  - PrfVault 벤치마크 원자료: `scripts/results/raw-scans.json` (50개 사이트 전수 스캔 데이터) 및 `scripts/results/benchmark-analysis.json`

---

## 1. 질문을 가설로 (T10-C01 - T10-C10)

### 1.1 관심 분야 (T10-C01)
- 클라이언트 중심 제로 서버(Zero-Server) 인증 아키텍처 및 국내 웹 생태계의 패스워드 매니저 호환성·암호 엔트로피 실태.

### 1.2 검토 후보 주제 10개 도출 및 최종 기각 후보 3개 상세 사유 (T10-C02, T10-C03)
- **초기 브레인스토밍 질문 10개 중 직접 데이터 수집이 불가능한 6개 제외 후 남은 4개 후보 비교**:
1. **후보 주제 1 (기각)**: "브라우저 순수 W3C WebAuthn PRF 확장 호출만으로 외부 서버 및 네이티브 모듈 없이 Windows 11 내장 TPM 2.0에서 256비트 볼트 마스터 키를 도출할 수 있다."
   - **기각 사유**: Intel 10세대 PTT TPM 2.0 및 Windows 11 실기 환경에서 실험한 결과, Chromium 가상 인증자(CDP)에서는 성공했으나 실제 OS 계층(`webauthn.dll`)이 `{hmacCreateSecret: false, prf: {enabled: false}}`를 반환하며 차단하여 브라우저 단독 실험 진행이 불가능했음.
2. **후보 주제 2 (기각)**: "온디맨드 단일 계정 복호화 구조는 전체 볼트 상주 구조 대비 크롬 확장프로그램 V8 엔진 힙 메모리의 평문 잔류 시간을 99% 이상 단축한다."
   - **기각 사유**: Rust Wasm 선형 메모리는 `zeroize`를 통해 즉시 `0x00` 덮어쓰기가 가능하나, DOM 주입 직후 생성되는 V8 문자열은 가비지 컬렉터(GC) 실행 시점이 비결정적(Non-deterministic)이어서 일주일 내 일관된 수치 측정이 불가능했음.
3. **후보 주제 3 (기각)**: "TOTP(RFC 6238) 6자리 코드는 로컬 패스워드 볼트의 대칭 암호화 키 유도 함수(KDF) 시드로 사용할 때 브루트포스 방어력을 제공한다."
   - **기각 사유**: 수학적 계산만으로 TOTP 시드 공간($10^6$)의 정보 엔트로피가 약 $19.93\text{ bits}$에 불과하여 오프라인 GPU 대입 시 수 밀리초 내 역산된다는 사실이 자명하므로 별도 실험 데이터 수집의 학술적 실익이 낮아 기각함.
4. **후보 주제 4 (최종 채택)**: "국내 웹사이트에 적용된 비표준 보안 인터페이스(가상 키패드 및 비밀번호 최대 길이 제한)는 표준 브라우저 패스워드 매니저의 자동 완성을 원천 차단하거나, 허용 암호 공간을 축소시켜 섀넌 정보 엔트로피를 표준 권고 대비 20% 이상 저하시킨다."

### 1.3 최종 가설 (T10-C04, T10-C05)
- **최종 가설 한 문장**: "국내 주요 웹사이트가 강제하는 비표준 보안 인터페이스(웹 가상 키패드 및 16자 이하 비밀번호 최대 길이 제한)는 표준 패스워드 매니저의 DOM 자동 완성을 차단하거나, 생성 가능한 암호의 섀넌 정보 엔트로피를 NIST 표준 권고치 대비 20% 이상 감소시킨다."
- **무엇이 무엇에 영향을 주는가 (인과 구조)**:
  - **독립변수 (원인)**: 웹사이트 로그인 페이지의 비표준 보안 인터페이스 도입 여부(가상 키패드 오버레이, HTML `maxlength` 16자 이하 제한 정책).
  - **종속변수 (결과)**: 브라우저 패스워드 매니저의 DOM 자동 입력 차단율(%) 및 사이트 허용 최대 암호의 섀넌 정보 엔트로피($E$, 단위 bits) 손실률(%).

### 1.4 가설 표현의 측정 정의 (T10-C06)
- **자동 완성 차단율 ($\text{Blocking Rate}$)**: Playwright 헤드리스 브라우저로 수집한 전체 표본($N_{\text{total}}=50$) 중 Transkey, MTK 등 가상 키패드 셀렉터(`div[class*="transkey" i]`, `input[data-tk-virtual="true"]` 등)가 활성화되어 표준 `<input type="password">` 직접 주입을 차단하는 사이트 비율($N_{\text{keypad}} / N_{\text{total}} \times 100$).
- **섀넌 정보 엔트로피 ($E$)**:
  $$E = \log_2(N^L) = L \times \log_2(N) \quad [\text{bits}]$$
  - $L$: 로그인 폼 `<input type="password">`의 `maxlength` 속성값 (미지정 시 표준 기준 길이 $L_{\text{std}}=20$ 적용).
  - $N$: 허용 문자군 크기 (영문 대소문자 52 + 숫자 10 + 특수문자 32 = $94$).
  - 표준 기준치 ($E_{\text{std}}$): NIST SP 800-63B 기반 $L_{\text{std}}=20, N_{\text{std}}=94$ 적용 시 $E_{\text{std}} = 20 \times \log_2(94) \approx 131.0918\text{ bits}$.
- **엔트로피 손실률 ($\text{Loss}$)**:
  $$\text{Loss}(\%) = \max\left(0, \frac{E_{\text{std}} - E}{E_{\text{std}}} \times 100\right)$$

### 1.5 가설이 틀렸다면 나올 결과 (반증 조건, T10-C07)
- 국내 50대 웹사이트 전수 조사 결과 가상 키패드 탐지 건수가 0건(차단율 0.0%)이고, 모든 사이트가 20자 이상의 비밀번호 길이를 허용($L \ge 20$)하여 엔트로피 손실률 20% 이상인 사이트가 0건으로 측정된다면 본 가설은 기각된다.

### 1.6 데이터 수집 기간 및 범위 (T10-C08)
- **수집 일시**: 2026-09-28 (`2026-09-28T05:54:54.340Z` - `2026-09-28T06:00:57.997Z`, 약 6분간 자동화 배치 실행).
- **표본 범위**: 국내 트래픽 상위 50대 주요 웹사이트 (8개 카테고리: 은행 8, 증권 6, 공공 8, 핀테크 5, 통신 3으로 구성된 MFA 의무화 규제군 30개소 + 포털 5, 커뮤니티 5, 이커머스 10으로 구성된 단일 팩터 레거시군 20개소).

### 1.7 AI와 가설을 다듬은 과정 (T10-C09)
- **1차 질문**: "국내 웹사이트의 보안 프로그램이 패스워드 매니저 사용을 방해한다는 점을 연구하고 싶다."
- **AI 응답 및 역질문 ("이건 어떻게 측정하지?")**: AI가 설문조사를 제안했으나, 주관적 체감 대신 DOM 셀렉터 탐지 유무(0/1)와 `maxlength` 정수값 기반의 섀넌 엔트로피 공식을 측정 지표로 재정의함.
- **2차 점검 ("내가 일주일 안에 데이터를 모을 수 있나?")**: 수동 조사는 재현성이 떨어지므로 Playwright 자동화 스캐너(`scanner.ts`)를 작성하여 50개 사이트를 10분 이내에 전수 스캔하도록 범위를 고정함.
- **3차 점검 ("결과가 반대로 나오면 그것도 의미가 있나?")**: 만약 액티브X와 가상 키패드가 모두 사라져 차단율 0%가 나오더라도, '국내 웹 환경의 웹 표준 전환 완료 실증'이라는 유의미한 결론이 되므로 검증 가능한 가설로 최종 확정함.

### 1.8 최종 가설 선정 이유 (T10-C10)
- 하드웨어 바인딩 로컬 볼트(PrfVault)를 직접 구현하면서 겪은 실제 문제에서 출발했으며, 외부 공개 웹사이트 50곳의 DOM 원자료를 자동화 스크립트로 즉시 수집·재현할 수 있고, 2026년 9월 발생한 금융권 크리덴셜 스터핑 유출 사고의 구조적 원인을 정량적으로 규명할 수 있기 때문이다.

---

## 2. 논거 세우기 (T10-C11 - T10-C20)

### 2.1 참고문헌 목록 및 가설 뒷받침 연결 (T10-C11 - T10-C14, T10-C16, T10-C19)
1. **Florêncio, D., & Herley, C. (2007)**. A Large-Scale Study of Web Password Habits. *Proceedings of the 16th International Conference on World Wide Web (WWW '07)*, ACM, 657-666. https://doi.org/10.1145/1242572.1242661
   - **가설 연결 한 줄**: 이 연구는 50만 명의 실사용 데이터를 통해 웹사이트의 복잡한 제약이 사용자의 비밀번호 재사용을 유발한다는 내 가설의 행동학적 전제를 뒷받침한다.
2. **Grassi, P. A., Fenton, J. L., Newton, E. M., Perlner, R. A., Regenscheid, A. R., Burr, W. E., Richer, J. P., Lefkovitz, N. B., Danker, J. M., Choong, Y.-Y., Greene, K. K., & Theofanos, M. F. (2017)**. *Digital Identity Guidelines: Authentication and Lifecycle Management* (NIST Special Publication 800-63B). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-63b
   - **가설 연결 한 줄**: 이 지침은 비밀번호 최대 길이 최소 64자 허용 및 패스워드 매니저 붙여넣기(Paste) 기능 보장 기준을 제시하여 내 가설의 표준 엔트로피 기준치($E_{\text{std}} = 131.09\text{ bits}$)와 자동 완성 허용 원칙을 뒷받침한다.
3. **W3C Web Authentication Working Group (2023)**. *Web Authentication: An API for accessing Public Key Credentials Level 3 - Pseudo-Random Function (prf) Extension*. World Wide Web Consortium (W3C). https://www.w3.org/TR/webauthn-3/#sctn-prf-extension
   - **가설 연결 한 줄**: 이 기술 명세는 하드웨어 인증자에서 256비트 대칭 시드를 도출하는 표준 규격을 정의하여 내 연구가 제안하는 클라이언트 패스워드 매니저(PrfVault)의 암호학적 타당성을 뒷받침한다.
4. **mmmphyun (2026)**. PrfVault 1편: W3C WebAuthn PRF와 Rust Wasm 코어 암호 엔진 설계. *Security Agent DevLog*. https://mmmphyun.github.io/security-agent-toolkit/blog/proj-prfvault-01-wasm-core-and-webauthn-prf/
   - **가설 연결 한 줄**: 이 연구 기록은 TOTP의 낮은 엔트로피($19.93\text{ bits}$) 한계와 Windows 11 `webauthn.dll`의 PRF 차단 현상을 실기 환경에서 실증하여 내 연구의 실험 도구 설계 및 플랫폼 제약 논의를 뒷받침한다.
5. **Bitwarden Community (2024)**. WebAuthn PRF support on Windows Platform via native Windows Hello (Issue #19858). *GitHub Repository (bitwarden/clients)*. https://github.com/bitwarden/clients/issues/19858
   - **가설 연결 한 줄**: 이 이슈 리포트는 상용 패스워드 매니저에서도 Windows 운영체제 계층의 PRF 미지원 문제가 동일하게 발생함을 보여 주어 내 연구의 로컬 실기 검증 결과를 교차 뒷받침한다.

### 2.2 확인 과정에서 걸러낸(제외한) 문헌 및 사유 (T10-C15, T10-C20)
1. **제외 문헌 1**: AI가 초기 추천한 *"Kim, J. & Lee, S. (2022). Empirical Analysis of Korean ActiveX Virtual Keypads in Banking. Journal of Information Security"*
   - **제외 사유**: DOI 및 Google Scholar, DBpia에서 제목과 저자로 교차 검색한 결과 실물이 존재하지 않는 AI 할루시네이션(가짜 논문)으로 판명되어 즉시 삭제함.
2. **제외 문헌 2**: *금융감독원 전자금융감독규정 (2015년 개정본)*
   - **제외 사유**: 액티브X 및 보안 프로그램 강제 의무 폐지라는 배경 설명에는 참고했으나, 개별 웹사이트의 현행 DOM 차단율을 직접 측정한 실증 데이터가 아니므로 핵심 참고문헌 목록에서 제외함.
- **출처 확인 방법 (T10-C20)**: 모든 문헌은 DOI 리졸버(`doi.org`), W3C 공식 기술 문서 저장소, GitHub 이슈 트래커 및 기술 블로그에 직접 HTTP GET 요청을 보내 제목, 저자, 발행 연도, 초록 및 본문 수치 일치 여부를 대조 확인함.

### 2.3 이미 알려진 사실과 새로 주장하는 것 구분 (T10-C17)
- **이미 알려진 사실**: 인간은 기억 한계로 인해 비밀번호를 재사용하며(Florêncio & Herley, 2007), NIST SP 800-63B는 긴 비밀번호 허용과 패스워드 매니저 자동 완성 지원을 권고한다.
- **내가 새로 주장하는 것**: 2026년 현재 국내 50대 웹사이트를 실측한 결과 설치형 키보드 보안 모듈(TouchEn, ASTx 등)은 0%로 퇴출되었으나, 금융·핀테크 규제군의 6.7%(삼성증권, 현대카드)는 여전히 웹 가상 키패드로 자동 완성을 차단하고 있으며, 초대형 포털(네이버)과 통신사(KT)의 16자 최대 길이 제한이 표준 대비 정확히 20.0%($26.22\text{ bits}$)의 엔트로피 손실을 강제하고 있다.

---

## 3. 실험 설계와 실행 (T10-C21 - T10-C30)

### 3.1 실험 설계표: 바꾼 조건과 고정 조건 (T10-C21, T10-C22, T10-C23, T10-C24)

| 설계 항목 | 세부 설정 및 내용 |
| :--- | :--- |
| **바꾼 조건 (독립변수)** | 조사 대상 웹사이트 도메인 50개 및 인증 규제 그룹 분류:<br>- **규제 준수 MFA 의무화 그룹 (30개소)**: 은행(8), 증권(6), 공공(8), 핀테크(5), 통신(3)<br>- **단일 패스워드 레거시 그룹 (20개소)**: 포털(5), 커뮤니티(5), 이커머스(10) |
| **고정 조건 (통제변수)** | - 브라우저 엔진: Playwright v1.63.0 (Chromium Headless)<br>- 네트워크 대기 조건: `waitUntil: 'networkidle'`, 타임아웃 `30,000ms`<br>- 탐지 시그니처: 5대 보안 모듈 셀렉터(`SCANNER_SECURITY_SELECTORS`)<br>- 엔트로피 기준 상수: $L_{\text{std}}=20, N_{\text{std}}=94, E_{\text{std}}=131.0918\text{ bits}$, 크랙 연산 속도 $R=10^{10}\text{ guesses/sec}$ |
| **반복 및 표본 수** | 총 50개 웹사이트 전수 스캔 (단위 파이프라인 검증 테스트 10건 별도 수행) |
| **측정 기록 값** | `hasLoginForm`(로그인 폼 유무), `maxPasswordLength`(최대 길이 $L$), `blockedByVirtualKeypad`(가상 키패드 차단 여부), `hasE2EKeyboardModule`(보안 모듈 유무), `entropyBits`(섀넌 엔트로피), `entropyLossPercent`(엔트로피 손실률 %) |

### 3.2 원자료 및 재현 스크립트 구성 (T10-C25 - T10-C30)
- **원자료 파일**:
  - `scripts/results/raw-scans.json` (50개 웹사이트 원시 DOM 스캔 데이터, 50건 정합성 100% 일치).
  - `scripts/results/benchmark-analysis.json` (50개 사이트 엔트로피 및 대조군 통계 산출 데이터).
- **실행 스크립트**:
  - `scripts/benchmark/targets.ts` (50개 타깃 도메인 정의)
  - `scripts/benchmark/scanner.ts` (Playwright 기반 헤드리스 DOM 스캐너)
  - `scripts/benchmark/analyzer.ts` (섀넌 엔트로피 및 대조군 정량 분석기)
- **짧은 재현 확인 방법 (T10-C29)**:
  1. 원자료 기반 정량 분석 즉시 재현 (외부 네트워크 불필요, 1초 이내 완료):
     `npm --prefix scripts run analyze`
  2. 스캐너 및 분석기 수학 공식 무결성 단위 테스트 (10개 테스트):
     `npm --prefix scripts test`
- **도중 설계 변경 기록 (T10-C30)**:
  - 초기 설계에서는 50개 사이트 중 1개라도 접속 실패 시 배치가 중단되도록 작성했으나, 시험 실행 중 KB국민카드(`card.kbstar.com`)에서 DNS 해석 오류(`net::ERR_NAME_NOT_RESOLVED`)가 발생함.
  - 이에 따라 에러 발생 시 해당 도메인의 `error` 필드에 원인을 기록하고 나머지 49개 사이트 스캔을 끝까지 완주하도록 예외 격리 로직을 추가했으며, 실패한 1건도 삭제하지 않고 원자료(`raw-scans.json` 47번째 항목)에 그대로 보존함.

---

## 4. 결과 해석 및 논문 패키징 계획 (T10-C31 - T10-C51)

- **논문 원고 파일**: `docs/T10-PAPER.md` (표지, 초록, 1. 서론, 2. 선행 연구 및 논거, 3. 연구 방법 및 실험 설계, 4. 실험 결과, 5. 논의 및 한계, 6. 결론, 참고문헌, 재현 방법, 부록 수록).
- **제출용 납품본 ZIP**: `submission/T10-PrfVault-Submission.zip`
  - 포함 파일: `PAPER.md`, `README.md`, `data/raw-scans.json`, `data/benchmark-analysis.json`, `scripts/` 재현 코드 일체.
  - 압축 해제 검증: 별도 임시 디렉터리에 압축을 풀고 누락 파일 유무 및 분석 스크립트 재현 동작을 검증.
