# PrfVault AI 에이전트 운영 하네스 규격 (Agent Harness Spec)

본 문서는 PrfVault 레포지토리에서 작업을 수행하는 모든 자율 AI 에이전트(Claude Code, Cursor, Antigravity, Aider 등)가 준수해야 하는 기계적 행동 제약(Mechanical Constraints) 및 가드레일을 정의한다.

---

## 1. Git 커밋 및 훅 우회 절대 금지 (Bypass Prohibition)

- **`--no-verify` 플래그 사용 금지**:
  - `git commit --no-verify`, `-n` 옵션 사용을 영구적으로 금지한다.
  - Pre-commit 훅 또는 Gitleaks 탐지 실패 시, 원인을 회피하지 말고 실제 시크릿 제거 또는 `.gitleaksignore` 등록 절차를 수행해야 한다.
- **원자적 커밋(Atomic Commit) 준수**:
  - 1개 작업 단위당 1개 커밋(1-Task 1-Commit)을 실행한다. 여러 서브모듈(Rust, Extension, Docs)의 변경사항을 묶는 '빅뱅 커밋'을 금지한다.
  - 커밋 메시지 규격: `<type>(<scope>): <한글 요약>` (Conventional Commits).
  - 허용 태그: `feat`, `fix`, `refactor`, `docs`, `chore`, `test`, `style`, `perf`, `ci`.

---

## 2. 보안 명세 및 의존성 불변성 보장 (Security Immutability)

- **`docs/` 내 보안 아키텍처 임의 수정 금지**:
  - `docs/` 내의 암호화 명세, 위협 모델, WebAuthn PRF 예외 처리 문서는 확정된 합의 명세이므로 사용자 명시적 승인 없이 변경할 수 없다.
- **임의 의존성 추가 금지**:
  - `Cargo.toml`, `package.json`, `requirements.txt`에 신규 서드파티 라이브러리를 추가할 때는 사전에 명시적 정당성(경량성, 라이선스, 공급망 보안)을 입증하고 승인을 받아야 한다.

---

## 3. 시크릿 오탐(False Positive) 처리 표준 절차

Gitleaks 탐지가 발생한 경우 아래 3단계 프로토콜을 따른다:

1. **실제 시크릿 여부 판별**:
   - 실제 개인키, 패스워드, 프로덕션 토큰인 경우 코드에서 완전히 제거하고 환경변수 또는 WebAuthn PRF 파이프라인으로 전환.
2. **테스트 픽스처/CAVP 벡터인 경우**:
   - 파일 위치가 `tests/fixtures/` 또는 `tests/vectors/`인지 확인 (해당 경로는 자동 allowlist 처리됨).
3. **개별 오탐 지문(Fingerprint) 격리**:
   - 특정 라인의 테스트 해시나 고엔트로피 문자열이 탐지된 경우, Gitleaks가 출력한 지문(Fingerprint)을 복사하여 `.gitleaksignore`에 등록.
   - 절대로 `.githooks/pre-commit` 스크립트를 변조하거나 룰을 전역 비활성화하지 않는다.
