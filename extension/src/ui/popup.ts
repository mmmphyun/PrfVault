/**
 * PrfVault MV3 Popup UI 엔트리포인트
 *
 * [보안 아키텍처 및 신뢰 경계]
 * - Extension Page(Popup)는 사용자의 물리적 인터랙션(User Gesture) 하에서 동작합니다.
 * - navigator.credentials(WebAuthn PRF 확장) 호출 및 Rust Wasm 암복호화 격리 런타임이 위치합니다.
 */

document.addEventListener('DOMContentLoaded', () => {
  const statusBox = document.getElementById('status-box');
  const btnAction = document.getElementById('btn-action') as HTMLButtonElement | null;

  if (statusBox) {
    statusBox.textContent = 'PrfVault 코어 준비 완료 (대기 중)';
  }

  if (btnAction) {
    btnAction.disabled = false;
  }
});
