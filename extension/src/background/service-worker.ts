/**
 * PrfVault MV3 Background Service Worker
 *
 * [보안 제약]
 * - Service Worker 컨텍스트에는 Window 객체가 부재하여 navigator.credentials(WebAuthn API) 호출이 불가능합니다.
 * - 브라우저 유휴 시 약 30초 내 프로세스가 자동 종료되므로, 메모리에 복호화된 마스터키나 자격증명을 캐싱하지 않습니다.
 * - 본 워커는 순수 암호화 블롭 I/O(chrome.storage.local) 및 탭-팝업 간 IPC 메시지 라우터 역할만 수행합니다.
 */

chrome.runtime.onInstalled.addListener(() => {
  console.info('[PrfVault] Service Worker가 설치되었습니다.');
});
