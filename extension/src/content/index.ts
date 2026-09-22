/**
 * PrfVault MV3 Content Script 엔트리포인트
 *
 * [보안 제약 및 격리 원칙]
 * - 웹페이지 DOM에 직접 접근하는 Isolated World 컨텍스트입니다.
 * - 볼트 스토리지 및 Wasm 메모리에 직접 접근할 수 없으며, 모든 처리는 Service Worker와의 IPC로만 수행합니다.
 */

console.info('[PrfVault] Content Script 주입 완료');
