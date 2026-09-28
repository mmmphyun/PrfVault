/**
 * PrfVault Phase 4.2: 섀넌 엔트로피 손실률 및 차단율 정량 분석기 단위 테스트
 */

import { strict as assert } from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import {
  STANDARD_BASELINE,
  calculateCharsetSize,
  calculatePasswordEntropy,
  calculateEntropyLossPercent,
  estimateCrackTimeSeconds,
  assessRiskLevel,
  analyzeBenchmarkResults,
  saveAnalysisReport,
  formatAnalysisReport,
  type BenchmarkAnalysisReport,
} from '../benchmark/analyzer.ts';
import { type ScanResult } from '../benchmark/scanner.ts';

async function runTests() {
  console.log('--- [Test 1] 섀넌 엔트로피 및 손실률 수학 공식 무결성 검증 ---');
  // 1. 표준 기준치 (L=20, N=94): E ≈ 131.09 bits, 손실률 0%
  const stdEntropy = calculatePasswordEntropy(20, 94);
  assert.equal(Math.round(stdEntropy * 100) / 100, 131.09, '표준 엔트로피 ≈ 131.09 bits');
  const stdLoss = calculateEntropyLossPercent(stdEntropy, stdEntropy);
  assert.equal(stdLoss, 0, '기준 엔트로피 손실률은 0%여야 함');

  // 2. 12자 복합 문자 (L=12, N=94): E ≈ 78.65 bits, 손실률 40.0%
  const len12Entropy = calculatePasswordEntropy(12, 94);
  assert.equal(Math.round(len12Entropy * 100) / 100, 78.66, '12자 복합 엔트로피 ≈ 78.66 bits');
  const len12Loss = calculateEntropyLossPercent(len12Entropy, stdEntropy);
  assert.equal(Math.round(len12Loss * 10) / 10, 40.0, '12자 복합 손실률 ≈ 40.0%');

  // 3. 8자 영숫자 전용 (L=8, N=62): E ≈ 47.63 bits, 손실률 ≈ 63.66%
  const len8AlphaEntropy = calculatePasswordEntropy(8, 62);
  assert.equal(Math.round(len8AlphaEntropy * 100) / 100, 47.63, '8자 영숫자 엔트로피 ≈ 47.63 bits');
  const len8Loss = calculateEntropyLossPercent(len8AlphaEntropy, stdEntropy);
  assert.equal(Math.round(len8Loss * 10) / 10, 63.7, '8자 영숫자 손실률 ≈ 63.7%');

  // 4. 경계 조건 검증 (길이 0 이하)
  assert.equal(calculatePasswordEntropy(0, 94), 0, '길이 0 엔트로피는 0');
  assert.equal(calculateEntropyLossPercent(0, stdEntropy), 100, '엔트로피 0의 손실률은 100%');
  console.log('✓ Test 1 Passed: 섀넌 엔트로피(E = L * log2(N)) 및 손실률 수학 공식 무결성');

  console.log('--- [Test 2] 적응형 허용 문자군 크기(N) 산출 검증 ---');
  // 1. 기본값: 표준 94개 ASCII 문자
  assert.equal(calculateCharsetSize(), 94, '기본 문자군 크기는 94');

  // 2. 특수문자 금지(allowedSymbols: ""): 62개
  assert.equal(calculateCharsetSize(''), 62, '특수문자 배제 시 62');

  // 3. 커스텀 특수문자 5종 허용: 62 + 5 = 67
  assert.equal(calculateCharsetSize('!@#$%'), 67, '커스텀 5종 특수문자 크기는 67');

  // 4. 중복 문자 제거 검증
  assert.equal(calculateCharsetSize('!!!@@@'), 64, '중복 특수문자 2종 반영 크기는 64');

  // 5. 정규식 제약 기반 숫자 전용 검증
  assert.equal(calculateCharsetSize(undefined, { pattern: '^[0-9]+$' }), 10, '숫자 전용 정규식은 10');
  console.log('✓ Test 2 Passed: 제약 조건 기반 허용 문자군 크기(N) 정밀 산출');

  console.log('--- [Test 3] 오프라인 크랙 시간 및 위험도(Risk Level) 평가 검증 ---');
  // 1. 47.63 비트(8자 영숫자): 2^46.63 / 10^10 ≈ 10,650초 (약 2.9시간)
  const crackTimeShort = estimateCrackTimeSeconds(47.63);
  assert.ok(crackTimeShort < 86400, '47비트 패스워드는 24시간 내 크랙 가능');

  // 2. 131.09 비트(표준 20자): 우주 수명 이상의 시간
  const crackTimeLong = estimateCrackTimeSeconds(131.09);
  assert.ok(crackTimeLong > 1e20, '131비트 패스워드는 우주적 크랙 시간 소요');

  // 3. 위험도 매트릭스 검증
  // 단일 팩터 + 50비트 -> CRITICAL
  assert.equal(assessRiskLevel(50, false, false), 'CRITICAL', 'MFA 없는 50비트는 CRITICAL');
  // 단일 팩터 + 75비트 -> HIGH
  assert.equal(assessRiskLevel(75, false, false), 'HIGH', 'MFA 없는 75비트는 HIGH');
  // MFA 강제 + 55비트 -> HIGH
  assert.equal(assessRiskLevel(55, true, false), 'HIGH', 'MFA 있어도 55비트는 HIGH');
  // MFA 강제 + 100비트 + 키패드 없음 -> LOW
  assert.equal(assessRiskLevel(100, true, false), 'LOW', 'MFA 있고 100비트는 LOW');
  // MFA 강제 + 100비트 + 가상키패드 차단 -> MEDIUM
  assert.equal(assessRiskLevel(100, true, true), 'MEDIUM', 'MFA와 고엔트로피지만 가상키패드 차단 시 MEDIUM');
  console.log('✓ Test 3 Passed: GPU 브루트포스 크랙 시간 및 위험도 매트릭스 판정 무결성');

  console.log('--- [Test 4] 대조군 집계 및 가상 키패드 차단율 분석 검증 ---');
  const mockDataset: ScanResult[] = [
    // 규제군 (MFA = true, 금융) - 3개
    {
      domain: 'bank-a.com',
      url: 'https://bank-a.com/login',
      category: 'banking',
      hasMfaEnforced: true,
      hasLoginForm: true,
      securityModules: ['TouchEn', 'VirtualKeypad'],
      maxPasswordLength: 12, // 12자 상한
      blockedByVirtualKeypad: true,
      hasE2EKeyboardModule: true,
      detectedSelectors: [],
      timestamp: new Date().toISOString(),
    },
    {
      domain: 'bank-b.com',
      url: 'https://bank-b.com/login',
      category: 'banking',
      hasMfaEnforced: true,
      hasLoginForm: true,
      securityModules: ['AnySign'],
      maxPasswordLength: 16,
      blockedByVirtualKeypad: false,
      hasE2EKeyboardModule: true,
      detectedSelectors: [],
      timestamp: new Date().toISOString(),
    },
    {
      domain: 'gov.go.kr',
      url: 'https://gov.go.kr/login',
      category: 'public',
      hasMfaEnforced: true,
      hasLoginForm: true,
      securityModules: [],
      maxPasswordLength: 20,
      blockedByVirtualKeypad: false,
      hasE2EKeyboardModule: false,
      detectedSelectors: [],
      timestamp: new Date().toISOString(),
    },
    // 레거시군 (MFA = false, 커뮤니티/포털) - 2개
    {
      domain: 'community-a.com',
      url: 'https://community-a.com/login',
      category: 'community',
      hasMfaEnforced: false,
      hasLoginForm: true,
      securityModules: [],
      maxPasswordLength: 8, // 8자 상한 (치명적)
      allowedSymbols: '', // 특수문자 금지 (N=62)
      blockedByVirtualKeypad: false,
      hasE2EKeyboardModule: false,
      detectedSelectors: [],
      timestamp: new Date().toISOString(),
    },
    {
      domain: 'portal-a.com',
      url: 'https://portal-a.com/login',
      category: 'portal',
      hasMfaEnforced: false,
      hasLoginForm: true,
      securityModules: ['VirtualKeypad'],
      maxPasswordLength: 16,
      blockedByVirtualKeypad: true,
      hasE2EKeyboardModule: false,
      detectedSelectors: [],
      timestamp: new Date().toISOString(),
    },
  ];

  const report = analyzeBenchmarkResults(mockDataset);

  // 전체 통계 검증
  assert.equal(report.totalScanned, 5, '총 5개 사이트');
  assert.equal(report.mfaEnforcedCount, 3, 'MFA 규제군 3개');
  assert.equal(report.singleFactorCount, 2, '단일 팩터 레거시군 2개');
  // 가상키패드 차단 사이트: bank-a.com, portal-a.com (2개) -> 2/5 = 40.0%
  assert.equal(report.overallBlockingRate, 40.0, '가상 키패드 차단율 40%');
  // 보안 모듈 도입 사이트: bank-a.com, bank-b.com, portal-a.com (3개) -> 3/5 = 60.0%
  assert.equal(report.overallSecurityModuleRate, 60.0, '보안 모듈 도입율 60%');

  // 대조군 분리 검증
  assert.equal(report.contrastAnalysis.mfaGroup.count, 3);
  assert.equal(report.contrastAnalysis.mfaGroup.virtualKeypadCount, 1);
  assert.equal(report.contrastAnalysis.mfaGroup.blockingRate, 33.3);

  assert.equal(report.contrastAnalysis.singleFactorGroup.count, 2);
  assert.equal(report.contrastAnalysis.singleFactorGroup.virtualKeypadCount, 1);
  assert.equal(report.contrastAnalysis.singleFactorGroup.blockingRate, 50.0);

  // 최대 엔트로피 손실 사이트 검증: community-a.com (8자, N=62, 손실률 ~63.7%)
  assert.equal(report.entropyLossSummary.maxLossSite, 'community-a.com');
  assert.ok(report.entropyLossSummary.averageEntropyLoss > 0);

  // 카테고리별 분할 검증
  assert.equal(report.categoryStats.banking.count, 2);
  assert.equal(report.categoryStats.community.count, 1);
  assert.equal(report.categoryStats.portal.count, 1);
  assert.equal(report.categoryStats.public.count, 1);
  assert.equal(report.categoryStats.ecommerce.count, 0);
  console.log('✓ Test 4 Passed: 대조군(MFA vs Single-Factor) 분리 및 차단율 정량 집계 무결성');

  console.log('--- [Test 5] 리포트 포매터 및 파일 저장/로드 무결성 검증 ---');
  const formattedText = formatAnalysisReport(report);
  assert.ok(formattedText.includes('PrfVault BENCHMARK QUANTITATIVE REPORT'), '헤더 포함');
  assert.ok(formattedText.includes('community-a.com'), '최대 손실 사이트 표기');
  assert.ok(formattedText.includes('40%'), '차단율 표기');

  const testReportPath = path.resolve(process.cwd(), 'results/test-analysis.json');
  saveAnalysisReport(report, testReportPath);
  assert.ok(fs.existsSync(testReportPath), '리포트 파일 생성 확인');

  const loadedReport: BenchmarkAnalysisReport = JSON.parse(fs.readFileSync(testReportPath, 'utf-8'));
  assert.equal(loadedReport.totalScanned, 5);
  assert.equal(loadedReport.overallBlockingRate, 40.0);
  assert.equal(loadedReport.entropyLossSummary.maxLossSite, 'community-a.com');
  fs.unlinkSync(testReportPath); // 정리
  console.log('✓ Test 5 Passed: 리포트 CLI 포맷팅 및 JSON 직렬화 무결성');

  console.log('\n========================================');
  console.log('  ALL 5 ANALYZER PIPELINE TESTS PASSED  ');
  console.log('========================================');
}

runTests().catch(err => {
  console.error('Analyzer test suite failed:', err);
  process.exit(1);
});
