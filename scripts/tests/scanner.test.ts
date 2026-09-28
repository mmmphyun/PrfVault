/**
 * PrfVault Phase 4.1: 스캐너 파이프라인 무결성 및 휴리스틱 단위 테스트
 */

import { strict as assert } from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import {
  BENCHMARK_TARGETS,
  validateTargets,
  getTargetsByCategory,
  getTargetById,
} from '../benchmark/targets.ts';
import {
  SCANNER_SECURITY_SELECTORS,
  saveScanResults,
  type ScanResult,
  scanTargetSite,
} from '../benchmark/scanner.ts';

async function runTests() {
  console.log('--- [Test 1] 50대 타깃 전수 무결성 검증 ---');
  const targetValidation = validateTargets();
  assert.equal(targetValidation.valid, true, '50개 타깃 검증 통과');
  assert.equal(targetValidation.total, 50, '정확히 50개 타깃 등록');
  assert.equal(targetValidation.duplicates.length, 0, '중복 ID 없음');
  console.log('✓ Test 1 Passed: 50개 타깃 HTTPS 프로토콜 및 ID 고유성 100% 검증');

  console.log('--- [Test 2] 카테고리별 타깃 분류 검증 ---');
  const categories = ['portal', 'banking', 'securities', 'public', 'ecommerce', 'fintech', 'telecom'] as const;
  let categorySum = 0;
  for (const cat of categories) {
    const list = getTargetsByCategory(cat);
    assert.ok(list.length > 0, `${cat} 카테고리에 타깃이 1개 이상 존재해야 함`);
    categorySum += list.length;
  }
  assert.equal(categorySum, 50, '전체 카테고리 합산 50개 일치');
  console.log('✓ Test 2 Passed: 7대 카테고리 타깃 분류 무결성');

  console.log('--- [Test 3] 비-HTTPS URL 진입 차단 정책 검증 ---');
  const invalidTarget = {
    id: 'insecure-test',
    name: '테스트',
    domain: 'insecure.test',
    category: 'portal' as const,
    loginUrl: 'http://insecure.test/login',
  };
  const blockedResult = await scanTargetSite(invalidTarget);
  assert.ok(blockedResult.error?.includes('HTTPS'), '비-HTTPS 접근 시 에러 반환');
  assert.equal(blockedResult.hasLoginForm, false);
  console.log('✓ Test 3 Passed: 비-HTTPS 예외 거부 및 에러 격리 정책 준수');

  console.log('--- [Test 4] 보안 모듈 셀렉터 정의 무결성 검증 ---');
  assert.ok(SCANNER_SECURITY_SELECTORS.touchEn.length > 0, 'TouchEn 셀렉터 존재');
  assert.ok(SCANNER_SECURITY_SELECTORS.anySign.length > 0, 'AnySign 셀렉터 존재');
  assert.ok(SCANNER_SECURITY_SELECTORS.astx.length > 0, 'ASTx 셀렉터 존재');
  assert.ok(SCANNER_SECURITY_SELECTORS.nProtect.length > 0, 'nProtect 셀렉터 존재');
  assert.ok(SCANNER_SECURITY_SELECTORS.virtualKeypad.length > 0, 'VirtualKeypad 셀렉터 존재');
  console.log('✓ Test 4 Passed: 5대 보안 모듈 시그니처 셀렉터 무결성');

  console.log('--- [Test 5] 스캔 결과 직렬화 및 파일 I/O 검증 ---');
  const testOutputPath = path.resolve(process.cwd(), 'results/test-results.json');
  const mockResults: ScanResult[] = [
    {
      domain: 'test.com',
      url: 'https://test.com/login',
      hasLoginForm: true,
      securityModules: ['TouchEn', 'VirtualKeypad'],
      maxPasswordLength: 16,
      blockedByVirtualKeypad: true,
      hasE2EKeyboardModule: true,
      detectedSelectors: ['input[data-enc="on"]', 'div.keypad'],
      timestamp: new Date().toISOString(),
    },
  ];
  saveScanResults(mockResults, testOutputPath);
  assert.ok(fs.existsSync(testOutputPath), '결과 파일이 정상 생성되어야 함');
  const loaded = JSON.parse(fs.readFileSync(testOutputPath, 'utf-8'));
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].domain, 'test.com');
  assert.equal(loaded[0].blockedByVirtualKeypad, true);
  fs.unlinkSync(testOutputPath); // 정리
  console.log('✓ Test 5 Passed: 스캔 결과 파일 저장 및 무결성');

  console.log('\n========================================');
  console.log('  ALL 5 SCANNER PIPELINE TESTS PASSED');
  console.log('========================================');
}

runTests().catch(err => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
