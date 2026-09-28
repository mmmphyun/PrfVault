/**
 * PrfVault Phase 4.2: 섀넌 엔트로피 손실률 및 가상 키패드 차단율 정량 분석 엔진
 *
 * [수학적 모델 및 정량 평가 지표]
 * 1. 키 공간 크기: S = N^L (N: 허용 문자군 크기, L: 최대 패스워드 길이)
 * 2. 섀넌 엔트로피: E = log2(S) = L * log2(N) [bits]
 *    - 표준 안전 기준치 (NIST SP 800-63B 권장): L_std = 20, N_std = 94 (ASCII 출력 가능 문자)
 *    - E_std = 20 * log2(94) ≈ 131.09 bits
 * 3. 엔트로피 손실률: Loss(%) = max(0, ((E_std - E) / E_std) * 100)
 * 4. 자동 완성 차단율: Blocking Rate = (N_keypad / N_total) * 100 [%]
 * 5. 오프라인 크랙 시간 추정: T = 2^(E - 1) / R (R = 10^10 guesses/sec, 현대 GPU 클러스터 기준)
 */

import * as fs from 'fs';
import * as path from 'path';
import { type SiteCategory } from './targets.ts';
import { type ScanResult } from './scanner.ts';

/**
 * 표준 엔트로피 기준 상수 정의
 */
export const STANDARD_BASELINE = {
  MAX_LENGTH: 20,
  CHARSET_SIZE_COMPLEX: 94, // 대문자 26 + 소문자 26 + 숫자 10 + 특수문자 32
  CHARSET_SIZE_ALPHANUMERIC: 62, // 대문자 26 + 소문자 26 + 숫자 10
  CHARSET_SIZE_LOWER_NUM: 36, // 소문자 26 + 숫자 10
  CHARSET_SIZE_NUMERIC: 10, // 숫자 10 (PIN)
  get STANDARD_ENTROPY_BITS(): number {
    return this.MAX_LENGTH * Math.log2(this.CHARSET_SIZE_COMPLEX); // ≈ 131.09 bits
  },
  DEFAULT_CRACK_HASH_RATE: 1e10, // 초당 100억 회 시도 (GPU 농장 기준)
} as const;

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface GroupMetrics {
  count: number;
  averageMaxPasswordLength: number;
  averageEntropyBits: number;
  averageEntropyLossPercent: number;
  virtualKeypadCount: number;
  blockingRate: number; // (%)
  securityModuleCount: number;
  securityModuleRate: number; // (%)
  estimatedCrackTimeSeconds: number;
}

export interface CategoryStat {
  category: SiteCategory;
  count: number;
  averageMaxPasswordLength: number;
  averageEntropyBits: number;
  averageEntropyLossPercent: number;
  virtualKeypadCount: number;
  blockingRate: number; // (%)
  securityModuleCount: number;
  securityModuleRate: number; // (%)
}

export interface EntropyLossSummary {
  maxLossSite: string;
  maxLossDomain?: string;
  maxLossPercent?: number;
  averageEntropyLoss: number;
  minLossSite?: string;
  minLossPercent?: number;
}

export interface SiteAnalysisDetail {
  domain: string;
  category: SiteCategory;
  hasMfaEnforced: boolean;
  maxPasswordLength: number;
  charsetSize: number;
  entropyBits: number;
  entropyLossPercent: number;
  blockedByVirtualKeypad: boolean;
  hasE2EModule: boolean;
  securityModules: string[];
  estimatedCrackTimeSeconds: number;
  riskLevel: RiskLevel;
}

export interface BenchmarkAnalysisReport {
  totalScanned: number;
  mfaEnforcedCount: number;
  singleFactorCount: number;
  overallBlockingRate: number; // 가상키패드 차단율 (%)
  overallSecurityModuleRate: number; // 보안모듈 도입률 (%)
  overallAverageEntropyBits: number;
  overallAverageEntropyLoss: number;
  categoryStats: Record<SiteCategory, CategoryStat>;
  contrastAnalysis: {
    mfaGroup: GroupMetrics;
    singleFactorGroup: GroupMetrics;
  };
  entropyLossSummary: {
    maxLossSite: string;
    averageEntropyLoss: number;
    maxLossDomain?: string;
    maxLossPercent?: number;
  };
  siteDetails?: SiteAnalysisDetail[];
  generatedAt: string;
}

export interface AnalyzerOptions {
  standardMaxLength?: number;
  standardCharsetSize?: number;
  hashRateGuessesPerSec?: number;
  includeSiteDetails?: boolean;
}

/**
 * 비밀번호 허용 문자군 크기(N) 산출
 * - allowedSymbols나 inputConstraints 패턴을 감지하여 적응형 계산
 */
export function calculateCharsetSize(
  allowedSymbols?: string,
  constraints?: ScanResult['inputConstraints']
): number {
  if (allowedSymbols !== undefined) {
    if (allowedSymbols.trim() === '') {
      return STANDARD_BASELINE.CHARSET_SIZE_ALPHANUMERIC; // 62
    }
    // 영숫자 62개 + 고유 특수문자 수
    const uniqueSymbols = new Set(allowedSymbols.split('')).size;
    return STANDARD_BASELINE.CHARSET_SIZE_ALPHANUMERIC + uniqueSymbols;
  }

  if (constraints?.pattern) {
    const pat = constraints.pattern;
    // 숫자 전용 패턴 감지 (예: ^[0-9]+$, ^\d{4,6}$, \d+)
    const isDigitsOnly =
      /^(\^)?(\[0-9\]|\\d|\d)([\+\*]|\{\d+(,\d+)?\})?(\$)?$/i.test(pat) ||
      (/^[0-9\^\\d\+\*\$\{\},\[\]-]+$/.test(pat) && !/[a-zA-Z]/.test(pat) && !/[!@#$%^&*()_+~`|{}[\]:;?><,./]/.test(pat.replace(/[\^\\d\+\*\$\{\},\[\]-]/g, '')));

    if (isDigitsOnly) {
      return STANDARD_BASELINE.CHARSET_SIZE_NUMERIC; // 10
    }

    // 영소문자 + 숫자만 허용 (예: ^[a-z0-9]+$)
    if (/[a-z]/.test(pat) && !/[A-Z]/.test(pat) && /[0-9]|\\d/.test(pat) && !/[\W_]/.test(pat.replace(/[\^\\d\+\*\$\{\},\[\]-]/g, ''))) {
      return STANDARD_BASELINE.CHARSET_SIZE_LOWER_NUM; // 36
    }

    // 영숫자 전용(특수문자 배제)인 경우 (예: ^[a-zA-Z0-9]+$)
    const hasAlpha = /[a-zA-Z]/.test(pat);
    const hasDigit = /[0-9]|\\d/.test(pat);
    const hasSpecialAllowed = /[\W_]/.test(pat.replace(/[\^\\d\+\*\$\{\},\[\]a-zA-Z0-9-]/g, ''));
    if (hasAlpha && hasDigit && !hasSpecialAllowed) {
      return STANDARD_BASELINE.CHARSET_SIZE_ALPHANUMERIC; // 62
    }
  }

  // 기본값: 표준 94개 ASCII 출력 가능 문자
  return STANDARD_BASELINE.CHARSET_SIZE_COMPLEX;
}

/**
 * 섀넌 엔트로피 (E = L * log2(N)) 계산
 */
export function calculatePasswordEntropy(
  maxLength: number,
  charsetSize: number = STANDARD_BASELINE.CHARSET_SIZE_COMPLEX
): number {
  const safeLength = Math.max(0, maxLength);
  const safeCharset = Math.max(1, charsetSize);
  const bits = safeLength * Math.log2(safeCharset);
  return Number(bits.toFixed(4));
}

/**
 * 기준 엔트로피 대비 손실률(Loss %) 계산
 */
export function calculateEntropyLossPercent(
  entropyBits: number,
  standardEntropy: number = STANDARD_BASELINE.STANDARD_ENTROPY_BITS
): number {
  if (standardEntropy <= 0) return 0;
  const loss = ((standardEntropy - entropyBits) / standardEntropy) * 100;
  return Number(Math.max(0, Math.min(100, loss)).toFixed(2));
}

/**
 * 오프라인 크랙 시간(초) 추정
 * T = 2^(E - 1) / R
 */
export function estimateCrackTimeSeconds(
  entropyBits: number,
  hashRate: number = STANDARD_BASELINE.DEFAULT_CRACK_HASH_RATE
): number {
  if (entropyBits <= 0) return 0;
  if (entropyBits > 1024) return Number.POSITIVE_INFINITY;
  const combinations = Math.pow(2, Math.max(0, entropyBits - 1));
  const seconds = combinations / hashRate;
  return Number.isFinite(seconds) ? Number(seconds.toExponential(4)) : Number.POSITIVE_INFINITY;
}

/**
 * 개별 사이트 취약성 위험도 판정
 */
export function assessRiskLevel(
  entropyBits: number,
  hasMfaEnforced: boolean,
  blockedByVirtualKeypad: boolean
): RiskLevel {
  // 1. 단일 패스워드 인증(MFA 부재) 환경
  if (!hasMfaEnforced) {
    if (entropyBits < 64) {
      // 64비트 미만은 크리덴셜 스터핑 및 GPU 레인보우 테이블에 즉각 노출
      return 'CRITICAL';
    }
    if (entropyBits < 85) {
      return 'HIGH';
    }
    return blockedByVirtualKeypad ? 'HIGH' : 'MEDIUM';
  }

  // 2. 2차 인증(MFA) 강제 환경
  if (entropyBits < 60) {
    return 'HIGH'; // 낮은 1차 엔트로피
  }
  if (blockedByVirtualKeypad) {
    return 'MEDIUM'; // MFA로 방어되나 패스워드 매니저 자동완성 차단으로 인한 UX 및 피싱 위험
  }
  return 'LOW';
}

/**
 * 그룹 통계 생성 헬퍼 함수
 */
function aggregateMetrics(items: SiteAnalysisDetail[]): GroupMetrics {
  const count = items.length;
  if (count === 0) {
    return {
      count: 0,
      averageMaxPasswordLength: 0,
      averageEntropyBits: 0,
      averageEntropyLossPercent: 0,
      virtualKeypadCount: 0,
      blockingRate: 0,
      securityModuleCount: 0,
      securityModuleRate: 0,
      estimatedCrackTimeSeconds: 0,
    };
  }

  const totalLength = items.reduce((acc, cur) => acc + cur.maxPasswordLength, 0);
  const totalEntropy = items.reduce((acc, cur) => acc + cur.entropyBits, 0);
  const totalLoss = items.reduce((acc, cur) => acc + cur.entropyLossPercent, 0);
  const keypadCount = items.filter(i => i.blockedByVirtualKeypad).length;
  const secModuleCount = items.filter(i => i.hasE2EModule || i.securityModules.length > 0).length;

  return {
    count,
    averageMaxPasswordLength: Number((totalLength / count).toFixed(1)),
    averageEntropyBits: Number((totalEntropy / count).toFixed(2)),
    averageEntropyLossPercent: Number((totalLoss / count).toFixed(2)),
    virtualKeypadCount: keypadCount,
    blockingRate: Number(((keypadCount / count) * 100).toFixed(1)),
    securityModuleCount: secModuleCount,
    securityModuleRate: Number(((secModuleCount / count) * 100).toFixed(1)),
    estimatedCrackTimeSeconds: estimateCrackTimeSeconds(totalEntropy / count),
  };
}

/**
 * 벤치마크 원시 스캔 결과 분석 엔진
 *
 * @param rawScans DOM 스캐너가 수집한 사이트별 결과 배열
 * @param options 분석 파라미터 (기준 길이, 기준 문자군, 해시레이트 등)
 */
export function analyzeBenchmarkResults(
  rawScans: ScanResult[],
  options: AnalyzerOptions = {}
): BenchmarkAnalysisReport {
  const stdLength = options.standardMaxLength ?? STANDARD_BASELINE.MAX_LENGTH;
  const stdCharset = options.standardCharsetSize ?? STANDARD_BASELINE.CHARSET_SIZE_COMPLEX;
  const stdEntropy = stdLength * Math.log2(stdCharset);
  const hashRate = options.hashRateGuessesPerSec ?? STANDARD_BASELINE.DEFAULT_CRACK_HASH_RATE;
  const includeDetails = options.includeSiteDetails ?? true;

  const siteDetails: SiteAnalysisDetail[] = rawScans.map(scan => {
    // 길이 상한 파싱: 명시적 maxPasswordLength가 없으면 inputConstraints.maxlength 확인, 없으면 기본 20으로 fallback
    let length = scan.maxPasswordLength;
    if (length === undefined || length <= 0) {
      if (scan.inputConstraints?.maxlength && scan.inputConstraints.maxlength > 0) {
        length = scan.inputConstraints.maxlength;
      } else {
        length = STANDARD_BASELINE.MAX_LENGTH;
      }
    }

    const charsetSize = calculateCharsetSize(scan.allowedSymbols, scan.inputConstraints);
    const entropyBits = calculatePasswordEntropy(length, charsetSize);
    const entropyLossPercent = calculateEntropyLossPercent(entropyBits, stdEntropy);
    const hasE2E = scan.hasE2EKeyboardModule || (scan.securityModules && scan.securityModules.length > 0);
    const crackTime = estimateCrackTimeSeconds(entropyBits, hashRate);
    const riskLevel = assessRiskLevel(entropyBits, scan.hasMfaEnforced, scan.blockedByVirtualKeypad);

    return {
      domain: scan.domain,
      category: scan.category,
      hasMfaEnforced: scan.hasMfaEnforced,
      maxPasswordLength: length,
      charsetSize,
      entropyBits,
      entropyLossPercent,
      blockedByVirtualKeypad: scan.blockedByVirtualKeypad,
      hasE2EModule: hasE2E,
      securityModules: scan.securityModules ?? [],
      estimatedCrackTimeSeconds: crackTime,
      riskLevel,
    };
  });

  const totalScanned = siteDetails.length;
  const mfaItems = siteDetails.filter(s => s.hasMfaEnforced);
  const singleFactorItems = siteDetails.filter(s => !s.hasMfaEnforced);

  const mfaGroupMetrics = aggregateMetrics(mfaItems);
  const singleFactorGroupMetrics = aggregateMetrics(singleFactorItems);

  // 카테고리별 집계
  const allCategories: SiteCategory[] = [
    'portal',
    'community',
    'banking',
    'securities',
    'public',
    'ecommerce',
    'fintech',
    'telecom',
  ];

  const categoryStats = {} as Record<SiteCategory, CategoryStat>;
  for (const cat of allCategories) {
    const catItems = siteDetails.filter(s => s.category === cat);
    const metrics = aggregateMetrics(catItems);
    categoryStats[cat] = {
      category: cat,
      count: metrics.count,
      averageMaxPasswordLength: metrics.averageMaxPasswordLength,
      averageEntropyBits: metrics.averageEntropyBits,
      averageEntropyLossPercent: metrics.averageEntropyLossPercent,
      virtualKeypadCount: metrics.virtualKeypadCount,
      blockingRate: metrics.blockingRate,
      securityModuleCount: metrics.securityModuleCount,
      securityModuleRate: metrics.securityModuleRate,
    };
  }

  // 전체 통계
  const totalBlockingCount = siteDetails.filter(s => s.blockedByVirtualKeypad).length;
  const totalSecModuleCount = siteDetails.filter(s => s.hasE2EModule || s.securityModules.length > 0).length;
  const overallBlockingRate = totalScanned > 0 ? Number(((totalBlockingCount / totalScanned) * 100).toFixed(1)) : 0;
  const overallSecModuleRate = totalScanned > 0 ? Number(((totalSecModuleCount / totalScanned) * 100).toFixed(1)) : 0;
  const totalEntropySum = siteDetails.reduce((acc, cur) => acc + cur.entropyBits, 0);
  const totalLossSum = siteDetails.reduce((acc, cur) => acc + cur.entropyLossPercent, 0);

  const overallAverageEntropyBits = totalScanned > 0 ? Number((totalEntropySum / totalScanned).toFixed(2)) : 0;
  const overallAverageEntropyLoss = totalScanned > 0 ? Number((totalLossSum / totalScanned).toFixed(2)) : 0;

  // 최대/최소 손실 사이트 도출
  let maxLossItem = siteDetails[0];
  let minLossItem = siteDetails[0];
  for (const item of siteDetails) {
    if (!maxLossItem || item.entropyLossPercent > maxLossItem.entropyLossPercent) {
      maxLossItem = item;
    }
    if (!minLossItem || item.entropyLossPercent < minLossItem.entropyLossPercent) {
      minLossItem = item;
    }
  }

  const entropyLossSummary: BenchmarkAnalysisReport['entropyLossSummary'] = {
    maxLossSite: maxLossItem ? maxLossItem.domain : 'N/A',
    maxLossDomain: maxLossItem ? maxLossItem.domain : 'N/A',
    maxLossPercent: maxLossItem ? maxLossItem.entropyLossPercent : 0,
    averageEntropyLoss: overallAverageEntropyLoss,
  };

  const report: BenchmarkAnalysisReport = {
    totalScanned,
    mfaEnforcedCount: mfaItems.length,
    singleFactorCount: singleFactorItems.length,
    overallBlockingRate,
    overallSecurityModuleRate: overallSecModuleRate,
    overallAverageEntropyBits,
    overallAverageEntropyLoss,
    categoryStats,
    contrastAnalysis: {
      mfaGroup: mfaGroupMetrics,
      singleFactorGroup: singleFactorGroupMetrics,
    },
    entropyLossSummary,
    siteDetails: includeDetails ? siteDetails : undefined,
    generatedAt: new Date().toISOString(),
  };

  return report;
}

/**
 * 분석 리포트 CLI 포맷 문자열 생성
 */
export function formatAnalysisReport(report: BenchmarkAnalysisReport): string {
  const lines: string[] = [];
  lines.push('================================================================================');
  lines.push('                   PrfVault BENCHMARK QUANTITATIVE REPORT                       ');
  lines.push('================================================================================');
  lines.push(`총 스캔 사이트 수: ${report.totalScanned}개 (MFA 의무화: ${report.mfaEnforcedCount}, 단일 팩터 레거시: ${report.singleFactorCount})`);
  lines.push(`전체 가상 키패드 차단율: ${report.overallBlockingRate}%`);
  lines.push(`전체 E2E 보안 모듈 도입률: ${report.overallSecurityModuleRate}%`);
  lines.push(`전체 평균 섀넌 엔트로피: ${report.overallAverageEntropyBits} bits (표준 131.09 bits 대비 평균 손실률: ${report.overallAverageEntropyLoss}%)`);
  lines.push(`최대 엔트로피 손실 사이트: ${report.entropyLossSummary.maxLossSite} (${report.entropyLossSummary.maxLossPercent}%)`);
  lines.push('');
  lines.push('--------------------------------------------------------------------------------');
  lines.push(' [대조군 정량 비교 분석 (MFA 규제군 vs 단일 패스워드 레거시군)]');
  lines.push('--------------------------------------------------------------------------------');
  const m = report.contrastAnalysis.mfaGroup;
  const s = report.contrastAnalysis.singleFactorGroup;
  lines.push(`1. 규제 준수 MFA 그룹 (${m.count}개 사이트 - 금융/증권/공공/통신):`);
  lines.push(`   - 평균 최대 길이: ${m.averageMaxPasswordLength}자 | 평균 엔트로피: ${m.averageEntropyBits} bits (손실률: ${m.averageEntropyLossPercent}%)`);
  lines.push(`   - 가상 키패드 차단율: ${m.blockingRate}% (${m.virtualKeypadCount}/${m.count})`);
  lines.push(`   - 보안 프로그램 설치율: ${m.securityModuleRate}% (${m.securityModuleCount}/${m.count})`);
  lines.push('');
  lines.push(`2. 단일 패스워드 레거시 그룹 (${s.count}개 사이트 - 포털/커뮤니티/이커머스):`);
  lines.push(`   - 평균 최대 길이: ${s.averageMaxPasswordLength}자 | 평균 엔트로피: ${s.averageEntropyBits} bits (손실률: ${s.averageEntropyLossPercent}%)`);
  lines.push(`   - 가상 키패드 차단율: ${s.blockingRate}% (${s.virtualKeypadCount}/${s.count})`);
  lines.push(`   - 보안 프로그램 설치율: ${s.securityModuleRate}% (${s.securityModuleCount}/${s.count})`);
  lines.push('');
  lines.push('--------------------------------------------------------------------------------');
  lines.push(' [카테고리별 정량 분석 통계]');
  lines.push('--------------------------------------------------------------------------------');
  lines.push('카테고리      | 사이트수 | 평균길이 | 평균엔트로피 | 손실률(%) | 키패드차단율 | 보안모듈율');
  lines.push('-------------|----------|----------|--------------|-----------|--------------|-----------');
  for (const [cat, stat] of Object.entries(report.categoryStats)) {
    const pad = (val: string | number, len: number) => String(val).padEnd(len, ' ');
    lines.push(
      `${pad(cat, 12)} | ${pad(stat.count, 8)} | ${pad(stat.averageMaxPasswordLength, 8)} | ${pad(stat.averageEntropyBits + 'b', 12)} | ${pad(stat.averageEntropyLossPercent + '%', 9)} | ${pad(stat.blockingRate + '%', 12)} | ${pad(stat.securityModuleRate + '%', 9)}`
    );
  }
  lines.push('================================================================================');
  return lines.join('\n');
}

/**
 * 분석 결과 JSON 파일 저장
 */
export function saveAnalysisReport(report: BenchmarkAnalysisReport, outputPath: string): void {
  const resolved = path.resolve(outputPath);
  const dir = path.dirname(resolved);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(resolved, JSON.stringify(report, null, 2), 'utf-8');
}

/**
 * CLI 직접 실행 핸들러
 */
async function runCli(): Promise<void> {
  const args = process.argv.slice(2);
  let inputPath = path.resolve(process.cwd(), 'results/raw-scans.json');
  let outputPath = path.resolve(process.cwd(), 'results/benchmark-analysis.json');

  for (const arg of args) {
    if (arg.startsWith('--input=')) {
      inputPath = path.resolve(arg.slice('--input='.length));
    } else if (arg.startsWith('--output=')) {
      outputPath = path.resolve(arg.slice('--output='.length));
    }
  }

  if (!fs.existsSync(inputPath)) {
    console.error(`[ERROR] 입력 파일을 찾을 수 없습니다: ${inputPath}`);
    console.error(`  - 먼저 스캐너를 실행하여 결과를 수집하거나: npm --prefix scripts run scan:quick`);
    console.error(`  - --input=<파일경로> 옵션으로 경로를 지정하십시오.`);
    process.exit(1);
  }

  const rawData: ScanResult[] = JSON.parse(fs.readFileSync(inputPath, 'utf-8'));
  const report = analyzeBenchmarkResults(rawData);

  saveAnalysisReport(report, outputPath);
  console.log(formatAnalysisReport(report));
  console.log(`[SAVED] 정량 분석 결과가 저장되었습니다: ${outputPath}`);
}

// 직접 실행 여부 판별 (Node.js ESM)
const isMain = process.argv[1] && (
  process.argv[1].endsWith('analyzer.ts') ||
  process.argv[1].endsWith('analyzer.js')
);

if (isMain) {
  runCli().catch(err => {
    console.error('[FATAL] 분석기 실행 오류:', err);
    process.exit(1);
  });
}
