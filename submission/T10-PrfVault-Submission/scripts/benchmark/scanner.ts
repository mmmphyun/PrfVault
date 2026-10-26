/**
 * PrfVault Phase 4.1: Playwright 기반 국내 50대 웹사이트 DOM 스캐너
 *
 * [동작 원리 및 보안 고려사항]
 * - 헤드리스 브라우저 환경에서 국내 주요 웹사이트의 로그인 페이지를 방문하여 DOM 구조를 분석합니다.
 * - E2E 보안 프로그램(TouchEn, AnySign, ASTx, nProtect) 및 가상 키패드 존재 여부를 감지합니다.
 * - 비밀번호 필드의 제약 조건(maxlength, minlength, pattern, 안내 텍스트)을 정량 수집합니다.
 * - 타임아웃, WAF 403, 또는 접근 불가 사이트는 예외를 격리하고 에러를 기록한 후 배치를 중단하지 않고 계속 진행합니다.
 */

import { chromium, type Browser, type BrowserContext, type Page } from 'playwright';
import * as fs from 'fs';
import * as path from 'path';
import { BENCHMARK_TARGETS, type BenchmarkTarget, type SiteCategory } from './targets.ts';

export interface ScanOptions {
  timeoutMs?: number;
  waitUntil?: 'load' | 'domcontentloaded' | 'networkidle' | 'commit';
  headless?: boolean;
  browser?: Browser;
}

export interface BatchScanOptions extends ScanOptions {
  limit?: number;
  category?: SiteCategory;
  targetId?: string;
  outputPath?: string;
  concurrency?: number;
}

export interface InputConstraints {
  maxlength?: number;
  minlength?: number;
  pattern?: string;
  placeholder?: string;
  ariaLabel?: string;
  hintText?: string;
}

export interface ScanResult {
  domain: string;
  url: string;
  category: SiteCategory;
  hasMfaEnforced: boolean;
  finalUrl?: string;
  pageTitle?: string;
  hasLoginForm: boolean;
  securityModules: string[];
  maxPasswordLength?: number;
  allowedSymbols?: string;
  blockedByVirtualKeypad: boolean;
  hasE2EKeyboardModule: boolean;
  isRegistration?: boolean;
  inputConstraints?: InputConstraints;
  detectedSelectors: string[];
  error?: string;
  timestamp: string;
}

/**
 * 국내 보안 프로그램 및 가상 키패드 셀렉터 정의 (extension/src/content/detector.ts 호환)
 */
export const SCANNER_SECURITY_SELECTORS = {
  touchEn: [
    'input[data-enc="on"]',
    'input[tk_type]',
    'input[data-tk-type]',
    '#TouchEnKey_tk_input',
    'embed[type*="touchen"]',
    'object[type*="touchen"]',
  ],
  anySign: [
    'input[data-any="on"]',
    'input[data-anysign]',
    'div#AnySign4PC',
    'div#AnySign4PC_Frame',
  ],
  astx: [
    'input[astx]',
    'input[data-astx]',
    'div#astx_install',
    'object[id*="astx"]',
  ],
  nProtect: [
    'input[npk]',
    'input[data-npk]',
    'form[name*="np"]',
    'div#nProtect',
  ],
  virtualKeypad: [
    'img[src*="keypad" i]',
    'div[class*="keypad" i]',
    'div[class*="transkey" i]',
    'div[id*="transkey" i]',
    'div[class*="mtk" i]',
    'div[id*="mtk" i]',
    'input[data-mode="virtual"]',
    'input[data-tk-virtual="true"]',
    'button[class*="keypad" i]',
    'a[class*="keypad" i]',
  ],
} as const;

/**
 * 단일 브라우저 인스턴스 론칭 헬퍼 (시스템 설치 Chrome 우선 시도)
 */
export async function launchScannerBrowser(headless = true): Promise<Browser> {
  try {
    return await chromium.launch({
      channel: 'chrome',
      headless,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-blink-features=AutomationControlled',
      ],
    });
  } catch {
    return await chromium.launch({
      headless,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
      ],
    });
  }
}

/**
 * 단일 웹사이트 DOM 스캔 실행
 */
export async function scanTargetSite(
  target: BenchmarkTarget,
  options: ScanOptions = {}
): Promise<ScanResult> {
  const timeoutMs = options.timeoutMs ?? 30000;
  const waitUntil = options.waitUntil ?? 'networkidle';
  const timestamp = new Date().toISOString();

  if (!target.loginUrl.startsWith('https://')) {
    return {
      domain: target.domain,
      url: target.loginUrl,
      category: target.category,
      hasMfaEnforced: target.hasMfaEnforced,
      hasLoginForm: false,
      securityModules: [],
      blockedByVirtualKeypad: false,
      hasE2EKeyboardModule: false,
      detectedSelectors: [],
      error: '프로토콜 위반: HTTPS URL만 허용됩니다.',
      timestamp,
    };
  }

  let ownBrowser = false;
  let browser = options.browser;
  if (!browser) {
    browser = await launchScannerBrowser(options.headless ?? true);
    ownBrowser = true;
  }

  let context: BrowserContext | null = null;
  let page: Page | null = null;

  try {
    context = await browser.newContext({
      userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
      viewport: { width: 1280, height: 800 },
      ignoreHTTPSErrors: true,
      locale: 'ko-KR',
    });

    // 헤드리스 자동화 탐지 플래그 완화 (WAF 차단 최소화)
    await context.addInitScript(() => {
      Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
      Object.defineProperty(navigator, 'languages', { get: () => ['ko-KR', 'ko', 'en-US', 'en'] });
      Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
    });

    page = await context.newPage();
    page.setDefaultTimeout(timeoutMs);

    // 1. 페이지 탐색 및 대기
    try {
      await page.goto(target.loginUrl, {
        waitUntil,
        timeout: timeoutMs,
      });
    } catch (gotoError) {
      // networkidle 타임아웃 발생 시 domcontentloaded 상태로 폴백 시도
      const msg = (gotoError as Error).message || '';
      if (msg.includes('Timeout') && waitUntil === 'networkidle') {
        try {
          await page.waitForLoadState('domcontentloaded', { timeout: 5000 });
        } catch {
          // 폴백도 실패한 경우 상위 catch로 전달
          throw gotoError;
        }
      } else {
        throw gotoError;
      }
    }

    const finalUrl = page.url();
    const pageTitle = await page.title().catch(() => '');

    // 2. 가상 키패드 렌더링을 위한 1초 안정화 대기
    await page.waitForTimeout(1000);

    // 3. 브라우저 컨텍스트 내에서 모든 프레임(메인 프레임 + 서브 iframe) 종합 평가
    const selectors = SCANNER_SECURITY_SELECTORS;
    const frames = page.frames();

    let combinedHasLoginForm = false;
    let combinedIsRegistration = false;
    const combinedSecurityModules = new Set<string>();
    let combinedHasVirtualKeypad = false;
    let combinedHasE2EKeyboard = false;
    const combinedDetectedSelectors = new Set<string>();
    let combinedMaxPasswordLength: number | undefined = undefined;
    let combinedMinLength: number | undefined = undefined;
    let combinedPattern: string | undefined = undefined;
    let combinedPlaceholder: string | undefined = undefined;
    let combinedAriaLabel: string | undefined = undefined;
    let combinedHintText: string | undefined = undefined;
    let combinedAllowedSymbols: string | undefined = undefined;

    for (const frame of frames) {
      try {
        const frameEval = await frame.evaluate((selMap) => {
          function isVisible(el: HTMLElement): boolean {
            if (el.tagName === 'INPUT' && (el as HTMLInputElement).type === 'hidden') return false;
            if (el.getAttribute('aria-hidden') === 'true') return false;
            const style = window.getComputedStyle(el);
            if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
            const rect = el.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0;
          }

          const detectedSelectors: string[] = [];
          const securityModules: string[] = [];
          let hasVirtualKeypad = false;
          let hasE2EKeyboardModule = false;

          function checkGroup(name: string, selectors: readonly string[], isKeypad: boolean) {
            for (const sel of selectors) {
              try {
                const found = document.querySelector(sel);
                if (found) {
                  detectedSelectors.push(sel);
                  if (!securityModules.includes(name)) {
                    securityModules.push(name);
                  }
                  if (isKeypad) hasVirtualKeypad = true;
                  else hasE2EKeyboardModule = true;
                }
              } catch {
                // 유효하지 않은 셀렉터 무시
              }
            }
          }

          checkGroup('TouchEn', selMap.touchEn, false);
          checkGroup('AnySign', selMap.anySign, false);
          checkGroup('ASTx', selMap.astx, false);
          checkGroup('nProtect', selMap.nProtect, false);
          checkGroup('VirtualKeypad', selMap.virtualKeypad, true);

          const allInputs = Array.from(document.querySelectorAll('input'));
          const passwordInputs = allInputs.filter(input => {
            const type = (input.type || '').toLowerCase();
            const auto = (input.getAttribute('autocomplete') || '').toLowerCase();
            return (type === 'password' || auto === 'current-password' || auto === 'new-password') && isVisible(input);
          });

          const hasLoginForm = passwordInputs.length > 0;
          const isRegistration =
            passwordInputs.length >= 2 ||
            passwordInputs.some(p => p.getAttribute('autocomplete')?.toLowerCase() === 'new-password');

          let maxPasswordLength: number | undefined = undefined;
          let minlength: number | undefined = undefined;
          let pattern: string | undefined = undefined;
          let placeholder: string | undefined = undefined;
          let ariaLabel: string | undefined = undefined;
          let hintText: string | undefined = undefined;

          if (passwordInputs.length > 0) {
            const targetPw = passwordInputs[0];
            const mlAttr = targetPw.getAttribute('maxlength');
            if (mlAttr && !isNaN(Number(mlAttr))) {
              const val = Number(mlAttr);
              if (val > 0 && val < 500) {
                maxPasswordLength = val;
              }
            }
            const minAttr = targetPw.getAttribute('minlength');
            if (minAttr && !isNaN(Number(minAttr))) {
              minlength = Number(minAttr);
            }
            pattern = targetPw.getAttribute('pattern') || undefined;
            placeholder = targetPw.getAttribute('placeholder') || undefined;
            ariaLabel = targetPw.getAttribute('aria-label') || undefined;

            const parent = targetPw.closest('form') || targetPw.parentElement?.parentElement || document.body;
            const text = parent.innerText || '';
            const lengthMatch = text.match(/([0-9]{1,2})\s*?[~-]\s*?([0-9]{1,2})\s*?[자자릿자리]/);
            if (lengthMatch) {
              hintText = lengthMatch[0];
              if (!maxPasswordLength) {
                maxPasswordLength = Number(lengthMatch[2]);
              }
            }
          }

          let allowedSymbols: string | undefined = undefined;
          if (document.body) {
            const bodyText = document.body.innerText || '';
            const symbolMatch = bodyText.match(/특수문자\s*?[(\[]([!@#$%^&*()_+~`\-={}[\]:;"'<>,.?/|\\]+)[)\]]/);
            if (symbolMatch) {
              allowedSymbols = symbolMatch[1];
            }
          }

          return {
            hasLoginForm,
            isRegistration,
            securityModules,
            hasVirtualKeypad,
            hasE2EKeyboardModule,
            detectedSelectors,
            maxPasswordLength,
            minlength,
            pattern,
            placeholder,
            ariaLabel,
            hintText,
            allowedSymbols,
          };
        }, selectors);

        if (frameEval.hasLoginForm) combinedHasLoginForm = true;
        if (frameEval.isRegistration) combinedIsRegistration = true;
        if (frameEval.hasVirtualKeypad) combinedHasVirtualKeypad = true;
        if (frameEval.hasE2EKeyboardModule) combinedHasE2EKeyboard = true;

        for (const sec of frameEval.securityModules) combinedSecurityModules.add(sec);
        for (const sel of frameEval.detectedSelectors) combinedDetectedSelectors.add(sel);

        if (frameEval.maxPasswordLength && !combinedMaxPasswordLength) {
          combinedMaxPasswordLength = frameEval.maxPasswordLength;
        }
        if (frameEval.minlength && !combinedMinLength) combinedMinLength = frameEval.minlength;
        if (frameEval.pattern && !combinedPattern) combinedPattern = frameEval.pattern;
        if (frameEval.placeholder && !combinedPlaceholder) combinedPlaceholder = frameEval.placeholder;
        if (frameEval.ariaLabel && !combinedAriaLabel) combinedAriaLabel = frameEval.ariaLabel;
        if (frameEval.hintText && !combinedHintText) combinedHintText = frameEval.hintText;
        if (frameEval.allowedSymbols && !combinedAllowedSymbols) combinedAllowedSymbols = frameEval.allowedSymbols;
      } catch {
        // frame이 detached되거나 접근 불가인 경우 격리
      }
    }

    return {
      domain: target.domain,
      url: target.loginUrl,
      category: target.category,
      hasMfaEnforced: target.hasMfaEnforced,
      finalUrl,
      pageTitle,
      hasLoginForm: combinedHasLoginForm,
      securityModules: Array.from(combinedSecurityModules),
      maxPasswordLength: combinedMaxPasswordLength,
      allowedSymbols: combinedAllowedSymbols,
      blockedByVirtualKeypad: combinedHasVirtualKeypad,
      hasE2EKeyboardModule: combinedHasE2EKeyboard,
      isRegistration: combinedIsRegistration,
      inputConstraints: {
        maxlength: combinedMaxPasswordLength,
        minlength: combinedMinLength,
        pattern: combinedPattern,
        placeholder: combinedPlaceholder,
        ariaLabel: combinedAriaLabel,
        hintText: combinedHintText,
      },
      detectedSelectors: Array.from(combinedDetectedSelectors),
      timestamp,
    };
  } catch (error) {
    const errorMsg = (error as Error).message || String(error);
    return {
      domain: target.domain,
      url: target.loginUrl,
      category: target.category,
      hasMfaEnforced: target.hasMfaEnforced,
      hasLoginForm: false,
      securityModules: [],
      blockedByVirtualKeypad: false,
      hasE2EKeyboardModule: false,
      detectedSelectors: [],
      error: errorMsg,
      timestamp,
    };
  } finally {
    if (page) await page.close().catch(() => {});
    if (context) await context.close().catch(() => {});
    if (ownBrowser && browser) await browser.close().catch(() => {});
  }
}

/**
 * 복수 사이트 배치 스캔 파이프라인
 */
export async function scanAllTargets(
  targets: readonly BenchmarkTarget[] = BENCHMARK_TARGETS,
  options: BatchScanOptions = {}
): Promise<ScanResult[]> {
  let filtered = [...targets];
  if (options.category) {
    filtered = filtered.filter(t => t.category === options.category);
  }
  if (options.targetId) {
    filtered = filtered.filter(t => t.id === options.targetId);
  }
  if (options.limit && options.limit > 0) {
    filtered = filtered.slice(0, options.limit);
  }

  const browser = await launchScannerBrowser(options.headless ?? true);
  const results: ScanResult[] = [];

  try {
    for (let i = 0; i < filtered.length; i++) {
      const target = filtered[i];
      process.stdout.write(`[${i + 1}/${filtered.length}] Scanning ${target.name} (${target.domain})... `);
      const res = await scanTargetSite(target, {
        ...options,
        browser,
      });

      if (res.error) {
        process.stdout.write(`[ERROR: ${res.error.slice(0, 40)}...]\n`);
      } else {
        const sec = res.securityModules.length > 0 ? res.securityModules.join(',') : 'None';
        const form = res.hasLoginForm ? 'Form:YES' : 'Form:NO';
        const keypad = res.blockedByVirtualKeypad ? 'Keypad:YES' : 'Keypad:NO';
        process.stdout.write(`[OK: ${form}, Sec:${sec}, ${keypad}]\n`);
      }
      results.push(res);
    }
  } finally {
    await browser.close().catch(() => {});
  }

  if (options.outputPath) {
    saveScanResults(results, options.outputPath);
  }

  return results;
}

/**
 * 스캔 결과 JSON 파일 저장
 */
export function saveScanResults(results: ScanResult[], outputPath: string): void {
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(outputPath, JSON.stringify(results, null, 2), 'utf-8');
}

/**
 * CLI 실행 엔트리포인트
 */
async function main() {
  const args = process.argv.slice(2);
  const getArg = (name: string): string | undefined => {
    const prefix = `--${name}=`;
    const arg = args.find(a => a.startsWith(prefix));
    return arg ? arg.slice(prefix.length) : undefined;
  };

  const limit = getArg('limit') ? Number(getArg('limit')) : undefined;
  const category = getArg('category') as SiteCategory | undefined;
  const targetId = getArg('target');
  const timeoutMs = getArg('timeout') ? Number(getArg('timeout')) : 30000;
  const outputPath = getArg('out') || path.resolve(process.cwd(), 'results/raw-scans.json');
  const headless = getArg('headless') !== 'false';

  console.log('================================================================');
  console.log('  PrfVault Phase 4.1: Playwright Benchmark DOM Scanner');
  console.log('================================================================');
  console.log(`Total Targets Selected: ${limit ?? BENCHMARK_TARGETS.length}`);
  console.log(`Output Path: ${outputPath}`);
  console.log(`Timeout: ${timeoutMs}ms, Headless: ${headless}\n`);

  const results = await scanAllTargets(BENCHMARK_TARGETS, {
    limit,
    category,
    targetId,
    timeoutMs,
    outputPath,
    headless,
  });

  const successful = results.filter(r => !r.error);
  const withForm = results.filter(r => r.hasLoginForm);
  const withKeypad = results.filter(r => r.blockedByVirtualKeypad);
  const withSec = results.filter(r => r.securityModules.length > 0);

  console.log('\n================================================================');
  console.log('  SCAN SUMMARY');
  console.log('================================================================');
  console.log(`Total Scanned : ${results.length}`);
  console.log(`Successful    : ${successful.length}`);
  console.log(`Failed/Error  : ${results.length - successful.length}`);
  console.log(`Login Forms   : ${withForm.length}`);
  console.log(`Security Mods : ${withSec.length}`);
  console.log(`Virtual Keypad: ${withKeypad.length}`);
  console.log(`Saved To      : ${outputPath}`);
  console.log('================================================================\n');
}

// 직접 CLI 실행 시 main() 호출
if (process.argv[1] && import.meta.url === `file:///${process.argv[1].replace(/\\/g, '/')}`) {
  main().catch(err => {
    console.error('Fatal scanner error:', err);
    process.exit(1);
  });
}
