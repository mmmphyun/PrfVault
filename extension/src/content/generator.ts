/**
 * PrfVault CSPRNG 기반 고엔트로피 비밀번호 생성 엔진
 *
 * [보안 제약 및 수학적 불변성]
 * - Web Crypto API (crypto.getRandomValues) 암호학적 난수 생성기를 사용합니다.
 * - Rejection Sampling을 통해 모듈로 바이어스(Modulo Bias)를 원천 차단하여 균일 분포를 보장합니다.
 * - 필수 문자군(대/소문자, 숫자, 특수문자) 최소 1자 이상 포함을 보장하고, Fisher-Yates 셔플로 위치를 무작위화합니다.
 */

export interface PasswordGeneratorOptions {
  length?: number;
  includeUppercase?: boolean;
  includeLowercase?: boolean;
  includeNumbers?: boolean;
  includeSymbols?: boolean;
  customSymbols?: string;
  excludeAmbiguous?: boolean;
}

export interface PasswordStrengthReport {
  password: string;
  length: number;
  poolSize: number;
  shannonEntropy: number;
  keySpaceEntropyBits: number;
  meetsRecommendedPolicy: boolean;
}

const DEFAULT_LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const DEFAULT_UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DEFAULT_NUMBERS = '0123456789';
const DEFAULT_SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';
const AMBIGUOUS_CHARS = new Set(['l', '1', 'I', 'o', '0', 'O', '`', '\'', '"', '~']);

/**
 * Rejection Sampling 기반 균일 난수 정수 생성기 (0 <= result < max)
 * 모듈로 연산으로 인한 특정 값 편향(Modulo Bias)을 수학적으로 배제합니다.
 */
export function secureRandomInt(max: number): number {
  if (max <= 0) {
    throw new Error('max 값은 1 이상이어야 합니다.');
  }
  if (max === 1) {
    return 0;
  }

  const range = 0x100000000; // 2^32
  const limit = range - (range % max);
  const buffer = new Uint32Array(1);

  while (true) {
    crypto.getRandomValues(buffer);
    const val = buffer[0];
    if (val < limit) {
      return val % max;
    }
  }
}

/**
 * 배열 요소를 CSPRNG 난수 기반 Fisher-Yates 알고리즘으로 무작위 셔플합니다.
 */
export function secureShuffle<T>(array: T[]): T[] {
  const result = [...array];
  for (let i = result.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    const temp = result[i];
    result[i] = result[j];
    result[j] = temp;
  }
  return result;
}

/**
 * 문자열에서 모호한(ambiguous) 문자를 제거합니다.
 */
function filterAmbiguous(charset: string): string {
  return charset
    .split('')
    .filter(ch => !AMBIGUOUS_CHARS.has(ch))
    .join('');
}

/**
 * 암호학적 난수를 사용하여 고엔트로피 비밀번호를 생성합니다.
 */
export function generatePassword(options: PasswordGeneratorOptions = {}): string {
  const {
    length = 20,
    includeUppercase = true,
    includeLowercase = true,
    includeNumbers = true,
    includeSymbols = true,
    customSymbols = DEFAULT_SYMBOLS,
    excludeAmbiguous = false,
  } = options;

  if (length < 8) {
    throw new Error('비밀번호 길이는 최소 8자 이상이어야 합니다.');
  }

  let lower = DEFAULT_LOWERCASE;
  let upper = DEFAULT_UPPERCASE;
  let numbers = DEFAULT_NUMBERS;
  let symbols = customSymbols;

  if (excludeAmbiguous) {
    lower = filterAmbiguous(lower);
    upper = filterAmbiguous(upper);
    numbers = filterAmbiguous(numbers);
    symbols = filterAmbiguous(symbols);
  }

  const activeCategories: string[] = [];
  if (includeLowercase && lower.length > 0) activeCategories.push(lower);
  if (includeUppercase && upper.length > 0) activeCategories.push(upper);
  if (includeNumbers && numbers.length > 0) activeCategories.push(numbers);
  if (includeSymbols && symbols.length > 0) activeCategories.push(symbols);

  if (activeCategories.length === 0) {
    throw new Error('최소 하나의 문자군이 활성화되어야 합니다.');
  }

  const fullCharset = activeCategories.join('');
  const passwordChars: string[] = [];

  // 1. 필수 조건 만족: 활성화된 각 문자군에서 최소 1자 무작위 추출
  for (const cat of activeCategories) {
    const idx = secureRandomInt(cat.length);
    passwordChars.push(cat[idx]);
  }

  // 2. 나머지 길이를 전체 문자 풀에서 균일 난수로 충원
  const remainingLength = length - passwordChars.length;
  for (let i = 0; i < remainingLength; i++) {
    const idx = secureRandomInt(fullCharset.length);
    passwordChars.push(fullCharset[idx]);
  }

  // 3. Fisher-Yates 알고리즘으로 위치 무작위 셔플
  const shuffled = secureShuffle(passwordChars);
  return shuffled.join('');
}

/**
 * 문자열 내 각 문자의 출현 빈도 기반 섀넌 엔트로피(Shannon Entropy)를 계산합니다.
 * H = -sum(p_i * log2(p_i))
 */
export function calculateShannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const frequencies = new Map<string, number>();
  for (const ch of str) {
    frequencies.set(ch, (frequencies.get(ch) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * 주어진 비밀번호 문자열의 엔트로피 및 정책 부합 여부를 종합 평가합니다.
 */
export function analyzePassword(
  password: string,
  customPoolSize?: number
): PasswordStrengthReport {
  const len = password.length;

  let hasLower = false;
  let hasUpper = false;
  let hasNumber = false;
  let hasSymbol = false;

  for (const ch of password) {
    if (DEFAULT_LOWERCASE.includes(ch)) hasLower = true;
    else if (DEFAULT_UPPERCASE.includes(ch)) hasUpper = true;
    else if (DEFAULT_NUMBERS.includes(ch)) hasNumber = true;
    else hasSymbol = true;
  }

  let poolSize = 0;
  if (hasLower) poolSize += DEFAULT_LOWERCASE.length;
  if (hasUpper) poolSize += DEFAULT_UPPERCASE.length;
  if (hasNumber) poolSize += DEFAULT_NUMBERS.length;
  if (hasSymbol) poolSize += DEFAULT_SYMBOLS.length;

  const effectivePool = customPoolSize ?? (poolSize > 0 ? poolSize : 1);
  const keySpaceEntropyBits = len * Math.log2(effectivePool);
  const shannonEntropy = calculateShannonEntropy(password);

  const meetsRecommendedPolicy =
    len >= 16 && hasLower && hasUpper && hasNumber && hasSymbol;

  return {
    password,
    length: len,
    poolSize: effectivePool,
    shannonEntropy,
    keySpaceEntropyBits,
    meetsRecommendedPolicy,
  };
}
