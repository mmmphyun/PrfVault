import { describe, it, expect } from 'vitest';
import {
  generatePassword,
  secureRandomInt,
  secureShuffle,
  calculateShannonEntropy,
  analyzePassword,
} from '../src/content/generator';

describe('CSPRNG 비밀번호 생성 엔진 단위 테스트 (generator.ts)', () => {
  it('secureRandomInt는 0 <= result < max 범위의 정수를 반환해야 한다', () => {
    for (let i = 0; i < 100; i++) {
      const val = secureRandomInt(10);
      expect(val).toBeGreaterThanOrEqual(0);
      expect(val).toBeLessThan(10);
      expect(Number.isInteger(val)).toBe(true);
    }

    expect(secureRandomInt(1)).toBe(0);
    expect(() => secureRandomInt(0)).toThrow();
  });

  it('secureShuffle은 원본 배열의 모든 요소를 보존하면서 셔플해야 한다', () => {
    const original = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const shuffled = secureShuffle(original);

    expect(shuffled.length).toBe(original.length);
    expect([...shuffled].sort((a, b) => a - b)).toEqual(original);
  });

  it('기본 옵션으로 생성된 비밀번호는 길이 20자 및 4대 문자군을 모두 포함해야 한다', () => {
    for (let i = 0; i < 20; i++) {
      const pwd = generatePassword();
      expect(pwd.length).toBe(20);

      const hasLower = /[a-z]/.test(pwd);
      const hasUpper = /[A-Z]/.test(pwd);
      const hasNumber = /[0-9]/.test(pwd);
      const hasSymbol = /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/.test(pwd);

      expect(hasLower).toBe(true);
      expect(hasUpper).toBe(true);
      expect(hasNumber).toBe(true);
      expect(hasSymbol).toBe(true);
    }
  });

  it('길이 제한 및 사용자 지정 길이 옵션을 정확히 반영해야 한다', () => {
    expect(() => generatePassword({ length: 7 })).toThrow('비밀번호 길이는 최소 8자 이상이어야 합니다.');

    const pwd16 = generatePassword({ length: 16 });
    expect(pwd16.length).toBe(16);

    const pwd32 = generatePassword({ length: 32 });
    expect(pwd32.length).toBe(32);
  });

  it('excludeAmbiguous 옵션 활성화 시 혼동 문자(0, O, l, 1 등)가 배제되어야 한다', () => {
    const ambiguousChars = ['l', '1', 'I', 'o', '0', 'O', '`', '\'', '"', '~'];
    for (let i = 0; i < 30; i++) {
      const pwd = generatePassword({ length: 30, excludeAmbiguous: true });
      for (const ch of ambiguousChars) {
        expect(pwd).not.toContain(ch);
      }
    }
  });

  it('단일 문자군 옵션 지정 시 해당 문자군으로만 구성되어야 한다', () => {
    const numOnly = generatePassword({
      length: 12,
      includeLowercase: false,
      includeUppercase: false,
      includeNumbers: true,
      includeSymbols: false,
    });
    expect(numOnly.length).toBe(12);
    expect(/^[0-9]+$/.test(numOnly)).toBe(true);

    expect(() =>
      generatePassword({
        includeLowercase: false,
        includeUppercase: false,
        includeNumbers: false,
        includeSymbols: false,
      })
    ).toThrow('최소 하나의 문자군이 활성화되어야 합니다.');
  });

  it('단일 문자 문자열의 섀넌 엔트로피는 0이어야 하고, 고유 문자가 많을수록 증가해야 한다', () => {
    expect(calculateShannonEntropy('aaaa')).toBe(0);

    const entropyAb = calculateShannonEntropy('aabb');
    expect(entropyAb).toBe(1); // 2개 심볼 균등 분포 -> log2(2) = 1

    const randomPwd = generatePassword({ length: 32 });
    const entropyRandom = calculateShannonEntropy(randomPwd);
    expect(entropyRandom).toBeGreaterThan(4.0); // 32자 고엔트로피
  });

  it('analyzePassword는 16자 이상 및 4종 문자군 만족 시 meetsRecommendedPolicy=true를 반환해야 한다', () => {
    const strongPwd = generatePassword({ length: 20 });
    const analysis = analyzePassword(strongPwd);

    expect(analysis.length).toBe(20);
    expect(analysis.meetsRecommendedPolicy).toBe(true);
    expect(analysis.keySpaceEntropyBits).toBeGreaterThan(120); // 20 * log2(94) ~= 131 bits
    expect(analysis.shannonEntropy).toBeGreaterThan(3.5);

    const weakAnalysis = analyzePassword('short1!');
    expect(weakAnalysis.meetsRecommendedPolicy).toBe(false);
  });
});
