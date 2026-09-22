import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  base64UrlEncode,
  base64UrlDecode,
  toHex,
  fromHex,
  registerPrfCredential,
  derivePrfSecret,
} from '../src/auth/webauthn-prf';

describe('WebAuthn PRF 클라이언트 및 유틸리티 단위 테스트', () => {
  it('Base64URL 인코딩 및 디코딩이 완벽하게 일치해야 한다', () => {
    const original = new Uint8Array([0x00, 0xff, 0xaa, 0x55, 0x12, 0x34, 0xef]);
    const encoded = base64UrlEncode(original);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');

    const decoded = base64UrlDecode(encoded);
    expect(decoded).toEqual(original);
  });

  it('Hex 인코딩 및 디코딩이 완벽하게 일치해야 한다', () => {
    const original = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    const hex = toHex(original);
    expect(hex).toBe('0123456789abcdef');

    const restored = fromHex(hex);
    expect(restored).toEqual(original);
  });

  describe('Mock WebAuthn credentials API 테스트', () => {
    let mockCreate: ReturnType<typeof vi.fn>;
    let mockGet: ReturnType<typeof vi.fn>;

    beforeEach(() => {
      mockCreate = vi.fn();
      mockGet = vi.fn();
      vi.stubGlobal('navigator', {
        credentials: {
          create: mockCreate,
          get: mockGet,
        },
      });
    });

    afterEach(() => {
      vi.unstubAllGlobals();
    });

    it('registerPrfCredential이 성공적으로 자격 증명 및 PRF 활성화 상태를 반환해야 한다', async () => {
      const mockRawId = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      mockCreate.mockResolvedValue({
        rawId: mockRawId.buffer,
        getClientExtensionResults: () => ({
          prf: { enabled: true },
        }),
      });

      const result = await registerPrfCredential('localhost', 'test-user');
      expect(result.prfEnabled).toBe(true);
      expect(result.credentialId).toBe(base64UrlEncode(mockRawId));
      expect(mockCreate).toHaveBeenCalledOnce();
    });

    it('derivePrfSecret이 하드웨어로부터 반환된 32바이트 대칭키를 정상 추출해야 한다', async () => {
      const mockDerivedKey = new Uint8Array(32).fill(0x88);
      mockGet.mockResolvedValue({
        getClientExtensionResults: () => ({
          prf: {
            results: {
              first: mockDerivedKey.buffer,
            },
          },
        }),
      });

      const salt = new Uint8Array(32).fill(0x12);
      const secret = await derivePrfSecret('AQIDBAUGBwg', salt, 'localhost');

      expect(secret).toEqual(mockDerivedKey);
      expect(mockGet).toHaveBeenCalledOnce();
    });

    it('Salt 길이가 32바이트가 아니면 예외를 던져야 한다', async () => {
      const badSalt = new Uint8Array(16);
      await expect(derivePrfSecret('AQIDBAUGBwg', badSalt)).rejects.toThrow(
        /Salt는 32바이트여야 합니다/
      );
    });

    it('인증자가 PRF 결과를 반환하지 않으면 예외를 던져야 한다', async () => {
      mockGet.mockResolvedValue({
        getClientExtensionResults: () => ({}), // prf 확장 결과 누락
      });

      const salt = new Uint8Array(32).fill(0x12);
      await expect(derivePrfSecret('AQIDBAUGBwg', salt)).rejects.toThrow(
        /PRF 대칭키가 반환되지 않았습니다/
      );
    });
  });
});
