/**
 * MV3 컨텍스트 간 내부 IPC 메시지 타입 및 Zod 런타임 스키마
 *
 * [보안 설계 및 제약사항]
 * - 브라우저 런타임에서 유입되는 모든 chrome.runtime.sendMessage 페이로드는 잠재적 악성 데이터입니다.
 * - Zod의 .strict()를 강제하여 __proto__, constructor 등 Prototype Pollution 공격 필드를 차단하고,
 *   각 문자열 필드에 엄격한 바이트 길이 상한(max)을 적용해 DoS 공격을 방어합니다.
 */

import { z } from 'zod';

export type IpcErrorCode =
  | 'UNAUTHORIZED_SENDER'
  | 'VAULT_LOCKED'
  | 'NO_CREDENTIALS_FOUND'
  | 'HARDWARE_AUTH_FAILED'
  | 'WASM_DECRYPTION_FAILED'
  | 'SECURITY_MODULE_BLOCKED'
  | 'STORAGE_ERROR'
  | 'INVALID_REQUEST_PAYLOAD';

export interface IpcRequest<TAction extends string = string, TPayload = unknown> {
  id: string;
  action: TAction;
  payload: TPayload;
  timestamp: number;
}

export interface IpcSuccessResponse<TData = unknown> {
  id: string;
  success: true;
  data: TData;
}

export interface IpcErrorResponse {
  id: string;
  success: false;
  error: {
    code: IpcErrorCode;
    message: string;
    details?: unknown;
  };
}

export type IpcResponse<TData = unknown> = IpcSuccessResponse<TData> | IpcErrorResponse;

// 1. CS_DETECT_SECURITY_MODULE
export const CsDetectSecurityModuleSchema = z.object({
  id: z.string().uuid(),
  action: z.literal('CS_DETECT_SECURITY_MODULE'),
  payload: z.object({
    domain: z.string().max(256),
    hasVirtualKeypad: z.boolean(),
    hasE2EKeyboardModule: z.boolean(),
    detectedSelectors: z.array(z.string().max(128)).max(32),
  }).strict(),
  timestamp: z.number().int().positive(),
});
export type CsDetectSecurityModuleRequest = z.infer<typeof CsDetectSecurityModuleSchema>;

// 2. CS_REQUEST_CREDENTIALS
export const CsRequestCredentialsSchema = z.object({
  id: z.string().uuid(),
  action: z.literal('CS_REQUEST_CREDENTIALS'),
  payload: z.object({
    formId: z.string().max(128).optional(),
    isPasswordChangeForm: z.boolean(),
  }).strict(),
  timestamp: z.number().int().positive(),
});
export type CsRequestCredentialsRequest = z.infer<typeof CsRequestCredentialsSchema>;

export interface CredentialCandidate {
  accountId: string;
  username: string;
  password?: string;
}

// 3. CS_REPORT_INJECTION_RESULT
export const CsReportInjectionResultSchema = z.object({
  id: z.string().uuid(),
  action: z.literal('CS_REPORT_INJECTION_RESULT'),
  payload: z.object({
    domain: z.string().max(256),
    accountId: z.string().max(128),
    status: z.enum(['SUCCESS', 'BLOCKED_BY_KEYPAD', 'DOM_INPUT_REJECTED']),
    interKeystrokeMs: z.number().nonnegative(),
  }).strict(),
  timestamp: z.number().int().positive(),
});
export type CsReportInjectionResultRequest = z.infer<typeof CsReportInjectionResultSchema>;

// 4. EP_GET_VAULT_STATUS
export const EpGetVaultStatusSchema = z.object({
  id: z.string().uuid(),
  action: z.literal('EP_GET_VAULT_STATUS'),
  payload: z.object({}).strict(),
  timestamp: z.number().int().positive(),
});
export type EpGetVaultStatusRequest = z.infer<typeof EpGetVaultStatusSchema>;

export interface EpGetVaultStatusData {
  isInitialized: boolean;
  isLocked: boolean;
  credentialId?: string;
  salt?: string;
  accountCount: number;
}

// 5. EP_UNLOCK_VAULT
export const EpUnlockVaultSchema = z.object({
  id: z.string().uuid(),
  action: z.literal('EP_UNLOCK_VAULT'),
  payload: z.object({
    decryptedAccountsSummary: z.array(
      z.object({
        id: z.string().max(128),
        domain: z.string().max(256),
        username: z.string().max(256),
      }).strict()
    ).max(5000),
  }).strict(),
  timestamp: z.number().int().positive(),
});
export type EpUnlockVaultRequest = z.infer<typeof EpUnlockVaultSchema>;

// 6. EP_SAVE_ENCRYPTED_VAULT
export const EpSaveEncryptedVaultSchema = z.object({
  id: z.string().uuid(),
  action: z.literal('EP_SAVE_ENCRYPTED_VAULT'),
  payload: z.object({
    encryptedBlobHex: z.string().min(132), // 최소 66바이트 Hex (132글자)
    schemaVersion: z.number().int().positive(),
  }).strict(),
  timestamp: z.number().int().positive(),
});
export type EpSaveEncryptedVaultRequest = z.infer<typeof EpSaveEncryptedVaultSchema>;

/**
 * 런타임 페이로드를 지정된 Zod 스키마로 검증하고 파싱합니다.
 */
export function validateIpcPayload<T>(schema: z.ZodType<T>, data: unknown): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    const issueMsg = result.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join(', ');
    throw new Error(`INVALID_REQUEST_PAYLOAD: ${issueMsg}`);
  }
  return result.data;
}
