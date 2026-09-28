/**
 * PrfVault MV3 Content Script DOM 탐지기
 *
 * [보안 제약 및 휴리스틱 설계]
 * - 웹페이지 DOM 내 로그인 및 회원가입 폼을 안전하게 식별합니다.
 * - 국내 50대 웹사이트의 가상 키패드 및 E2E 보안 프로그램(TouchEn, AnySign, ASTx, nProtect) 시그니처를 사전 감지합니다.
 * - Cross-origin iframe 탐색 시 발생할 수 있는 SecurityError는 try-catch 격리로 차단합니다.
 */

export interface DetectedForm {
  formElement: HTMLFormElement | null;
  usernameField: HTMLInputElement | null;
  passwordFields: HTMLInputElement[];
  isRegistration: boolean;
}

export interface FormDetectionResult {
  forms: DetectedForm[];
  hasSecurityModule: boolean;
  hasVirtualKeypad: boolean;
  hasE2EKeyboardModule: boolean;
  detectedSelectors: string[];
}

export interface SecurityModuleDetectionResult {
  hasSecurityModule: boolean;
  hasVirtualKeypad: boolean;
  hasE2EKeyboardModule: boolean;
  detectedSelectors: string[];
}

/**
 * 국내 주요 보안 프로그램(E2E) 및 가상 키패드 탐지용 CSS 셀렉터 시그니처
 */
export const SECURITY_MODULE_SELECTORS = {
  // 라온시큐어 TouchEn Key
  touchEn: [
    'input[data-enc="on"]',
    'input[tk_type]',
    'input[data-tk-type]',
    '#TouchEnKey_tk_input',
    'embed[type*="touchen"]',
    'object[type*="touchen"]',
  ],
  // 이니텍 AnySign / MoaSign
  anySign: [
    'input[data-any="on"]',
    'input[data-anysign]',
    'div#AnySign4PC',
    'div#AnySign4PC_Frame',
  ],
  // 안랩 AhnLab Safe Transaction (ASTx)
  astx: [
    'input[astx]',
    'input[data-astx]',
    'div#astx_install',
    'object[id*="astx"]',
  ],
  // 잉카인터넷 nProtect Online Security
  nProtect: [
    'input[npk]',
    'input[data-npk]',
    'form[name*="np"]',
    'div#nProtect',
  ],
  // 가상 키패드 (Virtual Keypad / Transkey / mTk)
  virtualKeypad: [
    'img[src*="keypad" i]',
    'div[class*="keypad" i]',
    'div[class*="transkey" i]',
    'div[id*="transkey" i]',
    'div[class*="mtk" i]',
    'div[id*="mtk" i]',
    'input[data-mode="virtual"]',
    'input[data-tk-virtual="true"]',
  ],
} as const;

/**
 * 대상 DOM 노드 또는 하위 노드에서 보안 프로그램 및 가상 키패드 시그니처를 스캔합니다.
 */
export function detectSecurityModules(root: ParentNode = document): SecurityModuleDetectionResult {
  const detectedSelectors: string[] = [];
  let hasE2EKeyboardModule = false;
  let hasVirtualKeypad = false;

  const checkSelectors = (selectors: readonly string[], isKeypad: boolean) => {
    for (const selector of selectors) {
      try {
        const found = root.querySelector(selector);
        if (found) {
          detectedSelectors.push(selector);
          if (isKeypad) {
            hasVirtualKeypad = true;
          } else {
            hasE2EKeyboardModule = true;
          }
        }
      } catch {
        // 유효하지 않은 셀렉터나 DOM 예외 격리
      }
    }
  };

  checkSelectors(SECURITY_MODULE_SELECTORS.touchEn, false);
  checkSelectors(SECURITY_MODULE_SELECTORS.anySign, false);
  checkSelectors(SECURITY_MODULE_SELECTORS.astx, false);
  checkSelectors(SECURITY_MODULE_SELECTORS.nProtect, false);
  checkSelectors(SECURITY_MODULE_SELECTORS.virtualKeypad, true);

  return {
    hasSecurityModule: hasE2EKeyboardModule || hasVirtualKeypad,
    hasVirtualKeypad,
    hasE2EKeyboardModule,
    detectedSelectors,
  };
}

/**
 * 입력 요소가 화면에 표시되는 가시적(visible) 요소인지 판별합니다.
 */
export function isElementVisible(el: HTMLElement): boolean {
  if (el.tagName === 'INPUT' && (el as HTMLInputElement).type === 'hidden') {
    return false;
  }
  if (el.getAttribute('aria-hidden') === 'true') {
    return false;
  }
  const style = el.style;
  if (style) {
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
      return false;
    }
  }
  // 브라우저 실제 DOM에서 offsetParent가 명시적으로 null이고 getBoundingClientRect가 0인 경우 비가시 처리
  if (
    'offsetParent' in el &&
    el.offsetParent === null &&
    style?.position !== 'fixed' &&
    typeof el.getBoundingClientRect === 'function'
  ) {
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) {
      return false;
    }
  }
  return true;
}

/**
 * 특정 폼 또는 컨테이너 내에서 사용자명(아이디) 입력 필드를 휴리스틱으로 식별합니다.
 */
function findUsernameField(
  container: ParentNode,
  passwordField: HTMLInputElement
): HTMLInputElement | null {
  const inputs = Array.from(container.querySelectorAll('input')).filter(input => {
    if (input === passwordField) return false;
    if (!isElementVisible(input)) return false;
    const type = (input.type || 'text').toLowerCase();
    return type === 'text' || type === 'email' || type === 'tel';
  });

  if (inputs.length === 0) return null;

  // 1순위: autocomplete="username"
  const autocompleteUsername = inputs.find(
    i => i.getAttribute('autocomplete')?.toLowerCase() === 'username'
  );
  if (autocompleteUsername) return autocompleteUsername;

  // 2순위: type="email"
  const emailInput = inputs.find(i => i.type.toLowerCase() === 'email');
  if (emailInput) return emailInput;

  // 3순위: id/name/placeholder 속성에 식별 키워드 매칭
  const userKeywords = /user|id|login|email|member|account|username/i;
  const keywordMatched = inputs.find(i => {
    const id = i.id || '';
    const name = i.name || '';
    const placeholder = i.placeholder || '';
    const ariaLabel = i.getAttribute('aria-label') || '';
    return (
      userKeywords.test(id) ||
      userKeywords.test(name) ||
      userKeywords.test(placeholder) ||
      userKeywords.test(ariaLabel)
    );
  });
  if (keywordMatched) return keywordMatched;

  // 4순위: DOM 순서상 비밀번호 필드 바로 이전의 텍스트 입력창
  const allInputs = Array.from(container.querySelectorAll('input'));
  const pwIndex = allInputs.indexOf(passwordField);
  for (let i = pwIndex - 1; i >= 0; i--) {
    const candidate = allInputs[i];
    if (inputs.includes(candidate)) {
      return candidate;
    }
  }

  // 기본 fallback: 첫 번째 텍스트 입력창
  return inputs[0] ?? null;
}

/**
 * 주어진 DOM 루트에서 로그인 및 회원가입 폼을 탐지하고 분석합니다.
 */
export function detectForms(root: Document | HTMLElement = document): FormDetectionResult {
  const securityCheck = detectSecurityModules(root);
  const forms: DetectedForm[] = [];

  // 1. 모든 가시적 비밀번호 필드 수집
  let allPasswordInputs: HTMLInputElement[] = [];
  try {
    const inputs = Array.from(root.querySelectorAll('input'));
    allPasswordInputs = inputs.filter(input => {
      const type = (input.type || '').toLowerCase();
      const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
      const isPw =
        type === 'password' ||
        autocomplete === 'current-password' ||
        autocomplete === 'new-password';
      return isPw && isElementVisible(input);
    });
  } catch {
    // DOM 쿼리 실패 시 빈 폼 반환
    return {
      forms: [],
      ...securityCheck,
    };
  }

  if (allPasswordInputs.length === 0) {
    return {
      forms: [],
      ...securityCheck,
    };
  }

  // 2. <form> 태그별로 그룹화
  const formMap = new Map<HTMLFormElement | null, HTMLInputElement[]>();
  for (const pwInput of allPasswordInputs) {
    const formElement = pwInput.closest('form');
    const existing = formMap.get(formElement) || [];
    existing.push(pwInput);
    formMap.set(formElement, existing);
  }

  // 3. 그룹별로 DetectedForm 생성
  for (const [formElement, pwInputs] of formMap.entries()) {
    const searchRoot: ParentNode = formElement || (pwInputs[0]?.parentElement?.parentElement ?? root);
    const usernameField = findUsernameField(searchRoot, pwInputs[0]);

    // 회원가입 폼 휴리스틱:
    // - 비밀번호 필드가 2개 이상 (비밀번호 + 비밀번호 확인)
    // - 또는 autocomplete 속성이 'new-password'
    const isRegistration =
      pwInputs.length >= 2 ||
      pwInputs.some(p => p.getAttribute('autocomplete')?.toLowerCase() === 'new-password');

    forms.push({
      formElement,
      usernameField,
      passwordFields: pwInputs,
      isRegistration,
    });
  }

  return {
    forms,
    ...securityCheck,
  };
}
