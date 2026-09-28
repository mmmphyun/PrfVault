/**
 * PrfVault Phase 4.1: 국내 50대 웹사이트 벤치마크 타깃 정의
 *
 * [선정 기준]
 * - 국내 트래픽 상위 포털, 금융(시중은행/인터넷은행/증권/카드), 공공기관/행정, e커머스, 통신/취업 플랫폼
 * - 전수 HTTPS 프로토콜 준수
 * - E2E 보안 프로그램(TouchEn, AnySign, ASTx, nProtect) 및 가상 키패드 적용 가능성이 높은 사이트 중심 선별
 */

export type SiteCategory =
  | 'portal'
  | 'banking'
  | 'securities'
  | 'public'
  | 'ecommerce'
  | 'fintech'
  | 'telecom';

export interface BenchmarkTarget {
  id: string;
  name: string;
  domain: string;
  category: SiteCategory;
  loginUrl: string;
  description?: string;
  requiresKeypadPrecaution?: boolean;
}

export const BENCHMARK_TARGETS: readonly BenchmarkTarget[] = [
  // 1. 포털 / 플랫폼 (6)
  {
    id: 'naver',
    name: '네이버',
    domain: 'naver.com',
    category: 'portal',
    loginUrl: 'https://nid.naver.com/nidlogin.login',
    description: '국내 최대 포털 서비스',
  },
  {
    id: 'kakao',
    name: '카카오',
    domain: 'kakao.com',
    category: 'portal',
    loginUrl: 'https://accounts.kakao.com/login',
    description: '통합 카카오 계정 인증 플랫폼',
  },
  {
    id: 'daum',
    name: '다음',
    domain: 'daum.net',
    category: 'portal',
    loginUrl: 'https://logins.daum.net/accounts/signinform.do',
    description: '다음 포털 로그인',
  },
  {
    id: 'google-kr',
    name: '구글 코리아',
    domain: 'google.co.kr',
    category: 'portal',
    loginUrl: 'https://accounts.google.com/signin',
    description: '글로벌 표준 계정 인증',
  },
  {
    id: 'nate',
    name: '네이트',
    domain: 'nate.com',
    category: 'portal',
    loginUrl: 'https://xo.nate.com/login.sk',
    description: 'SK컴즈 네이트 포털',
  },
  {
    id: 'zum',
    name: '줌인터넷',
    domain: 'zum.com',
    category: 'portal',
    loginUrl: 'https://user.zum.com/login',
    description: '개방형 포털',
  },

  // 2. 은행 / 시중은행 / 인터넷전문은행 (10)
  {
    id: 'kb-bank',
    name: 'KB국민은행',
    domain: 'kbstar.com',
    category: 'banking',
    loginUrl: 'https://obank.kbstar.com/quics?page=C016505',
    description: 'KB국민은행 인터넷뱅킹 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'shinhan-bank',
    name: '신한은행',
    domain: 'shinhan.com',
    category: 'banking',
    loginUrl: 'https://bank.shinhan.com/index.jsp#020501010000',
    description: '신한 쏠(SOL) 뱅킹 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'woori-bank',
    name: '우리은행',
    domain: 'wooribank.com',
    category: 'banking',
    loginUrl: 'https://spib.wooribank.com/pib/Dream?withyou=CMLGN0001',
    description: '우리은행 인터넷뱅킹 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'hana-bank',
    name: '하나은행',
    domain: 'kebhana.com',
    category: 'banking',
    loginUrl: 'https://www.kebhana.com/easyone/foreign/index.do',
    description: '하나원큐 인터넷뱅킹 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'nh-bank',
    name: 'NH농협은행',
    domain: 'banking.nonghyup.com',
    category: 'banking',
    loginUrl: 'https://banking.nonghyup.com/nhbank.html',
    description: 'NH농협 인터넷뱅킹',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'ibk-bank',
    name: 'IBK기업은행',
    domain: 'ibk.co.kr',
    category: 'banking',
    loginUrl: 'https://mybank.ibk.co.kr/uib/jsp/index.jsp',
    description: '기업은행 개인인터넷뱅킹',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'kakao-bank',
    name: '카카오뱅크',
    domain: 'kakaobank.com',
    category: 'banking',
    loginUrl: 'https://www.kakaobank.com/auth',
    description: '카카오뱅크 웹 인증센터',
  },
  {
    id: 'k-bank',
    name: '케이뱅크',
    domain: 'kbanknow.com',
    category: 'banking',
    loginUrl: 'https://www.kbanknow.com/ib20/mnu/CMMNOT010100',
    description: '케이뱅크 웹뱅킹 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'toss-bank',
    name: '토스뱅크',
    domain: 'tossbank.com',
    category: 'banking',
    loginUrl: 'https://www.tossbank.com',
    description: '토스뱅크 웹 랜딩 및 인증',
  },
  {
    id: 'sc-bank',
    name: 'SC제일은행',
    domain: 'standardchartered.co.kr',
    category: 'banking',
    loginUrl: 'https://www.standardchartered.co.kr/np/kr/Intro.jsp',
    description: 'SC제일은행 뱅킹 로그인',
    requiresKeypadPrecaution: true,
  },

  // 3. 증권사 (6)
  {
    id: 'kiwoom',
    name: '키움증권',
    domain: 'kiwoom.com',
    category: 'securities',
    loginUrl: 'https://bbn.kiwoom.com/login',
    description: '키움증권 웹 트레이딩 시스템 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'mirae-asset',
    name: '미래에셋증권',
    domain: 'securities.miraeasset.com',
    category: 'securities',
    loginUrl: 'https://securities.miraeasset.com/common/login.do',
    description: '미래에셋 투자 포털 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'samsung-sec',
    name: '삼성증권',
    domain: 'samsungpop.com',
    category: 'securities',
    loginUrl: 'https://www.samsungpop.com/ux/kor/login/login.do',
    description: '삼성증권 POP 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'korea-investment',
    name: '한국투자증권',
    domain: 'truefriend.com',
    category: 'securities',
    loginUrl: 'https://www.truefriend.com/main/login/login.jsp',
    description: '한국투자증권 TrueFriend 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'nh-sec',
    name: 'NH투자증권',
    domain: 'nhqv.com',
    category: 'securities',
    loginUrl: 'https://www.nhqv.com/login/login.do',
    description: '나무/NH투자증권 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'kb-sec',
    name: 'KB증권',
    domain: 'kbsec.com',
    category: 'securities',
    loginUrl: 'https://www.kbsec.com/go.able?linkcd=m01010000',
    description: 'KB증권 M-able 웹 로그인',
    requiresKeypadPrecaution: true,
  },

  // 4. 공공기관 / 정부 행정 (8)
  {
    id: 'gov-korea',
    name: '정부24',
    domain: 'gov.kr',
    category: 'public',
    loginUrl: 'https://www.gov.kr/nlogin/?curr_url=%2Fportal%2Fmain',
    description: '대한민국 정부 대표 포털 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'hometax',
    name: '국세청 홈택스',
    domain: 'hometax.go.kr',
    category: 'public',
    loginUrl: 'https://www.hometax.go.kr/websquare/websquare.html?w2xPath=/ui/pp/index_pp.xml',
    description: '국세청 세무 신고 및 전자고지 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'nhis',
    name: '국민건강보험공단',
    domain: 'nhis.or.kr',
    category: 'public',
    loginUrl: 'https://www.nhis.or.kr/nhis/etc/personalLogin.do',
    description: '국민건강보험 개인 민원 포털',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'nps',
    name: '국민연금공단',
    domain: 'nps.or.kr',
    category: 'public',
    loginUrl: 'https://www.nps.or.kr/jsppage/member/login/member_login.jsp',
    description: '국민연금 전자민원서비스 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'iros',
    name: '대법원 인터넷등기소',
    domain: 'iros.go.kr',
    category: 'public',
    loginUrl: 'https://www.iros.go.kr/pos1/jsp/coll/PINFLognL.jsp',
    description: '대법원 부동산/법인 등기 통합시스템',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'efine',
    name: '경찰청 교통민원24',
    domain: 'efine.go.kr',
    category: 'public',
    loginUrl: 'https://www.efine.go.kr/login/login.do',
    description: '이파인 운전면허/과태료 조회 시스템',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'wetax',
    name: '위택스 (지방세)',
    domain: 'wetax.go.kr',
    category: 'public',
    loginUrl: 'https://www.wetax.go.kr/main/?cmd=LPTIHA0R0',
    description: '행정안전부 지방세 인터넷 납부 시스템',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'bokjiro',
    name: '복지로',
    domain: 'bokjiro.go.kr',
    category: 'public',
    loginUrl: 'https://www.bokjiro.go.kr/ssis-tbu/twatbz/trgt/login/login.do',
    description: '보건복지부 복지 포털',
    requiresKeypadPrecaution: true,
  },

  // 5. 이커머스 / 배달 / 패션 (10)
  {
    id: 'coupang',
    name: '쿠팡',
    domain: 'coupang.com',
    category: 'ecommerce',
    loginUrl: 'https://login.coupang.com/login/login.pang',
    description: '국내 최대 e커머스 플랫폼',
  },
  {
    id: '11st',
    name: '11번가',
    domain: '11st.co.kr',
    category: 'ecommerce',
    loginUrl: 'https://login.11st.co.kr/auth/front/login.tmall',
    description: 'SK스퀘어 오픈마켓',
  },
  {
    id: 'gmarket',
    name: 'G마켓',
    domain: 'gmarket.co.kr',
    category: 'ecommerce',
    loginUrl: 'https://signinssl.gmarket.co.kr/login/login',
    description: '신세계 계열 오픈마켓',
  },
  {
    id: 'auction',
    name: '옥션',
    domain: 'auction.co.kr',
    category: 'ecommerce',
    loginUrl: 'https://memberssl.auction.co.kr/Authenticate',
    description: '온라인 오픈마켓',
  },
  {
    id: 'ssg',
    name: 'SSG닷컴',
    domain: 'ssg.com',
    category: 'ecommerce',
    loginUrl: 'https://member.ssg.com/member/login.ssg',
    description: '신세계·이마트 통합 온라인몰',
  },
  {
    id: 'lotte-on',
    name: '롯데ON',
    domain: 'lotteon.com',
    category: 'ecommerce',
    loginUrl: 'https://www.lotteon.com/display/viewLoginPage',
    description: '롯데 쇼핑 통합 이커머스',
  },
  {
    id: 'kurly',
    name: '컬리 (마켓컬리)',
    domain: 'kurly.com',
    category: 'ecommerce',
    loginUrl: 'https://www.kurly.com/member/login',
    description: '새벽배송 신선식품 플랫폼',
  },
  {
    id: 'musinsa',
    name: '무신사',
    domain: 'musinsa.com',
    category: 'ecommerce',
    loginUrl: 'https://www.musinsa.com/auth/login',
    description: '국내 1위 패션 플랫폼',
  },
  {
    id: 'baemin',
    name: '배달의민족',
    domain: 'baemin.com',
    category: 'ecommerce',
    loginUrl: 'https://ceo.baemin.com/login',
    description: '우아한형제들 배민 외식업광장 로그인',
  },
  {
    id: 'yogiyo',
    name: '요기요',
    domain: 'yogiyo.co.kr',
    category: 'ecommerce',
    loginUrl: 'https://owner.yogiyo.co.kr/owner/login/',
    description: '요기요 사장님 포털 로그인',
  },

  // 6. 핀테크 / 카드사 (6)
  {
    id: 'toss',
    name: '토스 (비바리퍼블리카)',
    domain: 'toss.im',
    category: 'fintech',
    loginUrl: 'https://toss.im',
    description: '모바일 금융 슈퍼앱 웹 포털',
  },
  {
    id: 'shinhan-card',
    name: '신한카드',
    domain: 'shinhancard.com',
    category: 'fintech',
    loginUrl: 'https://www.shinhancard.com/pconts/html/main.html#login',
    description: '신한카드 온라인 서비스 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'samsung-card',
    name: '삼성카드',
    domain: 'samsungcard.com',
    category: 'fintech',
    loginUrl: 'https://www.samsungcard.com/personal/member/login/UHPPME0101M0.jsp',
    description: '삼성카드 웹 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'hyundai-card',
    name: '현대카드',
    domain: 'hyundaicard.com',
    category: 'fintech',
    loginUrl: 'https://www.hyundaicard.com/cpa/ma/CPAMA0101_01.hc',
    description: '현대카드 웹 회원 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'kb-card',
    name: 'KB국민카드',
    domain: 'card.kbstar.com',
    category: 'fintech',
    loginUrl: 'https://card.kbstar.com/CXHIICNC0001.cms',
    description: 'KB국민카드 개인 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'lotte-card',
    name: '롯데카드',
    domain: 'lottecard.co.kr',
    category: 'fintech',
    loginUrl: 'https://www.lottecard.co.kr/app/LPMAIAA_V100.lc',
    description: '디지로카/롯데카드 웹 로그인',
    requiresKeypadPrecaution: true,
  },

  // 7. 통신 / 플랫폼 / 취업 (4)
  {
    id: 't-world',
    name: 'SK텔레콤 T월드',
    domain: 'tworld.co.kr',
    category: 'telecom',
    loginUrl: 'https://www.tworld.co.kr/poc/html/main/MA.html#login',
    description: 'SKT 통신 통합 계정 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'kt',
    name: 'KT',
    domain: 'kt.com',
    category: 'telecom',
    loginUrl: 'https://login.kt.com/wamui/AthWeb.do',
    description: 'KT 공식 인증 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'lguplus',
    name: 'LG유플러스',
    domain: 'lguplus.com',
    category: 'telecom',
    loginUrl: 'https://www.lguplus.com/login',
    description: 'LG U+ 통합 로그인',
    requiresKeypadPrecaution: true,
  },
  {
    id: 'saramin',
    name: '사람인',
    domain: 'saramin.co.kr',
    category: 'portal',
    loginUrl: 'https://www.saramin.co.kr/zf_user/auth',
    description: '국내 대표 구인구직 플랫폼',
  },
] as const;

/**
 * 타깃 개수 및 무결성 검증 헬퍼 함수
 */
export function getTargetsByCategory(category: SiteCategory): BenchmarkTarget[] {
  return BENCHMARK_TARGETS.filter(target => target.category === category);
}

export function getTargetById(id: string): BenchmarkTarget | undefined {
  return BENCHMARK_TARGETS.find(target => target.id === id);
}

export function validateTargets(): { valid: boolean; total: number; duplicates: string[] } {
  const seenIds = new Set<string>();
  const duplicates: string[] = [];

  for (const target of BENCHMARK_TARGETS) {
    if (seenIds.has(target.id)) {
      duplicates.push(target.id);
    }
    seenIds.add(target.id);

    if (!target.loginUrl.startsWith('https://')) {
      throw new Error(`타깃 URL 프로토콜 위반: ${target.id} (${target.loginUrl})`);
    }
  }

  return {
    valid: duplicates.length === 0 && BENCHMARK_TARGETS.length === 50,
    total: BENCHMARK_TARGETS.length,
    duplicates,
  };
}
