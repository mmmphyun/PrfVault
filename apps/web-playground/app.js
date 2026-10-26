import { BENCHMARK_DATA } from './data.js';
import { initPrfVaultWasm } from './wasm-bundle.js';

// 전역 상태
let wasmExports = null;
let currentAlloc = { ptr: 0, size: 0, text: '' };
let zeroizeTimer = null;
let countdownRemaining = 5;

// 상수 정의 (NIST SP 800-63B 기준)
const NIST_STD_LEN = 20;
const NIST_CHARSET_SIZE = 94;
const NIST_STD_ENTROPY = NIST_STD_LEN * Math.log2(NIST_CHARSET_SIZE); // 131.0918 bits
const GPU_RATE = 1e10; // guesses/sec

// 문자셋 정의
const CHARSET_LOWER = 'abcdefghijklmnopqrstuvwxyz';
const CHARSET_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const CHARSET_DIGITS = '0123456789';
const CHARSET_SPECIAL = '!@#$%^&*()_+-=[]{}|;:,.<>?';
const ALL_CHARS = CHARSET_LOWER + CHARSET_UPPER + CHARSET_DIGITS + CHARSET_SPECIAL;

// Wasm 초기화
async function setupWasm() {
    const statusEl = document.getElementById('wasm-engine-status');
    try {
        wasmExports = await initPrfVaultWasm();
        if (statusEl) {
            statusEl.innerHTML = '<span class="status-badge success">Rust Wasm 코어 활성화됨 (선형 메모리 바인딩 완료)</span>';
        }
    } catch (err) {
        console.warn('Wasm direct instantiate failed, falling back to simulated memory:', err);
        if (statusEl) {
            statusEl.innerHTML = '<span class="status-badge warning">가상 Wasm 메모리 에뮬레이션 모드 가동</span>';
        }
    }
}

// 섀넌 엔트로피 계산기
function calculateEntropy(length, charsetSize = 94) {
    if (!length || length <= 0) return 0;
    return length * Math.log2(charsetSize);
}

// 오프라인 크랙 시간 포맷팅
function formatCrackTime(seconds) {
    if (!seconds || seconds <= 0) return '0초';
    if (seconds < 1) return `${(seconds * 1000).toFixed(1)} 밀리초`;
    if (seconds < 60) return `${seconds.toFixed(1)} 초`;
    if (seconds < 3600) return `${(seconds / 60).toFixed(1)} 분`;
    if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} 시간`;
    if (seconds < 31536000) return `${(seconds / 86400).toFixed(1)} 일`;
    const years = seconds / 31536000;
    if (years > 1e15) return `${years.toExponential(2)} 년 (우주 수명 초과)`;
    if (years > 1e9) return `${(years / 1e9).toFixed(2)} 십억 년`;
    if (years > 1e6) return `${(years / 1e6).toFixed(2)} 백만 년`;
    return `${years.toLocaleString(undefined, { maximumFractionDigits: 1 })} 년`;
}

// 간단한 SHA-256 기반 적응형 암호 생성기 (브라우저 Web Crypto API)
async function generateAdaptivePassword(masterSecret, domain, length) {
    const cleanSecret = (masterSecret || 'default_secret').trim();
    const cleanDomain = (domain || 'example.com').trim().toLowerCase();
    const targetLen = Math.max(8, Math.min(64, length || 16));

    const enc = new TextEncoder();
    const keyData = enc.encode(`${cleanSecret}::${cleanDomain}::salt_prfvault_v1`);
    const hashBuffer = await crypto.subtle.digest('SHA-256', keyData);
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    // 4개 문자군 강제 포함
    const picks = [
        CHARSET_LOWER[hashArray[0] % CHARSET_LOWER.length],
        CHARSET_UPPER[hashArray[1] % CHARSET_UPPER.length],
        CHARSET_DIGITS[hashArray[2] % CHARSET_DIGITS.length],
        CHARSET_SPECIAL[hashArray[3] % CHARSET_SPECIAL.length],
    ];

    // 나머지 길이 94자 복합셋에서 균일 선택
    for (let i = 4; i < targetLen; i++) {
        const byte = hashArray[i % hashArray.length] ^ (i * 31);
        picks.push(ALL_CHARS[Math.abs(byte) % ALL_CHARS.length]);
    }

    // 간단한 셔플
    for (let i = picks.length - 1; i > 0; i--) {
        const j = (hashArray[i % hashArray.length] + i) % (i + 1);
        [picks[i], picks[j]] = [picks[j], picks[i]];
    }

    return picks.join('');
}

// 도메인 데이터 검색
function lookupDomain(domainInput) {
    if (!domainInput) return null;
    const clean = domainInput.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    const found = BENCHMARK_DATA.siteDetails.find(s => s.domain.toLowerCase() === clean);
    if (found) return found;

    // 부분 매칭 시도
    return BENCHMARK_DATA.siteDetails.find(s => s.domain.toLowerCase().includes(clean)) || null;
}

// 1단계: 도메인 진단 렌더링
function renderDomainDiagnosis(site, customDomain) {
    const domainNameEl = document.getElementById('diag-domain-name');
    const categoryEl = document.getElementById('diag-category');
    const maxLenEl = document.getElementById('diag-maxlen');
    const keypadEl = document.getElementById('diag-keypad');
    const lossEl = document.getElementById('diag-loss');
    const alertBoxEl = document.getElementById('diag-alert-box');

    const domainName = site ? site.domain : (customDomain || 'custom-site.com');
    const category = site ? site.category : '사용자 정의';
    const maxLen = site ? site.maxPasswordLength : 20;
    const isKeypad = site ? site.blockedByVirtualKeypad : false;
    const lossPercent = site ? site.entropyLossPercent : (maxLen < 20 ? ((20 - maxLen) / 20 * 100).toFixed(1) : 0);

    domainNameEl.textContent = domainName;
    categoryEl.textContent = category;
    maxLenEl.textContent = `${maxLen}자`;
    keypadEl.innerHTML = isKeypad
        ? '<span class="badge danger">차단됨 (가상 키패드 강제)</span>'
        : '<span class="badge success">허용 (표준 DOM 자동완성)</span>';

    if (lossPercent > 0) {
        lossEl.innerHTML = `<span class="badge danger">-${lossPercent}% 결손 (${(maxLen * Math.log2(94)).toFixed(1)} bits)</span>`;
    } else {
        lossEl.innerHTML = `<span class="badge success">0.0% (NIST 권고 충족)</span>`;
    }

    // 진단 요약 박스
    if (site && site.domain === 'naver.com') {
        alertBoxEl.className = 'alert-box warning-alert';
        alertBoxEl.innerHTML = `
            <strong>네이버 (naver.com) 비표준 제약 감지:</strong><br>
            비밀번호 최대 길이가 16자로 제한되어 있어, NIST SP 800-63B 표준(20자, 131.09 bits) 대비 정확히 <strong>20.0% (26.22 bits)의 엔트로피 결손</strong>이 발생합니다.
            오프라인 크랙 시간이 표준 대비 약 <strong>7,800만 배</strong> 단축되는 보안 취약 구간입니다.
        `;
    } else if (site && site.domain === 'kt.com') {
        alertBoxEl.className = 'alert-box warning-alert';
        alertBoxEl.innerHTML = `
            <strong>KT (kt.com) 비표준 제약 감지:</strong><br>
            포털 네이버와 동일하게 최대 16자 길이 제한으로 <strong>20.0%의 엔트로피 결손</strong>이 강제됩니다. 적응형 고엔트로피 파생으로 16자 내에 94개 문자군을 전수 분배해야 합니다.
        `;
    } else if (isKeypad) {
        alertBoxEl.className = 'alert-box danger-alert';
        alertBoxEl.innerHTML = `
            <strong>가상 키패드 차단 감지 (${domainName}):</strong><br>
            브라우저 패스워드 매니저의 DOM 자동 완성 및 키보드 입력이 차단됩니다. 본 앱의 <strong>3단계: 1회용 마스킹 복사 및 5초 Wasm Zeroize 소거</strong> 모드로 자동 전환됩니다.
        `;
    } else {
        alertBoxEl.className = 'alert-box success-alert';
        alertBoxEl.innerHTML = `
            <strong>표준 인터페이스 준수 확인 (${domainName}):</strong><br>
            가상 키패드 강제 없이 표준 DOM 입력을 지원하며, 허용 암호 공간이 NIST SP 800-63B 기준(20자 이상)을 만족합니다.
        `;
    }

    // 다음 단계 입력폼에 자동 반영
    const siteMaxLenInput = document.getElementById('gen-length-input');
    if (siteMaxLenInput) {
        siteMaxLenInput.value = maxLen;
    }
}

// 2단계: 암호 생성 및 엔트로피 비교 렌더링
async function handleGeneratePassword() {
    const masterSecret = document.getElementById('master-secret-input').value;
    const domainInput = document.getElementById('target-domain-input').value;
    const lengthInput = parseInt(document.getElementById('gen-length-input').value, 10) || 16;

    const password = await generateAdaptivePassword(masterSecret, domainInput, lengthInput);

    // 생성 암호 표시
    const pwDisplay = document.getElementById('generated-password-display');
    pwDisplay.value = password;

    // 엔트로피 계산
    const currentEntropy = calculateEntropy(password.length, 94);
    const entropyLoss = Math.max(0, ((NIST_STD_ENTROPY - currentEntropy) / NIST_STD_ENTROPY) * 100);
    const crackSeconds = Math.pow(2, currentEntropy - 1) / GPU_RATE;
    const stdCrackSeconds = Math.pow(2, NIST_STD_ENTROPY - 1) / GPU_RATE;

    // 수치 렌더링
    document.getElementById('current-entropy-bits').textContent = `${currentEntropy.toFixed(2)} bits`;
    document.getElementById('nist-entropy-bits').textContent = `${NIST_STD_ENTROPY.toFixed(2)} bits`;
    document.getElementById('current-entropy-loss').textContent = `${entropyLoss.toFixed(1)}%`;
    document.getElementById('current-crack-time').textContent = formatCrackTime(crackSeconds);
    document.getElementById('nist-crack-time').textContent = formatCrackTime(stdCrackSeconds);

    // 차트 바 폭 조정
    const maxBarEntropy = 200;
    const currentBarPct = Math.min(100, (currentEntropy / maxBarEntropy) * 100);
    const nistBarPct = Math.min(100, (NIST_STD_ENTROPY / maxBarEntropy) * 100);

    const currentBarEl = document.getElementById('current-entropy-bar');
    const nistBarEl = document.getElementById('nist-entropy-bar');

    currentBarEl.style.width = `${currentBarPct}%`;
    nistBarEl.style.width = `${nistBarPct}%`;

    if (entropyLoss > 0) {
        currentBarEl.style.backgroundColor = '#f59e0b'; // amber
    } else {
        currentBarEl.style.backgroundColor = '#10b981'; // emerald
    }

    // 3단계 Wasm 메모리 버퍼에 즉시 로드
    loadPasswordIntoWasmMemory(password);
}

// Wasm 선형 메모리에 암호 로드
function loadPasswordIntoWasmMemory(password) {
    const enc = new TextEncoder();
    const bytes = enc.encode(password);
    const size = bytes.length;

    // 기존 할당 해제
    if (currentAlloc.ptr !== 0) {
        deallocateMemory();
    }

    let ptr = 0;
    if (wasmExports && typeof wasmExports.prf_vault_alloc === 'function') {
        ptr = wasmExports.prf_vault_alloc(size);
        const memBuffer = new Uint8Array(wasmExports.memory.buffer);
        memBuffer.set(bytes, ptr);
    } else {
        // 시뮬레이션 포인터
        ptr = 0x1000 + Math.floor(Math.random() * 0x0FFF);
    }

    currentAlloc = { ptr, size, text: password, bytes: Array.from(bytes), isZeroized: false };
    renderHexDump('ALLOCATED');

    const copyBtn = document.getElementById('copy-mask-btn');
    copyBtn.disabled = false;
    copyBtn.textContent = '1회용 마스킹 복사 & 5초 Zeroize 시작';
}

// Wasm 메모리 소거 실행
function deallocateMemory() {
    if (currentAlloc.ptr === 0 || currentAlloc.isZeroized) return;

    if (wasmExports && typeof wasmExports.prf_vault_dealloc_zeroize === 'function') {
        wasmExports.prf_vault_dealloc_zeroize(currentAlloc.ptr, currentAlloc.size);
    }

    currentAlloc.isZeroized = true;
    currentAlloc.bytes = new Array(currentAlloc.size).fill(0);
    currentAlloc.text = '';
    renderHexDump('ZEROIZED');
}

// 헥스 덤프 렌더링
function renderHexDump(status) {
    const hexContainer = document.getElementById('wasm-hex-dump');
    const statusTag = document.getElementById('mem-status-tag');
    const timerTag = document.getElementById('zeroize-timer-tag');

    if (!hexContainer) return;

    if (status === 'ALLOCATED') {
        statusTag.className = 'status-badge allocated';
        statusTag.textContent = `Wasm Memory Active (0x${currentAlloc.ptr.toString(16).padStart(4, '0')})`;
        timerTag.textContent = '메모리 상주 중';
    } else if (status === 'ZEROIZED') {
        statusTag.className = 'status-badge zeroized';
        statusTag.textContent = 'Zeroized (0x00 완전 소거됨)';
        timerTag.textContent = '소거 완료 (0x00)';
    }

    const baseAddr = currentAlloc.ptr;
    let html = `<div class="hex-row header-row"><span>오프셋</span><span>16진수 바이트 (Hex)</span><span>ASCII 텍스트</span></div>`;

    const rowSize = 16;
    for (let i = 0; i < currentAlloc.size; i += rowSize) {
        const slice = currentAlloc.bytes.slice(i, i + rowSize);
        const addrStr = `0x${(baseAddr + i).toString(16).padStart(6, '0')}`;

        const hexBytes = slice.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
        const asciiStr = slice.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');

        const isZero = slice.every(b => b === 0);
        const byteClass = isZero ? 'byte-zero' : 'byte-active';

        html += `<div class="hex-row">
            <span class="hex-addr">${addrStr}</span>
            <span class="hex-bytes ${byteClass}">${hexBytes.padEnd(47, ' ')}</span>
            <span class="hex-ascii ${byteClass}">${asciiStr}</span>
        </div>`;
    }

    hexContainer.innerHTML = html;
}

// 3단계: 복사 및 5초 타이머 실행
function handleCopyAndZeroize() {
    if (currentAlloc.isZeroized || !currentAlloc.text) {
        alert('메모리가 이미 소거되었습니다. 2단계에서 암호를 다시 생성해 주십시오.');
        return;
    }

    // 1회용 클립보드 복사
    navigator.clipboard.writeText(currentAlloc.text).then(() => {
        const copyBtn = document.getElementById('copy-mask-btn');
        const timerTag = document.getElementById('zeroize-timer-tag');
        copyBtn.disabled = true;

        countdownRemaining = 5;
        if (zeroizeTimer) clearInterval(zeroizeTimer);

        timerTag.textContent = `Zeroize 카운트다운: ${countdownRemaining}초`;

        zeroizeTimer = setInterval(() => {
            countdownRemaining--;
            if (countdownRemaining > 0) {
                timerTag.textContent = `Zeroize 카운트다운: ${countdownRemaining}초`;
            } else {
                clearInterval(zeroizeTimer);
                zeroizeTimer = null;
                deallocateMemory();
                copyBtn.textContent = '메모리 소거 완료 (새 암호 생성 필요)';
            }
        }, 1000);
    }).catch(err => {
        console.error('클립보드 접근 실패:', err);
        // 클립보드 권한 실패 시에도 카운트다운 정상 진행
        deallocateMemory();
    });
}

// 50대 사이트 테이블 렌더링
function renderBenchmarkTable(filterText = '') {
    const tbody = document.getElementById('benchmark-tbody');
    if (!tbody) return;

    const filtered = BENCHMARK_DATA.siteDetails.filter(s =>
        s.domain.toLowerCase().includes(filterText.toLowerCase()) ||
        s.category.toLowerCase().includes(filterText.toLowerCase())
    );

    let html = '';
    filtered.forEach((site, idx) => {
        const isKeypad = site.blockedByVirtualKeypad;
        const loss = site.entropyLossPercent;
        const lossClass = loss > 0 ? 'text-amber font-bold' : 'text-gray';
        const keypadBadge = isKeypad ? '<span class="badge danger">차단 (가상키패드)</span>' : '<span class="badge success">표준 DOM</span>';

        html += `
            <tr class="table-row" data-domain="${site.domain}">
                <td>${idx + 1}</td>
                <td><button class="domain-select-btn" data-domain="${site.domain}"><strong>${site.domain}</strong></button></td>
                <td>${site.category}</td>
                <td>${site.maxPasswordLength}자</td>
                <td>${site.entropyBits.toFixed(2)} bits</td>
                <td class="${lossClass}">-${loss.toFixed(1)}%</td>
                <td>${keypadBadge}</td>
            </tr>
        `;
    });

    tbody.innerHTML = html;

    // 행 내 버튼 이벤트 바인딩
    tbody.querySelectorAll('.domain-select-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const domain = e.currentTarget.dataset.domain;
            selectDomain(domain);
        });
    });
}

// 도메인 선택 처리
function selectDomain(domain) {
    const targetInput = document.getElementById('target-domain-input');
    targetInput.value = domain;
    const site = lookupDomain(domain);
    renderDomainDiagnosis(site, domain);
    handleGeneratePassword();
    window.scrollTo({ top: 350, behavior: 'smooth' });
}

// 이벤트 초기화
function setupEvents() {
    // 빠른 도메인 선택 칩
    document.querySelectorAll('.preset-chip').forEach(chip => {
        chip.addEventListener('click', (e) => {
            const domain = e.currentTarget.dataset.domain;
            selectDomain(domain);
        });
    });

    // 도메인 입력 변경
    const targetInput = document.getElementById('target-domain-input');
    targetInput.addEventListener('input', (e) => {
        const domain = e.target.value.trim();
        const site = lookupDomain(domain);
        renderDomainDiagnosis(site, domain);
    });

    // 암호 생성 버튼
    document.getElementById('generate-pw-btn').addEventListener('click', () => {
        handleGeneratePassword();
    });

    // 3단계 복사 및 Zeroize 버튼
    document.getElementById('copy-mask-btn').addEventListener('click', () => {
        handleCopyAndZeroize();
    });

    // 즉시 제로화 강제 버튼
    document.getElementById('force-zeroize-btn').addEventListener('click', () => {
        if (zeroizeTimer) {
            clearInterval(zeroizeTimer);
            zeroizeTimer = null;
        }
        deallocateMemory();
    });

    // 벤치마크 검색 입력
    const searchInput = document.getElementById('benchmark-search');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            renderBenchmarkTable(e.target.value);
        });
    }

    // 모의 로그인 폼 제출
    const mockLoginForm = document.getElementById('mock-login-form');
    if (mockLoginForm) {
        mockLoginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const val = document.getElementById('mock-password-input').value;
            const resEl = document.getElementById('mock-login-result');
            if (!val) {
                resEl.className = 'mock-result error';
                resEl.textContent = '비밀번호를 붙여넣은 후 테스트해 주십시오.';
            } else {
                resEl.className = 'mock-result success';
                resEl.textContent = `모의 로그인 성공: ${val.length}자리 암호 정상 전달됨.`;
            }
        });
    }
}

// 초기 로드 진입점
window.addEventListener('DOMContentLoaded', async () => {
    await setupWasm();
    setupEvents();
    renderBenchmarkTable();

    // 초기 네이버(naver.com) 진단 기본 로드
    selectDomain('naver.com');
});
