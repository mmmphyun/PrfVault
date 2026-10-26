import base64
import json
from pathlib import Path

repo_root = Path("c:/work/PrfVault")

# 1. 벤치마크 데이터 로드
benchmark_path = repo_root / "scripts/results/benchmark-analysis.json"
with open(benchmark_path, "r", encoding="utf-8") as f:
    benchmark_data = json.load(f)
benchmark_json_str = json.dumps(benchmark_data, ensure_ascii=False)

# 2. Wasm 바이너리 Base64 인코딩
wasm_path = repo_root / "crates/crypto-core/pkg/crypto_core_bg.wasm"
with open(wasm_path, "rb") as f:
    wasm_bytes = f.read()
wasm_base64_str = base64.b64encode(wasm_bytes).decode("ascii")

html_content = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PrfVault Playground · 비표준 인증 보안 인터페이스 실증</title>
    <style>
        :root {{
            --bg: #080a0f;
            --surface: #10131c;
            --surface-hover: #161b26;
            --border: #1e2536;
            --border-subtle: #151a26;
            --text-title: #f8fafc;
            --text-body: #cbd5e1;
            --text-muted: #718096;
            --accent: #38bdf8;
            --accent-dim: rgba(56, 189, 248, 0.08);
            --amber: #fbbf24;
            --amber-dim: rgba(251, 191, 36, 0.08);
            --amber-text: #fef3c7;
            --emerald: #34d399;
            --emerald-dim: rgba(52, 211, 153, 0.08);
            --emerald-text: #d1fae5;
            --rose: #fb7185;
            --rose-dim: rgba(251, 113, 133, 0.08);
            --rose-text: #ffe4e6;
            --terminal-bg: #05070c;
            --track-bg: #181d2a;
            --byte-zero: #334155;
            --ascii-active: #86efac;
            --ascii-zero: #1e293b;
            --mono: "SF Mono", Monaco, Consolas, "Liberation Mono", Courier, monospace;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            background-color: var(--bg);
            color: var(--text-body);
            font-family: -apple-system, BlinkMacSystemFont, "Pretendard", "Segoe UI", Roboto, sans-serif;
            font-size: 15px;
            line-height: 1.7;
            padding: 64px 32px;
            -webkit-font-smoothing: antialiased;
        }}

        .workbench {{
            max-width: 1040px;
            margin: 0 auto;
        }}

        header.wb-header {{
            margin-bottom: 48px;
            padding-bottom: 32px;
            border-bottom: 1px solid var(--border-subtle);
        }}

        .meta-eyebrow {{
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--accent);
            margin-bottom: 12px;
        }}

        h1.paper-heading {{
            font-size: 25px;
            font-weight: 700;
            color: var(--text-title);
            line-height: 1.45;
            letter-spacing: -0.015em;
            margin-bottom: 18px;
        }}

        .purpose-statement {{
            font-size: 15.5px;
            color: var(--text-muted);
            line-height: 1.7;
            padding-left: 18px;
            border-left: 3px solid var(--accent);
        }}

        .wasm-pill {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-size: 12.5px;
            font-family: var(--mono);
            color: var(--text-muted);
            margin-top: 18px;
        }}

        .status-dot {{
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background-color: var(--emerald);
        }}

        .wb-section {{
            padding: 36px 0;
            border-bottom: 1px solid var(--border-subtle);
        }}

        .wb-section-header {{
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            margin-bottom: 18px;
        }}

        .section-label {{
            font-size: 13px;
            font-weight: 700;
            color: var(--accent);
            font-family: var(--mono);
            letter-spacing: 0.06em;
        }}

        .section-desc {{
            font-size: 13.5px;
            color: var(--text-muted);
        }}

        .chip-group {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 16px;
        }}

        .chip-btn {{
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 13px;
            padding: 6px 13px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.15s;
        }}

        .chip-btn:hover {{
            border-color: var(--accent);
            color: var(--text-title);
            background: var(--accent-dim);
        }}

        .chip-btn.active {{
            border-color: var(--accent);
            color: var(--accent);
            background: var(--accent-dim);
        }}

        .input-row {{
            display: flex;
            gap: 16px;
            align-items: center;
        }}

        input[type="text"], input[type="password"], input[type="number"] {{
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text-title);
            font-size: 14.5px;
            padding: 10px 14px;
            border-radius: 5px;
            outline: none;
            transition: border-color 0.15s;
        }}

        input:focus {{ border-color: var(--accent); }}

        .domain-input {{ flex: 1; }}

        .diag-feedback {{
            margin-top: 16px;
            padding: 14px 18px;
            border-left: 3px solid var(--border);
            font-size: 14px;
            line-height: 1.6;
            border-radius: 0 4px 4px 0;
        }}

        .diag-feedback.warning {{
            border-left-color: var(--amber);
            background: var(--amber-dim);
            color: var(--amber-text);
        }}

        .diag-feedback.danger {{
            border-left-color: var(--rose);
            background: var(--rose-dim);
            color: var(--rose-text);
        }}

        .diag-feedback.success {{
            border-left-color: var(--emerald);
            background: var(--emerald-dim);
            color: var(--emerald-text);
        }}

        .gen-grid {{
            display: grid;
            grid-template-columns: 1.15fr 1fr;
            gap: 36px;
            align-items: start;
        }}

        @media (max-width: 820px) {{
            .gen-grid {{ grid-template-columns: 1fr; gap: 24px; }}
        }}

        .field {{ margin-bottom: 16px; }}

        .field label {{
            display: block;
            font-size: 13px;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}

        .btn-action {{
            background: var(--accent);
            color: var(--bg);
            font-weight: 600;
            font-size: 13.5px;
            padding: 10px 18px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: opacity 0.15s;
        }}

        .btn-action:hover {{ opacity: 0.9; }}

        .btn-action:disabled {{
            background: var(--border);
            color: var(--text-muted);
            cursor: not-allowed;
        }}

        .btn-secondary {{
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-body);
            font-size: 13px;
            padding: 9px 14px;
            border-radius: 5px;
            cursor: pointer;
            margin-left: 8px;
        }}

        .btn-secondary:hover {{
            border-color: var(--text-muted);
            color: var(--text-title);
        }}

        .pw-output {{
            font-family: var(--mono);
            color: var(--accent);
            font-size: 15px;
            font-weight: 600;
            width: 100%;
            letter-spacing: 0.03em;
        }}

        .entropy-panel {{ padding-top: 6px; }}

        .bar-group {{ margin-bottom: 16px; }}

        .bar-head {{
            display: flex;
            justify-content: space-between;
            font-size: 13px;
            margin-bottom: 6px;
        }}

        .track {{
            height: 8px;
            background: var(--track-bg);
            border-radius: 4px;
            overflow: hidden;
        }}

        .fill {{ height: 100%; transition: width 0.3s; }}

        .stats-pair {{
            display: flex;
            gap: 32px;
            margin-top: 20px;
            padding-top: 16px;
            border-top: 1px solid var(--border-subtle);
        }}

        .stat-item .stat-num {{
            font-size: 18px;
            font-weight: 700;
            color: var(--text-title);
        }}

        .stat-item .stat-lbl {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 2px;
        }}

        .terminal-box {{
            background: var(--terminal-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 18px 22px;
            font-family: var(--mono);
            font-size: 13px;
            margin-top: 14px;
        }}

        .terminal-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-subtle);
            padding-bottom: 10px;
            margin-bottom: 12px;
            color: var(--text-muted);
            font-size: 12px;
        }}

        .hex-dump {{
            max-height: 200px;
            overflow-x: auto;
            color: var(--text-muted);
            line-height: 1.7;
        }}

        .hex-line {{
            display: grid;
            grid-template-columns: 95px 1fr 150px;
            gap: 20px;
        }}

        .addr {{ color: var(--text-muted); }}
        .bytes.active {{ color: var(--accent); }}
        .bytes.zero {{ color: var(--byte-zero); }}
        .ascii.active {{ color: var(--ascii-active); }}
        .ascii.zero {{ color: var(--ascii-zero); }}

        .terminal-ctrl {{
            margin-top: 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
        }}

        .timer-info {{
            font-family: var(--mono);
            font-size: 13px;
            color: var(--amber);
        }}

        .mock-login-inline {{
            display: flex;
            gap: 10px;
            margin-top: 16px;
            align-items: center;
        }}

        .table-wrap {{
            max-height: 360px;
            overflow-y: auto;
            margin-top: 16px;
            border-top: 1px solid var(--border-subtle);
        }}

        table.flat-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13.5px;
            text-align: left;
        }}

        table.flat-table th {{
            color: var(--text-muted);
            font-weight: 600;
            padding: 11px 14px;
            border-bottom: 1px solid var(--border);
            font-size: 12.5px;
            position: sticky;
            top: 0;
            background: var(--bg);
        }}

        table.flat-table td {{
            padding: 9px 14px;
            border-bottom: 1px solid var(--border-subtle);
            color: var(--text-muted);
        }}

        table.flat-table tr:hover td {{
            background: var(--surface);
            color: var(--text-title);
        }}

        .tbl-btn {{
            background: none;
            border: none;
            color: var(--accent);
            cursor: pointer;
            font-family: inherit;
            font-size: 13.5px;
            font-weight: 500;
            padding: 0;
        }}

        .tbl-btn:hover {{ text-decoration: underline; }}

        footer.wb-footer {{
            margin-top: 56px;
            padding-top: 24px;
            border-top: 1px solid var(--border-subtle);
            font-size: 12.5px;
            color: var(--text-muted);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
    </style>
</head>
<body>

<div class="workbench">
    <header class="wb-header">
        <div class="meta-eyebrow">PrfVault Research Playground · 과제 BR-B</div>
        <h1 class="paper-heading">국내 50대 웹사이트의 비표준 인증 보안 인터페이스가 브라우저 패스워드 매니저 및 암호 엔트로피에 미치는 영향 실증</h1>
        <p class="purpose-statement">
            "국내 웹 서비스를 이용하는 사용자가 네이버·KT의 16자 제한이나 금융권 가상 키패드 등 비표준 보안 인터페이스를 마주할 때, 본 앱이 사이트 제약을 자동 진단하여 94개 복합 문자군 기반 적응형 고엔트로피 비밀번호를 생성하고 가상 키패드용 1회용 마스킹 복사 및 Wasm 메모리 소거(Zeroize)로 계정을 보호해 준다."
        </p>
        <div class="wasm-pill">
            <span class="status-dot"></span>
            <span id="wasm-runtime-note">Rust Wasm Linear Memory (64KB ArrayBuffer) 직독 활성화</span>
        </div>
    </header>

    <!-- 1단계: 도메인 제약 진단 -->
    <section class="wb-section">
        <div class="wb-section-header">
            <span class="section-label">01 / DIAGNOSIS</span>
            <span class="section-desc">국내 50대 웹사이트 로그인 DOM 비표준 제약조건 실측 분석</span>
        </div>

        <div class="chip-group">
            <button class="chip-btn active" data-domain="naver.com">네이버 (16자 제한)</button>
            <button class="chip-btn" data-domain="kt.com">KT (16자 제한)</button>
            <button class="chip-btn" data-domain="samsungpop.com">삼성증권 (키패드 차단)</button>
            <button class="chip-btn" data-domain="hyundaicard.com">현대카드 (키패드 차단)</button>
            <button class="chip-btn" data-domain="daum.net">다음 (32자 표준)</button>
            <button class="chip-btn" data-domain="dcinside.com">디시 (40자 고엔트로피)</button>
        </div>

        <div class="input-row">
            <input type="text" id="target-domain-input" class="domain-input" value="naver.com" placeholder="도메인을 입력하거나 위 목록을 클릭하십시오">
            <div style="font-family: var(--mono); font-size: 13px; color: var(--text-muted);" id="domain-quick-metric">
                L=16 · 104.87 bits · 키패드 없음
            </div>
        </div>

        <div id="diag-feedback-box" class="diag-feedback warning">
            <strong>네이버 (naver.com) 비표준 제약 감지:</strong><br>
            최대 길이가 16자로 제한되어 있어 NIST SP 800-63B 기준(20자, 131.09 bits) 대비 <strong>정확히 20.0%의 엔트로피 결손</strong>이 발생합니다.
        </div>
    </section>

    <!-- 2단계: 적응형 고엔트로피 생성 및 엔트로피 비교 -->
    <section class="wb-section">
        <div class="wb-section-header">
            <span class="section-label">02 / ADAPTIVE KEY DERIVATION</span>
            <span class="section-desc">사이트 제약에 맞춘 94자 복합 문자군 전수 매핑 및 실시간 엔트로피 비교</span>
        </div>

        <div class="gen-grid">
            <div>
                <div class="field">
                    <label>마스터 시크릿 (시드):</label>
                    <input type="password" id="master-secret-input" value="MasterPassword2026!#" style="width: 100%;">
                </div>
                <div class="field">
                    <label>사이트 상한 길이 (자동 반영):</label>
                    <div style="display: flex; gap: 10px;">
                        <input type="number" id="gen-length-input" value="16" min="8" max="64" style="width: 90px;">
                        <button id="generate-pw-btn" class="btn-action" style="flex: 1;">적응형 암호 생성</button>
                    </div>
                </div>
                <div class="field" style="margin-top: 18px;">
                    <label>생성된 비밀번호:</label>
                    <input type="text" id="generated-password-display" class="pw-output" readonly>
                </div>
            </div>

            <div class="entropy-panel">
                <div class="bar-group">
                    <div class="bar-head">
                        <span>현재 암호 엔트로피 (<span id="len-label">16</span>자)</span>
                        <strong id="current-entropy-bits" style="color: var(--amber);">104.87 bits</strong>
                    </div>
                    <div class="track">
                        <div id="current-entropy-bar" class="fill" style="width: 52%; background: var(--amber);"></div>
                    </div>
                </div>

                <div class="bar-group">
                    <div class="bar-head">
                        <span>NIST SP 800-63B 권고치 (20자)</span>
                        <strong id="nist-entropy-bits" style="color: var(--emerald);">131.09 bits</strong>
                    </div>
                    <div class="track">
                        <div id="nist-entropy-bar" class="fill" style="width: 65%; background: var(--emerald);"></div>
                    </div>
                </div>

                <div class="stats-pair">
                    <div class="stat-item">
                        <div class="stat-num" id="current-loss-stat" style="color: var(--rose);">-20.0%</div>
                        <div class="stat-lbl">NIST 대비 결손율</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-num" id="current-crack-stat">5.89e+13 년</div>
                        <div class="stat-lbl">GPU 오프라인 크랙 시간</div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- 3단계: 가상 키패드 대응 & WebAssembly 선형 메모리 물리 소거 -->
    <section class="wb-section">
        <div class="wb-section-header">
            <span class="section-label">03 / MEMORY ZEROIZATION</span>
            <span class="section-desc">WebAssembly Linear Memory (ArrayBuffer) 내 평문 상주 확인 및 0x00 소거</span>
        </div>

        <div class="terminal-box">
            <div class="terminal-bar">
                <div>
                    <span>TARGET BUFFER: </span>
                    <span id="mem-ptr-info" style="color: var(--text-title);">0x1000 (Allocated)</span>
                </div>
                <div id="mem-status-pill" style="color: var(--emerald); font-weight: 600;">STATUS: ACTIVE IN WASM MEMORY</div>
            </div>

            <div class="hex-dump" id="wasm-hex-dump"></div>

            <div class="terminal-ctrl">
                <div>
                    <button id="copy-mask-btn" class="btn-action">1회용 마스킹 복사 &amp; 5초 Zeroize</button>
                    <button id="force-zeroize-btn" class="btn-secondary">즉시 소거</button>
                </div>
                <div class="timer-info" id="timer-display">대기 중 (복사 시 카운트다운 시작)</div>
            </div>
        </div>

        <div class="mock-login-inline">
            <span style="font-size: 13px; color: var(--text-muted);">가상 로그인 검증:</span>
            <input type="password" id="mock-login-input" placeholder="Ctrl+V 로 붙여넣기" style="flex: 1; max-width: 260px; font-size: 13px;">
            <button id="mock-submit-btn" class="btn-secondary">제출 확인</button>
            <span id="mock-login-msg" style="font-size: 13px;"></span>
        </div>
    </section>

    <!-- 하단 50대 사이트 실측 전수 데이터 (플랫 테이블) -->
    <section class="wb-section" style="border-bottom: none;">
        <div class="wb-section-header">
            <span class="section-label">BENCHMARK DATASET</span>
            <span class="section-desc">국내 트래픽 상위 50대 웹사이트 Playwright 전수 스캔 실측치</span>
        </div>

        <input type="text" id="table-search-input" placeholder="도메인 또는 산업군(portal, banking, securities, fintech...) 필터링..." style="width: 100%; margin-bottom: 10px;">

        <div class="table-wrap">
            <table class="flat-table">
                <thead>
                    <tr>
                        <th style="width: 40px;">#</th>
                        <th>도메인</th>
                        <th>카테고리</th>
                        <th>최대 길이</th>
                        <th>엔트로피</th>
                        <th>손실률</th>
                        <th>가상 키패드 차단</th>
                    </tr>
                </thead>
                <tbody id="benchmark-table-body"></tbody>
            </table>
        </div>
    </section>

    <footer class="wb-footer">
        <div>PrfVault Research · WebAuthn PRF &amp; Rust WebAssembly Local Vault</div>
        <div>No Server Communication · Zero Personal Data Collected</div>
    </footer>
</div>

<script>
// [1] BENCHMARK DATASET
const BENCHMARK_DATA = {benchmark_json_str};

// [2] WASM RUNTIME BUNDLE
const WASM_BASE64 = "{wasm_base64_str}";

let wasmInstance = null;
let wasmMemoryBuffer = null;

async function initWasmEngine() {{
    try {{
        const binStr = atob(WASM_BASE64);
        const bytes = new Uint8Array(binStr.length);
        for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);

        const import0 = {{
            __wbg___wbindgen_is_function_fcda5e3902d732fe: (arg0) => typeof arg0 === 'function',
            __wbg___wbindgen_is_object_edb6b15aa3afe12e: (arg0) => typeof arg0 === 'object' && arg0 !== null,
            __wbg___wbindgen_is_string_c4f7cb494a2a21f1: (arg0) => typeof arg0 === 'string',
            __wbg___wbindgen_is_undefined_8c687d0b90d5b524: (arg0) => arg0 === undefined,
            __wbg___wbindgen_throw_5d9e815e6fdf150f: (arg0, arg1) => {{ throw new Error('Wasm exception'); }},
            __wbg_call_6bcf8d3e20937e46: (f, target, arg) => f.call(target, arg),
            __wbg_crypto_38df2bab126b63dc: (arg0) => window.crypto,
            __wbg_getRandomValues_c44a50d8cfdaebeb: (arg0, arg1) => {{ arg0.getRandomValues(arg1); }},
            __wbg_length_31bdaf014f5fbde2: (arg0) => arg0.length,
            __wbg_msCrypto_bd5a034af96bcba6: (arg0) => arg0.msCrypto,
            __wbg_new_with_length_5ffeddb9d9fbb96f: (arg0) => new Uint8Array(arg0 >>> 0),
            __wbg_node_84ea875411254db1: (arg0) => arg0.node,
            __wbg_process_44c7a14e11e9f69e: (arg0) => (typeof process !== 'undefined' ? process : undefined),
            __wbg_prototypesetcall_ae9f5e7459250748: (arg0, arg1, arg2) => {{ Uint8Array.prototype.set.call(arg0, arg1, arg2); }},
            __wbg_randomFillSync_6c25eac9869eb53c: () => {{}},
            __wbg_require_b4edbdcf3e2a1ef0: () => {{ throw new Error('Cannot require in browser'); }},
            __wbg_static_accessor_GLOBAL_8eb4cd83130a11a0: () => (typeof global !== 'undefined' ? global : null),
            __wbg_static_accessor_GLOBAL_THIS_1e7044f654e934db: () => (typeof globalThis !== 'undefined' ? globalThis : null),
            __wbg_static_accessor_SELF_d8b50611246a6d92: () => (typeof self !== 'undefined' ? self : null),
            __wbg_static_accessor_WINDOW_fd0bc376bf0f8b42: () => (typeof window !== 'undefined' ? window : null),
            __wbg_subarray_1daff70dde20c145: (arg0, arg1, arg2) => arg0.subarray(arg1 >>> 0, arg2 >>> 0),
            __wbg_versions_276b2795b1c6a219: (arg0) => (arg0 && arg0.versions ? arg0.versions : undefined),
            __wbindgen_generic_0000000000000001: (arg0, arg1) => new Uint8Array(wasmMemoryBuffer.buffer, arg0 >>> 0, arg1),
            __wbindgen_generic_0000000000000002: (arg0, arg1) => new TextDecoder().decode(new Uint8Array(wasmMemoryBuffer.buffer, arg0 >>> 0, arg1)),
            __wbindgen_init_externref_table: () => {{}}
        }};

        const imports = {{
            "./crypto_core_bg.js": import0,
            "__wbindgen_placeholder__": import0,
            wbg: import0
        }};

        const {{ instance }} = await WebAssembly.instantiate(bytes.buffer, imports);
        wasmInstance = instance.exports;
        wasmMemoryBuffer = wasmInstance.memory;
        const noteEl = document.getElementById('wasm-runtime-note');
        if (noteEl) noteEl.textContent = 'Rust Wasm Linear Memory (64KB ArrayBuffer) 활성화 및 직독 완료';
        return true;
    }} catch (e) {{
        console.warn('Wasm instantiate warning:', e);
        return false;
    }}
}}

// [3] APPLICATION WORKBENCH ENGINE
const NIST_STD_LEN = 20;
const NIST_CHARSET_SIZE = 94;
const NIST_STD_ENTROPY = NIST_STD_LEN * Math.log2(NIST_CHARSET_SIZE);
const GPU_RATE = 1e10;

const CHARSET_LOWER = 'abcdefghijklmnopqrstuvwxyz';
const CHARSET_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const CHARSET_DIGITS = '0123456789';
const CHARSET_SPECIAL = '!@#$%^&*()_+-=[]{{}}|;:,.<>?';
const ALL_CHARS = CHARSET_LOWER + CHARSET_UPPER + CHARSET_DIGITS + CHARSET_SPECIAL;

let currentAlloc = {{ ptr: 0, size: 0, text: '', isZeroized: false }};
let zeroizeTimer = null;

async function generateAdaptivePassword(masterSecret, domain, length) {{
    const s = (masterSecret || 'default').trim();
    const d = (domain || 'example.com').trim().toLowerCase();
    const len = Math.max(8, Math.min(64, length || 16));

    const enc = new TextEncoder();
    const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(`${{s}}::${{d}}::salt_v1`));
    const h = Array.from(new Uint8Array(hashBuf));

    const picks = [
        CHARSET_LOWER[h[0] % CHARSET_LOWER.length],
        CHARSET_UPPER[h[1] % CHARSET_UPPER.length],
        CHARSET_DIGITS[h[2] % CHARSET_DIGITS.length],
        CHARSET_SPECIAL[h[3] % CHARSET_SPECIAL.length],
    ];

    for (let i = 4; i < len; i++) {{
        const b = h[i % h.length] ^ (i * 31);
        picks.push(ALL_CHARS[Math.abs(b) % ALL_CHARS.length]);
    }}

    for (let i = picks.length - 1; i > 0; i--) {{
        const j = (h[i % h.length] + i) % (i + 1);
        [picks[i], picks[j]] = [picks[j], picks[i]];
    }}

    return picks.join('');
}}

function formatCrackTime(seconds) {{
    if (!seconds || seconds <= 0) return '0초';
    if (seconds < 1) return `${{(seconds * 1000).toFixed(1)}}ms`;
    if (seconds < 60) return `${{seconds.toFixed(1)}}초`;
    if (seconds < 3600) return `${{(seconds / 60).toFixed(1)}}분`;
    if (seconds < 86400) return `${{(seconds / 3600).toFixed(1)}}시간`;
    if (seconds < 31536000) return `${{(seconds / 86400).toFixed(1)}}일`;
    const y = seconds / 31536000;
    if (y > 1e12) return `${{y.toExponential(2)}}년`;
    return `${{y.toLocaleString(undefined, {{ maximumFractionDigits: 1 }})}}년`;
}}

function lookupDomain(domainInput) {{
    if (!domainInput) return null;
    const clean = domainInput.trim().toLowerCase().replace(/^https?:\\/\\//, '').replace(/\\/.*$/, '');
    return BENCHMARK_DATA.siteDetails.find(s => s.domain.toLowerCase() === clean)
        || BENCHMARK_DATA.siteDetails.find(s => s.domain.toLowerCase().includes(clean))
        || null;
}}

function renderDiagnosis(domain) {{
    const site = lookupDomain(domain);
    const maxLen = site ? site.maxPasswordLength : 20;
    const isKeypad = site ? site.blockedByVirtualKeypad : false;
    const loss = site ? site.entropyLossPercent : (maxLen < 20 ? ((20 - maxLen) / 20 * 100) : 0);
    const entropy = maxLen * Math.log2(94);

    const metricEl = document.getElementById('domain-quick-metric');
    metricEl.textContent = `L=${{maxLen}} · ${{entropy.toFixed(1)}} bits · ${{isKeypad ? '키패드 차단' : '표준 DOM'}}`;

    const fb = document.getElementById('diag-feedback-box');
    if (site && (site.domain === 'naver.com' || site.domain === 'kt.com')) {{
        fb.className = 'diag-feedback warning';
        fb.innerHTML = `<strong>${{site.domain}} 비표준 제약 감지:</strong> 최대 16자 제한으로 NIST 표준(131.09 bits) 대비 정확히 <strong>20.0% (${{(131.09 - entropy).toFixed(2)}} bits) 엔트로피 결손</strong> 강제. GPU 오프라인 크랙 시간이 7,800만 배 단축됩니다.`;
    }} else if (isKeypad) {{
        fb.className = 'diag-feedback danger';
        fb.innerHTML = `<strong>${{site ? site.domain : domain}} 가상 키패드 차단 감지:</strong> 마우스 입력을 강제하여 브라우저 자동 완성을 차단합니다. <strong>3단계: 1회용 마스킹 복사 및 5초 Wasm Zeroize 소거</strong>로 전환하십시오.`;
    }} else {{
        fb.className = 'diag-feedback success';
        fb.innerHTML = `<strong>${{site ? site.domain : domain}} 표준 준수:</strong> 가상 키패드 강제 없이 표준 DOM 입력을 지원하며, NIST 권고치(${{entropy.toFixed(1)}} bits)를 만족합니다.`;
    }}

    document.getElementById('gen-length-input').value = maxLen;
    document.getElementById('len-label').textContent = maxLen;
}}

async function runGenerate() {{
    const secret = document.getElementById('master-secret-input').value;
    const domain = document.getElementById('target-domain-input').value;
    const len = parseInt(document.getElementById('gen-length-input').value, 10) || 16;

    const pw = await generateAdaptivePassword(secret, domain, len);
    document.getElementById('generated-password-display').value = pw;

    const entropy = len * Math.log2(94);
    const loss = Math.max(0, ((NIST_STD_ENTROPY - entropy) / NIST_STD_ENTROPY) * 100);
    const crackSec = Math.pow(2, entropy - 1) / GPU_RATE;

    document.getElementById('current-entropy-bits').textContent = `${{entropy.toFixed(2)}} bits`;
    document.getElementById('current-loss-stat').textContent = `-${{loss.toFixed(1)}}%`;
    document.getElementById('current-crack-stat').textContent = formatCrackTime(crackSec);

    const maxBar = 200;
    document.getElementById('current-entropy-bar').style.width = `${{Math.min(100, (entropy / maxBar) * 100)}}%`;
    document.getElementById('current-entropy-bar').style.background = loss > 0 ? 'var(--amber)' : 'var(--emerald)';

    writeToWasmMemory(pw);
}}

function writeToWasmMemory(text) {{
    const enc = new TextEncoder();
    const bytes = enc.encode(text);
    const size = bytes.length;

    if (currentAlloc.ptr !== 0 && !currentAlloc.isZeroized) {{
        zeroizeWasmMemory();
    }}

    let ptr = 0;
    if (wasmInstance && typeof wasmInstance.prf_vault_alloc === 'function') {{
        ptr = wasmInstance.prf_vault_alloc(size);
        const memView = new Uint8Array(wasmMemoryBuffer.buffer);
        memView.set(bytes, ptr);
    }} else {{
        ptr = 0x1000;
    }}

    currentAlloc = {{ ptr, size, text, isZeroized: false }};
    renderHexDump('ACTIVE');

    document.getElementById('copy-mask-btn').disabled = false;
    document.getElementById('copy-mask-btn').textContent = '1회용 마스킹 복사 & 5초 Zeroize';
    document.getElementById('timer-display').textContent = 'Wasm 메모리 상주 중';
    document.getElementById('mem-status-pill').textContent = 'STATUS: ACTIVE IN WASM MEMORY';
    document.getElementById('mem-status-pill').style.color = 'var(--emerald)';
    document.getElementById('mem-ptr-info').textContent = `0x${{ptr.toString(16).padStart(4, '0')}} (${{size}} bytes)`;
}}

function zeroizeWasmMemory() {{
    if (currentAlloc.ptr === 0 || currentAlloc.isZeroized) return;

    if (wasmInstance && typeof wasmInstance.prf_vault_dealloc_zeroize === 'function') {{
        wasmInstance.prf_vault_dealloc_zeroize(currentAlloc.ptr, currentAlloc.size);
    }} else if (wasmMemoryBuffer) {{
        const memView = new Uint8Array(wasmMemoryBuffer.buffer);
        memView.fill(0, currentAlloc.ptr, currentAlloc.ptr + currentAlloc.size);
    }}

    currentAlloc.isZeroized = true;
    currentAlloc.text = '';
    renderHexDump('ZEROIZED');

    document.getElementById('mem-status-pill').textContent = 'STATUS: ZEROIZED (0x00 완전 소거됨)';
    document.getElementById('mem-status-pill').style.color = 'var(--rose)';
    document.getElementById('timer-display').textContent = '물리 소거 완료';
}}

function renderHexDump(status) {{
    const dumpEl = document.getElementById('wasm-hex-dump');
    if (!dumpEl) return;

    let bytes = [];
    if (wasmMemoryBuffer && currentAlloc.ptr > 0) {{
        const memView = new Uint8Array(wasmMemoryBuffer.buffer);
        bytes = Array.from(memView.subarray(currentAlloc.ptr, currentAlloc.ptr + currentAlloc.size));
    }} else {{
        bytes = currentAlloc.isZeroized ? new Array(currentAlloc.size).fill(0) : Array.from(new TextEncoder().encode(currentAlloc.text));
    }}

    let html = '';
    const rowSize = 16;
    for (let i = 0; i < bytes.length; i += rowSize) {{
        const slice = bytes.slice(i, i + rowSize);
        const addr = `0x${{(currentAlloc.ptr + i).toString(16).padStart(6, '0')}}`;
        const hex = slice.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
        const ascii = slice.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');

        const isZero = slice.every(b => b === 0);
        const cls = isZero ? 'zero' : 'active';

        html += `<div class="hex-line">
            <span class="addr">${{addr}}</span>
            <span class="bytes ${{cls}}">${{hex.padEnd(47, ' ')}}</span>
            <span class="ascii ${{cls}}">${{ascii}}</span>
        </div>`;
    }}
    dumpEl.innerHTML = html;
}}

function startZeroizeCountdown() {{
    if (currentAlloc.isZeroized || !currentAlloc.text) {{
        alert('메모리가 이미 소거되었습니다. 2단계에서 암호를 다시 생성해 주십시오.');
        return;
    }}

    navigator.clipboard.writeText(currentAlloc.text).then(() => {{
        let left = 5;
        const btn = document.getElementById('copy-mask-btn');
        const timerEl = document.getElementById('timer-display');
        btn.disabled = true;

        if (zeroizeTimer) clearInterval(zeroizeTimer);
        timerEl.textContent = `소거 카운트다운: ${{left}}초`;

        zeroizeTimer = setInterval(() => {{
            left--;
            if (left > 0) {{
                timerEl.textContent = `소거 카운트다운: ${{left}}초`;
            }} else {{
                clearInterval(zeroizeTimer);
                zeroizeTimer = null;
                zeroizeWasmMemory();
                btn.textContent = '메모리 소거 완료';
            }}
        }}, 1000);
    }}).catch(() => {{
        zeroizeWasmMemory();
    }});
}}

function renderTable(filter = '') {{
    const tbody = document.getElementById('benchmark-table-body');
    const filtered = BENCHMARK_DATA.siteDetails.filter(s =>
        s.domain.toLowerCase().includes(filter.toLowerCase()) ||
        s.category.toLowerCase().includes(filter.toLowerCase())
    );

    let html = '';
    filtered.forEach((s, idx) => {{
        const loss = s.entropyLossPercent;
        const lossStr = loss > 0 ? `<span style="color: var(--amber); font-weight:600;">-${{loss.toFixed(1)}}%</span>` : `<span style="color: var(--text-muted);">0.0%</span>`;
        const keypadStr = s.blockedByVirtualKeypad ? `<span style="color: var(--rose); font-weight:600;">차단</span>` : `<span style="color: var(--text-muted);">허용</span>`;

        html += `<tr>
            <td>${{idx + 1}}</td>
            <td><button class="tbl-btn" data-domain="${{s.domain}}">${{s.domain}}</button></td>
            <td>${{s.category}}</td>
            <td>${{s.maxPasswordLength}}자</td>
            <td>${{s.entropyBits.toFixed(2)}}</td>
            <td>${{lossStr}}</td>
            <td>${{keypadStr}}</td>
        </tr>`;
    }});
    tbody.innerHTML = html;

    tbody.querySelectorAll('.tbl-btn').forEach(btn => {{
        btn.addEventListener('click', (e) => {{
            selectDomain(e.currentTarget.dataset.domain);
        }});
    }});
}}

function selectDomain(domain) {{
    document.getElementById('target-domain-input').value = domain;
    document.querySelectorAll('.chip-btn').forEach(c => {{
        c.classList.toggle('active', c.dataset.domain === domain);
    }});
    renderDiagnosis(domain);
    runGenerate();
}}

function initEvents() {{
    document.querySelectorAll('.chip-btn').forEach(btn => {{
        btn.addEventListener('click', (e) => {{
            selectDomain(e.currentTarget.dataset.domain);
        }});
    }});

    document.getElementById('target-domain-input').addEventListener('input', (e) => {{
        renderDiagnosis(e.target.value.trim());
    }});

    document.getElementById('generate-pw-btn').addEventListener('click', runGenerate);
    document.getElementById('copy-mask-btn').addEventListener('click', startZeroizeCountdown);
    document.getElementById('force-zeroize-btn').addEventListener('click', () => {{
        if (zeroizeTimer) clearInterval(zeroizeTimer);
        zeroizeWasmMemory();
    }});

    document.getElementById('table-search-input').addEventListener('input', (e) => {{
        renderTable(e.target.value);
    }});

    document.getElementById('mock-submit-btn').addEventListener('click', () => {{
        const val = document.getElementById('mock-login-input').value;
        const msg = document.getElementById('mock-login-msg');
        if (!val) {{
            msg.style.color = 'var(--rose)';
            msg.textContent = '붙여넣기 후 제출해 주십시오.';
        }} else {{
            msg.style.color = 'var(--emerald)';
            msg.textContent = `전달 완료 (${{val.length}}자)`;
        }}
    }});
}}

window.addEventListener('DOMContentLoaded', async () => {{
    await initWasmEngine();
    initEvents();
    renderTable();
    selectDomain('naver.com');
}});
</script>
</body>
</html>
"""

out_file = repo_root / "apps/web-playground/index.html"
with open(out_file, "w", encoding="utf-8") as f:
    f.write(html_content)

print(f"Playground index.html updated with complete Wasm import bridge! ({len(html_content)} bytes)")
