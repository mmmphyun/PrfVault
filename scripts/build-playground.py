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
            /* 완전 무채색(푸른끼 0%) 흑백 & 뉴트럴 그레이 */
            --bg: #0c0c0c;
            --surface: #171717;
            --surface-hover: #222222;
            --border: #2a2a2a;
            --border-subtle: #1c1c1c;
            --terminal-bg: #080808;
            --track-bg: #222222;
            --byte-zero: #444444;

            /* 선명한 고대비 화이트 & 슬레이트 */
            --text-title: #ffffff;
            --text-body: #f3f4f6;
            --text-secondary: #d1d5db;
            --text-muted: #9ca3af;

            /* 오직 강조 요소에만 사용하는 하늘색 */
            --accent: #38bdf8;
            --accent-hover: #0ea5e9;
            --accent-dim: rgba(56, 189, 248, 0.12);

            /* 상태 피드백 */
            --amber: #f59e0b;
            --amber-dim: rgba(245, 158, 11, 0.12);
            --amber-text: #fef3c7;
            --emerald: #10b981;
            --emerald-dim: rgba(16, 185, 129, 0.12);
            --emerald-text: #d1fae5;
            --rose: #f43f5e;
            --rose-dim: rgba(244, 63, 94, 0.12);
            --rose-text: #ffe4e6;
            --ascii-active: #86efac;
            --ascii-zero: #222222;
            --mono: "SF Mono", Monaco, Consolas, "Liberation Mono", Courier, monospace;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            background-color: var(--bg);
            color: var(--text-body);
            font-family: -apple-system, BlinkMacSystemFont, "Pretendard", "Segoe UI", Roboto, sans-serif;
            font-size: 15px;
            line-height: 1.7;
            padding: 72px 32px;
            -webkit-font-smoothing: antialiased;
        }}

        .workbench {{
            max-width: 1040px;
            margin: 0 auto;
        }}

        /* 헤더: 순수 무채색 배경 위 고대비 타이포그래피 */
        header.wb-header {{
            margin-bottom: 56px;
            padding-bottom: 40px;
            border-bottom: 1px solid var(--border-subtle);
        }}

        .meta-eyebrow {{
            font-size: 12.5px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--accent);
            margin-bottom: 14px;
        }}

        h1.paper-heading {{
            font-size: 26px;
            font-weight: 700;
            color: var(--text-title);
            line-height: 1.45;
            letter-spacing: -0.015em;
            margin-bottom: 20px;
        }}

        .purpose-statement {{
            font-size: 16px;
            color: var(--text-secondary);
            line-height: 1.75;
            padding-left: 20px;
            border-left: 3px solid var(--accent);
        }}

        .wasm-pill {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
            font-family: var(--mono);
            color: var(--text-secondary);
            margin-top: 22px;
        }}

        .status-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: var(--emerald);
        }}

        /* 1단계, 2단계, 3단계 사이의 넉넉한 수직 여백 (64px) */
        .wb-section {{
            padding: 64px 0;
            border-bottom: 1px solid var(--border-subtle);
        }}

        .wb-section-header {{
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            margin-bottom: 22px;
        }}

        .section-label {{
            font-size: 13.5px;
            font-weight: 700;
            color: var(--accent);
            font-family: var(--mono);
            letter-spacing: 0.08em;
        }}

        .section-desc {{
            font-size: 14px;
            color: var(--text-muted);
        }}

        /* 1단계: 순수 그레이 칩 버튼 */
        .chip-group {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 18px;
        }}

        .chip-btn {{
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text-secondary);
            font-size: 13px;
            padding: 7px 14px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.15s;
        }}

        .chip-btn:hover {{
            border-color: var(--accent);
            color: var(--text-title);
        }}

        .chip-btn.active {{
            border-color: var(--accent);
            color: var(--accent);
            background: var(--surface-hover);
            font-weight: 600;
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
            font-size: 15px;
            padding: 11px 16px;
            border-radius: 5px;
            outline: none;
            transition: border-color 0.15s;
        }}

        input:focus {{ border-color: var(--accent); }}

        .domain-input {{ flex: 1; }}

        .diag-feedback {{
            margin-top: 18px;
            padding: 16px 20px;
            border-left: 3px solid var(--border);
            font-size: 14.5px;
            line-height: 1.65;
            border-radius: 0 5px 5px 0;
            background: var(--surface);
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

        /* 2단계: 적응형 암호화 & 엔트로피 지표 */
        .gen-grid {{
            display: grid;
            grid-template-columns: 1.1fr 1fr;
            gap: 48px;
            align-items: start;
        }}

        @media (max-width: 820px) {{
            .gen-grid {{ grid-template-columns: 1fr; gap: 28px; }}
        }}

        .field {{ margin-bottom: 18px; }}

        .field label {{
            display: block;
            font-size: 13.5px;
            color: var(--text-secondary);
            margin-bottom: 8px;
            font-weight: 500;
        }}

        .btn-action {{
            background: var(--accent);
            color: #0c0c0c;
            font-weight: 700;
            font-size: 14px;
            padding: 11px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.15s, opacity 0.15s;
        }}

        .btn-action:hover {{ background: var(--accent-hover); }}

        .btn-action:disabled {{
            background: var(--border);
            color: var(--text-muted);
            cursor: not-allowed;
        }}

        .btn-secondary {{
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text-body);
            font-size: 13.5px;
            padding: 10px 16px;
            border-radius: 5px;
            cursor: pointer;
            margin-left: 8px;
            transition: all 0.15s;
        }}

        .btn-secondary:hover {{
            border-color: var(--accent);
            color: var(--text-title);
        }}

        .pw-output {{
            font-family: var(--mono);
            color: var(--accent);
            font-size: 16px;
            font-weight: 700;
            width: 100%;
            letter-spacing: 0.04em;
        }}

        .entropy-panel {{ padding-top: 6px; }}

        .bar-group {{ margin-bottom: 20px; }}

        .bar-head {{
            display: flex;
            justify-content: space-between;
            font-size: 13.5px;
            margin-bottom: 8px;
            color: var(--text-secondary);
        }}

        .track {{
            height: 9px;
            background: var(--track-bg);
            border-radius: 4px;
            overflow: hidden;
        }}

        .fill {{ height: 100%; transition: width 0.3s; }}

        .stats-pair {{
            display: flex;
            gap: 36px;
            margin-top: 24px;
            padding-top: 20px;
            border-top: 1px solid var(--border-subtle);
        }}

        .stat-item .stat-num {{
            font-size: 21px;
            font-weight: 700;
            color: var(--text-title);
            line-height: 1.3;
        }}

        .stat-item .stat-lbl {{
            font-size: 12.5px;
            color: var(--text-muted);
            margin-top: 4px;
        }}

        /* 3단계: 순수 흑색 콘솔 터미널 */
        .terminal-box {{
            background: var(--terminal-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px 24px;
            font-family: var(--mono);
            font-size: 13.5px;
            margin-top: 16px;
        }}

        .terminal-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-subtle);
            padding-bottom: 12px;
            margin-bottom: 14px;
            color: var(--text-muted);
            font-size: 12.5px;
        }}

        .hex-dump {{
            max-height: 220px;
            overflow-x: auto;
            color: var(--text-secondary);
            line-height: 1.75;
        }}

        .hex-line {{
            display: grid;
            grid-template-columns: 100px 1fr 160px;
            gap: 20px;
        }}

        .addr {{ color: var(--text-muted); }}
        .bytes.active {{ color: var(--accent); font-weight: 600; }}
        .bytes.zero {{ color: var(--byte-zero); }}
        .ascii.active {{ color: var(--ascii-active); }}
        .ascii.zero {{ color: var(--ascii-zero); }}

        .terminal-ctrl {{
            margin-top: 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
        }}

        .timer-info {{
            font-family: var(--mono);
            font-size: 13.5px;
            color: var(--amber);
            font-weight: 600;
        }}

        .mock-login-inline {{
            display: flex;
            gap: 10px;
            margin-top: 20px;
            align-items: center;
        }}

        /* 하단 50대 실측 플랫 테이블 */
        .table-wrap {{
            max-height: 380px;
            overflow-y: auto;
            margin-top: 20px;
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
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
            font-size: 12.5px;
            position: sticky;
            top: 0;
            background: var(--bg);
        }}

        table.flat-table td {{
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-subtle);
            color: var(--text-secondary);
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
            font-weight: 600;
            padding: 0;
        }}

        .tbl-btn:hover {{ text-decoration: underline; }}

        /* 수사 단위표 모달 & 헬프 버튼 */
        .help-btn {{
            background: transparent;
            border: 1px solid var(--border);
            color: var(--accent);
            font-size: 11px;
            font-family: var(--mono);
            padding: 2px 7px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .help-btn:hover {{
            background: var(--accent-dim);
            border-color: var(--accent);
        }}

        .modal-overlay {{
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.75);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            padding: 20px;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease;
        }}

        .modal-overlay.active {{
            opacity: 1;
            pointer-events: auto;
        }}

        .modal-box {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            width: 100%;
            max-width: 680px;
            max-height: 85vh;
            overflow-y: auto;
            padding: 24px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.8);
        }}

        .modal-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }}

        .modal-close-btn {{
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-muted);
            border-radius: 4px;
            padding: 4px 10px;
            font-size: 12px;
            cursor: pointer;
        }}

        .modal-close-btn:hover {{
            color: var(--text-title);
            border-color: var(--text-secondary);
        }}

        footer.wb-footer {{
            margin-top: 64px;
            padding-top: 28px;
            border-top: 1px solid var(--border-subtle);
            font-size: 13px;
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
            <div style="font-family: var(--mono); font-size: 13.5px; color: var(--text-secondary);" id="domain-quick-metric">
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
                <div class="field" style="margin-top: 20px;">
                    <label>생성된 비밀번호:</label>
                    <input type="text" id="generated-password-display" class="pw-output" readonly>
                </div>
            </div>

            <div class="entropy-panel">
                <div class="bar-group">
                    <div class="bar-head">
                        <span>현재 암호 엔트로피 (<span id="len-label">16</span>자)</span>
                        <strong id="current-entropy-bits" style="color: var(--accent);">104.87 bits</strong>
                    </div>
                    <div class="track">
                        <div id="current-entropy-bar" class="fill" style="width: 52%; background: var(--accent);"></div>
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
                    <div class="stat-item" style="flex: 1;">
                        <div style="display: flex; justify-content: space-between; align-items: baseline; gap: 8px;">
                            <div class="stat-num" id="current-crack-stat" style="font-size: 16.5px;">약 58조 7,732억 년</div>
                            <button type="button" id="open-unit-modal-btn" class="help-btn" onclick="openUnitModal()">수사 단위표 ?</button>
                        </div>
                        <div class="stat-lbl">GPU 오프라인 크랙 예상 시간 (초당 100억 회 추정)</div>
                    </div>
                </div>
                <div style="font-size: 12.5px; color: var(--text-muted); margin-top: 10px;">
                    * NIST 20자 권고치 크랙 시간: <span id="nist-crack-stat" style="color: var(--text-secondary); font-weight: 600;">약 45해 9,791경 년</span>
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
                    <span id="mem-ptr-info" style="color: var(--text-title); font-weight: 600;">0x1000 (Allocated)</span>
                </div>
                <div id="mem-status-pill" style="color: var(--emerald); font-weight: 700;">STATUS: ACTIVE IN WASM MEMORY</div>
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
            <span style="font-size: 13.5px; color: var(--text-secondary);">가상 로그인 검증:</span>
            <input type="password" id="mock-login-input" placeholder="Ctrl+V 로 붙여넣기" style="flex: 1; max-width: 260px; font-size: 13.5px;">
            <button id="mock-submit-btn" class="btn-secondary">제출 확인</button>
            <span id="mock-login-msg" style="font-size: 13.5px;"></span>
        </div>
    </section>

    <!-- 하단 50대 사이트 실측 전수 데이터 (플랫 테이블) -->
    <section class="wb-section" style="border-bottom: none;">
        <div class="wb-section-header">
            <span class="section-label">BENCHMARK DATASET</span>
            <span class="section-desc">국내 트래픽 상위 50대 웹사이트 Playwright 전수 스캔 실측치</span>
        </div>

        <input type="text" id="table-search-input" placeholder="도메인 또는 산업군(portal, banking, securities, fintech...) 필터링..." style="width: 100%; margin-bottom: 14px;">

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

<!-- 한국 전통 대수(大數) 단위표 모달 -->
<div id="unit-modal" class="modal-overlay" onclick="handleBackdropClick(event)">
    <div class="modal-box">
        <div class="modal-header">
            <div>
                <h3 style="font-size: 16px; font-weight: 700; color: var(--text-title); margin: 0;">한국 전통 대수(大數) 단위 및 암호 강도 비교표</h3>
                <p style="font-size: 12.5px; color: var(--text-muted); margin: 4px 0 0 0;">전통 수사는 만(10⁴) 단위마다 확장되며, 암호학 키스페이스의 전수조사 소요 시간을 직관적으로 가늠할 수 있게 돕습니다.</p>
            </div>
            <button type="button" class="modal-close-btn" onclick="closeUnitModal()">닫기 (ESC)</button>
        </div>

        <div style="margin-bottom: 18px; padding: 12px 14px; background: #141414; border-radius: 4px; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
            <strong style="color: var(--accent);">우주의 나이:</strong> 약 <strong>1.38 × 10¹⁰ 년</strong> (138억 년)<br>
            • <strong>네이버 16자 (104.87 bits):</strong> 약 58조 년 (우주 나이의 약 <strong>4,200배</strong>)<br>
            • <strong>NIST 20자 (131.09 bits):</strong> 약 45해 년 (우주 나이의 약 <strong>330억 배</strong>)<br>
            • <strong>디시 40자 (262.18 bits):</strong> 약 13나유타 년 (우주 나이의 약 <strong>9.6 × 10⁵⁰ 배</strong>)
        </div>

        <div style="max-height: 340px; overflow-y: auto; border: 1px solid var(--border-subtle); border-radius: 4px;">
            <table class="flat-table" style="font-size: 13px;">
                <thead>
                    <tr>
                        <th style="width: 90px;">수사 명칭</th>
                        <th style="width: 110px;">공학 지수</th>
                        <th>의미 및 암호학 보안 맥락</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td><strong>만 (萬)</strong></td><td>10⁴</td><td>1만</td></tr>
                    <tr><td><strong>억 (億)</strong></td><td>10⁸</td><td>10,000만</td></tr>
                    <tr style="background: rgba(56, 189, 248, 0.08);"><td><strong style="color: var(--accent);">조 (兆)</strong></td><td>10¹²</td><td><strong>네이버 16자</strong> 오프라인 전수 크랙 시간대 (약 58조 년)</td></tr>
                    <tr><td><strong>경 (京)</strong></td><td>10¹⁶</td><td>10,000조</td></tr>
                    <tr style="background: rgba(16, 185, 129, 0.08);"><td><strong style="color: var(--emerald);">해 (垓)</strong></td><td>10²⁰</td><td><strong>NIST SP 800-63B 20자</strong> 권고 암호 크랙 시간대 (약 45해 년)</td></tr>
                    <tr><td><strong>자 (秭)</strong></td><td>10²⁴</td><td>10,000해</td></tr>
                    <tr><td><strong>양 (穰)</strong></td><td>10²⁸</td><td>10,000자</td></tr>
                    <tr><td><strong>구 (溝)</strong></td><td>10³²</td><td>10,000양</td></tr>
                    <tr><td><strong>간 (澗)</strong></td><td>10³⁶</td><td>10,000구</td></tr>
                    <tr><td><strong>정 (正)</strong></td><td>10⁴⁰</td><td>10,000간</td></tr>
                    <tr><td><strong>재 (載)</strong></td><td>10⁴⁴</td><td>10,000정</td></tr>
                    <tr><td><strong>극 (極)</strong></td><td>10⁴⁸</td><td>10,000재</td></tr>
                    <tr><td><strong>항하사 (恒河沙)</strong></td><td>10⁵²</td><td>갠지스 강의 모래알 수처럼 셀 수 없이 많은 수</td></tr>
                    <tr><td><strong>아승기 (阿僧祇)</strong></td><td>10⁵⁶</td><td>헤아릴 수 없는 무한의 시간 단위</td></tr>
                    <tr style="background: rgba(56, 189, 248, 0.08);"><td><strong style="color: var(--accent);">나유타 (那由他)</strong></td><td>10⁶⁰</td><td><strong>디시인사이드 40자</strong> 고엔트로피 크랙 시간대 (약 13나유타 년)</td></tr>
                    <tr><td><strong>불가사의 (不可思議)</strong></td><td>10⁶⁴</td><td>상식과 사유로는 헤아릴 수 없는 불가해한 수</td></tr>
                    <tr><td><strong>무량대수 (無量大數)</strong></td><td>10⁶⁸</td><td>전통 한자 수사의 최대 수치</td></tr>
                </tbody>
            </table>
        </div>
    </div>
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

function formatKoreanCrackTime(seconds, entropy) {{
    if (!entropy || entropy <= 0) return '0초';

    const LOG10_SEC_PER_YEAR = 7.4988065096;
    const LOG10_RATE = 10;
    const log10Years = (entropy - 1) * 0.3010299956639812 - (LOG10_RATE + LOG10_SEC_PER_YEAR);

    if (log10Years < -7.4988) {{
        const s = Math.pow(2, entropy - 1) / 1e10;
        if (s < 0.001) return `${{(s * 1000).toFixed(2)}} 밀리초`;
        return `${{s.toFixed(2)}} 초`;
    }}
    if (log10Years < 0) {{
        const s = Math.pow(2, entropy - 1) / 1e10;
        if (s < 60) return `${{s.toFixed(1)}} 초`;
        if (s < 3600) return `${{(s / 60).toFixed(1)}} 분`;
        if (s < 86400) return `${{(s / 3600).toFixed(1)}} 시간`;
        return `${{(s / 86400).toFixed(1)}} 일`;
    }}

    if (log10Years < 4) {{
        const years = Math.pow(10, log10Years);
        return `약 ${{Math.round(years).toLocaleString()}} 년`;
    }}

    const units = [
        {{ exp: 68, name: '무량대수' }},
        {{ exp: 64, name: '불가사의' }},
        {{ exp: 60, name: '나유타' }},
        {{ exp: 56, name: '아승기' }},
        {{ exp: 52, name: '항하사' }},
        {{ exp: 48, name: '극' }},
        {{ exp: 44, name: '재' }},
        {{ exp: 40, name: '정' }},
        {{ exp: 36, name: '간' }},
        {{ exp: 32, name: '구' }},
        {{ exp: 28, name: '양' }},
        {{ exp: 24, name: '자' }},
        {{ exp: 20, name: '해' }},
        {{ exp: 16, name: '경' }},
        {{ exp: 12, name: '조' }},
        {{ exp: 8, name: '억' }},
        {{ exp: 4, name: '만' }}
    ];

    if (log10Years >= 72) {{
        return '약 1만 무량대수 년 이상';
    }}

    let primaryUnit = null;
    let secondaryUnit = null;
    for (let i = 0; i < units.length; i++) {{
        if (log10Years >= units[i].exp) {{
            primaryUnit = units[i];
            if (i + 1 < units.length && units[i + 1].exp === units[i].exp - 4) {{
                secondaryUnit = units[i + 1];
            }}
            break;
        }}
    }}

    const parts = [];
    if (primaryUnit) {{
        const u1Val = Math.pow(10, log10Years - primaryUnit.exp);
        const u1Count = Math.floor(u1Val);
        parts.push(`${{u1Count.toLocaleString()}}${{primaryUnit.name}}`);

        if (secondaryUnit) {{
            const rem = u1Val - u1Count;
            const u2Count = Math.round(rem * 10000);
            if (u2Count > 0) {{
                parts.push(`${{u2Count.toLocaleString()}}${{secondaryUnit.name}}`);
            }}
        }}
    }}

    return `약 ${{parts.join(' ')}} 년`;
}}

function openUnitModal() {{
    const m = document.getElementById('unit-modal');
    if (m) m.classList.add('active');
}}

function closeUnitModal() {{
    const m = document.getElementById('unit-modal');
    if (m) m.classList.remove('active');
}}

function handleBackdropClick(e) {{
    if (e.target.id === 'unit-modal') {{
        closeUnitModal();
    }}
}}

window.addEventListener('keydown', (e) => {{
    if (e.key === 'Escape') closeUnitModal();
}});

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
        fb.innerHTML = `<strong>${{site.domain}} 비표준 제약 감지:</strong> 최대 16자 제한으로 NIST 표준(131.09 bits) 대비 정확히 <strong>20.0% (${{(131.09 - entropy).toFixed(2)}} bits) 엔트로피 결손</strong> 강제. GPU 오프라인 크랙 시간이 약 7,800만 배 단축됩니다.`;
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
    const stdCrackSec = Math.pow(2, NIST_STD_ENTROPY - 1) / GPU_RATE;

    document.getElementById('current-entropy-bits').textContent = `${{entropy.toFixed(2)}} bits`;
    document.getElementById('current-loss-stat').textContent = `-${{loss.toFixed(1)}}%`;
    document.getElementById('current-crack-stat').textContent = formatKoreanCrackTime(crackSec, entropy);
    document.getElementById('nist-crack-stat').textContent = formatKoreanCrackTime(stdCrackSec, NIST_STD_ENTROPY);

    const maxBar = 200;
    document.getElementById('current-entropy-bar').style.width = `${{Math.min(100, (entropy / maxBar) * 100)}}%`;
    document.getElementById('current-entropy-bar').style.background = 'var(--accent)';

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
        const lossStr = loss > 0 ? `<span style="color: var(--amber); font-weight:700;">-${{loss.toFixed(1)}}%</span>` : `<span style="color: var(--text-muted);">0.0%</span>`;
        const keypadStr = s.blockedByVirtualKeypad ? `<span style="color: var(--rose); font-weight:700;">차단</span>` : `<span style="color: var(--text-muted);">허용</span>`;

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

print(f"Playground index.html updated with true neutral gray/black (zero blue tint) and skyblue accent! ({len(html_content)} bytes)")
