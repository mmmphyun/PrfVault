const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const DEBUG_PORT = 9222;
const TARGET_URL = 'http://localhost:3000';

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', reject);
  });
}

class CdpClient {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.id = 1;
    this.callbacks = new Map();
    this.eventListeners = new Map();
  }

  async connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.wsUrl);
      this.ws.onopen = () => resolve();
      this.ws.onerror = (err) => reject(err);
      this.ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.id && this.callbacks.has(msg.id)) {
          const { resolve, reject } = this.callbacks.get(msg.id);
          this.callbacks.delete(msg.id);
          if (msg.error) {
            reject(new Error(msg.error.message || JSON.stringify(msg.error)));
          } else {
            resolve(msg.result);
          }
        } else if (msg.method) {
          const listeners = this.eventListeners.get(msg.method) || [];
          listeners.forEach((fn) => fn(msg.params));
        }
      };
    });
  }

  send(method, params = {}, sessionId = undefined) {
    return new Promise((resolve, reject) => {
      const id = this.id++;
      this.callbacks.set(id, { resolve, reject });
      const payload = { id, method, params };
      if (sessionId) payload.sessionId = sessionId;
      this.ws.send(JSON.stringify(payload));
    });
  }

  on(event, handler) {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, []);
    }
    this.eventListeners.get(event).push(handler);
  }

  close() {
    if (this.ws) {
      this.ws.close();
    }
  }
}

async function run() {
  console.log('[1/5] Chrome 가상 인증자 자동화 테스트 시작...');

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'prfvault-cdp-'));
  const chromeProc = spawn(CHROME_PATH, [
    '--headless=new',
    `--remote-debugging-port=${DEBUG_PORT}`,
    `--user-data-dir=${tempDir}`,
    '--no-first-run',
    '--no-default-browser-check',
  ]);

  const cleanup = () => {
    try {
      chromeProc.kill();
    } catch {}
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  };

  try {
    // 1. CDP 디버깅 포트 활성화 대기
    let versionInfo = null;
    for (let i = 0; i < 30; i++) {
      try {
        versionInfo = await fetchJson(`http://127.0.0.1:${DEBUG_PORT}/json/version`);
        if (versionInfo && versionInfo.webSocketDebuggerUrl) break;
      } catch {}
      await wait(200);
    }

    if (!versionInfo) {
      throw new Error('Chrome CDP 포트 연결 실패 (9222)');
    }

    console.log(`[2/5] Chrome CDP 연결 성공: ${versionInfo['Browser']}`);
    const cdp = new CdpClient(versionInfo.webSocketDebuggerUrl);
    await cdp.connect();

    // 2. 새 탭 생성 및 연결
    const { targetId } = await cdp.send('Target.createTarget', { url: TARGET_URL });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });

    // 3. 도메인 활성화 및 WebAuthn PRF 가상 인증자 등록
    await cdp.send('Page.enable', {}, sessionId);
    await cdp.send('Runtime.enable', {}, sessionId);
    await cdp.send('WebAuthn.enable', {}, sessionId);

    console.log('[3/5] CDP WebAuthn 가상 인증자 등록 (hasPrf: true, ctap2)...');
    const authResult = await cdp.send(
      'WebAuthn.addVirtualAuthenticator',
      {
        options: {
          protocol: 'ctap2',
          transport: 'internal',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          hasPrf: true, // 핵심 PRF 활성화 플래그
        },
      },
      sessionId
    );
    console.log(`      가상 인증자 생성 완료: ID = ${authResult.authenticatorId}`);

    // 4. 페이지 로드 및 Wasm 모듈 준비 대기 (btn-register가 활성화될 때까지)
    console.log('      초기화 및 사전 진단 완료 대기...');
    for (let i = 0; i < 20; i++) {
      const checkRes = await cdp.send(
        'Runtime.evaluate',
        {
          expression: `!document.getElementById("btn-register").disabled;`,
          returnByValue: true,
        },
        sessionId
      );
      if (checkRes.result && checkRes.result.value === true) break;
      await wait(300);
    }

    // 5. 브라우저 컨텍스트 내 버튼 순차 실행
    console.log('[4/5] WebAuthn PRF 파이프라인 단계별 트리거 실행...');

    // 1) 등록 버튼 클릭
    console.log('      [Step 1] 자격 증명 등록 (create) 트리거...');
    await cdp.send(
      'Runtime.evaluate',
      {
        expression: `document.getElementById("btn-register").click();`,
      },
      sessionId
    );
    // 등록 완료 대기 (btn-derive가 활성화될 때까지)
    for (let i = 0; i < 20; i++) {
      await wait(300);
      const res = await cdp.send(
        'Runtime.evaluate',
        {
          expression: `!document.getElementById("btn-derive").disabled;`,
          returnByValue: true,
        },
        sessionId
      );
      if (res.result && res.result.value === true) break;
    }

    // 2) 유도 버튼 클릭
    console.log('      [Step 2] PRF 32바이트 대칭키 유도 (get) 트리거...');
    await cdp.send(
      'Runtime.evaluate',
      {
        expression: `document.getElementById("btn-derive").click();`,
      },
      sessionId
    );
    // 유도 완료 대기 (btn-wasm-crypto가 활성화될 때까지)
    for (let i = 0; i < 20; i++) {
      await wait(300);
      const res = await cdp.send(
        'Runtime.evaluate',
        {
          expression: `!document.getElementById("btn-wasm-crypto").disabled;`,
          returnByValue: true,
        },
        sessionId
      );
      if (res.result && res.result.value === true) break;
    }

    // 3) Wasm 볼트 암복호화 버튼 클릭
    console.log('      [Step 3] Rust Wasm C-ABI 암복호화 파이프라인 트리거...');
    await cdp.send(
      'Runtime.evaluate',
      {
        expression: `document.getElementById("btn-wasm-crypto").click();`,
      },
      sessionId
    );
    await wait(1000);

    // 6. 결과 로그 수집
    console.log('[5/5] 실행 로그 수집 및 무결성 판정:');
    const logRes = await cdp.send(
      'Runtime.evaluate',
      {
        expression: `document.getElementById("log-output").innerText;`,
      },
      sessionId
    );

    const logText = logRes.result ? logRes.result.value : '';
    console.log('------------------------------------------------------------');
    console.log(logText);
    console.log('------------------------------------------------------------');

    cdp.close();

    const hasSuccessPrf = logText.includes('PRF 확장 활성화 확인됨') || logText.includes('하드웨어 PRF 키 유도 성공');
    const hasSuccessCrypto = logText.includes('복호화 완벽 일치') && logText.includes('Zeroize');

    if (hasSuccessPrf && hasSuccessCrypto) {
      console.log('\n[TEST PASSED] 가상 인증자(hasPrf: true) 환경에서 PRF 키 유도 및 Wasm 암복호화/Zeroize 100% 성공!');
      cleanup();
      process.exit(0);
    } else {
      console.log('\n[TEST FAILED] 일부 조건이 충족되지 않았습니다.');
      cleanup();
      process.exit(1);
    }
  } catch (err) {
    console.error(`테스트 실행 에러: ${err.message}`);
    cleanup();
    process.exit(1);
  }
}

run();
