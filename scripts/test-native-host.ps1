#Requires -Version 5.1
<#
.SYNOPSIS
    native-host.exe 표준 입출력(stdin/stdout) 4바이트 uint32 LE 통신 무결성 통합 테스트.

.DESCRIPTION
    1. PING 메시지 전송 및 {"status":"OK","data":{"pong":true}} 수신 검증.
    2. PRF_DERIVE 메시지 전송 및 정상 응답 수신 검증.
    3. 비정상 JSON 페이로드 전송 시 INVALID_PAYLOAD 응답 수신 및 Fail-safe 프로세스 자동 종료 검증.
#>

[CmdletBinding()]
param (
    [string]$BinaryPath = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path "$PSScriptRoot/..").Path

if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    $debugPath = Join-Path $repoRoot "target/debug/native-host.exe"
    $releasePath = Join-Path $repoRoot "target/release/native-host.exe"

    if (Test-Path $debugPath) {
        $BinaryPath = (Resolve-Path $debugPath).Path
    } elseif (Test-Path $releasePath) {
        $BinaryPath = (Resolve-Path $releasePath).Path
    } else {
        Write-Error "native-host.exe를 찾을 수 없습니다. 먼저 'cargo build -p native-host'를 실행하십시오."
    }
}

Write-Host "============================================================"
Write-Host "  Native Messaging Host 통신 파이프라인 E2E 검증"
Write-Host "  Binary: $BinaryPath"
Write-Host "============================================================"

function Send-Frame {
    param (
        [System.IO.Stream]$Stream,
        [string]$JsonPayload
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($JsonPayload)
    $length = [uint32]$bytes.Length
    $lenBytes = [System.BitConverter]::GetBytes($length)

    # Little-Endian 보장
    if (-not [System.BitConverter]::IsLittleEndian) {
        [System.Array]::Reverse($lenBytes)
    }

    $Stream.Write($lenBytes, 0, 4)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

function Read-Frame {
    param (
        [System.IO.Stream]$Stream
    )
    $lenBytes = New-Object byte[] 4
    $readCount = 0
    while ($readCount -lt 4) {
        $r = $Stream.Read($lenBytes, $readCount, 4 - $readCount)
        if ($r -eq 0) {
            return $null # EOF
        }
        $readCount += $r
    }

    if (-not [System.BitConverter]::IsLittleEndian) {
        [System.Array]::Reverse($lenBytes)
    }
    $length = [System.BitConverter]::ToUInt32($lenBytes, 0)

    $buf = New-Object byte[] $length
    $bodyRead = 0
    while ($bodyRead -lt $length) {
        $r = $Stream.Read($buf, $bodyRead, $length - $bodyRead)
        if ($r -eq 0) {
            throw "페이로드 본문 수신 중 예기치 못한 EOF 발생 (기대 크기: $length, 수신: $bodyRead)"
        }
        $bodyRead += $r
    }

    return [System.Text.Encoding]::UTF8.GetString($buf)
}

$passCount = 0
$failCount = 0

# --- Test Case 1: PING / PONG (Liveness) ---
Write-Host -NoNewline "[TEST 1] PING / PONG Liveness 체크 ... "

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $BinaryPath
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true

$proc = [System.Diagnostics.Process]::Start($psi)

try {
    $inStream = $proc.StandardInput.BaseStream
    $outStream = $proc.StandardOutput.BaseStream

    Send-Frame -Stream $inStream -JsonPayload '{"type":"PING"}'
    $rawResp = Read-Frame -Stream $outStream

    $resp = $rawResp | ConvertFrom-Json
    if ($resp.status -eq "OK" -and $resp.data.pong -eq $true) {
        Write-Host "PASS (수신: $rawResp)" -ForegroundColor Green
        $passCount++
    } else {
        Write-Host "FAIL (예상: pong=true, 실제: $rawResp)" -ForegroundColor Red
        $failCount++
    }

    # --- Test Case 2: PRF_DERIVE ---
    Write-Host -NoNewline "[TEST 2] PRF_DERIVE 요청 검증 ... "
    $prfPayload = '{"type":"PRF_DERIVE","domain":"test.vault.internal","challenge":"chal_seed_999"}'
    Send-Frame -Stream $inStream -JsonPayload $prfPayload
    $rawPrfResp = Read-Frame -Stream $outStream

    $prfResp = $rawPrfResp | ConvertFrom-Json
    if ($prfResp.status -eq "OK" -and $prfResp.data.domain -eq "test.vault.internal" -and $prfResp.data.derived -eq $true) {
        Write-Host "PASS (수신: $rawPrfResp)" -ForegroundColor Green
        $passCount++
    } else {
        Write-Host "FAIL (예상: derived=true, 실제: $rawPrfResp)" -ForegroundColor Red
        $failCount++
    }

    # --- Test Case 3: INVALID_PAYLOAD & Fail-safe 종료 ---
    Write-Host -NoNewline "[TEST 3] INVALID_PAYLOAD 에러 수신 및 Fail-safe 종료 검증 ... "
    Send-Frame -Stream $inStream -JsonPayload '{"broken_json": true' # 유효하지 않은 JSON
    $rawErrResp = Read-Frame -Stream $outStream

    $errResp = $rawErrResp | ConvertFrom-Json
    $proc.WaitForExit(3000)

    if ($errResp.status -eq "ERROR" -and $errResp.code -eq "INVALID_PAYLOAD" -and $proc.HasExited) {
        Write-Host "PASS (에러 반환 후 프로세스 정상 종료 확인)" -ForegroundColor Green
        $passCount++
    } else {
        Write-Host "FAIL (에러 코드: $($errResp.code), 프로세스 종료 여부: $($proc.HasExited))" -ForegroundColor Red
        $failCount++
    }
} finally {
    if (-not $proc.HasExited) {
        $proc.Kill()
    }
    $proc.Dispose()
}

Write-Host "============================================================"
Write-Host "테스트 결과: PASS: $passCount, FAIL: $failCount"
Write-Host "============================================================"

if ($failCount -gt 0) {
    exit 1
} else {
    exit 0
}
