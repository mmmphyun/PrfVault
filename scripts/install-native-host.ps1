#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 환경 Chrome Native Messaging Host 등록 스크립트.

.DESCRIPTION
    crates/native-host의 빌드 아티팩트(native-host.exe)를 가리키는 호스트 매니페스트 JSON을 생성하고,
    Windows 레지스트리(HKCU\Software\Google\Chrome\NativeMessagingHosts\com.prfvault.native_host)에 등록합니다.

.PARAMETER ExtensionId
    연동할 Chrome 확장 프로그램 ID (기본값: 개발 편의를 위한 임시 키 또는 와일드카드)

.PARAMETER BinaryPath
    native-host.exe 실행 파일의 절대 경로 (미지정 시 target/debug/native-host.exe 기본 탐색)
#>

[CmdletBinding()]
param (
    [string]$ExtensionId = "abcdefghijklmnopqrstuvwxyz123456",
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
        Write-Error "native-host.exe 바이너리를 찾을 수 없습니다. 먼저 'cargo build -p native-host'를 실행하십시오."
    }
}

$hostName = "com.prfvault.native_host"
$manifestPath = Join-Path $repoRoot "crates/native-host/$hostName.json"

# Chrome 네이티브 호스트 매니페스트 규격
$manifestObject = @{
    name = $hostName
    description = "PrfVault Chrome Native Messaging Host"
    path = $BinaryPath
    type = "stdio"
    allowed_origins = @(
        "chrome-extension://$ExtensionId/"
    )
}

$manifestJson = $manifestObject | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($manifestPath, $manifestJson, [System.Text.Encoding]::UTF8)
Write-Host "[INFO] 호스트 매니페스트 생성 완료: $manifestPath"

# Windows HKCU 레지스트리 등록
$registryKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName"

if (-not (Test-Path $registryKey)) {
    New-Item -Path $registryKey -Force | Out-Null
    Write-Host "[INFO] 신규 레지스트리 키 생성: $registryKey"
}

Set-ItemProperty -Path $registryKey -Name "(Default)" -Value $manifestPath
Write-Host "[SUCCESS] Native Messaging Host 등록 완료!"
Write-Host "  - Host Name : $hostName"
Write-Host "  - Manifest  : $manifestPath"
Write-Host "  - Binary    : $BinaryPath"
Write-Host "  - Registry  : $registryKey"
