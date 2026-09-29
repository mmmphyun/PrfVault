#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 환경 Chrome Native Messaging Host 등록 해제 스크립트.
#>

[CmdletBinding()]
param ()

$ErrorActionPreference = "Stop"

$hostName = "com.prfvault.native_host"
$registryKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName"

if (Test-Path $registryKey) {
    Remove-Item -Path $registryKey -Recurse -Force
    Write-Host "[SUCCESS] 레지스트리 키 제거 완료: $registryKey"
} else {
    Write-Host "[INFO] 등록된 레지스트리 키가 존재하지 않습니다: $registryKey"
}

$repoRoot = (Resolve-Path "$PSScriptRoot/..").Path
$manifestPath = Join-Path $repoRoot "crates/native-host/$hostName.json"

if (Test-Path $manifestPath) {
    Remove-Item -Path $manifestPath -Force
    Write-Host "[SUCCESS] 매니페스트 파일 제거 완료: $manifestPath"
}
