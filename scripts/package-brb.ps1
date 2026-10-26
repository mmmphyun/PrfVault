# PrfVault BR-B 패키징 및 무결성 자동 검증 스크립트
$ErrorActionPreference = "Stop"

$sourceDir = "c:/work/PrfVault/apps/web-playground"
$outputDir = "c:/work/PrfVault/submission/T12-BRB-Submission"
$zipPath = "$outputDir/PrfVault-Web-Playground.zip"

Write-Output "[1/4] 소스 디렉토리 검사: $sourceDir"
$requiredFiles = @("index.html", "app.js", "data.js", "wasm-bundle.js", "README.md")
foreach ($f in $requiredFiles) {
    $fullPath = Join-Path $sourceDir $f
    if (-not (Test-Path $fullPath)) {
        throw "필수 파일 누락: $f"
    }
}

Write-Output "[2/4] 출력 디렉토리 확인 및 기존 ZIP 정리: $outputDir"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
}
if (Test-Path $zipPath) {
    Remove-Item -Force $zipPath
}

Write-Output "[3/4] 실행 묶음(ZIP) 생성 중: $zipPath"
Compress-Archive -Path "$sourceDir/*" -DestinationPath $zipPath -CompressionLevel Optimal
$zipItem = Get-Item $zipPath
Write-Output "   ZIP 파일 크기: $($zipItem.Length) 바이트"

Write-Output "[4/4] 새 임시 폴더 압축 해제 및 무결성 검증 (BRB-C08, BRB-C09)"
$tempExtractDir = Join-Path $env:TEMP ("prf-verify-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempExtractDir | Out-Null

try {
    Expand-Archive -Path $zipPath -DestinationPath $tempExtractDir -Force
    foreach ($f in $requiredFiles) {
        $extractedFile = Join-Path $tempExtractDir $f
        if (-not (Test-Path $extractedFile)) {
            throw "임시 폴더 압축 해제 검증 실패 - 파일 누락: $f"
        }
    }
    Write-Output "   임시 폴더 압축 해제 및 5개 파일 정상 확인 완료: $tempExtractDir"
} finally {
    if (Test-Path $tempExtractDir) {
        Remove-Item -Recurse -Force $tempExtractDir -ErrorAction SilentlyContinue
    }
}

Write-Output "`n[성공] PrfVault BR-B 실행 묶음 패키징 및 임시 폴더 검증 완료!"
