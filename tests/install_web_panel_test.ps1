<#
.SYNOPSIS
Tests for scripts/install_web_panel.ps1 that need no administrator rights.

.DESCRIPTION
Loads the installer's functions (dot-sourcing does not run it) and checks the
release asset name and SHA256SUMS parsing, downloading a release (from a local
stand-in for GitHub), copying an old auth file, the task command, and - with
-PanelExe, a real kid-pc-web-panel.exe - installing it into a temporary folder
and storing the shared secret through it. With -Python, also checks that
Python's secrets_store reads that secret.

    powershell -ExecutionPolicy Bypass -File tests\install_web_panel_test.ps1 [-PanelExe go\kid-pc-web-panel.exe] [-Python venv\Scripts\python.exe]

Keep this file ASCII-only, like the installer.
#>
param([string]$PanelExe, [string]$Python)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$testPanelExe = $PanelExe
. (Join-Path $repo 'scripts\install_web_panel.ps1')

$work = Join-Path ([IO.Path]::GetTempPath()) ("kpm-panel-installer-test-{0}" -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
$script:ConfigDir = Join-Path $work 'localappdata\kid-pc-monitor'
$script:InstallDir = Join-Path $script:ConfigDir 'bin'
$script:TaskName = 'KidPCMonitorWebPanel-test-does-not-exist'
$env:KID_PC_MONITOR_SECRETS_DIR = Join-Path $work 'secrets'
$env:KID_PC_MONITOR_SECRET_KEY = ''
$script:failures = 0

function Check([string]$Name, $Got, $Want) {
    if ("$Got" -ceq "$Want") {
        Write-Host "  ok    $Name"
    } else {
        Write-Host "  FAIL  $Name`n          got  $Got`n          want $Want"
        $script:failures++
    }
}

function Throws([scriptblock]$Block) {
    try { & $Block | Out-Null; return $false } catch { return $true }
}

try {
    Write-Host "release assets"
    Check 'amd64 asset name' (Get-PanelAssetName 'amd64') 'kid-pc-web-panel-windows-amd64.exe'
    $sums = Read-Checksums ("{0}  kid-pc-web-panel-windows-amd64.exe`r`n{1} *kid-pc-agent-windows-amd64.exe`nnot a line" -f ('A' * 64), ('b' * 64))
    Check 'checksum lower-cased' $sums['kid-pc-web-panel-windows-amd64.exe'] ('a' * 64)
    Check 'binary-mode line parsed' $sums['kid-pc-agent-windows-amd64.exe'] ('b' * 64)
    Check 'junk ignored' $sums.Count 2

    Write-Host "download a release (local stand-in for GitHub)"
    $release = Join-Path $work 'release'
    New-Item -ItemType Directory -Path $release | Out-Null
    $fakeExe = Join-Path $release 'kid-pc-web-panel-windows-amd64.exe'
    [IO.File]::WriteAllText($fakeExe, 'not really an exe')
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $fakeExe).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $release 'SHA256SUMS'), "$hash  kid-pc-web-panel-windows-amd64.exe`n")
    [IO.File]::WriteAllText((Join-Path $release 'latest.json'), '{"tag_name": "v9.9.9"}')
    $script:downloads = @()
    function Invoke-Download([string]$Url, [string]$OutFile) {
        $script:downloads += $Url
        if ($Url -like '*/releases/latest') {
            Copy-Item -LiteralPath (Join-Path $release 'latest.json') -Destination $OutFile
        } elseif ($Url -like '*/releases/download/v9.9.9/*') {
            Copy-Item -LiteralPath (Join-Path $release ($Url -split '/')[-1]) -Destination $OutFile
        } else {
            throw "Could not download ${Url}: 404"
        }
    }
    $script:Version = ''
    Check 'latest tag' (Get-ReleaseTag) 'v9.9.9'
    $got = Get-VerifiedReleaseAsset 'v9.9.9' 'kid-pc-web-panel-windows-amd64.exe' '.exe'
    Check 'asset downloaded and verified' ((Get-FileHash $got).Hash) ((Get-FileHash $fakeExe).Hash)
    Remove-Item -LiteralPath $got -Force
    Check 'missing asset refused' (Throws { Get-VerifiedReleaseAsset 'v9.9.9' 'kid-pc-web-panel-windows-arm64.exe' '.exe' }) $true
    [IO.File]::WriteAllText($fakeExe, 'tampered')
    $before = @(Get-ChildItem ([IO.Path]::GetTempPath()) -Filter 'kid-pc-web-panel-*').Count
    Check 'checksum mismatch refused' (Throws { Get-VerifiedReleaseAsset 'v9.9.9' 'kid-pc-web-panel-windows-amd64.exe' '.exe' }) $true
    Check 'refused download deleted' (@(Get-ChildItem ([IO.Path]::GetTempPath()) -Filter 'kid-pc-web-panel-*').Count) $before
    $script:Version = 'v404'
    Check 'missing release refused' (Throws { Get-VerifiedReleaseAsset 'v404' 'kid-pc-web-panel-windows-amd64.exe' '.exe' }) $true
    $script:Version = ''

    Write-Host "old auth file"
    $fakeRepo = Join-Path $work 'repo'
    $legacyDir = Join-Path $fakeRepo 'src\kid_pc_monitor'
    New-Item -ItemType Directory -Path $legacyDir | Out-Null
    [IO.File]::WriteAllText((Join-Path $legacyDir 'web_panel_auth.json'), '{"password_hash": "legacy"}')
    $script:RepoRoot = $fakeRepo
    Check 'copied when only the old file exists' (Copy-LegacyAuth) $true
    Check 'copy has the old contents' ([IO.File]::ReadAllText((Join-Path $script:ConfigDir 'web_panel_auth.json'))) '{"password_hash": "legacy"}'
    [IO.File]::WriteAllText((Join-Path $script:ConfigDir 'web_panel_auth.json'), '{"password_hash": "newer"}')
    Check 'not copied over a newer file' (Copy-LegacyAuth) $false
    Check 'newer file kept' ([IO.File]::ReadAllText((Join-Path $script:ConfigDir 'web_panel_auth.json'))) '{"password_hash": "newer"}'
    $script:RepoRoot = $repo

    Write-Host "task"
    $cmd = Get-PanelTaskCommand 'C:\x\kid-pc-web-panel.exe'
    Check 'task runs the installed exe' $cmd.Execute 'C:\x\kid-pc-web-panel.exe'
    Check 'task runs it in the background' $cmd.Argument 'serve -background'
    Check 'task works in the config folder' $cmd.WorkingDirectory $script:ConfigDir

    Write-Host "resolve the exe"
    $script:PanelExe = Join-Path $work 'missing.exe'
    Check 'missing -PanelExe refused' (Throws { Resolve-PanelExe }) $true
    $script:PanelExe = ''
    $script:Download = $true
    [IO.File]::WriteAllText($fakeExe, 'not really an exe')
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $fakeExe).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $release 'SHA256SUMS'), "$hash  kid-pc-web-panel-windows-amd64.exe`n$hash  kid-pc-web-panel-windows-arm64.exe`n")
    Copy-Item -LiteralPath $fakeExe -Destination (Join-Path $release 'kid-pc-web-panel-windows-arm64.exe')
    $viaRelease = Resolve-PanelExe
    Check '-Download uses the release' ((Get-FileHash $viaRelease.Path).Hash) ((Get-FileHash $fakeExe).Hash)
    Check 'downloaded exe is temporary' $viaRelease.Temporary $true
    Write-Host "install refuses an exe that does not run"
    Check 'broken exe refused' (Throws { Install-PanelExe $viaRelease }) $true
    Check 'staging file removed' (Test-Path -LiteralPath (Get-StagingPanelPath)) $false
    Remove-Item -LiteralPath $viaRelease.Path -Force
    $script:Download = $false

    if ($testPanelExe) {
        Write-Host "install the real exe"
        $script:PanelExe = $testPanelExe
        $resolved = Resolve-PanelExe
        Check '-PanelExe used as is' $resolved.Temporary $false
        $installed = Install-PanelExe $resolved
        Check 'installed where the task runs it' $installed (Join-Path $script:InstallDir 'kid-pc-web-panel.exe')
        Check 'installed exe runs' ((& $installed version) -ne $null) $true
        $again = Install-PanelExe $resolved
        Check 'reinstall replaces it' (Test-Path -LiteralPath $again) $true
        Check 'no staging file left' (Test-Path -LiteralPath (Get-StagingPanelPath)) $false

        Write-Host "shared secret through the exe"
        $output = "kid-pc-secret-1`nkid-pc-secret-1`n" | & $installed set-secret
        Check 'set-secret succeeded' $LASTEXITCODE 0
        Check 'secret file written' (Test-Path -LiteralPath (Join-Path $env:KID_PC_MONITOR_SECRETS_DIR 'panel-agent-shared-secret.enc')) $true
        $reuse = '' | & $installed set-secret
        Check 'second run reuses it' (($reuse | Out-String) -match 'Reusing existing shared secret') $true
        if ($Python) {
            $env:PYTHONPATH = Join-Path $repo 'src'
            $read = "from kid_pc_monitor import secrets_store; print(secrets_store.load_secret('panel-agent-shared-secret'))" | & $Python - 2>&1
            Check 'Python reads the secret the Go panel stored' (($read | Out-String).Trim()) 'kid-pc-secret-1'
        }
    }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Host "`n$($script:failures) check(s) FAILED"
    exit 1
}
Write-Host "`nall web panel installer checks passed"
exit 0
