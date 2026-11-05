<#
.SYNOPSIS
Install the Kid PC Monitor web panel (the Go kid-pc-web-panel.exe) on the
parent's Windows PC. No Python needed.

.DESCRIPTION
A PowerShell counterpart of scripts/install_web_panel.py for the Go panel.
Run it from an elevated Windows PowerShell 5.1 (or PowerShell 7) prompt,
either from a checkout or on its own (it is attached to every GitHub release):

    powershell -ExecutionPolicy Bypass -File install_web_panel.ps1

With no switches it shows a menu (install / remove). Installing:
  - gets kid-pc-web-panel.exe: -PanelExe if given, else a build from go/ when
    Go and the sources are present, else the GitHub release's exe for this
    PC's architecture (checked against the release's SHA256SUMS);
  - copies it to %LOCALAPPDATA%\kid-pc-monitor\bin;
  - copies an old web_panel_auth.json from the checkout's package folder into
    %LOCALAPPDATA%\kid-pc-monitor when only the old one exists;
  - stores the panel <-> agent shared secret (kid-pc-web-panel set-secret:
    reuses one already stored, else asks for it);
  - registers the KidPCMonitorWebPanel task (replacing the Python panel's
    task of that name) to run "serve -background" at startup and logon, and
    starts it; the panel logs to %LOCALAPPDATA%\kid-pc-monitor\web_panel.log;
  - offers inbound firewall rules for TCP 5000 (UI) and 9998 (agents).

The panel keeps the Python panel's panel.db, password and secret, so either
can replace the other. Keep this file ASCII-only: Windows PowerShell 5.1 reads
BOM-less scripts as ANSI.

.PARAMETER PanelExe
Install this kid-pc-web-panel.exe instead of building or downloading one.

.PARAMETER Download
Use the GitHub release even when Go and the sources are present.

.PARAMETER Version
Release tag to download (default: the latest release).

.PARAMETER Repository
GitHub owner/name to download from.

.PARAMETER Install
Install without the menu.

.PARAMETER Uninstall
Remove the task, the firewall rules and the installed exe (keeps panel.db,
the password and the secret).

.PARAMETER NoFirewall
Do not offer firewall rules.
#>
[CmdletBinding()]
param(
    [string]$PanelExe,
    [switch]$Download,
    [string]$Version,
    [string]$Repository = 'cpmurphy/kid-pc-monitor',
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$NoFirewall
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TaskName = 'KidPCMonitorWebPanel'
$PanelExeName = 'kid-pc-web-panel.exe'
$LocalAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $HOME 'AppData\Local' }
$ConfigDir = Join-Path $LocalAppData 'kid-pc-monitor'
$InstallDir = Join-Path $ConfigDir 'bin'
$AuthFile = 'web_panel_auth.json'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$GitHubApi = 'https://api.github.com'
$GitHubWeb = 'https://github.com'
$FirewallRules = @(
    @{ Name = 'Kid PC Monitor Web Panel (TCP 5000)'; Port = 5000 },
    @{ Name = 'Kid PC Monitor Web Panel agents (TCP 9998)'; Port = 9998 }
)

# ---------------------------------------------------------------------------
# Small helpers (the download and checksum ones match install_agent.ps1)
# ---------------------------------------------------------------------------

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-GoTool {
    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($candidate in @((Join-Path $env:ProgramFiles 'Go\bin\go.exe'), 'C:\Go\bin\go.exe')) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

function Test-GoSources {
    return Test-Path -LiteralPath (Join-Path $RepoRoot 'go\cmd\kid-pc-web-panel')
}

# The release asset suffix for this Windows: amd64 or arm64.
function Get-PanelArch {
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        default { throw "There is no released web panel for $arch Windows; build it with Go instead." }
    }
}

function Get-PanelAssetName([string]$Arch) {
    return "kid-pc-web-panel-windows-$Arch.exe"
}

# SHA256SUMS ("<hash>  <name>" per line, as sha256sum writes it) as a
# name -> lower-case hash table.
function Read-Checksums([string]$Text) {
    $sums = @{}
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -cmatch '^([0-9a-fA-F]{64}) [ *](.+)$') {
            $sums[$Matches[2].Trim()] = $Matches[1].ToLowerInvariant()
        }
    }
    return $sums
}

function Invoke-Download([string]$Url, [string]$OutFile) {
    # Windows PowerShell 5.1 may not offer TLS 1.2 by default; GitHub needs it.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor
        [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue' # the progress bar makes downloads crawl in 5.1
    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
    } catch {
        throw "Could not download ${Url}: $($_.Exception.Message)"
    }
}

function New-TempPath([string]$Extension) {
    return Join-Path ([IO.Path]::GetTempPath()) ("kid-pc-web-panel-{0}{1}" -f [guid]::NewGuid(), $Extension)
}

# The release to install: -Version, else the latest release's tag.
function Get-ReleaseTag {
    if ($Version) { return $Version }
    $latest = New-TempPath '.json'
    try {
        Invoke-Download "$GitHubApi/repos/$Repository/releases/latest" $latest
        $obj = [IO.File]::ReadAllText($latest) | ConvertFrom-Json
        $tag = $obj.tag_name
    } finally {
        Remove-Item -LiteralPath $latest -Force -ErrorAction SilentlyContinue
    }
    if (-not ($tag -is [string] -and $tag)) { throw "Could not find the latest release of $Repository." }
    return $tag
}

# Download one asset of a release into a temporary file and check it against
# the release's SHA256SUMS. Returns the file's path.
function Get-VerifiedReleaseAsset([string]$Tag, [string]$Name, [string]$Extension) {
    $sumsFile = New-TempPath '.sha256'
    try {
        Invoke-Download "$GitHubWeb/$Repository/releases/download/$Tag/SHA256SUMS" $sumsFile
        $sums = Read-Checksums ([IO.File]::ReadAllText($sumsFile))
    } finally {
        Remove-Item -LiteralPath $sumsFile -Force -ErrorAction SilentlyContinue
    }
    $expected = $sums[$Name]
    if (-not $expected) { throw "Release $Tag has no $Name (it may predate the Go web panel)." }
    $path = New-TempPath $Extension
    try {
        Invoke-Download "$GitHubWeb/$Repository/releases/download/$Tag/$Name" $path
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "The downloaded $Name does not match SHA256SUMS (got $actual, expected $expected)."
        }
    } catch {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        throw
    }
    Write-Host "   $Name SHA-256 verified: $actual"
    return $path
}

# The kid-pc-web-panel.exe to install: -PanelExe; else a build from go/ when
# Go and the sources are here (and -Download was not given); else the
# released exe. Returns @{ Path; Temporary } (Temporary files are deleted
# after copying).
function Resolve-PanelExe {
    if ($PanelExe) {
        if (-not (Test-Path -LiteralPath $PanelExe -PathType Leaf)) {
            throw "Panel executable not found: $PanelExe"
        }
        return @{ Path = (Resolve-Path -LiteralPath $PanelExe).ProviderPath; Temporary = $false }
    }
    $go = Find-GoTool
    if (-not $Download -and -not $Version -and $go -and (Test-GoSources)) {
        $out = New-TempPath '.exe'
        Write-Host "`nBuilding the Go web panel with $go ..."
        Push-Location (Join-Path $RepoRoot 'go')
        try {
            & $go build -trimpath -buildvcs=false -ldflags '-s -w' -o $out ./cmd/kid-pc-web-panel
            if ($LASTEXITCODE -ne 0) { throw "go build failed (exit code $LASTEXITCODE)." }
        } finally {
            Pop-Location
        }
        return @{ Path = $out; Temporary = $true }
    }
    $tag = Get-ReleaseTag
    Write-Host "`nDownloading release $tag of $Repository ..."
    return @{ Path = (Get-VerifiedReleaseAsset $tag (Get-PanelAssetName (Get-PanelArch)) '.exe'); Temporary = $true }
}

function Get-InstalledPanelPath {
    return Join-Path $InstallDir $PanelExeName
}

function Stop-PanelTask {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue }
    # A panel started by hand (or the task's process) keeps the exe locked.
    $installed = Get-InstalledPanelPath
    Get-Process -Name 'kid-pc-web-panel' -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and ($_.Path -eq $installed) } |
        Stop-Process -Force -ErrorAction SilentlyContinue
}

# Copy the resolved exe into $InstallDir via a temporary name, check that it
# runs, then replace the installed one. Returns the installed path.
function Install-PanelExe($Resolved) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $target = Get-InstalledPanelPath
    $staging = "$target.new"
    Copy-Item -LiteralPath $Resolved.Path -Destination $staging -Force
    $runs = $false
    try {
        $panelVersion = & $staging version
        $runs = ($LASTEXITCODE -eq 0)
    } catch {
        $runs = $false
    }
    if (-not $runs) {
        Remove-Item -LiteralPath $staging -Force -ErrorAction SilentlyContinue
        throw "The panel executable does not run on this PC."
    }
    Move-Item -LiteralPath $staging -Destination $target -Force
    Write-Host "Installed $target ($panelVersion)"
    return $target
}

# Installs before the May 2026 package layout kept web_panel_auth.json in the
# package folder; the Go panel reads only %LOCALAPPDATA%\kid-pc-monitor.
# Returns $true when a file was copied.
function Copy-LegacyAuth {
    $canonical = Join-Path $ConfigDir $AuthFile
    $legacy = Join-Path $RepoRoot "src\kid_pc_monitor\$AuthFile"
    if ((Test-Path -LiteralPath $canonical) -or -not (Test-Path -LiteralPath $legacy -PathType Leaf)) {
        return $false
    }
    New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
    Copy-Item -LiteralPath $legacy -Destination $canonical
    Write-Host "Copied the panel password file to $canonical."
    return $true
}

# kid-pc-web-panel set-secret: reuses a stored secret, else prompts. Returns
# $false when it was cancelled (the install still continues, as with Python).
function Invoke-SetSecret([string]$Exe) {
    & $Exe set-secret
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Shared secret not changed. Set it later with: `"$Exe`" set-secret"
        return $false
    }
    return $true
}

# The task's program, arguments and working folder.
function Get-PanelTaskCommand([string]$Exe) {
    return @{ Execute = $Exe; Argument = 'serve -background'; WorkingDirectory = $ConfigDir }
}

function Register-PanelTask([string]$Exe) {
    $user = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$env:USERNAME" } else { $env:USERNAME }
    $cmd = Get-PanelTaskCommand $Exe
    $action = New-ScheduledTaskAction -Execute $cmd.Execute -Argument $cmd.Argument -WorkingDirectory $cmd.WorkingDirectory
    $triggers = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn -User $user))
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -DontStopOnIdleEnd -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Hours 0) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal `
        -Settings $settings -Force | Out-Null
    Write-Host "Registered the $TaskName task (runs as $user at startup and logon)."
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "Started the web panel."
}

function Add-FirewallRules {
    foreach ($rule in $FirewallRules) {
        if (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue) {
            Write-Host "   Firewall rule already present: $($rule.Name)"
            continue
        }
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Protocol TCP `
            -LocalPort $rule.Port -Action Allow -Profile Private, Domain | Out-Null
        Write-Host "   Added firewall rule: $($rule.Name) (private and domain networks)"
    }
}

function Remove-FirewallRules {
    foreach ($rule in $FirewallRules) {
        if (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue) {
            Remove-NetFirewallRule -DisplayName $rule.Name
            Write-Host "Removed firewall rule: $($rule.Name)"
        }
    }
}

function Get-PanelUrl {
    $scheme = 'http'
    $tls = Join-Path $ConfigDir 'tls'
    if ((Test-Path -LiteralPath (Join-Path $tls 'cert.pem')) -and (Test-Path -LiteralPath (Join-Path $tls 'key.pem'))) {
        $scheme = 'https'
    }
    $ip = $null
    try {
        $ip = (Get-NetIPConfiguration -ErrorAction Stop |
            Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
            Select-Object -First 1).IPv4Address.IPAddress
    } catch {
        $ip = $null
    }
    if (-not $ip) { $ip = '<this-pc-ip>' }
    return "${scheme}://${ip}:5000"
}

# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------

function Invoke-Install {
    $resolved = Resolve-PanelExe
    try {
        Stop-PanelTask
        $exe = Install-PanelExe $resolved
    } finally {
        if ($resolved.Temporary) { Remove-Item -LiteralPath $resolved.Path -Force -ErrorAction SilentlyContinue }
    }
    Copy-LegacyAuth | Out-Null
    Write-Host ""
    Invoke-SetSecret $exe | Out-Null
    Write-Host ""
    Register-PanelTask $exe
    if (-not $NoFirewall) {
        Write-Host "`nThe panel needs inbound TCP 5000 (your browser or phone) and 9998 (the kid PCs)."
        $answer = (Read-Host "Add Windows Firewall rules for them? (Y/n)").Trim()
        if ($answer -eq '' -or $answer -match '^[Yy]') { Add-FirewallRules }
    }
    Write-Host "`nSetup complete. Open the web panel from any device on your network at:"
    Write-Host "   $(Get-PanelUrl)"
    Write-Host "Log: $(Join-Path $ConfigDir 'web_panel.log')"
    return $true
}

function Remove-Panel {
    Stop-PanelTask
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed the $TaskName task."
    } else {
        Write-Host "No $TaskName task was found."
    }
    Remove-FirewallRules
    $installed = Get-InstalledPanelPath
    if (Test-Path -LiteralPath $installed) {
        Remove-Item -LiteralPath $installed -Force
        Write-Host "Removed $installed."
    }
    Write-Host "Kept $ConfigDir (panel.db, password, log) and the shared secret."
}

function Invoke-Main {
    Write-Host "Kid PC Monitor - Web Panel Setup (Go panel)"
    Write-Host ('=' * 45)
    if (-not (Test-Admin)) {
        Write-Host "`nERROR: This script needs to run as Administrator!"
        Write-Host "   Open PowerShell with 'Run as administrator' and try again."
        if (-not ($Install -or $Uninstall)) { Read-Host "`nPress Enter to exit" | Out-Null }
        return 1
    }
    try {
        if ($Uninstall) { Remove-Panel; return 0 }
        if ($Install) { if (Invoke-Install) { return 0 } else { return 1 } }

        Write-Host "`nWhat would you like to do?"
        Write-Host "1. Install/update the web panel"
        Write-Host "2. Remove the web panel"
        Write-Host "3. Exit"
        $choice = (Read-Host "`nChoice (1-3)").Trim()
        $code = 0
        if ($choice -eq '1') {
            if (-not (Invoke-Install)) { $code = 1 }
        } elseif ($choice -eq '2') {
            Remove-Panel
        } else {
            Write-Host "`nExiting..."
        }
        Read-Host "`nPress Enter to close" | Out-Null
        return $code
    } catch {
        Write-Host "`nERROR: $($_.Exception.Message)"
        if (-not ($Install -or $Uninstall)) { Read-Host "`nPress Enter to close" | Out-Null }
        return 1
    }
}

# Dot-sourcing (". .\install_web_panel.ps1") loads the functions without running.
if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-Main)
}
