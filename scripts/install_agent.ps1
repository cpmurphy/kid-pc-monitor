<#
.SYNOPSIS
Kid PC Monitor agent installer for the Go agent (go/cmd/kid-pc-agent).

.DESCRIPTION
A PowerShell port of scripts/install.py that installs the compiled Go agent
instead of the Python one, so the kid's PC needs neither Python nor Git. Run it
from an elevated Windows PowerShell 5.1 (or PowerShell 7) prompt, either from
a checkout or on its own (it is attached to every GitHub release):

    powershell -ExecutionPolicy Bypass -File install_agent.ps1

With no switches it shows a menu (install / remove). It:
  - gets kid-pc-agent.exe: -AgentExe if given, else a build from go/ when Go
    1.22+ and the sources are present, else the GitHub release's exe for this
    PC's architecture (checked against the release's SHA256SUMS);
  - copies it to %ProgramData%\KidPCMonitor, removes the Python agent's
    files from there, and restricts the folder to SYSTEM and Administrators
    (full control) plus the monitored account (read + execute);
  - saves the daily schedule to ProgramData and to the child's profile;
  - stores the panel <-> agent shared secret (Fernet-encrypted, readable by
    the Python and Go agents and the web panel);
  - registers the KidPCMonitor logon task (replacing a Python agent's task)
    and starts it;
  - keeps version.txt, a copy of this installer and update.cmd next to the
    agent, so updates need neither the repository nor Git, and offers to
    turn on automatic updates.

-Update with a released agent does nothing when version.txt already names
the latest release, so the daily automatic update does not restart the agent.

.PARAMETER AgentExe
A prebuilt kid-pc-agent.exe to install instead of building one. Build it with
  go build -ldflags "-H=windowsgui" ./cmd/kid-pc-agent
so the task does not open a console window.

.PARAMETER Download
Download the released agent even when Go is installed.

.PARAMETER Version
The release tag to download (for example v1.2.0). Default: the latest release.

.PARAMETER Repository
The GitHub repository to download releases from (owner/name).

.PARAMETER Install
Run the install without showing the menu (it still asks its questions).

.PARAMETER Uninstall
Remove the scheduled task without showing the menu.

.PARAMETER Update
Re-deploy the agent for the previously installed account (non-interactive):
the latest release (skipped when already installed), or a fresh build from a
checkout with Go.

.PARAMETER Pull
With -Update: run "git pull --ff-only" in the repo first.

.PARAMETER EnableAutoUpdate
Install a SYSTEM task that runs "-Update -Pull" after startup and daily.

.PARAMETER DisableAutoUpdate
Remove the automatic-update task.
#>
[CmdletBinding()]
param(
    [string]$AgentExe,
    [switch]$Download,
    [string]$Version,
    [string]$Repository = 'cpmurphy/kid-pc-monitor',
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Update,
    [switch]$Pull,
    [switch]$EnableAutoUpdate,
    [switch]$DisableAutoUpdate
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TaskName = 'KidPCMonitor'
$AutoUpdateTaskName = 'KidPCMonitorUpdate'
$ProgramDataRoot = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
$InstallDir = Join-Path $ProgramDataRoot 'KidPCMonitor'
$AgentExeName = 'kid-pc-agent.exe'
$DailySettingsFile = 'daily_settings.json'
$SharedSecretName = 'panel-agent-shared-secret'
$MinSecretLength = 8
$LegacyFirewallRule = 'Kid PC Monitor Agent (TCP 9999)'
$LegacyPythonFiles = @('kid_pc_monitor', 'pc_control.py', 'requirements.txt')
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$GitHubApi = 'https://api.github.com'
$GitHubWeb = 'https://github.com'

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Write UTF-8 without a BOM (the agents reject a BOM as corrupt JSON), via a
# temporary file so a reader never sees half a file.
function Write-FileAtomic([string]$Path, [string]$Text) {
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    $tmp = "$Path.tmp"
    [IO.File]::WriteAllText($tmp, $Text, $Utf8NoBom)
    if (Test-Path -LiteralPath $Path) {
        [IO.File]::Replace($tmp, $Path, [NullString]::Value)
    } else {
        [IO.File]::Move($tmp, $Path)
    }
}

# Parse a JSON file that should hold an object; $null when it is missing,
# unreadable, not JSON or not an object.
function Read-JsonObject([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $obj = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    } catch {
        return $null
    }
    if ($obj -is [System.Management.Automation.PSCustomObject]) { return $obj }
    return $null
}

# A JSON property by exact (case-sensitive) name, or $null.
function Get-JsonValue($Obj, [string]$Name) {
    if ($null -eq $Obj) { return $null }
    foreach ($p in $Obj.PSObject.Properties) {
        if ($p.Name -ceq $Name) { return $p.Value }
    }
    return $null
}

# H:MM or HH:MM (lock_policy.parse_time_hhmm), normalized to HH:MM.
function ConvertTo-HHMM([string]$Raw) {
    $value = $Raw.Trim()
    if ($value -cnotmatch '^([0-9]{1,2}):([0-9]{2})\z') {
        throw "Invalid time '$Raw'; use HH:MM"
    }
    $hour = [int]$Matches[1]
    $minute = [int]$Matches[2]
    if ($hour -gt 23 -or $minute -gt 59) {
        throw "Invalid time '$Raw'; hour/minute out of range"
    }
    return '{0:D2}:{1:D2}' -f $hour, $minute
}

# A whole number the agents accept (integer, integral float, decimal string;
# never a bool), or $null.
function ConvertTo-WholeNumber($Value) {
    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    if ($Value -is [int] -or $Value -is [long]) { return [long]$Value }
    if ($Value -is [double] -or $Value -is [decimal]) {
        if ([math]::Floor($Value) -eq $Value -and [math]::Abs($Value) -le 9007199254740992) {
            return [long]$Value
        }
        return $null
    }
    if ($Value -is [string] -and $Value.Trim() -cmatch '^[+-]?[0-9]+\z') {
        try { return [long]$Value.Trim() } catch { return $null }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Accounts and profiles
# ---------------------------------------------------------------------------

# The account's canonical local name, or $null when there is no such account.
function Find-LocalAccount([string]$Name) {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $match = @(Get-LocalUser | Where-Object { $_.Name -eq $Name })
        if ($match.Count -gt 0) { return $match[0].Name }
        return $null
    }
    # 32-bit PowerShell has no LocalAccounts module.
    try {
        $account = New-Object Security.Principal.NTAccount($env:COMPUTERNAME, $Name)
        [void]$account.Translate([Security.Principal.SecurityIdentifier])
        return $Name
    } catch {
        return $null
    }
}

# %LOCALAPPDATA%\KidPCMonitor of the account that will run the agent, or $null
# when the account has no profile yet. Never guesses a path: creating
# C:\Users\<name> before the first logon makes Windows give the real profile a
# different folder.
function Get-AgentStateDir([string]$User, [bool]$IsSelf) {
    if ($IsSelf) {
        if (-not $env:LOCALAPPDATA) { return $null }
        return Join-Path $env:LOCALAPPDATA 'KidPCMonitor'
    }
    try {
        $account = New-Object Security.Principal.NTAccount($env:COMPUTERNAME, $User)
        $sid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $null
    }
    $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    if (-not (Test-Path -LiteralPath $key)) { return $null }
    $profileDir = (Get-ItemProperty -LiteralPath $key).ProfileImagePath
    if (-not $profileDir -or -not (Test-Path -LiteralPath $profileDir)) { return $null }
    return Join-Path $profileDir 'AppData\Local\KidPCMonitor'
}

function Confirm-SelfInstall([string]$CurrentUser) {
    Write-Host ""
    Write-Host "WARNING: You entered the current account ('$CurrentUser')."
    Write-Host "   Monitoring the same account that runs the installer is allowed,"
    Write-Host "   but it is the weakest setup:"
    Write-Host "   * The agent runs unelevated (LeastPrivilege), so this account can"
    Write-Host "     stop or delete the scheduled task and the install files."
    Write-Host "   * A remote lock can be undone by this same account."
    Write-Host "   * For real enforcement, monitor a separate standard (non-admin)"
    Write-Host "     account and run this installer from an administrator account."
    $choice = (Read-Host "`nProceed monitoring your own account anyway? (y/N)").Trim().ToLower()
    return ($choice -eq 'y' -or $choice -eq 'yes')
}

function Read-TargetUser([string]$CurrentUser, [string]$DefaultUser) {
    while ($true) {
        if ($DefaultUser) {
            $raw = (Read-Host "`nWhich Windows account should be monitored (the child's username) [$DefaultUser]").Trim()
            $name = if ($raw) { $raw } else { $DefaultUser }
        } else {
            $name = (Read-Host "`nWhich Windows account should be monitored (the child's username)").Trim()
        }
        if (-not $name) {
            Write-Host "ERROR: Username cannot be empty."
            continue
        }
        $found = Find-LocalAccount $name
        if (-not $found) {
            Write-Host "ERROR: Could not find a local Windows account named '$name'."
            $retry = (Read-Host "Try a different name? (y/n)").Trim().ToLower()
            if ($retry -ne 'y') { return $null }
            $DefaultUser = $null
            continue
        }
        if ($CurrentUser -and $found -eq $CurrentUser) {
            if (-not (Confirm-SelfInstall $CurrentUser)) { continue }
        }
        return $found
    }
}

# ---------------------------------------------------------------------------
# Agent binary and files
# ---------------------------------------------------------------------------

function Find-GoTool {
    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($candidate in @((Join-Path $env:ProgramFiles 'Go\bin\go.exe'), 'C:\Go\bin\go.exe')) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

function Test-GoSources {
    return Test-Path -LiteralPath (Join-Path $RepoRoot 'go\go.mod')
}

# The release asset suffix for this Windows: amd64 or arm64.
function Get-AgentArch {
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        default { throw "There is no released agent for $arch Windows; build it with Go instead." }
    }
}

function Get-AgentAssetName([string]$Arch) {
    return "kid-pc-agent-windows-$Arch.exe"
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
    return Join-Path ([IO.Path]::GetTempPath()) ("kid-pc-agent-{0}{1}" -f [guid]::NewGuid(), $Extension)
}

# The release to install: -Version, else the latest release's tag.
function Get-ReleaseTag {
    if ($Version) { return $Version }
    $latest = New-TempPath '.json'
    try {
        Invoke-Download "$GitHubApi/repos/$Repository/releases/latest" $latest
        $tag = Get-JsonValue (Read-JsonObject $latest) 'tag_name'
    } finally {
        Remove-Item -LiteralPath $latest -Force -ErrorAction SilentlyContinue
    }
    if (-not ($tag -is [string] -and $tag)) { throw "Could not find the latest release of $Repository." }
    return $tag
}

# Download one asset of a release into a temporary file and check it against
# the release's SHA256SUMS (as a name -> hash table). Returns the file's path.
function Get-VerifiedReleaseAsset([string]$Tag, [string]$Name, $Sums, [string]$Extension) {
    $expected = $Sums[$Name]
    if (-not $expected) { throw "SHA256SUMS in release $Tag has no entry for $Name." }
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

# This architecture's agent and the installer from a GitHub release, both
# checked against the release's SHA256SUMS.
function Get-ReleasedAgent([string]$Tag) {
    if (-not $Tag) { $Tag = Get-ReleaseTag }
    $asset = Get-AgentAssetName (Get-AgentArch)
    Write-Host "`nDownloading release $Tag of $Repository ..."
    $sumsFile = New-TempPath '.sha256'
    try {
        Invoke-Download "$GitHubWeb/$Repository/releases/download/$Tag/SHA256SUMS" $sumsFile
        $sums = Read-Checksums ([IO.File]::ReadAllText($sumsFile))
    } finally {
        Remove-Item -LiteralPath $sumsFile -Force -ErrorAction SilentlyContinue
    }
    $exe = Get-VerifiedReleaseAsset $Tag $asset $sums '.exe'
    $installer = $null
    if ($sums.ContainsKey('install_agent.ps1')) {
        try {
            $installer = Get-VerifiedReleaseAsset $Tag 'install_agent.ps1' $sums '.ps1'
        } catch {
            Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue
            throw
        }
    }
    return @{ Path = $exe; Temporary = $true; Version = $Tag; Installer = $installer }
}

# True when the agent will come from a release rather than -AgentExe or a build.
function Test-ReleaseMode {
    if ($AgentExe) { return $false }
    if ($Download) { return $true }
    return -not ((Find-GoTool) -and (Test-GoSources))
}

# The kid-pc-agent.exe to install: -AgentExe; else a build from go/ when Go and
# the sources are here (and -Download was not given); else the released exe.
# Returns @{ Path; Temporary; Version; Installer }: Temporary files are deleted
# after copying, Version is recorded in version.txt, and Installer (when set)
# is the install_agent.ps1 to keep next to the agent.
function Resolve-AgentExe([string]$Tag) {
    if ($AgentExe) {
        if (-not (Test-Path -LiteralPath $AgentExe -PathType Leaf)) {
            throw "Agent executable not found: $AgentExe"
        }
        $path = (Resolve-Path -LiteralPath $AgentExe).ProviderPath
        return @{ Path = $path; Temporary = $false; Version = 'custom'; Installer = $null }
    }
    if (Test-ReleaseMode) {
        if (-not $Download) { Write-Host "`nGo or the agent sources are not here; using the released agent." }
        return Get-ReleasedAgent $Tag
    }
    $go = Find-GoTool
    $out = New-TempPath '.exe'
    Write-Host "`nBuilding the Go agent with $go ..."
    Push-Location (Join-Path $RepoRoot 'go')
    try {
        & $go build -trimpath -buildvcs=false -ldflags '-H=windowsgui -s -w' -o $out ./cmd/kid-pc-agent
        if ($LASTEXITCODE -ne 0) { throw "go build failed (exit code $LASTEXITCODE)." }
    } finally {
        Pop-Location
    }
    return @{ Path = $out; Temporary = $true; Version = 'local build'; Installer = $null }
}

function Remove-ResolvedAgent($Agent) {
    if ($Agent.Temporary) { Remove-Item -LiteralPath $Agent.Path -Force -ErrorAction SilentlyContinue }
    if ($Agent.Installer) { Remove-Item -LiteralPath $Agent.Installer -Force -ErrorAction SilentlyContinue }
}

# The version recorded by the last install ("v1.2.0", "local build", "custom"),
# or $null.
function Get-InstalledVersion {
    $path = Join-Path $InstallDir 'version.txt'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $text = ([IO.File]::ReadAllText($path)).Trim()
    if ($text) { return $text }
    return $null
}

function Stop-AgentTask {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
}

function Start-AgentTask([string]$User) {
    try {
        Start-ScheduledTask -TaskName $TaskName
        Write-Host "Started the $TaskName agent (it runs now if $User is signed in, otherwise at their next logon)."
    } catch {
        Write-Host "Could not start the agent now (normal if $User isn't signed in); it runs at their next logon."
    }
}

# SYSTEM and Administrators: full control; the monitored account: read and
# execute; nobody else. ProgramData's default ACL would also let any user
# create files next to the agent.
function Set-InstallDirAcl([string]$User) {
    $output = & icacls.exe $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${User}:(OI)(CI)RX" /Q
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "icacls could not set permissions on ${InstallDir}: $output"
        return
    }
    if (Get-ChildItem -LiteralPath $InstallDir -Force | Select-Object -First 1) {
        $output = & icacls.exe (Join-Path $InstallDir '*') /reset /T /C /Q
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "icacls could not reset permissions under ${InstallDir}: $output"
        }
    }
}

# update.cmd, kept next to the agent so the parent can update (or switch
# automatic updates on and off) without the repository or Git.
$UpdateCmd = @'
@echo off
setlocal
rem Kid PC Monitor - update the agent to the latest release.
rem   update.cmd            update now
rem   update.cmd auto       turn ON automatic updates (startup + daily), then update
rem   update.cmd auto-off   turn OFF automatic updates
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    if "%~1"=="" (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '%*'"
    )
    exit /b
)
set "INSTALLER=powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_agent.ps1""
if /i "%~1"=="auto-off" (
    %INSTALLER% -DisableAutoUpdate
    goto :done
)
if /i "%~1"=="auto" %INSTALLER% -EnableAutoUpdate
%INSTALLER% -Update
:done
echo(
pause
'@

# Copy the agent into ProgramData with its version, a copy of the installer and
# update.cmd; remove the Python agent's files there and lock the folder down.
# Agent is what Resolve-AgentExe returned. Returns the installed agent's path.
function Install-AgentFiles([string]$User, $Agent) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Stop-AgentTask
    $dest = Join-Path $InstallDir $AgentExeName
    for ($attempt = 1; ; $attempt++) {
        try {
            Copy-Item -LiteralPath $Agent.Path -Destination $dest -Force
            break
        } catch {
            if ($attempt -ge 10) {
                throw "Could not replace $dest (is the agent still running?): $($_.Exception.Message)"
            }
            Start-Sleep -Milliseconds 500
        }
    }
    foreach ($name in $LegacyPythonFiles) {
        $legacy = Join-Path $InstallDir $name
        if (Test-Path -LiteralPath $legacy) {
            Remove-Item -LiteralPath $legacy -Recurse -Force
            Write-Host "   Removed the Python agent's $legacy"
        }
    }
    Write-FileAtomic (Join-Path $InstallDir 'version.txt') "$($Agent.Version)`r`n"
    # Keep an installer next to the agent: the release's when we have it, else
    # this one. (A running script is already parsed, so replacing it is safe.)
    $installerSource = if ($Agent.Installer) { $Agent.Installer } else { $PSCommandPath }
    $installerDest = Join-Path $InstallDir 'install_agent.ps1'
    if ($installerSource -and $installerSource -ne $installerDest) {
        Copy-Item -LiteralPath $installerSource -Destination $installerDest -Force
    }
    Write-FileAtomic (Join-Path $InstallDir 'update.cmd') ($UpdateCmd -replace "`r?`n", "`r`n")
    Set-InstallDirAcl $User
    return $dest
}

# ---------------------------------------------------------------------------
# Daily schedule
# ---------------------------------------------------------------------------

function Get-ProgramDataTargetUser {
    $target = Get-JsonValue (Read-JsonObject (Join-Path $InstallDir $DailySettingsFile)) 'target_user'
    if ($target -is [string] -and $target.Trim()) { return $target.Trim() }
    return $null
}

# @{ WakeTime; BedTime; Allowance } when the object has a usable wake time,
# bed time and positive allowance (agent_state.is_complete_daily_dict).
function Get-CompleteDaily($Obj) {
    if ($null -eq $Obj) { return $null }
    $wake = Get-JsonValue $Obj 'wake_time'
    $bed = Get-JsonValue $Obj 'bed_time'
    if (-not ($wake -is [string] -and $wake.Trim()) -or -not ($bed -is [string] -and $bed.Trim())) {
        return $null
    }
    $allowance = ConvertTo-WholeNumber (Get-JsonValue $Obj 'allowance')
    if ($null -eq $allowance -or $allowance -le 0) { return $null }
    try {
        return @{ WakeTime = (ConvertTo-HHMM $wake); BedTime = (ConvertTo-HHMM $bed); Allowance = $allowance }
    } catch {
        return $null
    }
}

function Read-ScheduleTime([string]$Prompt, [string]$Default) {
    while ($true) {
        $raw = (Read-Host "`n$Prompt (HH:MM, default $Default)").Trim()
        if (-not $raw) { $raw = $Default }
        try {
            return ConvertTo-HHMM $raw
        } catch {
            Write-Host "ERROR: $($_.Exception.Message)"
        }
    }
}

function Read-Allowance {
    while ($true) {
        $raw = (Read-Host "`nDaily allowance in minutes (blank for no limit)").Trim()
        if (-not $raw) { return $null }
        $minutes = ConvertTo-WholeNumber $raw
        if ($null -ne $minutes -and $minutes -gt 0) { return $minutes }
        Write-Host "ERROR: Enter a positive number of minutes."
    }
}

function Read-Schedule {
    Write-Host "`nBedtime"
    Write-Host "   The PC locks at this time and stays locked until wake-up."
    $bed = Read-ScheduleTime 'Bedtime' '21:00'
    Write-Host "`nWake-up time"
    Write-Host "   Bedtime locks stay active until this time each morning."
    Write-Host "   Daily screen-time limits also reset at wake-up (not at midnight)."
    $wake = Read-ScheduleTime 'Wake-up time' '07:00'
    Write-Host "`nDaily allowance"
    Write-Host "   Maximum screen time per day in minutes."
    Write-Host "   Leave blank for no daily cap (bedtime lock still applies)."
    $allowance = Read-Allowance
    return @{ WakeTime = $wake; BedTime = $bed; Allowance = $allowance }
}

function Write-ProgramDataDaily([string]$User, $Schedule) {
    $path = Join-Path $InstallDir $DailySettingsFile
    $payload = [ordered]@{
        target_user = $User
        wake_time   = $Schedule.WakeTime
        bed_time    = $Schedule.BedTime
        allowance   = $Schedule.Allowance
    }
    Write-FileAtomic $path ($payload | ConvertTo-Json)
    return $path
}

# Merge the schedule into the child's daily_settings.json, keeping any other
# keys, and give the child modify rights on its state folder.
function Write-ProfileDaily([string]$StateDir, [string]$User, $Schedule) {
    $path = Join-Path $StateDir $DailySettingsFile
    $merged = [ordered]@{}
    $existing = Read-JsonObject $path
    if ($null -ne $existing) {
        foreach ($p in $existing.PSObject.Properties) { $merged[$p.Name] = $p.Value }
    }
    $merged['wake_time'] = $Schedule.WakeTime
    $merged['bed_time'] = $Schedule.BedTime
    $merged['allowance'] = $Schedule.Allowance
    Write-FileAtomic $path ($merged | ConvertTo-Json -Depth 20)
    $output = & icacls.exe $StateDir /grant "${User}:(OI)(CI)M" /T /C /Q
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "icacls could not grant $User access to ${StateDir}: $output"
    }
    return $path
}

function Format-Allowance($Allowance) {
    if ($null -eq $Allowance) { return 'no daily cap' }
    return "$Allowance min/day"
}

# ---------------------------------------------------------------------------
# Shared secret (secrets_store.py: Fernet with a PBKDF2-derived key)
# ---------------------------------------------------------------------------

function Get-SecretsDirs {
    $override = "$env:KID_PC_MONITOR_SECRETS_DIR".Trim()
    if ($override) { return , @($override) }
    $machine = Join-Path $InstallDir 'secrets'
    $userBase = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $HOME }
    $user = Join-Path (Join-Path $userBase 'kid-pc-monitor') 'secrets'
    if ($user -eq $machine) { return , @($machine) }
    return , @($machine, $user)
}

$script:FernetKeyCache = @{}

function Get-FernetKey {
    $material = "$env:KID_PC_MONITOR_SECRET_KEY".Trim()
    if (-not $material) { $material = 'kid-pc-monitor-v3-shared-secret-kdf-2026' }
    if ($script:FernetKeyCache.ContainsKey($material)) { return , $script:FernetKeyCache[$material] }
    $password = [Text.Encoding]::UTF8.GetBytes($material)
    $salt = [Text.Encoding]::ASCII.GetBytes('kpm-fernet-salt')
    try {
        $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($password, $salt, 600000,
            [Security.Cryptography.HashAlgorithmName]::SHA256)
    } catch {
        throw "Deriving the secret key needs .NET Framework 4.7.2 or later: $($_.Exception.Message)"
    }
    try {
        [byte[]]$key = $kdf.GetBytes(32)
    } finally {
        $kdf.Dispose()
    }
    $script:FernetKeyCache[$material] = $key
    return , $key
}

function ConvertTo-Base64Url([byte[]]$Bytes) {
    return [Convert]::ToBase64String($Bytes).Replace('+', '-').Replace('/', '_')
}

function Get-HmacSha256([byte[]]$Key, [byte[]]$Data) {
    $hmac = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (, $Key)
    try { return , $hmac.ComputeHash($Data) } finally { $hmac.Dispose() }
}

# A Fernet token for PlainText (version 0x80 | timestamp | IV | AES-128-CBC | HMAC).
function Protect-Fernet([byte[]]$Key, [string]$PlainText) {
    [byte[]]$signKey = $Key[0..15]
    [byte[]]$encKey = $Key[16..31]
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $encKey
        $aes.GenerateIV()
        $plain = [Text.Encoding]::UTF8.GetBytes($PlainText)
        $encryptor = $aes.CreateEncryptor()
        try { $cipherText = $encryptor.TransformFinalBlock($plain, 0, $plain.Length) } finally { $encryptor.Dispose() }
        $iv = $aes.IV
    } finally {
        $aes.Dispose()
    }
    $timestamp = [BitConverter]::GetBytes([long][DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($timestamp) }
    $stream = New-Object IO.MemoryStream
    $stream.WriteByte(0x80)
    $stream.Write($timestamp, 0, 8)
    $stream.Write($iv, 0, 16)
    $stream.Write($cipherText, 0, $cipherText.Length)
    [byte[]]$body = $stream.ToArray()
    [byte[]]$tag = Get-HmacSha256 $signKey $body
    return ConvertTo-Base64Url ([byte[]]($body + $tag))
}

# The plaintext of a Fernet token, or $null when it does not verify.
function Unprotect-Fernet([byte[]]$Key, [string]$Token) {
    try {
        $b64 = $Token.Trim().Replace('-', '+').Replace('_', '/')
        [byte[]]$raw = [Convert]::FromBase64String($b64)
    } catch {
        return $null
    }
    if ($raw.Length -lt 73 -or $raw[0] -ne 0x80 -or (($raw.Length - 57) % 16) -ne 0) { return $null }
    [byte[]]$body = $raw[0..($raw.Length - 33)]
    [byte[]]$tag = $raw[($raw.Length - 32)..($raw.Length - 1)]
    [byte[]]$expected = Get-HmacSha256 ([byte[]]$Key[0..15]) $body
    $diff = 0
    for ($i = 0; $i -lt 32; $i++) { $diff = $diff -bor ($expected[$i] -bxor $tag[$i]) }
    if ($diff -ne 0) { return $null }
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = [byte[]]$Key[16..31]
        $aes.IV = [byte[]]$body[9..24]
        [byte[]]$cipherText = $body[25..($body.Length - 1)]
        $decryptor = $aes.CreateDecryptor()
        try {
            $plain = $decryptor.TransformFinalBlock($cipherText, 0, $cipherText.Length)
        } finally {
            $decryptor.Dispose()
        }
        return (New-Object System.Text.UTF8Encoding($false, $true)).GetString($plain)
    } catch {
        return $null
    } finally {
        $aes.Dispose()
    }
}

# @{ Secret; Path } for the first stored copy that decrypts, else $null.
function Find-StoredSecret([string]$Name) {
    $key = Get-FernetKey
    foreach ($dir in (Get-SecretsDirs)) {
        $path = Join-Path $dir "$Name.enc"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        try { $token = [IO.File]::ReadAllText($path) } catch { continue }
        $plain = Unprotect-Fernet $key $token
        if ($null -ne $plain) { return @{ Secret = $plain; Path = $path } }
    }
    return $null
}

# Encrypt and write the secret to the first secrets directory that accepts it.
function Save-StoredSecret([string]$Name, [string]$Value) {
    $token = Protect-Fernet (Get-FernetKey) $Value
    $lastError = $null
    foreach ($dir in (Get-SecretsDirs)) {
        try {
            $path = Join-Path $dir "$Name.enc"
            Write-FileAtomic $path $token
            return $path
        } catch {
            $lastError = $_
        }
    }
    throw "No writable secrets directory: $lastError"
}

function Read-SecretOnce([string]$Prompt) {
    $secure = Read-Host $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr).Trim()
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Read-NewSharedSecret {
    Write-Host "`nShared secret (web panel <-> monitoring agent)"
    Write-Host "`n   The web panel and the monitoring agent must share one secret so each"
    Write-Host "   can confirm the other's messages are genuine. Enter the SAME secret"
    Write-Host "   here and when you install the other half."
    Write-Host "`n   Best option:"
    Write-Host "     * Generate a random string in a password manager (Bitwarden,"
    Write-Host "       1Password, Apple Keychain, etc.) and paste it in on each PC."
    Write-Host "`n   If you can't use a password manager, pick something that is:"
    Write-Host "     * Easy for YOU to remember and type"
    Write-Host "     * Hard for your child (or anyone else) to guess"
    Write-Host "     * Like a password - but NOT one you use anywhere else"
    Write-Host "`n   A short phrase of a few unrelated words works well."
    Write-Host "`n   To change an existing secret, delete its .enc file under the secrets"
    Write-Host "   directory and re-run the installer."
    while ($true) {
        $secret = Read-SecretOnce "`n   Enter shared secret"
        if ($secret.Length -lt $MinSecretLength) {
            Write-Host "   ERROR: Too short - use at least $MinSecretLength characters."
            continue
        }
        $confirm = Read-SecretOnce '   Re-enter to confirm'
        if ($secret -cne $confirm) {
            Write-Host "   ERROR: Entries did not match. Please try again."
            continue
        }
        return $secret
    }
}

# Reuse a stored secret (re-saving it machine-wide, which migrates a copy an
# older install left in the admin's profile) or prompt for a new one.
function Install-SharedSecret {
    $existing = Find-StoredSecret $SharedSecretName
    if ($null -ne $existing) {
        $dest = Save-StoredSecret $SharedSecretName $existing.Secret
        if ($existing.Path -ne $dest) {
            Write-Host "`nReusing existing shared secret from $($existing.Path) (also saved to $dest)."
        } else {
            Write-Host "`nReusing existing shared secret from $dest."
        }
        return
    }
    $secret = Read-NewSharedSecret
    $path = Save-StoredSecret $SharedSecretName $secret
    Write-Host "   Shared secret saved (encrypted at rest) at $path."
}

# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------

function Get-AgentTaskXml([string]$UserId, [string]$ExePath) {
    $user = [Security.SecurityElement]::Escape($UserId)
    $command = [Security.SecurityElement]::Escape($ExePath)
    $workDir = [Security.SecurityElement]::Escape($InstallDir)
    return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Kid PC Monitor - Manages computer usage time</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>$user</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$user</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$command</Command>
      <WorkingDirectory>$workDir</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
}

# Register the logon task for the monitored account (unelevated, in their
# session, battery-friendly). Falls back to schtasks /xml if the cmdlets fail.
function Register-AgentTask([string]$User, [string]$ExePath, [bool]$IsSelf) {
    $userId = "$env:COMPUTERNAME\$User"
    $selfNote = if ($IsSelf) { ' (self-install)' } else { '' }
    Write-Host "`nTask configuration:"
    Write-Host "   Agent:      $ExePath"
    Write-Host "   Task name:  $TaskName"
    Write-Host "   Runs as:    $User$selfNote"
    $confirm = (Read-Host "`nProceed with these settings? (y/n)").Trim().ToLower()
    if ($confirm -ne 'y') {
        Write-Host "Setup cancelled."
        return $false
    }

    try {
        $action = New-ScheduledTaskAction -Execute $ExePath -WorkingDirectory $InstallDir
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
        $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -DontStopOnIdleEnd -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $TaskName -Description 'Kid PC Monitor - Manages computer usage time' `
            -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    } catch {
        Write-Warning "Register-ScheduledTask failed: $($_.Exception.Message)"
        Write-Host "Trying the XML method..."
        $xmlPath = Join-Path ([IO.Path]::GetTempPath()) ("kid-pc-monitor-task-{0}.xml" -f [guid]::NewGuid())
        try {
            [IO.File]::WriteAllText($xmlPath, (Get-AgentTaskXml $userId $ExePath), [Text.Encoding]::Unicode)
            $output = & schtasks.exe /create /tn $TaskName /xml $xmlPath /f
            if ($LASTEXITCODE -ne 0) {
                Write-Host "ERROR: Could not create the task: $output"
                return $false
            }
        } finally {
            Remove-Item -LiteralPath $xmlPath -Force -ErrorAction SilentlyContinue
        }
    }

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Host "ERROR: The task was not found after registering it."
        return $false
    }
    Write-Host "`nTask created and verified."
    Write-Host "   - Triggers: at logon of $User"
    Write-Host "   - Runs as:  $User (unelevated)"
    Write-Host "   - Battery:  starts and keeps running on battery"
    Write-Host "`nYou can check it in Task Scheduler (taskschd.msc)."
    return $true
}

function Remove-LegacyFirewallRule {
    $rules = Get-NetFirewallRule -DisplayName $LegacyFirewallRule -ErrorAction SilentlyContinue
    if (-not $rules) {
        Write-Host "INFO: No firewall rule to remove"
        return
    }
    $rules | Remove-NetFirewallRule
    Write-Host "SUCCESS: Firewall rule removed"
}

function Remove-Agent {
    Write-Host "`nRemoving task '$TaskName'..."
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-AgentTask
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Task removed successfully!"
    } else {
        Write-Host "Task not found or already removed."
    }
    # Left behind, the update task would put the agent files back.
    if (Get-ScheduledTask -TaskName $AutoUpdateTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $AutoUpdateTaskName -Confirm:$false
        Write-Host "Automatic-update task removed."
    }
    Write-Host "`nRemoving Windows Firewall rule..."
    Remove-LegacyFirewallRule
}

# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------

function Invoke-Install {
    $currentUser = "$env:USERNAME"
    $existingTarget = Get-ProgramDataTargetUser
    if ($existingTarget) {
        Write-Host "`nPrevious install targeted '$existingTarget' ($(Join-Path $InstallDir $DailySettingsFile))."
    }
    $targetUser = Read-TargetUser $currentUser $existingTarget
    if (-not $targetUser) {
        Write-Host "No valid user provided. Aborting."
        return $false
    }
    $isSelf = [bool]$currentUser -and $targetUser -eq $currentUser

    $agent = Resolve-AgentExe
    try {
        Write-Host "`nInstalling the agent ($($agent.Version)) to $InstallDir ..."
        $exePath = Install-AgentFiles $targetUser $agent
        Write-Host "   Granted $targetUser read+execute on the install directory."
    } finally {
        Remove-ResolvedAgent $agent
    }

    $stateDir = Get-AgentStateDir $targetUser $isSelf
    $profileDaily = if ($stateDir) { Read-JsonObject (Join-Path $stateDir $DailySettingsFile) } else { $null }
    $schedule = Get-CompleteDaily $profileDaily
    $source = if ($schedule) { Join-Path $stateDir $DailySettingsFile } else { $null }
    if (-not $schedule) {
        $schedule = Get-CompleteDaily (Read-JsonObject (Join-Path $InstallDir $DailySettingsFile))
        if ($schedule) { $source = Join-Path $InstallDir $DailySettingsFile }
    }
    if ($schedule) {
        Write-Host "`nReusing daily schedule from $source"
        Write-Host "   Wake-up: $($schedule.WakeTime) - Bedtime: $($schedule.BedTime) - Allowance: $(Format-Allowance $schedule.Allowance)"
    } else {
        $schedule = Read-Schedule
    }
    $configPath = Write-ProgramDataDaily $targetUser $schedule
    Write-Host "   Install daily_settings: $configPath"
    if ($stateDir) {
        $dailyPath = Write-ProfileDaily $stateDir $targetUser $schedule
        Write-Host "`nSchedule saved to $dailyPath"
        Write-Host "   Wake-up: $($schedule.WakeTime) - Bedtime: $($schedule.BedTime) - Allowance: $(Format-Allowance $schedule.Allowance)"
    } else {
        Write-Host ""
        Write-Warning ("$targetUser has no Windows profile yet, so the schedule was saved to ProgramData only. " +
            "The agent applies it at their first logon.")
    }

    Install-SharedSecret

    if (-not (Register-AgentTask $targetUser $exePath $isSelf)) {
        Write-Host "`nCould not create the task. Please check the messages above."
        return $false
    }
    Start-AgentTask $targetUser
    Update-LegacyAutoUpdateTask
    if (-not (Get-ScheduledTask -TaskName $AutoUpdateTaskName -ErrorAction SilentlyContinue)) {
        $answer = (Read-Host "`nInstall agent updates automatically (after startup and daily at 4am)? (Y/n)").Trim().ToLower()
        if ($answer -eq '' -or $answer -eq 'y' -or $answer -eq 'yes') {
            [void](Enable-AutoUpdate)
        } else {
            Write-Host "To update later, run $(Join-Path $InstallDir 'update.cmd') (or 'update.cmd auto' to turn on automatic updates)."
        }
    }
    Write-Host "`nSetup complete! The agent runs at $targetUser's logon, even on battery."
    return $true
}

function Invoke-GitPull {
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) {
        Write-Host "WARNING: git was not found; redeploying the current files."
        return
    }
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $git.Source -C $RepoRoot pull --ff-only 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            Write-Host "git pull: $($output.Trim())"
        } else {
            Write-Host "WARNING: 'git pull' failed: $($output.Trim()); redeploying the current files."
        }
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Invoke-Update {
    $targetUser = Get-ProgramDataTargetUser
    if (-not $targetUser) {
        Write-Host "ERROR: No previous install found (no monitored user recorded in ProgramData)."
        Write-Host "   Run a full install first:  install_agent.ps1"
        return $false
    }
    if ($Pull) { Invoke-GitPull }
    $tag = $null
    if (Test-ReleaseMode) {
        $tag = Get-ReleaseTag
        $installed = Get-InstalledVersion
        if ($installed -eq $tag) {
            # Nothing to do, and no reason to restart the agent (the automatic
            # update runs daily).
            Write-Host "The agent is already up to date ($tag)."
            if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
                Write-Host "WARNING: The $TaskName task is missing; run a full install to recreate it."
            }
            return $true
        }
        $from = if ($installed) { $installed } else { 'unknown version' }
        Write-Host "Updating from $from to $tag."
    }
    $agent = Resolve-AgentExe $tag
    try {
        Write-Host "Updating the agent in $InstallDir for '$targetUser' ..."
        Install-AgentFiles $targetUser $agent | Out-Null
        Write-Host "Agent updated ($($agent.Version))."
    } finally {
        Remove-ResolvedAgent $agent
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Start-AgentTask $targetUser
    } else {
        Write-Host "WARNING: The $TaskName task is missing; run a full install to recreate it."
    }
    return $true
}

function Enable-AutoUpdate {
    $fromCheckout = Test-GoSources
    if ($fromCheckout) {
        # Run this checkout's installer: git pull, then build with Go (or
        # download when Go is missing).
        $script = $PSCommandPath
        $workDir = $RepoRoot
        $arguments = '-Update -Pull'
        $git = Get-Command git -ErrorAction SilentlyContinue
        if ($git) {
            # The task runs as SYSTEM; trust the (user-owned) repo for it.
            $previous = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            & $git.Source config --system --add safe.directory ($RepoRoot -replace '\\', '/') 2>&1 | Out-Null
            $ErrorActionPreference = $previous
        }
    } else {
        # A standalone copy of this script (say, from a release download):
        # SYSTEM must not run it from a folder others can write to, so run a
        # copy kept in the locked-down install folder.
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        $script = Join-Path $InstallDir 'install_agent.ps1'
        if ($PSCommandPath -ne $script) { Copy-Item -LiteralPath $PSCommandPath -Destination $script -Force }
        $workDir = $InstallDir
        $arguments = '-Update'
    }
    if ($Download) { $arguments += ' -Download' }
    if ($Repository -ne 'cpmurphy/kid-pc-monitor') { $arguments += " -Repository `"$Repository`"" }
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        $action = New-ScheduledTaskAction -Execute $powershell `
            -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`" $arguments" `
            -WorkingDirectory $workDir
        $atStartup = New-ScheduledTaskTrigger -AtStartup
        $atStartup.Delay = 'PT2M'
        $daily = New-ScheduledTaskTrigger -Daily -At 4am
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $AutoUpdateTaskName -Action $action -Trigger @($atStartup, $daily) `
            -Principal $principal -Settings $settings -Force | Out-Null
    } catch {
        Write-Host "ERROR: Could not enable automatic updates: $($_.Exception.Message)"
        return $false
    }
    Write-Host "Automatic updates enabled (scheduled task '$AutoUpdateTaskName')."
    if ($fromCheckout) {
        Write-Host "   ~2 min after startup and daily at 4am the PC pulls this checkout and rebuilds"
        Write-Host "   the agent (Go and Git installed for all users), or downloads the latest"
        Write-Host "   release when Go is missing."
        Write-Host "   The task runs this checkout's code as SYSTEM: keep it where the child cannot write."
    } else {
        Write-Host "   ~2 min after startup and daily at 4am the PC installs the latest release."
    }
    return $true
}

# An automatic-update task left by the Python installer would keep copying the
# Python agent into ProgramData while the Go agent never updates. Point it at
# this installer instead, or remove it when Go is not available to rebuild.
function Update-LegacyAutoUpdateTask {
    $task = Get-ScheduledTask -TaskName $AutoUpdateTaskName -ErrorAction SilentlyContinue
    if (-not $task) { return }
    $runsPython = @($task.Actions | Where-Object { "$($_.Execute) $($_.Arguments)" -match 'install\.py' }).Count -gt 0
    if (-not $runsPython) { return }
    Write-Host "`nThe automatic-update task '$AutoUpdateTaskName' still runs the Python installer; updating it."
    if (Enable-AutoUpdate) { return }
    Unregister-ScheduledTask -TaskName $AutoUpdateTaskName -Confirm:$false
    Write-Host "   Removed it. Re-enable automatic updates with -EnableAutoUpdate."
}

function Disable-AutoUpdate {
    if (Get-ScheduledTask -TaskName $AutoUpdateTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $AutoUpdateTaskName -Confirm:$false
        Write-Host "Automatic updates disabled ('$AutoUpdateTaskName' removed)."
    } else {
        Write-Host "No automatic-update task was found."
    }
    return $true
}

function Invoke-Main {
    Write-Host "Kid PC Monitor - Agent Setup (Go agent)"
    Write-Host ('=' * 45)
    $nonInteractive = $Update -or $EnableAutoUpdate -or $DisableAutoUpdate

    if (-not (Test-Admin)) {
        Write-Host "`nERROR: This script needs to run as Administrator!"
        Write-Host "   Open PowerShell with 'Run as administrator' and try again."
        if (-not $nonInteractive) { Read-Host "`nPress Enter to exit" | Out-Null }
        return 1
    }

    try {
        if ($DisableAutoUpdate) { if (Disable-AutoUpdate) { return 0 } else { return 1 } }
        if ($EnableAutoUpdate) { if (Enable-AutoUpdate) { return 0 } else { return 1 } }
        if ($Update) { if (Invoke-Update) { return 0 } else { return 1 } }
        if ($Uninstall) { Remove-Agent; return 0 }
        if ($Install) { if (Invoke-Install) { return 0 } else { return 1 } }

        Write-Host "`nWhat would you like to do?"
        Write-Host "1. Create/Update scheduled task"
        Write-Host "2. Remove scheduled task"
        Write-Host "3. Exit"
        $choice = (Read-Host "`nChoice (1-3)").Trim()
        $code = 0
        if ($choice -eq '1') {
            Write-Host "`nCreating scheduled task with battery-friendly settings...`n"
            if (-not (Invoke-Install)) { $code = 1 }
        } elseif ($choice -eq '2') {
            Remove-Agent
        } else {
            Write-Host "`nExiting..."
        }
        Read-Host "`nPress Enter to close" | Out-Null
        return $code
    } catch {
        Write-Host "`nERROR: $($_.Exception.Message)"
        if (-not $nonInteractive) { Read-Host "`nPress Enter to close" | Out-Null }
        return 1
    }
}

# Dot-sourcing (". .\install_agent.ps1") loads the functions without running.
if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-Main)
}
