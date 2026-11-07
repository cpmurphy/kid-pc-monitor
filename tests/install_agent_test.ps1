<#
.SYNOPSIS
Tests for scripts/install_agent.ps1 that need no administrator rights.

.DESCRIPTION
Loads the installer's functions (dot-sourcing does not run it) and checks
time/number validation, the settings files it writes, Fernet secrets, the
task XML, the file install and ACL (in a temporary folder, never the real
ProgramData), and downloading a release (from a local stand-in for GitHub).
The release download is served by a local TCP listener, so the test needs no
Python.

    powershell -ExecutionPolicy Bypass -File tests\install_agent_test.ps1

Keep this file ASCII-only, like the installer.
#>

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'scripts\install_agent.ps1')

$work = Join-Path ([IO.Path]::GetTempPath()) ("kpm-installer-test-{0}" -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
$script:InstallDir = Join-Path $work 'programdata\KidPCMonitor'
$script:TaskName = 'KidPCMonitor-test-does-not-exist'
$script:AutoUpdateTaskName = 'KidPCMonitorUpdate-test-does-not-exist'
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

function Start-StaticServer([string]$Root, [int]$Port) {
    $state = [hashtable]::Synchronized(@{ Listener = $null })
    $ready = New-Object System.Threading.ManualResetEvent $false
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $script = {
        param($Root, $Port, $Ready, $State)
        $listener = New-Object System.Net.Sockets.TcpListener ([Net.IPAddress]::Loopback), $Port
        $State.Listener = $listener
        $listener.Start()
        [void]$Ready.Set()
        try {
            while ($true) {
                $client = $listener.AcceptTcpClient()
                try {
                    $stream = $client.GetStream()
                    $reader = New-Object System.IO.StreamReader ($stream, [Text.Encoding]::ASCII, $false, 1024, $true)
                    $request = $reader.ReadLine()
                    while ($true) {
                        $line = $reader.ReadLine()
                        if ([string]::IsNullOrEmpty($line)) { break }
                    }
                    $pathPart = '/'
                    if ($request -match '^GET\s+(\S+)') { $pathPart = $Matches[1] }
                    $pathPart = ($pathPart -split '\?')[0]
                    $rel = [Uri]::UnescapeDataString($pathPart.TrimStart('/')).Replace('/', [IO.Path]::DirectorySeparatorChar)
                    $file = Join-Path $Root $rel
                    if (-not $rel) {
                        $bytes = [Text.Encoding]::ASCII.GetBytes('ok')
                        $header = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n")
                        $stream.Write($header, 0, $header.Length)
                        $stream.Write($bytes, 0, $bytes.Length)
                    } elseif (Test-Path -LiteralPath $file -PathType Leaf) {
                        $bytes = [IO.File]::ReadAllBytes($file)
                        $header = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n")
                        $stream.Write($header, 0, $header.Length)
                        $stream.Write($bytes, 0, $bytes.Length)
                    } else {
                        $header = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 404 Not Found`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
                        $stream.Write($header, 0, $header.Length)
                    }
                    $stream.Flush()
                } catch {
                } finally {
                    $client.Close()
                }
            }
        } catch {
        } finally {
            $listener.Stop()
        }
    }
    [void]$ps.AddScript($script).AddArgument($Root).AddArgument($Port).AddArgument($ready).AddArgument($state)
    $handle = $ps.BeginInvoke()
    if (-not $ready.WaitOne(5000)) { throw 'static server did not start' }
    return @{ Runspace = $rs; PowerShell = $ps; Handle = $handle; State = $state }
}

function Stop-StaticServer($Server) {
    if (-not $Server) { return }
    try { if ($Server.State.Listener) { $Server.State.Listener.Stop() } } catch {}
    try { $Server.PowerShell.Stop() } catch {}
    try { $Server.Runspace.Close() } catch {}
}

try {
    Write-Host "times"
    Check 'H:MM normalized' (ConvertTo-HHMM ' 7:05 ') '07:05'
    Check 'surrounding whitespace stripped, as Python' (ConvertTo-HHMM "07:00`n") '07:00'
    foreach ($bad in @('24:00', '7:5', '07:60', 'ab:cd', '07:00x', '0 7:00')) {
        Check "rejects '$bad'" (Throws { ConvertTo-HHMM $bad }) $true
    }

    Write-Host "whole numbers"
    Check 'int' (ConvertTo-WholeNumber 90) 90
    Check 'integral float' (ConvertTo-WholeNumber 90.0) 90
    Check 'string' (ConvertTo-WholeNumber ' 45 ') 45
    Check 'bool rejected' ($null -eq (ConvertTo-WholeNumber $true)) $true
    Check 'fraction rejected' ($null -eq (ConvertTo-WholeNumber 1.5)) $true
    Check 'text rejected' ($null -eq (ConvertTo-WholeNumber 'ten')) $true

    Write-Host "complete schedule detection"
    $c = Get-CompleteDaily ('{"wake_time":"7:00","bed_time":"21:30","allowance":120}' | ConvertFrom-Json)
    Check 'complete' "$($c.WakeTime) $($c.BedTime) $($c.Allowance)" '07:00 21:30 120'
    foreach ($json in @(
            '{"wake_time":"7:00","bed_time":"21:30","allowance":null}',
            '{"wake_time":"7:00","bed_time":"21:30","allowance":0}',
            '{"wake_time":"25:00","bed_time":"21:30","allowance":5}',
            '{"Wake_Time":"7:00","bed_time":"21:30","allowance":5}')) {
        Check "incomplete: $json" ($null -eq (Get-CompleteDaily ($json | ConvertFrom-Json))) $true
    }

    Write-Host "settings files"
    $pd = Write-ProgramDataDaily 'kid' @{ WakeTime = '07:00'; BedTime = '21:00'; Allowance = $null }
    $stateDir = Join-Path $work 'profile\KidPCMonitor'
    New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
    [IO.File]::WriteAllText((Join-Path $stateDir 'daily_settings.json'), '{"allowance": 30, "extra": {"keep": [1, 2]}}')
    $prof = Write-ProfileDaily $stateDir $env:USERNAME @{ WakeTime = '06:45'; BedTime = '20:15'; Allowance = [long]90 }
    Check 'ProgramData file has no BOM' ([IO.File]::ReadAllBytes($pd)[0] -ne 0xEF) $true
    Check 'profile file has no BOM' ([IO.File]::ReadAllBytes($prof)[0] -ne 0xEF) $true
    Check 'target user recorded' (Get-ProgramDataTargetUser) 'kid'
    Check 'no .tmp left behind' (@(Get-ChildItem $stateDir -Filter *.tmp).Count) 0
    $merged = Read-JsonObject $prof
    Check 'merge keeps other keys' ((Get-JsonValue (Get-JsonValue $merged 'extra') 'keep') -join ',') '1,2'

    Write-Host "secrets"
    $key = Get-FernetKey
    Check 'key matches Python' (ConvertTo-Base64Url $key) 'qUqA0U6WzA-GgRiReFTkIGQJvDcJGqpYhxFpUg4w_sI='
    # Made by secrets_store (see secrets/secrets_test.go).
    $pyToken = 'gAAAAABp6t5AAAECAwQFBgcICQoLDA0OD_OFRh0TKmlE6CdoPCuWAwWGZ0ejHt5aU4hnXhhPx_X-d52027H8ltcRJYONXFCy9DxO4VCHyxyxDkVBrFgcstM='
    Check 'decrypts a Python token' (Unprotect-Fernet $key $pyToken) 'correct horse battery staple'
    $secret = 'PS-made secret ' + [char]0xFC + 'n' + [char]0xEF + ' ' + [char]0x2713
    $token = Protect-Fernet $key $secret
    Check 'round trip' (Unprotect-Fernet $key $token) $secret
    $flip = if ($token[40] -eq 'A') { 'B' } else { 'A' }
    Check 'tampered token rejected' ($null -eq (Unprotect-Fernet $key ($token.Substring(0, 40) + $flip + $token.Substring(41)))) $true
    $saved = Save-StoredSecret 'panel-agent-shared-secret' $secret
    Check 'saved where expected' $saved (Join-Path $env:KID_PC_MONITOR_SECRETS_DIR 'panel-agent-shared-secret.enc')
    Check 'found again' (Find-StoredSecret 'panel-agent-shared-secret').Secret $secret

    Write-Host "task XML"
    $xml = [xml](Get-AgentTaskXml 'PC\kid & co' 'C:\ProgramData\KidPCMonitor\kid-pc-agent.exe')
    Check 'user escaped' $xml.Task.Principals.Principal.UserId 'PC\kid & co'
    Check 'run level' $xml.Task.Principals.Principal.RunLevel 'LeastPrivilege'

    Write-Host "release checksums"
    $sums = Read-Checksums ("{0}  kid-pc-agent-windows-amd64.exe`n{1} *install_agent.ps1`r`nnot a line" -f ('A' * 64), ('b' * 64))
    Check 'text-mode entry, lower-cased' $sums['kid-pc-agent-windows-amd64.exe'] ('a' * 64)
    Check 'binary-mode entry' $sums['install_agent.ps1'] ('b' * 64)
    Check 'junk ignored' $sums.Count 2
    Check 'asset name' (Get-AgentAssetName 'arm64') 'kid-pc-agent-windows-arm64.exe'

    Write-Host "file install"
    $fakeExe = Join-Path $work 'fake-agent.exe'
    [IO.File]::WriteAllBytes($fakeExe, [byte[]](1..200))
    New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir 'kid_pc_monitor') | Out-Null
    Set-Content -LiteralPath (Join-Path $InstallDir 'pc_control.py') -Value 'legacy'
    $dest = Install-AgentFiles $env:USERNAME @{ Path = $fakeExe; Temporary = $false; Version = 'v0.0.1'; Installer = $null }
    Check 'agent copied' ((Get-FileHash $dest).Hash) ((Get-FileHash $fakeExe).Hash)
    Check 'legacy package removed' (Test-Path (Join-Path $InstallDir 'kid_pc_monitor')) $false
    Check 'legacy launcher removed' (Test-Path (Join-Path $InstallDir 'pc_control.py')) $false
    Check 'version recorded' (Get-InstalledVersion) 'v0.0.1'
    Check 'installer kept next to the agent' ((Get-FileHash (Join-Path $InstallDir 'install_agent.ps1')).Hash) ((Get-FileHash (Join-Path $repo 'scripts\install_agent.ps1')).Hash)
    $cmd = [IO.File]::ReadAllText((Join-Path $InstallDir 'update.cmd'))
    Check 'update.cmd runs the kept installer' ($cmd.Contains('%~dp0install_agent.ps1') -and $cmd.Contains('-Update')) $true
    Check 'update.cmd has CRLF line endings' (($cmd -split "`r`n").Count -eq ($cmd -split "`n").Count) $true
    $acl = Get-Acl $InstallDir
    Check 'inheritance removed' $acl.AreAccessRulesProtected $true
    $ids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    $mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Check 'only SYSTEM, Administrators and the child' ($ids -join ',') ((@('S-1-5-18', 'S-1-5-32-544', $mySid) | Sort-Object) -join ',')

    Write-Host "release download (local stand-in for GitHub)"
        $root = Join-Path $work 'release-server'
        $assetName = Get-AgentAssetName (Get-AgentArch)
        $dl = Join-Path $root 'web\owner\repo\releases\download\v9.9.9'
        New-Item -ItemType Directory -Force -Path $dl, (Join-Path $root 'api\repos\owner\repo\releases') | Out-Null
        Copy-Item $fakeExe (Join-Path $dl $assetName)
        $hash = (Get-FileHash -Algorithm SHA256 $fakeExe).Hash.ToLowerInvariant()
        $releasedInstaller = Join-Path $dl 'install_agent.ps1'
        [IO.File]::WriteAllText($releasedInstaller, "# the v9.9.9 installer`r`n", $Utf8NoBom)
        $installerHash = (Get-FileHash -Algorithm SHA256 $releasedInstaller).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText((Join-Path $dl 'SHA256SUMS'), "$hash  $assetName`n$installerHash  install_agent.ps1`n", $Utf8NoBom)
        [IO.File]::WriteAllText((Join-Path $root 'api\repos\owner\repo\releases\latest'), '{"tag_name": "v9.9.9"}', $Utf8NoBom)
        $bad = Join-Path $root 'web\owner\repo\releases\download\v0.0.1'
        New-Item -ItemType Directory -Force -Path $bad | Out-Null
        Copy-Item $fakeExe (Join-Path $bad $assetName)
        [IO.File]::WriteAllText((Join-Path $bad 'SHA256SUMS'), ('0' * 64) + "  $assetName`n", $Utf8NoBom)

        $probe = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
        $probe.Start(); $port = $probe.LocalEndpoint.Port; $probe.Stop()
        $server = Start-StaticServer $root $port
        try {
            $script:GitHubApi = "http://127.0.0.1:$port/api"
            $script:GitHubWeb = "http://127.0.0.1:$port/web"
            $script:Repository = 'owner/repo'
            for ($i = 0; $i -lt 50; $i++) {
                try { Invoke-WebRequest "http://127.0.0.1:$port/" -UseBasicParsing | Out-Null; break } catch { Start-Sleep -Milliseconds 200 }
            }
            $script:Version = ''
            $got = Get-ReleasedAgent
            Check 'latest release downloaded and verified' ((Get-FileHash $got.Path).Hash) ((Get-FileHash $fakeExe).Hash)
            Check 'release version reported' $got.Version 'v9.9.9'
            Check 'release installer downloaded and verified' ((Get-FileHash $got.Installer).Hash) ((Get-FileHash $releasedInstaller).Hash)
            Remove-ResolvedAgent $got
            Check 'downloads cleaned up' ((Test-Path $got.Path) -or (Test-Path $got.Installer)) $false
            $script:Version = 'v0.0.1'
            $before = @(Get-ChildItem ([IO.Path]::GetTempPath()) -Filter 'kid-pc-agent-*').Count
            Check 'checksum mismatch refused' (Throws { Get-ReleasedAgent }) $true
            Check 'refused download deleted' (@(Get-ChildItem ([IO.Path]::GetTempPath()) -Filter 'kid-pc-agent-*').Count) $before
            $script:Version = 'v404'
            Check 'missing release refused' (Throws { Get-ReleasedAgent }) $true
            $script:Version = ''
            $script:AgentExe = ''
            $script:Download = $true
            $viaResolve = Resolve-AgentExe
            Check '-Download uses the release' ((Get-FileHash $viaResolve.Path).Hash) ((Get-FileHash $fakeExe).Hash)
            Remove-ResolvedAgent $viaResolve

            Write-Host "update from a release (no Git, no checkout)"
            # A fresh install folder whose ACL this test does not tighten, so a
            # non-elevated run can write to it again.
            $script:InstallDir = Join-Path $work 'programdata2\KidPCMonitor'
            function Set-InstallDirAcl([string]$User) { }
            Write-ProgramDataDaily $env:USERNAME @{ WakeTime = '07:00'; BedTime = '21:00'; Allowance = $null } | Out-Null
            Install-AgentFiles $env:USERNAME @{ Path = $fakeExe; Temporary = $false; Version = 'v0.0.1'; Installer = $null } | Out-Null
            Check 'update to the latest release' (Invoke-Update) $true
            Check 'new version recorded' (Get-InstalledVersion) 'v9.9.9'
            Check 'kept installer replaced by the release one' ((Get-FileHash (Join-Path $InstallDir 'install_agent.ps1')).Hash) ((Get-FileHash $releasedInstaller).Hash)
            $exeTime = (Get-Item (Join-Path $InstallDir $AgentExeName)).LastWriteTimeUtc
            Start-Sleep -Milliseconds 50
            Check 'second update succeeds' (Invoke-Update) $true
            Check 'up-to-date agent left alone' ((Get-Item (Join-Path $InstallDir $AgentExeName)).LastWriteTimeUtc) $exeTime
        } finally {
            Stop-StaticServer $server
        }
} finally {
    # The test made $InstallDir read-only for this account; as its owner we can
    # still restore inherited permissions and delete everything.
    & icacls.exe $work /reset /T /C /Q | Out-Null
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Host "`n$($script:failures) check(s) FAILED"
    exit 1
}
Write-Host "`nall installer checks passed"
exit 0
