<#
.SYNOPSIS
    Build the DeskRally Remote Agent MSI (docs/01 §6) from packaging/msi/RmtAgent.wxs via the WiX v4+ `wix`
    CLI. Packages a release agent_host.exe and registers the RmtAgent service.

.DESCRIPTION
    Idempotent: overwrites the output MSI. Locates `wix` on PATH or at the default WiX v7 install
    location. FAILS LOUDLY (throw) if wix is missing or the build fails; the caller (build-release.ps1)
    decides whether a missing wix is fatal or a skip.

.PARAMETER AgentExe
    Path to the release agent_host.exe to package. Default: dist/agent/agent_host.exe under the repo.

.PARAMETER Version
    MSI ProductVersion (major.minor.build). Must be 1.3.N for agent 0.1.N (auto-update version identity).

.PARAMETER Out
    Output .msi path. Default: dist/RmtAgent.msi.
#>
[CmdletBinding()]
param(
    [string]$AgentExe,
    [string]$Version = "1.3.0",
    [string]$Out,
    # Build kit own feed (docs/48 B.3): the exact https://<host> the agent was built with. The
    # packaged agent must report this feed; without it only DeskRally's feed is accepted.
    [string]$ExpectedFeed,
    # Explicit exceptions: a lab feed, or a build with auto-update disabled.
    [switch]$AllowTestFeed,
    [switch]$AllowNoPin
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Wxs = Join-Path $RepoRoot 'packaging/msi/RmtAgent.wxs'
if (-not $AgentExe) { $AgentExe = Join-Path $RepoRoot 'dist/agent/agent_host.exe' }
if (-not $Out)      { $Out      = Join-Path $RepoRoot 'dist/RmtAgent.msi' }

# Resolve the wix CLI: PATH first (the winget install adds it to the machine PATH), then the default
# WiX v7 location so a shell whose PATH predates the install still works.
function Resolve-Wix {
    $cmd = Get-Command wix -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $default = Join-Path ${env:ProgramFiles} 'WiX Toolset v7.0/bin/wix.exe'
    if (Test-Path $default) { return $default }
    return $null
}

$wix = Resolve-Wix
if (-not $wix) {
    throw "wix CLI not found (install with: winget install WiXToolset.WiXCLI). Cannot build the MSI."
}
if (-not (Test-Path $AgentExe)) {
    throw "agent exe not found at '$AgentExe' — build the agent (build-release.ps1) first."
}

# Refuse an agent without the provisioning/auto-update commands. Ask the binary (below) instead of
# scanning its bytes: once msi-capabilities printed several lines, the marker literal was no longer
# a contiguous run in the image (measured 2026-10-14), so a byte scan refused a correct build.

$abi = @(& $AgentExe msi-capabilities)
if ($LASTEXITCODE -ne 0 -or $abi -notcontains 'RMT-MSI-PROVISION-v1') { throw 'Agent MSI provisioning ABI probe failed.' }
# The package's custom actions call msi-health-gate / msi-autoupdate (auto-update design v3..v10.1).
if ($abi -notcontains 'RMT-MSI-AUTOUPDATE-v1') { throw 'Agent binary predates the auto-update MSI ABI.' }

# Auto-update packaging guards (design v3/v4): production feed, a real signer pin, and one version
# identity: agent 0.1.N <-> ProductVersion 1.3.N <-> agent_host FileVersion 0.1.N.0.
$feed = ($abi | Where-Object { $_ -like 'FEED=*' }) -replace '^FEED=', ''
$publisher = ($abi | Where-Object { $_ -like 'UPDATE-PUBLISHER=*' }) -replace '^UPDATE-PUBLISHER=', ''
if (($feed -eq 'none' -or -not $feed -or $publisher -eq 'none' -or -not $publisher) -and -not $AllowNoPin) {
    throw 'Agent has no compiled update identity; set DESKRALLY_UPDATE_OFFICIAL=1 or all three build-kit variables (DESKRALLY_UPDATE_FEED, DESKRALLY_UPDATE_PUBKEY_FILE, DESKRALLY_UPDATE_PUBLISHER), or pass -AllowNoPin.'
}
$wantFeed = if ($ExpectedFeed) { $ExpectedFeed } else { 'https://main.deskrally.com' }
if ($feed -ne $wantFeed -and -not $AllowTestFeed) {
    throw "Agent reports update feed '$feed' but '$wantFeed' was expected (update-test-feed build, or pass -ExpectedFeed for a build-kit own feed); refusing to package it."
}
$pin = ($abi | Where-Object { $_ -like 'UPDATE-PIN=*' }) -replace '^UPDATE-PIN=', ''
if ($pin -notmatch '^[0-9a-f]{64}$' -and -not $AllowNoPin) {
    throw 'Agent has no compiled update signer pin; set DESKRALLY_UPDATE_OFFICIAL=1 or all three build-kit variables (DESKRALLY_UPDATE_FEED, DESKRALLY_UPDATE_PUBKEY_FILE, DESKRALLY_UPDATE_PUBLISHER), or pass -AllowNoPin.'
}
# The agent must link the C runtime statically (+crt-static): a fresh Windows machine has no
# VC++ redistributable, and a dynamically linked agent_host fails to start (0xC0000135), which the
# MSI surfaces as a provisioning failure and rolls back (measured on the acceptance VM 2026-10-14).
$vsRoot2 = & (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe') -latest -products * -property installationPath
$dumpbin = Get-ChildItem (Join-Path $vsRoot2 'VC/Tools/MSVC') -Recurse -Filter dumpbin.exe -ErrorAction SilentlyContinue |
    Where-Object FullName -like '*Hostx64*x64*' | Select-Object -First 1
if (-not $dumpbin) { throw 'dumpbin.exe not found; cannot verify the agent links the CRT statically.' }
$dumpOut = @(& $dumpbin.FullName /nologo /dependents $AgentExe)
if ($LASTEXITCODE -ne 0) { throw "dumpbin could not read agent_host.exe's imports (exit $LASTEXITCODE)." }
$deps = @($dumpOut | Where-Object { $_ -match '\.dll\s*$' } | ForEach-Object { $_.Trim().ToLowerInvariant() })
# Every real agent imports kernel32; an empty or kernel32-less list means the inspection failed.
if ($deps.Count -eq 0 -or $deps -notcontains 'kernel32.dll') { throw "dumpbin returned no usable import list for agent_host.exe; refusing to package." }
$dynamicCrt = @($deps | Where-Object { $_ -like 'vcruntime*' -or $_ -like 'msvcp*' -or $_ -like 'api-ms-win-crt-*' -or $_ -like 'ucrtbase*' })
if ($dynamicCrt.Count -gt 0) { throw ("agent_host.exe links the CRT dynamically ({0}); build with RUSTFLAGS='-C target-feature=+crt-static'." -f ($dynamicCrt -join ', ')) }

$agentVersion = (& $AgentExe version).Trim()
if ($agentVersion -notmatch '^0\.1\.(\d+)(\+[0-9a-f]+)?$') { throw "Agent version '$agentVersion' is not 0.1.N." }
$n = [int]$Matches[1]
if ($Version -ne "1.3.$n") { throw "ProductVersion '$Version' does not map to agent $agentVersion (expected 1.3.$n)." }
$fileVersion = (Get-Item $AgentExe).VersionInfo.FileVersion
if ($fileVersion -ne "0.1.$n.0") { throw "agent_host.exe FileVersion '$fileVersion' is not 0.1.$n.0 (VERSIONINFO missing or stale)." }

$outDir = Split-Path -Parent $Out
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

# Static-CRT native bridge; no shell or secret command-line enrollment arguments.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vsRoot = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsRoot) { throw 'MSVC x64 build tools are required for the MSI custom action.' }
$devCmd = Join-Path $vsRoot 'VC/Auxiliary/Build/vcvarsall.bat'
$actionsDir = Join-Path $RepoRoot 'target/msi-actions'
New-Item -ItemType Directory -Force -Path $actionsDir | Out-Null
$actionsDll = Join-Path $actionsDir 'DeskRallyMsiActions.dll'
$actionsSource = Join-Path $RepoRoot 'packaging/msi/actions.cpp'
$compileScript = Join-Path $actionsDir 'compile-actions.cmd'
$compileLines = @('@echo off', ('call "{0}" x64 >nul' -f $devCmd),
    'if errorlevel 1 exit /b %errorlevel%',
    ('cl.exe /nologo /LD /MT /EHsc /std:c++17 /W4 /WX /O2 "{0}" /link msi.lib version.lib advapi32.lib ole32.lib /OUT:"{1}"' -f $actionsSource, $actionsDll),
    'exit /b %errorlevel%')
[IO.File]::WriteAllLines($compileScript, $compileLines, [Text.Encoding]::ASCII)
Push-Location $actionsDir
try {
    & $env:ComSpec /d /c $compileScript
    if ($LASTEXITCODE -ne 0) { throw "MSI custom-action compilation failed: $LASTEXITCODE" }
} finally { Pop-Location }

Write-Host "[msi] wix: $wix"
Write-Host "[msi] packaging: $AgentExe  ->  $Out  (v$Version)"
# WiX v7 refuses to build until the Open Source Maintenance Fee (OSMF) EULA is accepted (WIX7015). The
# repo owner accepted these terms (2026-08-19, loop 61); persist the acceptance here so every build — the
# gate and the release — runs non-interactively. `wix eula accept` is idempotent (a no-op once accepted).
& $wix eula accept wix7 2>&1 | Out-Null
# The MSI carries LICENSE, NOTICE and the third-party notices of everything linked into the agent.
# A stale notices file (Cargo.lock changed since it was generated) fails the package, not a reader.
# Prefer an explicit interpreter: a bare `python` can be the Microsoft Store alias stub.
$python = Get-Command $(if ($env:DESKRALLY_PYTHON) { $env:DESKRALLY_PYTHON } else { 'C:/Python314/python.exe' }) -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python3, python -ErrorAction SilentlyContinue | Where-Object { $_.Source -notlike '*WindowsApps*' } | Select-Object -First 1 }
if (-not $python) { throw 'python is required to verify packaging/notices/THIRD-PARTY-NOTICES.txt' }
& $python.Source -I (Join-Path $RepoRoot 'scripts/third_party_notices.py') --check
if ($LASTEXITCODE -ne 0) { throw 'third-party notices are stale: run scripts/third_party_notices.py and commit the result' }
& $wix build $Wxs -arch x64 "-d" "AgentExe=$AgentExe" "-d" "Version=$Version" "-d" "ActionsDll=$actionsDll" "-d" "RepoRoot=$RepoRoot" "-o" $Out
if ($LASTEXITCODE -ne 0) { throw "wix build failed (exit $LASTEXITCODE)" }
if (-not (Test-Path $Out)) { throw "wix build reported success but produced no MSI at '$Out'" }

# Windows Installer fails an install with error 2613 when any script-generating custom action is
# sequenced between InstallInitialize and RemoveExistingProducts (acceptance VM, 2026-10-15).
$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Out, 0))
$view = $db.OpenView('SELECT `Action`, `Sequence` FROM `InstallExecuteSequence`')
$view.Execute()
$seq = @{}
while ($row = $view.Fetch()) { $seq[$row.StringData(1)] = $row.IntegerData(2) }
$ca = $db.OpenView('SELECT `Action`, `Type` FROM `CustomAction`')
$ca.Execute()
while ($row = $ca.Fetch()) {
    $name = $row.StringData(1); $type = $row.IntegerData(2)
    $scripted = ($type -band 0x400) -ne 0   # msidbCustomActionTypeInScript
    if ($scripted -and $seq.ContainsKey($name) -and $seq[$name] -gt $seq['InstallInitialize'] -and $seq[$name] -lt $seq['RemoveExistingProducts']) {
        throw "custom action '$name' is scheduled between InstallInitialize and RemoveExistingProducts (Windows Installer error 2613)"
    }
}
Write-Host '[ok] No script action between InstallInitialize and RemoveExistingProducts'
# Release every COM reference now: a leaked database handle kept the MSI open, and the signing
# step that follows packaging failed with "file is being used by another process" (2026-10-15).
$view.Close(); $ca.Close()
foreach ($o in @($row, $view, $ca, $db, $installer)) {
    if ($null -ne $o) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($o) }
}
$row = $view = $ca = $db = $installer = $null
[GC]::Collect(); [GC]::WaitForPendingFinalizers()
& (Join-Path $PSScriptRoot 'test-msi-contents.ps1') -Msi $Out
Write-Host "[ ok ] built $Out ($([math]::Round((Get-Item $Out).Length / 1KB)) KiB)"
