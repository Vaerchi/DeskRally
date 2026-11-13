<#
.SYNOPSIS
    Build DeskRallySetup.exe: preconfigured-ZIP bootstrap for a fixed MSI + baked endpoints.

.DESCRIPTION
    Validates inputs, bakes config into a generated header, compiles setup.cpp with the static
    CRT (/MT /W4 /WX /std:c++17), embeds the manifest via mt.exe, then emits the output ZIP
    contents (DeskRallyAgent.msi, DeskRallySetup.exe, installer-manifest.json) to OutDir.

    The control plane supplies enrollment.token and README.txt only after an authorized download
    request. Never bake an enrollment token into this shared release directory.

    vcvarsall.bat runs inside a cmd subshell so the PowerShell environment is not modified.

.PARAMETER Msi
    Path to the pre-built, verified DeskRallyAgent.msi to bundle.

.PARAMETER ControlPlaneUrl
    HTTPS control-plane URL baked into the binary (no userinfo/query/fragment).

.PARAMETER SignalingUrl
    WSS signaling URL baked into the binary (no userinfo/query/fragment).

.PARAMETER GrantIssuerPubkey
    Exactly 64 lowercase hexadecimal characters — the grant-issuer public key pin.

.PARAMETER OutDir
    Directory to receive DeskRallyAgent.msi, DeskRallySetup.exe, installer-manifest.json.

.PARAMETER Mode
    Baked (default; unchanged): the server's URLs, grant key and MSI hash are compiled in.
    Pass (docs/48 C): a GENERIC Setup that carries only -PassRootKey and takes the server from a
    signed deployment pass and the MSI identity from a signed release attestation beside it.
    -ControlPlaneUrl/-SignalingUrl are refused; -GrantIssuerPubkey, if given, only goes into a
    "mode":"pass" installer-manifest.json for one server.

.PARAMETER PassRootKey
    Pass mode only: DeskRally's deployment-pass root public key, 130 lowercase hex
    (rmt-pass-sign pubkey).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Msi,
    [string]$ControlPlaneUrl,
    [string]$SignalingUrl,
    [string]$GrantIssuerPubkey,
    [Parameter(Mandatory)][string]$OutDir,
    [ValidateSet('Baked', 'Pass')][string]$Mode = 'Baked',
    [string]$PassRootKey
)

$ErrorActionPreference = 'Stop'
$RepoRoot  = Split-Path -Parent $PSScriptRoot
$SetupSrc  = Join-Path $RepoRoot 'packaging/setup'
$TargetDir = Join-Path $RepoRoot 'target/setup'

# ---- Mode: an explicit, complete configuration or no build (docs/48 "Principles" 1) ----------
if ($Mode -eq 'Baked') {
    if ($PassRootKey) { throw '-PassRootKey belongs to -Mode Pass; a baked Setup must not carry it.' }
    foreach ($p in 'ControlPlaneUrl', 'SignalingUrl', 'GrantIssuerPubkey') {
        if (-not (Get-Variable $p -ValueOnly)) { throw "-Mode Baked needs -$p." }
    }
} else {
    if ($ControlPlaneUrl -or $SignalingUrl) { throw '-Mode Pass must not bake -ControlPlaneUrl/-SignalingUrl: the signed pass names the server.' }
    if ($PassRootKey -notmatch '^04[0-9a-f]{128}$') { throw '-Mode Pass needs -PassRootKey: 130 lowercase hex (SEC1 uncompressed P-256).' }
}
$ModeLabel = if ($Mode -eq 'Pass') { "MODE=PASS PASS_ROOT_KEY=$PassRootKey" } else { 'MODE=BAKED' }

# ---- Validate URIs -------------------------------------------------------

function Assert-SafeUri([string]$raw, [string]$scheme, [string]$name) {
    if ($raw -match '[^\x21-\x7e]|["\\]' -or $raw.Contains('?') -or $raw.Contains('#')) {
        throw "$name must be an ASCII URL without whitespace, query, fragment or backslash."
    }
    $u = $null
    if (-not [Uri]::TryCreate($raw, [UriKind]::Absolute, [ref]$u)) {
        throw "$name is not a valid absolute URI."
    }
    if ($u.Scheme -ne $scheme -or -not $u.Host) { throw "$name must use '$scheme' and name a host." }
    if ($u.UserInfo)              { throw "$name must not contain user-info." }
    if ($u.Query)                 { throw "$name must not contain a query string." }
    if ($u.Fragment)              { throw "$name must not contain a fragment." }
    # Guard against path-traversal characters that could escape a C string literal.
    if ($raw -match '["\r\n\x00]') { throw "$name contains characters that cannot be embedded safely." }
}

if ($Mode -eq 'Baked') {
    Assert-SafeUri $ControlPlaneUrl 'https' 'ControlPlaneUrl'
    Assert-SafeUri $SignalingUrl    'wss'   'SignalingUrl'
}

# ---- Validate pubkey --------------------------------------------------------

if ($GrantIssuerPubkey) {
    if ($GrantIssuerPubkey -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'GrantIssuerPubkey must be exactly 64 hexadecimal characters.'
    }
    $GrantIssuerPubkey = $GrantIssuerPubkey.ToLower()
}

# ---- Resolve and verify MSI -------------------------------------------------

if (-not (Test-Path -LiteralPath $Msi)) { throw "MSI not found: $Msi" }
$Msi = (Resolve-Path -LiteralPath $Msi).Path
if ([IO.Path]::GetExtension($Msi) -ne '.msi') { throw "Msi parameter must point to a .msi file." }
if ((Get-Item -LiteralPath $Msi).Length -gt 128MB) { throw 'MSI exceeds the supported artifact limit.' }
& (Join-Path $PSScriptRoot 'test-msi-contents.ps1') -Msi $Msi

# ---- Compute MSI SHA-256 ----------------------------------------------------

$sha = [Security.Cryptography.SHA256]::Create()
try {
    $msiStream = [IO.File]::OpenRead($Msi)
    try   { $msiHashBytes = $sha.ComputeHash($msiStream) }
    finally { $msiStream.Dispose() }
    $msiHash = ($msiHashBytes | ForEach-Object { $_.ToString('x2') }) -join ''
} finally { $sha.Dispose() }

# ---- Generate setup_config.h ------------------------------------------------

New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
$configPath = Join-Path $TargetDir 'setup_config.h'

# Escape backslash and double-quote for use in C wide string literals.
# Validated URIs and pubkey are ASCII-only; no other escapes are needed.
function Escape-CWide([string]$s) { $s.Replace('\', '\\').Replace('"', '\"') }

$cpuEsc  = Escape-CWide $ControlPlaneUrl
$sigEsc  = Escape-CWide $SignalingUrl

if ($Mode -eq 'Baked') {
$header = @"
#pragma once
// Generated by build-setup.ps1 -- do not edit.
#define SETUP_CONTROL_PLANE_URL   L"$cpuEsc"
#define SETUP_SIGNALING_URL       L"$sigEsc"
#define SETUP_GRANT_ISSUER_PUBKEY L"$GrantIssuerPubkey"
#define SETUP_MSI_SHA256          L"$msiHash"
#define SETUP_REQUIRE_SESSION_POLICY 1
"@
} else {
$header = @"
#pragma once
// Generated by build-setup.ps1 -Mode Pass -- do not edit. GENERIC: no server values, no MSI hash.
#define SETUP_MODE_PASS 1
#define SETUP_PASS_ROOT_KEY "$PassRootKey"
"@
}
[IO.File]::WriteAllText($configPath, $header, [Text.Encoding]::ASCII)
Write-Host "[setup] Generated $configPath ($ModeLabel)"

# ---- Version resource: the build MODE, readable from the exe (docs/48) -------------------------
$rcPath  = Join-Path $TargetDir 'setup_version.rc'
$resPath = Join-Path $TargetDir 'setup_version.res'
$rc = @"
#include <winver.h>
LANGUAGE 0x09, 0x01
1 VERSIONINFO
 FILEVERSION 1,0,0,0
 PRODUCTVERSION 1,0,0,0
 FILEOS VOS_NT_WINDOWS32
 FILETYPE VFT_APP
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "DeskRally"
      VALUE "FileVersion", "1.0.0.0"
      VALUE "ProductVersion", "1.0.0.0"
      VALUE "FileDescription", "DeskRally Setup"
      VALUE "ProductName", "DeskRally"
      VALUE "OriginalFilename", "DeskRallySetup.exe"
      VALUE "Comments", "$ModeLabel"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"@
[IO.File]::WriteAllText($rcPath, $rc, [Text.Encoding]::ASCII)

# ---- Locate MSVC -----------------------------------------------------------

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found. Install Visual Studio Build Tools.' }
$vsRoot  = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                       -property installationPath
if (-not $vsRoot) { throw 'MSVC x64 build tools not found.' }
$devCmd  = Join-Path $vsRoot 'VC/Auxiliary/Build/vcvarsall.bat'

# ---- Write isolated compile script ------------------------------------------
# vcvarsall.bat sets PATH, INCLUDE, LIB etc.; running inside cmd /d /c keeps those
# changes out of the PowerShell process environment entirely.

$setupExe      = Join-Path $TargetDir 'DeskRallySetup.exe'
$srcCpp        = Join-Path $SetupSrc  'setup.cpp'
$srcManifest   = Join-Path $SetupSrc  'setup.manifest'
$compileScript = Join-Path $TargetDir 'compile-setup.cmd'

$clArgs = '/nologo /MT /EHsc /std:c++17 /W4 /WX /O2'
$incArg = '/I"{0}"' -f $TargetDir
$linkArgs = 'bcrypt.lib shell32.lib ole32.lib user32.lib advapi32.lib /SUBSYSTEM:WINDOWS /MANIFEST:NO /DEPENDENTLOADFLAG:0x800'

$lines = @(
    '@echo off',
    ('call "{0}" x64 >nul' -f $devCmd),
    'if errorlevel 1 exit /b %errorlevel%',
    ('rc.exe /nologo /n /fo "{0}" "{1}"' -f $resPath, $rcPath),
    'if errorlevel 1 exit /b %errorlevel%',
    ('cl.exe {0} {1} /I"{5}" "{2}" /link {3} "{6}" /OUT:"{4}"' -f $clArgs, $incArg, $srcCpp, $linkArgs, $setupExe, $SetupSrc, $resPath),
    'if errorlevel 1 exit /b %errorlevel%',
    ('mt.exe -nologo -manifest "{0}" -outputresource:"{1}";1' -f $srcManifest, $setupExe),
    'exit /b %errorlevel%'
)
[IO.File]::WriteAllLines($compileScript, $lines, [Text.Encoding]::ASCII)

# ---- Compile ----------------------------------------------------------------

Write-Host "[setup] Compiling setup.cpp ..."
Push-Location $TargetDir
try {
    & $env:ComSpec /d /c $compileScript
    if ($LASTEXITCODE -ne 0) { throw "setup.cpp compilation failed (exit $LASTEXITCODE)" }
} finally { Pop-Location }

if (-not (Test-Path $setupExe)) {
    throw "Compile reported success but produced no exe at $setupExe"
}
# The mode, MEASURED from the built exe: what the signing pipeline asserts.
$builtMode = (Get-Item -LiteralPath $setupExe).VersionInfo.Comments
if ($builtMode -ne $ModeLabel) { throw "DeskRallySetup.exe reports '$builtMode', expected '$ModeLabel' (version resource missing or stale)." }
Write-Host "[setup] Version resource: $builtMode"

# ---- Compute setup SHA-256 --------------------------------------------------

$sha2 = [Security.Cryptography.SHA256]::Create()
try {
    $exeStream = [IO.File]::OpenRead($setupExe)
    try   { $setupHashBytes = $sha2.ComputeHash($exeStream) }
    finally { $exeStream.Dispose() }
    $setupHash = ($setupHashBytes | ForEach-Object { $_.ToString('x2') }) -join ''
} finally { $sha2.Dispose() }

# ---- Generate installer-manifest.json ---------------------------------------

$manifestPath = Join-Path $TargetDir 'installer-manifest.json'
Remove-Item -LiteralPath $manifestPath -ErrorAction SilentlyContinue
if ($Mode -eq 'Baked') {
    $manifest = [ordered]@{
        version               = 1
        control_plane_url     = $ControlPlaneUrl
        signaling_url         = $SignalingUrl
        grant_issuer_pubkey   = $GrantIssuerPubkey
        require_session_policy = $true
        msi_sha256            = $msiHash
        setup_sha256          = $setupHash
    }
} elseif ($GrantIssuerPubkey) {
    # A pass-mode manifest for ONE server: no URLs (the control plane takes them from the pass).
    $manifest = [ordered]@{
        version               = 1
        mode                  = 'pass'
        grant_issuer_pubkey   = $GrantIssuerPubkey
        require_session_policy = $true
        msi_sha256            = $msiHash
        setup_sha256          = $setupHash
    }
} else {
    $manifest = $null  # the generic artifacts alone; each server writes its own manifest
}
if ($manifest) {
    $manifestJson = $manifest | ConvertTo-Json -Depth 3
    [IO.File]::WriteAllText($manifestPath, $manifestJson, (New-Object Text.UTF8Encoding $false))
    Write-Host "[setup] Generated installer-manifest.json"
}

# ---- Copy to OutDir ---------------------------------------------------------

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

Copy-Item -LiteralPath $Msi         -Destination (Join-Path $OutDir 'DeskRallyAgent.msi')        -Force
Copy-Item -LiteralPath $setupExe    -Destination (Join-Path $OutDir 'DeskRallySetup.exe')         -Force
if ($manifest) { Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $OutDir 'installer-manifest.json') -Force }
if ((Get-FileHash -LiteralPath (Join-Path $OutDir 'DeskRallyAgent.msi') -Algorithm SHA256).Hash.ToLower() -ne $msiHash) {
    throw 'MSI changed while packaging. Rebuild the installer release.'
}

Write-Host "[ ok ] DeskRallySetup.exe  -> $OutDir  (sha256=$setupHash)"
Write-Host "[ ok ] DeskRallyAgent.msi  -> $OutDir  (sha256=$msiHash)"
if ($manifest) { Write-Host "[ ok ] installer-manifest.json -> $OutDir" }
Write-Host ""
Write-Host "Next: verify this release in the disposable Windows VM, then configure CP_MANAGED_INSTALL_DIR."
