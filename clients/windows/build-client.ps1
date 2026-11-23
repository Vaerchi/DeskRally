#Requires -Version 5.1
<#
.SYNOPSIS
    Build DeskRally Windows client (client.cpp + WebView2).

.DESCRIPTION
    1. Locates MSVC BuildTools via vswhere.
    2. Downloads/verifies WebView2 NuGet package (pinned SHA-256).
    3. Compiles client.cpp /MT with static WebView2Loader.
    4. Compiles client_policy_test.cpp (no WebView2 - pure policy tests).
    5. Runs policy tests.
    6. Optionally compiles smoke-test variant (SMOKE_TEST defined) - not launched.
    Default output: the repository target\desktop-client directory.
    Override with -OutDir.

.PARAMETER OutDir
    Output directory for all build artifacts. Defaults to the repository target\desktop-client directory.

.PARAMETER TenantZone
    Bare organization DNS suffix; defaults to the hosted service deskrally.com.

.PARAMETER OfficialUpdates
    Explicitly pin packaging/official-update-identity.json for official releases.
.PARAMETER UpdateHost
    Own update host[:port], paired with UpdatePublisher; excludes OfficialUpdates.
.PARAMETER UpdatePublisher
    Exact Authenticode subject for the own update host.
.PARAMETER SmokeTestBuild
    Also produce DeskRallyClient-smoke.exe (SMOKE_TEST defined; not launched here).

.EXAMPLE
    .\build-client.ps1
    .\build-client.ps1 -SmokeTestBuild
    .\build-client.ps1 -OutDir C:\build-output -SmokeTestBuild
#>
param(
    [string]$OutDir = "",
    [string]$TenantZone = "",
    [switch]$SmokeTestBuild,
    [switch]$OfficialUpdates,
    [string]$UpdateHost = "",
    [string]$UpdatePublisher = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = Join-Path $PSScriptRoot '..\..\target\desktop-client' }
$OutDir = [IO.Path]::GetFullPath($OutDir)

# Resolve identity before discovering tools or acquiring build dependencies.
$ownHost = $PSBoundParameters.ContainsKey('UpdateHost')
$ownPublisher = $PSBoundParameters.ContainsKey('UpdatePublisher')
if ($OfficialUpdates -and ($ownHost -or $ownPublisher)) {
    throw '-OfficialUpdates cannot be combined with -UpdateHost or -UpdatePublisher'
}
if ($ownHost -ne $ownPublisher) { throw '-UpdateHost and -UpdatePublisher must be supplied together' }
if ($OfficialUpdates) {
    $identity = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\packaging\official-update-identity.json') -Raw | ConvertFrom-Json
    if ($identity.feed -isnot [string] -or -not $identity.feed.StartsWith('https://')) {
        throw 'Official update feed must start with https://'
    }
    $UpdateHost = $identity.feed.Substring(8)
    if ($identity.publisher -isnot [string]) { throw 'Official publisher must be a string' }
    $UpdatePublisher = $identity.publisher
}
$UpdateDefines = @()
if ($OfficialUpdates -or $ownHost) {
    $uri = $null
    # Port 0 would reach WinHTTP as "default port" (443) while the manifest URL check expects ":0".
    if ([string]::IsNullOrWhiteSpace($UpdateHost) -or $UpdateHost -match '[/@?#\\";\s\x00-\x1f\x7f]' -or
        ($UpdateHost -match ':(\d+)$' -and ([long]$Matches[1] -lt 1 -or [long]$Matches[1] -gt 65535)) -or
        -not [Uri]::TryCreate("https://$UpdateHost", [UriKind]::Absolute, [ref]$uri) -or
        $uri.HostNameType -eq [UriHostNameType]::Unknown -or $uri.AbsolutePath -ne '/') {
        throw 'UpdateHost must be a bare host[:port], without scheme, path, userinfo, or whitespace'
    }
    if ([string]::IsNullOrWhiteSpace($UpdatePublisher) -or $UpdatePublisher -match '[\x00-\x1f\x7f"]') {
        throw 'UpdatePublisher must be non-empty, one line, without double quotes'
    }
    # Response-file arguments avoid PowerShell's native argument quote rewriting.
    # Outer quotes group each argument; \" reaches cl as a C string-literal quote.
    $publisherLiteral = $UpdatePublisher.Replace('\', '\\')
    # A trailing C-literal backslash run precedes the closing escaped quote;
    # double that run again for the response-file argument parser.
    $publisherLiteral = [regex]::Replace($publisherLiteral, '\\+$', {
        param($match)
        $match.Value + $match.Value
    })
    $UpdateDefines = @(
        ('"/DDESKRALLY_UPDATE_HOST=\"{0}\""' -f $UpdateHost),
        ('"/DDESKRALLY_UPDATE_PUBLISHER=\"{0}\""' -f $publisherLiteral)
    )
    Write-Host "Self-update configured for $UpdateHost"
} else {
    Write-Host 'Self-update is OFF: updates are not configured in this build'
}

# Keep the tenant define in the same response file as the update defines.
if ($PSBoundParameters.ContainsKey('TenantZone')) {
    if ($TenantZone.Length -gt 253 -or $TenantZone -cnotmatch '\A[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)+\z') {
        throw 'TenantZone must be a lowercase DNS suffix with at least one dot, no empty labels or label-edge hyphens, and at most 253 characters'
    }
    $UpdateDefines += ('"/DDESKRALLY_TENANT_ZONE=\"{0}\""' -f $TenantZone)
    Write-Host "Tenant zone: $TenantZone"
} else {
    Write-Host 'Tenant zone: deskrally.com (hosted service default)'
}

# Use .NET SHA256 directly; Get-FileHash may be absent when $PSModulePath is modified.
function Get-Sha256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha.ComputeHash(
            [System.IO.File]::ReadAllBytes($Path))).Replace('-','').ToLower()
    } finally { $sha.Dispose() }
}

# ── Paths ──────────────────────────────────────────────────────────────────
$SrcDir   = $PSScriptRoot
$NugetDir = Join-Path $OutDir 'nuget'
$WebView2 = 'Microsoft.Web.WebView2'
$WV2Ver   = '1.0.4191.47'
$WV2Pkg   = Join-Path $NugetDir "$WebView2.$WV2Ver.nupkg"

# Pinned SHA-256 verified at package acquisition (2026-09-30).
$WV2Sha256 = 'f492bbf547d0da329553b6727435b677579b1e9f91cc9e4a1ad029366d5f23d0'

New-Item -ItemType Directory -Force -Path $OutDir  | Out-Null
New-Item -ItemType Directory -Force -Path $NugetDir | Out-Null

# Smoke test fixture directory
$FixtureDir = Join-Path $OutDir 'test-fixtures'
New-Item -ItemType Directory -Force -Path $FixtureDir | Out-Null

# ── Locate vswhere ─────────────────────────────────────────────────────────
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vsWhere)) { throw "vswhere not found at $vsWhere" }

$vsInstall = & $vsWhere -products '*' -prerelease -latest -property installationPath
if (-not $vsInstall) { throw "No Visual Studio / BuildTools installation found" }
Write-Host "VS install: $vsInstall"

# ── Find cl.exe ────────────────────────────────────────────────────────────
# cl.exe lives at: <install>\VC\Tools\MSVC\<ver>\bin\Hostx64\x64\cl.exe
# Three .Parent steps from Directory gives the MSVC version root.
$clPath = Get-ChildItem "$vsInstall\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe" |
            Sort-Object FullName | Select-Object -Last 1
if (-not $clPath) { throw "cl.exe not found under $vsInstall" }
$ClExe   = $clPath.FullName
$MSVCDir = $clPath.Directory.Parent.Parent.Parent.FullName  # …/VC/Tools/MSVC/<ver>
$LinkExe = Join-Path $clPath.Directory 'link.exe'
$RcExe   = Join-Path $clPath.Directory 'rc.exe'
Write-Host "cl.exe:  $ClExe"
Write-Host "MSVC:    $MSVCDir"

# ── Find Windows SDK ───────────────────────────────────────────────────────
$KitRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
$KitVer  = Get-ChildItem "$KitRoot\Include" | Where-Object PSIsContainer |
           Sort-Object Name | Select-Object -Last 1 -ExpandProperty Name
if (-not $KitVer) { throw "Windows 10 SDK not found under $KitRoot" }
Write-Host "Win SDK: $KitVer"

$IncMSVC  = "$MSVCDir\include"
$IncUM    = "$KitRoot\Include\$KitVer\um"
$IncUCRT  = "$KitRoot\Include\$KitVer\ucrt"
$IncSh    = "$KitRoot\Include\$KitVer\shared"
$IncWinRT = "$KitRoot\Include\$KitVer\winrt"  # WRL headers live here
$LibMSVC  = "$MSVCDir\lib\x64"
$LibUM    = "$KitRoot\Lib\$KitVer\um\x64"
$LibUCRT  = "$KitRoot\Lib\$KitVer\ucrt\x64"

$RcExeKit = "$KitRoot\bin\$KitVer\x64\rc.exe"
if (Test-Path $RcExeKit) { $RcExe = $RcExeKit }
if (-not (Test-Path $RcExe)) { throw "rc.exe not found" }

# ── Download WebView2 NuGet package ───────────────────────────────────────
$WV2Url = "https://www.nuget.org/api/v2/package/$WebView2/$WV2Ver"
if (-not (Test-Path $WV2Pkg)) {
    Write-Host "Downloading $WebView2 $WV2Ver ..."
    Invoke-WebRequest -Uri $WV2Url -OutFile $WV2Pkg -UseBasicParsing
    Write-Host "Downloaded: $WV2Pkg"
}

# Verify pinned SHA-256
$actual = Get-Sha256 $WV2Pkg
Write-Host "WebView2 package SHA-256: $actual"
if ($actual -ne $WV2Sha256.ToLower()) {
    throw "WebView2 package SHA-256 mismatch!`nExpected: $WV2Sha256`nActual:   $actual"
}
Write-Host "Hash verified OK"

# ── Extract NuGet package (it's a zip) ────────────────────────────────────
$WV2ExtDir = Join-Path $NugetDir "$WebView2.$WV2Ver"
if (-not (Test-Path $WV2ExtDir)) {
    Write-Host "Extracting WebView2 package ..."
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($WV2Pkg, $WV2ExtDir)
}

$WV2Inc = "$WV2ExtDir\build\native\include"
$WV2Lib = "$WV2ExtDir\build\native\x64\WebView2LoaderStatic.lib"
if (-not (Test-Path $WV2Inc)) { throw "WebView2 headers not found at $WV2Inc" }
if (-not (Test-Path $WV2Lib)) { throw "WebView2LoaderStatic.lib not found at $WV2Lib" }
Write-Host "WebView2 include: $WV2Inc"
Write-Host "WebView2 lib:     $WV2Lib"

# ── Common compiler flags ─────────────────────────────────────────────────
# Build-time source metadata for Help > About (a label, not provenance): the short commit, "-dirty"
# when clients/windows had uncommitted changes when sampled, and "unknown" when either git query
# fails, rather than a clean-looking commit nobody verified.
$BuildCommit = 'dev'
try {
    $head = (& git -C $SrcDir rev-parse --short=7 HEAD 2>$null)
    $headOk = ($LASTEXITCODE -eq 0) -and $head
    $dirty = (& git -C $SrcDir status --porcelain -- . 2>$null)
    $statusOk = ($LASTEXITCODE -eq 0)
    if ($headOk -and $statusOk) {
        $BuildCommit = if ($dirty) { "$head-dirty" } else { "$head" }
    } elseif ($headOk) {
        $BuildCommit = "$head-unknown"
    }
} catch { $BuildCommit = 'dev' }
$BuildInfoHeader = Join-Path $OutDir 'build_info.h'
[IO.File]::WriteAllText($BuildInfoHeader, "#pragma once`r`n#define DESKRALLY_COMMIT L`"$BuildCommit`"`r`n", [Text.UTF8Encoding]::new($false))
Write-Host "Build commit: $BuildCommit"
$UpdateDefinesFile = Join-Path $OutDir 'update-defines.rsp'
[IO.File]::WriteAllLines($UpdateDefinesFile, $UpdateDefines, [Text.UTF8Encoding]::new($false))
$CommonCFlags = @(
    # No literal quotes: PowerShell quotes the argument itself if the path has spaces.
    ('@{0}' -f $UpdateDefinesFile),
    '/nologo', '/W4', '/WX', '/EHsc', '/std:c++17', '/MT', '/utf-8',
    '/DUNICODE', '/D_UNICODE', '/DWINVER=0x0A00', '/D_WIN32_WINNT=0x0A00',
    '/DWIN32_LEAN_AND_MEAN',
    "/I`"$IncMSVC`"", "/I`"$IncUM`"", "/I`"$IncUCRT`"", "/I`"$IncSh`"",
    "/I`"$IncWinRT`"",
    "/I`"$SrcDir`"",
    "/FI`"$BuildInfoHeader`""
)

$CommonLFlags = @(
    '/nologo',
    "/LIBPATH:`"$LibMSVC`"", "/LIBPATH:`"$LibUM`"", "/LIBPATH:`"$LibUCRT`"",
    'user32.lib', 'shell32.lib', 'ole32.lib', 'oleaut32.lib',
    'shlwapi.lib', 'version.lib', 'advapi32.lib', 'runtimeobject.lib',
    'winhttp.lib', 'wintrust.lib', 'crypt32.lib', 'bcrypt.lib', 'comctl32.lib', 'gdi32.lib'
)

# ── Build: policy tests (no WebView2 headers needed) ─────────────────────
Write-Host "`n=== Building policy tests ==="
$PolicyTestObj = Join-Path $OutDir 'client_policy_test.obj'
$PolicyTestExe = Join-Path $OutDir 'policy_test.exe'

$policyArgs = $CommonCFlags + @(
    '/c', "`"$SrcDir\client_policy_test.cpp`"",
    "/Fo`"$PolicyTestObj`""
)
& $ClExe @policyArgs
if ($LASTEXITCODE -ne 0) { throw "Policy test compile failed (exit $LASTEXITCODE)" }

$linkPolicyArgs = $CommonLFlags + @(
    "`"$PolicyTestObj`"",
    "/OUT:`"$PolicyTestExe`""
)
& $LinkExe @linkPolicyArgs
if ($LASTEXITCODE -ne 0) { throw "Policy test link failed (exit $LASTEXITCODE)" }
Write-Host "policy_test.exe built: $PolicyTestExe"

# ── Run policy tests ───────────────────────────────────────────────────────
Write-Host "`n=== Running policy tests ==="
$testOut = & $PolicyTestExe 2>&1
$testOut | Write-Host
if ($LASTEXITCODE -ne 0) { throw "Policy tests FAILED (exit $LASTEXITCODE)" }
Write-Host "Policy tests PASSED"

Write-Host "`n=== Building update policy tests ==="
$UpdateTestObj = Join-Path $OutDir 'update_policy_test.obj'
$UpdateTestExe = Join-Path $OutDir 'update_policy_test.exe'
& $ClExe @CommonCFlags /c "`"$SrcDir\update_policy_test.cpp`"" "/Fo`"$UpdateTestObj`""
if ($LASTEXITCODE -ne 0) { throw 'Update policy test compile failed' }
$updateTestLink = $CommonLFlags + @("`"$UpdateTestObj`"", "/OUT:`"$UpdateTestExe`"")
& $LinkExe @updateTestLink
if ($LASTEXITCODE -ne 0) { throw 'Update policy test link failed' }
& $UpdateTestExe
if ($LASTEXITCODE -ne 0) { throw 'Update policy tests failed' }

$UpdateObj = Join-Path $OutDir 'client_update.obj'
& $ClExe @CommonCFlags /c "`"$SrcDir\client_update.cpp`"" "/Fo`"$UpdateObj`""
if ($LASTEXITCODE -ne 0) { throw 'Client updater compile failed' }

Write-Host "`n=== Building update runtime tests ==="
$RuntimeTestObj = Join-Path $OutDir 'update_runtime_test.obj'
$RuntimeTestExe = Join-Path $OutDir 'update_runtime_test.exe'
& $ClExe @CommonCFlags /c "`"$SrcDir\update_runtime_test.cpp`"" "/Fo`"$RuntimeTestObj`""
if ($LASTEXITCODE -ne 0) { throw 'Update runtime test compile failed' }
$runtimeTestLink = $CommonLFlags + @("`"$RuntimeTestObj`"", "/OUT:`"$RuntimeTestExe`"")
& $LinkExe @runtimeTestLink
if ($LASTEXITCODE -ne 0) { throw 'Update runtime test link failed' }
& $RuntimeTestExe
if ($LASTEXITCODE -ne 0) { throw 'Update runtime tests failed' }

# ── Compile resource file ─────────────────────────────────────────────────
Write-Host "`n=== Compiling resource ==="
$RcObj = Join-Path $OutDir 'client.res'
& $RcExe /nologo /I "$IncUM" /I "$IncUCRT" /I "$IncSh" /fo "$RcObj" "$SrcDir\client.rc"
if ($LASTEXITCODE -ne 0) { throw "rc.exe failed (exit $LASTEXITCODE)" }

# ── Build: main client ─────────────────────────────────────────────────────
Write-Host "`n=== Building DeskRallyClient.exe ==="
$ClientObj = Join-Path $OutDir 'client.obj'
$ClientExe = Join-Path $OutDir 'DeskRallyClient.exe'

$clientArgs = $CommonCFlags + @(
    "/I`"$WV2Inc`"",
    '/c', "`"$SrcDir\client.cpp`"",
    "/Fo`"$ClientObj`""
)
& $ClExe @clientArgs
if ($LASTEXITCODE -ne 0) { throw "Client compile failed (exit $LASTEXITCODE)" }

$linkClientArgs = $CommonLFlags + @(
    "`"$ClientObj`"", "`"$UpdateObj`"", "`"$RcObj`"", "`"$WV2Lib`"",
    '/SUBSYSTEM:WINDOWS', '/ENTRY:wWinMainCRTStartup',
    "/OUT:`"$ClientExe`""
)
& $LinkExe @linkClientArgs
if ($LASTEXITCODE -ne 0) { throw "Client link failed (exit $LASTEXITCODE)" }
Write-Host "DeskRallyClient.exe built: $ClientExe"

# ── Optional smoke-test variant ────────────────────────────────────────────
if ($SmokeTestBuild) {
    Write-Host "`n=== Building smoke-test variant ==="

    # Ensure test fixture exists; smoke test requires it at kSmokeFixtureDir.
    $FixtureSrc  = Join-Path $SrcDir 'test-fixtures\index.html'
    $FixtureDest = Join-Path $FixtureDir 'index.html'
    if (Test-Path $FixtureSrc) {
        Copy-Item $FixtureSrc $FixtureDest -Force
    }
    if (-not (Test-Path $FixtureDest)) {
        throw "Smoke test fixture not found at $FixtureDest (expected test-fixtures\index.html in source)"
    }

    $SmokeObj = Join-Path $OutDir 'client_smoke.obj'
    $SmokeExe = Join-Path $OutDir 'DeskRallyClient-smoke.exe'

    $smokeArgs = $CommonCFlags + @(
        "/I`"$WV2Inc`"", '/DSMOKE_TEST',
        '/c', "`"$SrcDir\client.cpp`"",
        "/Fo`"$SmokeObj`""
    )
    & $ClExe @smokeArgs
    if ($LASTEXITCODE -ne 0) { throw "Smoke compile failed (exit $LASTEXITCODE)" }

    $linkSmokeArgs = $CommonLFlags + @(
        "`"$SmokeObj`"", "`"$UpdateObj`"", "`"$RcObj`"", "`"$WV2Lib`"",
        '/SUBSYSTEM:WINDOWS', '/ENTRY:wWinMainCRTStartup',
        "/OUT:`"$SmokeExe`""
    )
    & $LinkExe @linkSmokeArgs
    if ($LASTEXITCODE -ne 0) { throw "Smoke link failed (exit $LASTEXITCODE)" }
    Write-Host "DeskRallyClient-smoke.exe built: $SmokeExe"
    Write-Host "NOTE: Smoke binary not launched. Codex reviews before execution."
}

Write-Host "`n=== Build complete ==="
Write-Host "Outputs: $OutDir"
