<#
.SYNOPSIS
    DeskRally Windows build kit (docs/48 B): build the Windows binaries for YOUR server, signed with
    YOUR certificate.

.DESCRIPTION
    Produces, in -OutDir:
      DeskRallyAgent.msi       the agent package (generic: its server settings come from the bundle)
      DeskRallySetup.exe       the one-click installer, with your server baked in (BAKED mode)
      DeskRallySupport.exe     the attended support tool, with your server baked in (BAKED mode)
      installer-manifest.json  what the control plane validates at startup (incl. support_sha256)
      SHA256SUMS, README.txt
    Put DeskRallyAgent.msi + DeskRallySetup.exe + DeskRallySupport.exe + installer-manifest.json in
    MANAGED_INSTALL_HOST_DIR, and DeskRallySupport.exe (+ its .sha256.txt) under ARTIFACT_DIR.

    Order matters and is enforced: every binary is SIGNED before anything hashes it, and the MSI is
    signed before Setup bakes the MSI's hash.

    Needs (install-windows-build-prereqs.ps1 installs them): Visual Studio Build Tools (C++ + Windows
    SDK), Rust (MSVC), vcpkg libvpx/opus x64-windows-static, the WiX CLI.

.PARAMETER ServerUrl
    Your console address, exactly https://<host>[:<port>], e.g. https://remote.example.com.
.PARAMETER GrantIssuerPubkey
    Your control plane's grant issuer public key (64 hex): `docker compose ... logs controlplane | grep grant_issuer_pubkey`.
.PARAMETER Sign
    Unsigned | Thumbprint | Script. Thumbprint signs with signtool and a certificate in your store;
    Script calls -SignScript with -Path <file> for each file (e.g. a cloud signing wrapper).
.PARAMETER UpdateFeed / UpdatePubkeyFile / UpdatePublisher
    Optional, all three or none (docs/48 B.3): run your own agent update feed.
    Without these or -OfficialUpdates, auto-update is OFF.
.PARAMETER OfficialUpdates
    Explicitly trust the official DeskRally update identity; excludes the own-feed parameters.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ServerUrl,
    [Parameter(Mandatory)][string]$GrantIssuerPubkey,
    [Parameter(Mandatory)][ValidateSet('Unsigned', 'Thumbprint', 'Script')][string]$Sign,
    [string]$CertThumbprint,
    [string]$SignScript,
    [Parameter(Mandatory)][string]$OutDir,
    [string]$MsiVersion,
    [string]$UpdateFeed,
    [string]$UpdatePubkeyFile,
    [string]$UpdatePublisher,
    [switch]$OfficialUpdates
)
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }

# ── Inputs ────────────────────────────────────────────────────────────────────────────────────────
if ($ServerUrl -notmatch '^https://[a-z0-9.-]+(:[0-9]{1,5})?$') {
    throw "ServerUrl must be exactly https://<host>[:<port>] in lower case, no path (got '$ServerUrl')."
}
$hostPort = $ServerUrl.Substring(8)
$ControlPlaneUrl = "$ServerUrl/cp"
$SignalingUrl = "wss://$hostPort/ws"
$GrantIssuerPubkey = $GrantIssuerPubkey.Trim().ToLowerInvariant()
if ($GrantIssuerPubkey -notmatch '^[0-9a-f]{64}$') { throw 'GrantIssuerPubkey must be 64 hex characters.' }
if ($Sign -eq 'Thumbprint' -and -not $CertThumbprint) { throw '-Sign Thumbprint needs -CertThumbprint.' }
if ($Sign -eq 'Script' -and -not (Test-Path $SignScript)) { throw '-Sign Script needs an existing -SignScript.' }
$own = @($UpdateFeed, $UpdatePubkeyFile, $UpdatePublisher) | Where-Object { $_ }
if ($own.Count -ne 0 -and $own.Count -ne 3) { throw 'UpdateFeed, UpdatePubkeyFile and UpdatePublisher go together (all three or none).' }
if ($OfficialUpdates -and $own.Count -ne 0) { throw '-OfficialUpdates cannot be combined with own-feed parameters.' }
if (-not $MsiVersion) {
    $ws = (Select-String -Path (Join-Path $RepoRoot 'Cargo.toml') -Pattern '^version = "0\.1\.(\d+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
    $MsiVersion = "1.3.$ws"   # agent 0.1.N <-> MSI 1.3.N (build-msi.ps1's version identity)
}
if (Test-Path $OutDir) {
    if (Get-ChildItem $OutDir -Force | Select-Object -First 1) { throw "OutDir '$OutDir' is not empty; use a fresh directory." }
} else { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$OutDir = (Resolve-Path $OutDir).Path
$Work = Join-Path $OutDir '.work'
New-Item -ItemType Directory -Path $Work | Out-Null

foreach ($tool in 'cargo') { if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool not found. Run scripts/install-windows-build-prereqs.ps1." } }

function Sign-File([string]$Path) {
    switch ($Sign) {
        'Unsigned' { Write-Warning "NOT signing $(Split-Path -Leaf $Path) (-Sign Unsigned): Windows will show 'Unknown publisher'." }
        'Thumbprint' {
            $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
                Where-Object FullName -like '*\x64\*' | Sort-Object FullName -Descending | Select-Object -First 1
            if (-not $signtool) { throw 'signtool.exe not found (Windows SDK).' }
            & $signtool.FullName sign /sha1 $CertThumbprint /fd sha256 /tr http://timestamp.digicert.com /td sha256 $Path
            if ($LASTEXITCODE -ne 0) { throw "signtool failed on $Path" }
        }
        'Script' { & $SignScript -Path $Path; if ($LASTEXITCODE) { throw "$SignScript failed on $Path" } }
    }
    if ($Sign -ne 'Unsigned') {
        $s = Get-AuthenticodeSignature $Path
        if ($s.Status -ne 'Valid') { throw "Signature on $Path is $($s.Status)." }
        Write-Host "    signed: $($s.SignerCertificate.Subject)"
    }
}
function Sha([string]$p) { (Get-FileHash -Algorithm SHA256 $p).Hash.ToLowerInvariant() }

# ── 1. Agent (no server baked in; the MSI is generic) ────────────────────────────────────────────
Step 'Building the agent (release, static CRT)'
$env:RUSTFLAGS = '-C target-feature=+crt-static'
Remove-Item Env:RMT_CONTROL_PLANE_URL -ErrorAction SilentlyContinue
# The update identity is selected for THIS cargo build only: restore the caller's values afterwards
# (also on failure), so a later plain build in the same session cannot inherit the official identity.
$updateVars = 'DESKRALLY_UPDATE_OFFICIAL', 'DESKRALLY_UPDATE_FEED', 'DESKRALLY_UPDATE_PUBKEY_FILE', 'DESKRALLY_UPDATE_PUBLISHER'
$savedUpdateEnv = @{}
foreach ($v in $updateVars) { $savedUpdateEnv[$v] = [Environment]::GetEnvironmentVariable($v) }
try {
    foreach ($v in $updateVars) { [Environment]::SetEnvironmentVariable($v, $null) }
    if ($own.Count -eq 3) {
        $env:DESKRALLY_UPDATE_FEED = $UpdateFeed
        $env:DESKRALLY_UPDATE_PUBKEY_FILE = (Resolve-Path $UpdatePubkeyFile).Path
        $env:DESKRALLY_UPDATE_PUBLISHER = $UpdatePublisher
    }
    if ($OfficialUpdates) { $env:DESKRALLY_UPDATE_OFFICIAL = '1' }
    cargo build --release --manifest-path (Join-Path $RepoRoot 'Cargo.toml') -p rmt-agent-windows --bin agent_host
    if ($LASTEXITCODE -ne 0) { throw 'agent build failed' }
} finally {
    foreach ($v in $updateVars) { [Environment]::SetEnvironmentVariable($v, $savedUpdateEnv[$v]) }
}
$targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $RepoRoot 'target' }
$agent = Join-Path $Work 'agent_host.exe'
Copy-Item (Join-Path $targetDir 'release\agent_host.exe') $agent
& $agent version
Sign-File $agent

# ── 2. MSI (signed BEFORE Setup bakes its hash) ──────────────────────────────────────────────────
Step "Building DeskRallyAgent.msi $MsiVersion"
$msi = Join-Path $OutDir 'DeskRallyAgent.msi'
$msiArgs = @{ AgentExe = $agent; Version = $MsiVersion; Out = $msi }
if ($own.Count -eq 3) { $msiArgs.ExpectedFeed = $UpdateFeed }
elseif (-not $OfficialUpdates) {
    $msiArgs.ExpectedFeed = 'none'
    $msiArgs.AllowNoPin = $true
}
& (Join-Path $PSScriptRoot 'build-msi.ps1') @msiArgs
if (-not (Test-Path $msi)) { throw 'build-msi.ps1 did not produce the MSI' }
Sign-File $msi
Remove-Item (Join-Path $OutDir '*.wixpdb') -ErrorAction SilentlyContinue   # WiX debug symbols; not shipped

# ── 3. Setup (BAKED: server + MSI hash compiled in) ──────────────────────────────────────────────
Step 'Building DeskRallySetup.exe'
$setupOut = Join-Path $Work 'setup'
& (Join-Path $PSScriptRoot 'build-setup.ps1') -Msi $msi -ControlPlaneUrl $ControlPlaneUrl -SignalingUrl $SignalingUrl -GrantIssuerPubkey $GrantIssuerPubkey -OutDir $setupOut
$setup = Join-Path $OutDir 'DeskRallySetup.exe'
Copy-Item (Join-Path $setupOut 'DeskRallySetup.exe') $setup
Sign-File $setup

# ── 4. Support (BAKED control-plane URL) ─────────────────────────────────────────────────────────────────────
Step 'Building DeskRallySupport.exe'
$env:DESKRALLY_BUILD_MODE = 'baked'  # docs/48 C: explicit BAKED mode; a missing URL fails the compile
$env:RMT_CONTROL_PLANE_URL = $ControlPlaneUrl  # Support appends /attended-sessions/... to this, so it must be the /cp URL
cargo build --release --manifest-path (Join-Path $RepoRoot 'Cargo.toml') -p rmt-agent-windows --bin deskrally_support
if ($LASTEXITCODE -ne 0) { throw 'support build failed' }
Remove-Item Env:RMT_CONTROL_PLANE_URL, Env:DESKRALLY_BUILD_MODE
$support = Join-Path $OutDir 'DeskRallySupport.exe'
Copy-Item (Join-Path $targetDir 'release\deskrally_support.exe') $support
$mt = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter mt.exe -ErrorAction SilentlyContinue |
    Where-Object FullName -like '*\x64\*' | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $mt) { throw 'mt.exe not found (Windows SDK); the support tool needs its application manifest.' }
& $mt.FullName -nologo -manifest (Join-Path $RepoRoot 'crates/agent-windows/resources/deskrally_support.manifest') "-outputresource:$support;#1"
if ($LASTEXITCODE -ne 0) { throw 'mt.exe failed to embed the support manifest' }
# The baked control-plane URL, MEASURED (a GUI-subsystem exe prints nothing to a pipe; redirect to a file).
$probe = Join-Path $Work 'origin.txt'
Start-Process -FilePath $support -ArgumentList '--deployment' -RedirectStandardOutput $probe -NoNewWindow -Wait
$baked = (Get-Content $probe -Raw).Trim()
if ($baked -ne $ControlPlaneUrl) { throw "DeskRallySupport.exe reports control plane '$baked', expected '$ControlPlaneUrl'." }
Sign-File $support

# ── 5. Manifest, sums, README — from the FINAL (signed) files only ──────────────────────────────
Step 'Writing installer-manifest.json, SHA256SUMS, README.txt'
$manifest = [ordered]@{
    version                = 1
    control_plane_url      = $ControlPlaneUrl
    signaling_url          = $SignalingUrl
    grant_issuer_pubkey    = $GrantIssuerPubkey
    require_session_policy = $true
    msi_sha256             = (Sha $msi)
    setup_sha256           = (Sha $setup)
    support_sha256         = (Sha $support)
}
[IO.File]::WriteAllText((Join-Path $OutDir 'installer-manifest.json'), (($manifest | ConvertTo-Json) + "`n"), [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText("$support.sha256.txt", "$(Sha $support)  DeskRallySupport.exe`n", [Text.UTF8Encoding]::new($false))
Remove-Item -Recurse -Force $Work
$sums = Get-ChildItem $OutDir -File | Sort-Object Name | ForEach-Object { "$(Sha $_.FullName)  $($_.Name)" }
[IO.File]::WriteAllLines((Join-Path $OutDir 'SHA256SUMS'), $sums)
$feedNote = if ($own.Count -eq 3) { "Agents update from YOUR feed: $UpdateFeed (publisher '$UpdatePublisher')." } elseif ($OfficialUpdates) { 'Agents take official DeskRally updates; your server settings are kept.' } else { 'Auto-update is OFF: this build has no update identity.' }
@"
DeskRally Windows build kit output for $ServerUrl

Copy to your server:
  MANAGED_INSTALL_HOST_DIR  <- DeskRallyAgent.msi, DeskRallySetup.exe, DeskRallySupport.exe, installer-manifest.json
  ARTIFACT_DIR (/download/) <- DeskRallySupport.exe, DeskRallySupport.exe.sha256.txt
Then set CP_MANAGED_INSTALL_CONTROL_PLANE_URL=$ControlPlaneUrl and recreate the control plane with
deploy/docker-compose.installer.yml (see INSTALL.md, "Publish installers").

Agent updates: $feedNote
Signing: $Sign
"@ | Set-Content -Encoding utf8 (Join-Path $OutDir 'README.txt')
Get-Content (Join-Path $OutDir 'SHA256SUMS')
Write-Host "Done: $OutDir" -ForegroundColor Green
