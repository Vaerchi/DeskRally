<#
.SYNOPSIS
    Reproducible release build for the RMT remote-access platform. Produces a top-level dist/.

.DESCRIPTION
    Builds every shippable component and stages it under <repo>/dist:

      dist/agent/     static-CRT release agent_host.exe + stream_probe.exe, a config.template.json,
                      a README, and install-agent.ps1 (enrolls the machine via the agent's `enroll`
                      subcommand, then installs the Windows service).
      dist/servers/   release signaling.exe, relay.exe, controlplane.exe + control-plane migrations.
      dist/viewer/    the built static viewer bundle (index.html + assets).
      dist/README.md, dist/MANIFEST.txt

    The agent binaries are built with the STATIC CRT (RUSTFLAGS="-C target-feature=+crt-static") so
    they run on a bare Windows box with no vcruntime140.dll (otherwise 0xC0000135 at load).

    The script is idempotent: each component's dist subdirectory is rebuilt in place. It fails loudly
    if any component build fails.

.PARAMETER SkipRust
    Skip the (slow) Rust agent build and reuse whatever is already in dist/agent. For fast iteration
    on the servers/viewer only.

.PARAMETER SkipViewer
    Skip the viewer (npm) build and reuse whatever is already in dist/viewer.

.PARAMETER RequireFreshAgent
    Fail the build unless the agent binary STAGED in dist/agent was built from the commit HEAD is on
    right now. This is the flag a real release build passes.

    It is deliberately NOT the default, and the reason is worth writing down: scripts/verify-all.ps1
    and scripts/ci-guard.ps1 both invoke this script as `-SkipRust -SkipViewer` on EVERY run, on
    purpose, to exercise the packaging guards without paying for a two-minute cargo build. Making a
    stale agent binary a hard failure of -SkipRust would therefore break the gate on every commit
    after a build, which is strictly worse than the bug it would be fixing. So staleness is always
    MEASURED and always REPORTED -- a banner on the console, a STALE marker in dist/MANIFEST.txt --
    and this switch is what turns that report into a refusal for the one caller that must never ship
    a bundle whose binaries predate its source.

.EXAMPLE
    pwsh -File scripts/build-release.ps1
    pwsh -File scripts/build-release.ps1 -SkipRust -SkipViewer
    pwsh -File scripts/build-release.ps1 -RequireFreshAgent    # what a real release build runs
#>
[CmdletBinding()]
param(
    [switch]$SkipRust,
    [switch]$SkipViewer,
    [switch]$RequireFreshAgent,
    # The control-plane origin baked into DeskRallySupport.exe (docs/27 step 12). OPT-IN: when empty
    # (the default, and what the gate and CI guard run), the support client is NOT built and
    # dist/artifacts stays empty — so no new guard fires on the packaging path. Supplying it builds,
    # stages, and MEASURES the support client.
    [string]$ControlPlaneUrl = '',
    # Live-probe -ControlPlaneUrl before building: POST <base>/attended-sessions/redeem with a
    # deliberately invalid body and require the control plane's JSON error (a 4xx other than
    # 404/405, application/json). Refuses 404/405/HTML/connection failure. OPT-IN because the gate
    # and CI run without network; the production support-client handoff MUST pass it. The base is
    # `https://<host>/cp` behind the Compose Caddy front; a native server without a proxy may be a
    # root URL such as `http://host:8081`, which the probe accepts if it answers like the API.
    [switch]$ProbeControlPlane,
    # Sign the support client (and the MSI). Signing is deferred until external sharing; without this
    # the support client is staged unsigned for VM testing. LocalCertificate requires -CertThumbprint.
    [switch]$Sign,
    [string]$CertThumbprint = '',
    [ValidateSet('LocalCertificate', 'AzureArtifact')][string]$SigningProvider = 'LocalCertificate',
    [string]$ArtifactSigningEndpoint = '',
    [string]$ArtifactSigningAccountName = '',
    [string]$ArtifactSigningProfileName = '',
    [string]$ArtifactSignToolPath = '',
    [string]$ArtifactSigningDlibPath = '',
    # Allow an untimestamped signature (a timestamp-server outage). Off by default: an untimestamped
    # signature expires with the certificate, which is a silent time-bomb on a shipped binary.
    [switch]$AllowUntimestamped
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Fail before any build/staging mutation. Supplying Azure options never enables signing by itself.
function Assert-ReleaseSigningConfiguration {
    $azureValues = @($ArtifactSigningEndpoint, $ArtifactSigningAccountName, $ArtifactSigningProfileName,
        $ArtifactSignToolPath, $ArtifactSigningDlibPath)
    if (-not $Sign) {
        if ($SigningProvider -ne 'LocalCertificate' -or ($azureValues | Where-Object { $_ -ne '' })) {
            throw 'Azure Artifact Signing requires explicit -Sign.'
        }
        return
    }
    if ($SigningProvider -eq 'LocalCertificate') {
        if ([string]::IsNullOrWhiteSpace($CertThumbprint)) { throw '-Sign requires -CertThumbprint.' }
        if ($azureValues | Where-Object { $_ -ne '' }) { throw 'Azure options require -SigningProvider AzureArtifact.' }
    } else {
        if ($CertThumbprint -ne '' -or $AllowUntimestamped) {
            throw 'Azure Artifact Signing does not accept -CertThumbprint or -AllowUntimestamped.'
        }
        if (@($azureValues | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
            throw 'Azure Artifact Signing requires endpoint, account, profile, SignTool path, and dlib path.'
        }
        $endpointUri = $null
        if (-not [Uri]::TryCreate($ArtifactSigningEndpoint, [UriKind]::Absolute, [ref]$endpointUri) -or
            $endpointUri.Scheme -ne 'https' -or -not $endpointUri.IsDefaultPort -or $endpointUri.UserInfo -or $endpointUri.Query -or
            $endpointUri.Fragment -or $endpointUri.AbsolutePath -ne '/' -or
            -not $endpointUri.Host.EndsWith('.codesigning.azure.net', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Invalid Azure Artifact Signing regional HTTPS endpoint.'
        }
        foreach ($name in @($ArtifactSigningAccountName, $ArtifactSigningProfileName)) {
            if ($name -notmatch '^[A-Za-z0-9-]+$') { throw 'Invalid Artifact Signing account/profile name.' }
        }
        foreach ($toolPath in @($ArtifactSignToolPath, $ArtifactSigningDlibPath)) {
            if (-not (Test-Path -LiteralPath $toolPath -PathType Leaf)) { throw "Required signing tool missing: $toolPath" }
        }
    }
}
Assert-ReleaseSigningConfiguration

function Invoke-ReleaseSignature {
    param([string]$ArtifactPath)
    if ($SigningProvider -eq 'AzureArtifact') {
        & (Join-Path $PSScriptRoot 'sign-artifact-release.ps1') -Path $ArtifactPath `
            -Endpoint $ArtifactSigningEndpoint -AccountName $ArtifactSigningAccountName `
            -CertificateProfileName $ArtifactSigningProfileName -SignToolPath $ArtifactSignToolPath `
            -DlibPath $ArtifactSigningDlibPath
    } else {
        $signArgs = @('-NoProfile', '-NonInteractive', '-File', (Join-Path $PSScriptRoot 'sign-release.ps1'),
                      '-Path', $ArtifactPath, '-CertThumbprint', $CertThumbprint)
        if ($AllowUntimestamped) { $signArgs += '-AllowUntimestamped' }
        Invoke-Checked "sign $ArtifactPath" { pwsh @signArgs }
    }
}

# --- Paths ---------------------------------------------------------------------------------------
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Dist     = Join-Path $RepoRoot 'dist'
$Target   = Join-Path $RepoRoot 'target'

function Info($msg)  { Write-Host "[build] $msg" -ForegroundColor Cyan }
function Ok($msg)    { Write-Host "[ ok ] $msg"  -ForegroundColor Green }
function Warn($msg)  { Write-Host "[warn] $msg"  -ForegroundColor Yellow }

# Run an external command and throw on non-zero exit (fail loudly).
function Invoke-Checked {
    param([string]$What, [scriptblock]$Script)
    Info $What
    & $Script
    if ($LASTEXITCODE -ne 0) {
        throw "$What FAILED (exit $LASTEXITCODE)"
    }
}

function Reset-Dir($path) {
    if (Test-Path $path) { Remove-Item -Recurse -Force $path }
    New-Item -ItemType Directory -Force -Path $path | Out-Null
}

# Write UTF-8 WITHOUT a BOM (PowerShell's Set-Content -Encoding utf8 adds a BOM on older hosts; the
# agent config loader tolerates a BOM but we avoid emitting one).
function Write-Utf8NoBom($path, $content) {
    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding($false)))
}

# Write UTF-8 WITH a BOM. Required for every shipped .ps1: the target machine runs Windows
# PowerShell 5.1 (the only PowerShell on a stock Windows box — pwsh is not installed), and 5.1
# decodes a BOM-less script using the system ANSI codepage, not UTF-8. A single non-ASCII
# character (this installer contains em-dashes) then mis-decodes and breaks the parse, so the
# installer dies before it copies a byte. Verified on a bare Win11 VM.
function Write-Utf8Bom($path, $content) {
    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding($true)))
}

# --- Verification helpers ------------------------------------------------------------------------
# These exist because every failure they catch is invisible until the agent is on a customer machine:
# a dynamically-linked CRT is 0xC0000135 at service start, a config key the agent does not parse is
# silently ignored, an installer with a syntax error fails halfway through, and a missing migration
# is a control plane that will not boot.

# Locate dumpbin.exe: PATH first, then the VS installation vswhere reports. Returns $null if the
# MSVC toolchain cannot be found (the caller must then say so, not assume success).
function Resolve-Dumpbin {
    $onPath = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { return $null }
    $vsRoot = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vsRoot) { return $null }
    $msvc = Join-Path $vsRoot 'VC\Tools\MSVC'
    if (-not (Test-Path $msvc)) { return $null }
    foreach ($ver in (Get-ChildItem $msvc -Directory | Sort-Object Name -Descending)) {
        $candidate = Join-Path $ver.FullName 'bin\Hostx64\x64\dumpbin.exe'
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

# Locate mt.exe (the manifest tool) under the Windows Kits bin, highest version first. Used to embed
# the application manifest into DeskRallySupport.exe post-link (docs/27 step 12).
function Resolve-Mt {
    $onPath = Get-Command mt.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    foreach ($base in @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "$env:ProgramFiles\Windows Kits\10\bin")) {
        if (-not (Test-Path $base)) { continue }
        foreach ($ver in (Get-ChildItem $base -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
            $candidate = Join-Path $ver.FullName 'x64\mt.exe'
            if (Test-Path $candidate) { return $candidate }
        }
    }
    return $null
}

# Read the origin a support binary was baked for, by running `<exe> --deployment` and capturing its
# stdout. MEASURED via Start-Process with redirected output: a GUI-subsystem `& $exe` captures
# nothing (the process has no console), so this is the only reliable read (docs/27 step 12).
function Get-BakedOrigin($Exe) {
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        Start-Process -FilePath $Exe -ArgumentList '--deployment' -Wait -NoNewWindow `
            -RedirectStandardOutput $tmp | Out-Null
        $out = Get-Content -Raw $tmp -ErrorAction SilentlyContinue
        if ($null -eq $out) { return '' }
        return $out.Trim()
    } finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
}

# ---- control-plane base guards (the 10-29 support client was baked with "https://host" and no /cp;
# Caddy routes only /cp/* to the control plane, so every redeem hit the static handler: 405). -------

# Pure: is a non-loopback https base missing the path prefix a reverse proxy normally needs? The
# Compose/Caddy layout serves the control plane at https://<host>/cp; a native server with no proxy
# legitimately has a root URL, so this is a WARNING (and the live probe is the authority), not a refusal.
function Get-ControlPlaneBaseWarning([string]$Base) {
    $u = $null
    if (-not [System.Uri]::TryCreate($Base.Trim(), [System.UriKind]::Absolute, [ref]$u)) { return $null }
    if ($u.Scheme -ne 'https') { return $null }
    if ($u.IsLoopback) { return $null }
    if ($u.AbsolutePath.Trim('/') -ne '') { return $null }
    return ("-ControlPlaneUrl '{0}' has an EMPTY PATH. Behind the Compose/Caddy front the control plane is served at '{0}/cp' " +
            "(Caddy sends only /cp/* to it; a bare origin falls through to the static site and every support code fails with a 405). " +
            "Use https://<host>/cp unless this is a native server with no proxy, and run with -ProbeControlPlane to prove it.") -f $Base.Trim().TrimEnd('/')
}

# Pure: a base the support client would refuse at runtime anyway (validate_control_plane_url wants
# https, loopback excepted). Failing here is earlier and cheaper than baking an unusable client.
function Get-ControlPlaneBaseRefusal([string]$Base) {
    $u = $null
    if (-not [System.Uri]::TryCreate($Base.Trim(), [System.UriKind]::Absolute, [ref]$u)) {
        return "-ControlPlaneUrl '$Base' is not an absolute URL."
    }
    # userinfo / query / fragment: the client appends '/attended-sessions/...' to the base, so a query or
    # fragment would swallow the path, and userinfo ('https://good.example@evil.example/cp') disguises the
    # real host. Checked on the raw text: .NET normalises an empty '?' or '#' away.
    if ($Base.Trim() -match '[?#@]') {
        return "-ControlPlaneUrl '$Base' must not contain userinfo ('@'), a query ('?') or a fragment ('#'); give a plain https://<host>[:port][/cp] base."
    }
    if ($u.Scheme -eq 'https') { return $null }
    if ($u.Scheme -eq 'http' -and $u.IsLoopback) { return $null }
    return "-ControlPlaneUrl '$Base' must be https (http is allowed only for a loopback host); the support client refuses a cleartext control-plane address."
}

# Pure: given what the probe POST got back, did the control plane's attended API answer?
# Required: a 4xx other than 404/405 (an invalid body must be REFUSED by the API), Content-Type
# application/json (or +json), and a JSON body whose "error" is the control plane's own message for
# that status (see $script:ControlPlaneProbeAnswers). Anything else -- a static handler's 405/404, an HTML 200 SPA fallback, a proxy
# 5xx -- is not proof the base reaches the control plane.
$script:ControlPlaneProbeAnswers = @{
    400 = 'code is required'
    403 = 'access from this network is not allowed'
    429 = 'too many attempts'
}
function Get-ControlPlaneProbeVerdict([int]$Status, [string]$ContentType, [string]$Body) {
    $fail = { param($why) [pscustomobject]@{ Ok = $false; Reason = $why } }
    if ($Status -eq 404 -or $Status -eq 405) {
        return (& $fail "HTTP ${Status}: the base URL points at something that is not the control plane (a static handler, or a missing path prefix such as /cp)")
    }
    if ($Status -lt 400 -or $Status -ge 500) {
        return (& $fail "HTTP ${Status}: expected the API to REFUSE an invalid redeem with a 4xx; a ${Status} is not the control plane's answer")
    }
    $essence = ''
    if ($ContentType) { $essence = ($ContentType -split ';')[0].Trim().ToLowerInvariant() }
    if ($essence -ne 'application/json' -and -not $essence.EndsWith('+json')) {
        return (& $fail "HTTP ${Status} with Content-Type '$ContentType': expected application/json (an HTML or text reply is a proxy or static site, not the control plane)")
    }
    $obj = $null
    try { $obj = $Body | ConvertFrom-Json -ErrorAction Stop } catch { $obj = $null }
    if ($null -eq $obj -or -not ($obj.PSObject.Properties.Name -contains 'error') -or $obj.error -isnot [string]) {
        return (& $fail "HTTP ${Status} application/json, but the body is not the control plane's {""error"": ""...""} shape")
    }
    # Only the control plane's OWN answers to the {} probe count; any other JSON API's 4xx {"error":..}
    # must not pass. The exact (status, message) pairs come from the Go source (pinned by
    # Assert-ControlPlaneProbeStringsMatchGo, so a wording change there fails the gate):
    #   400 handleRedeemAttended: writeError(400, "code is required")   (http_attended.go)
    #   429 writeThrottled: writeError(429, ErrTooManyAttempts.Error()) (throttle.go; auth.go "too many attempts")
    #   403 IP allow-list: writeError(403, "access from this network is not allowed") (ipallow.go)
    if (-not $script:ControlPlaneProbeAnswers.ContainsKey($Status) -or $script:ControlPlaneProbeAnswers[$Status] -cne $obj.error) {
        return (& $fail "HTTP ${Status} application/json error '$($obj.error)' is not one of the control plane's own answers to an empty redeem (a different JSON API behind this URL?)")
    }
    return [pscustomobject]@{ Ok = $true; Reason = "HTTP $Status application/json error: '$($obj.error)'" }
}

# Live probe. Network, so only under -ProbeControlPlane. The body {} is refused with 400
# "code is required" before any code lookup, so it cannot redeem or burn anything.
function Invoke-ControlPlaneProbe([string]$Base) {
    $url = $Base.Trim().TrimEnd('/') + '/attended-sessions/redeem'
    try {
        $r = Invoke-WebRequest -Uri $url -Method Post -Body '{}' -ContentType 'application/json' `
            -SkipHttpErrorCheck -TimeoutSec 20 -MaximumRedirection 0 -ErrorAction Stop
    } catch {
        throw "Control-plane probe FAILED: could not reach $url ($($_.Exception.Message)). The support client would show 'could not reach the support service'."
    }
    $ct = ''
    if ($r.Headers.ContainsKey('Content-Type')) { $ct = [string]($r.Headers['Content-Type'] | Select-Object -First 1) }
    $v = Get-ControlPlaneProbeVerdict -Status ([int]$r.StatusCode) -ContentType $ct -Body ([string]$r.Content)
    if (-not $v.Ok) {
        throw "Control-plane probe FAILED for -ControlPlaneUrl '$Base': POST $url -> $($v.Reason). Fix the base URL (Compose/Caddy: https://<host>/cp) before baking it into a client."
    }
    Ok "Control-plane probe: POST $url -> $($v.Reason)"
}

# The probe verdict's accepted messages are copies of Go string literals. Pin them: each must still be
# present in the control-plane source, or a reword there would make every probe of a good base fail (or,
# worse, silently drift). Needles are split with concatenation so this file cannot match itself.
function Assert-ControlPlaneProbeStringsMatchGo {
    $cpDir = Join-Path $RepoRoot 'control-plane'
    if (-not (Test-Path -LiteralPath $cpDir)) { Info "control-plane source not present; skipping the probe-string pin"; return }
    $pins = @(
        @{ File = 'http_attended.go'; Needle = ('writeError(w, http.StatusBadRequest, "code is ' + 'required")');        Answer = $script:ControlPlaneProbeAnswers[400] },
        @{ File = 'ipallow.go';       Needle = ('writeError(w, http.StatusForbidden, "access from this ' + 'network is not allowed")'); Answer = $script:ControlPlaneProbeAnswers[403] },
        @{ File = 'auth.go';          Needle = ('ErrTooManyAttempts = errors.New("too many ' + 'attempts")');            Answer = $script:ControlPlaneProbeAnswers[429] }
    )
    foreach ($p in $pins) {
        $text = [System.IO.File]::ReadAllText((Join-Path $cpDir $p.File))
        if (-not $text.Contains($p.Needle)) { throw "Assert-ControlPlaneProbeStringsMatchGo: control-plane/$($p.File) no longer contains '$($p.Needle)'; update `$script:ControlPlaneProbeAnswers in build-release.ps1" }
        if (-not $p.Needle.Contains($p.Answer)) { throw "Assert-ControlPlaneProbeStringsMatchGo: the accepted answer '$($p.Answer)' is not the string pinned to control-plane/$($p.File)" }
    }
    Ok "control-plane probe answers pinned to the Go source ($($pins.Count) literals)"
}

# Always-on self-check of the two pure functions above (no network): the gate runs it, so a weakened
# verdict fails the gate instead of shipping.
function Assert-ControlPlaneGuardLogic {
    $json = 'application/json; charset=utf-8'
    $good = '{"error":"code is required"}'
    $cases = @(
        @{ Why = 'API 400 JSON';           S = 400; C = $json;       B = $good;                      Ok = $true  },
        @{ Why = 'API 403 ip-allow JSON';  S = 403; C = $json;       B = '{"error":"access from this network is not allowed"}'; Ok = $true  },
        @{ Why = 'API 429 throttle problem+json'; S = 429; C = 'application/problem+json'; B = '{"error":"too many attempts"}'; Ok = $true  },
        @{ Why = 'foreign JSON API 400';   S = 400; C = $json;       B = '{"error":"invalid request"}'; Ok = $false },
        @{ Why = 'foreign JSON API 401';   S = 401; C = $json;       B = '{"error":"code is required"}'; Ok = $false },
        @{ Why = 'foreign 429 wording';    S = 429; C = $json;       B = '{"error":"rate limit exceeded"}'; Ok = $false },
        @{ Why = '403 with wrong message'; S = 403; C = $json;       B = $good;                      Ok = $false },
        @{ Why = '400 wrong case';         S = 400; C = $json;       B = '{"error":"Code is required"}'; Ok = $false },
        @{ Why = 'static 405 (the incident)'; S = 405; C = '';       B = '';                         Ok = $false },
        @{ Why = '405 even with JSON';     S = 405; C = $json;       B = $good;                      Ok = $false },
        @{ Why = 'static 404';             S = 404; C = 'text/html'; B = '<h1>404</h1>';             Ok = $false },
        @{ Why = '404 even with JSON error'; S = 404; C = $json;     B = $good;                      Ok = $false },
        @{ Why = '200 HTML SPA fallback';  S = 200; C = 'text/html'; B = '<html></html>';            Ok = $false },
        @{ Why = '200 JSON (not refused)'; S = 200; C = $json;       B = '{"ok":true}';              Ok = $false },
        @{ Why = '400 HTML';               S = 400; C = 'text/html'; B = '<html></html>';            Ok = $false },
        @{ Why = '400 JSON without error'; S = 400; C = $json;       B = '{"detail":"x"}';           Ok = $false },
        @{ Why = '400 JSON not JSON body'; S = 400; C = $json;       B = 'nope';                     Ok = $false },
        @{ Why = '502 proxy';              S = 502; C = $json;       B = $good;                      Ok = $false }
    )
    foreach ($c in $cases) {
        $v = Get-ControlPlaneProbeVerdict -Status $c.S -ContentType $c.C -Body $c.B
        if ($v.Ok -ne $c.Ok) { throw "Assert-ControlPlaneGuardLogic: probe verdict for '$($c.Why)' was Ok=$($v.Ok), expected Ok=$($c.Ok)" }
    }
    $refuseCases = @(
        @{ Why = 'https';              U = 'https://main.deskrally.com/cp'; R = $false },
        @{ Why = 'http non-loopback';  U = 'http://main.deskrally.com/cp';  R = $true  },
        @{ Why = 'http loopback';      U = 'http://127.0.0.1:8081';         R = $false },
        @{ Why = 'ftp';                U = 'ftp://main.deskrally.com/cp';   R = $true  },
        @{ Why = 'not a URL';          U = 'main.deskrally.com';            R = $true  },
        @{ Why = 'userinfo';           U = 'https://good.example@evil.example/cp'; R = $true },
        @{ Why = 'userinfo with password'; U = 'https://u:p@main.deskrally.com/cp'; R = $true },
        @{ Why = 'query';              U = 'https://main.deskrally.com/cp?x=1'; R = $true },
        @{ Why = 'empty query';        U = 'https://main.deskrally.com/cp?'; R = $true },
        @{ Why = 'fragment';           U = 'https://main.deskrally.com/cp#frag'; R = $true },
        @{ Why = 'loopback http + query'; U = 'http://127.0.0.1:8081/?a=b'; R = $true }
    )
    foreach ($c in $refuseCases) {
        $w = $null -ne (Get-ControlPlaneBaseRefusal $c.U)
        if ($w -ne $c.R) { throw "Assert-ControlPlaneGuardLogic: scheme refusal for '$($c.Why)' ($($c.U)) was $w, expected $($c.R)" }
    }
    $warnCases = @(
        @{ Why = 'bare https origin';       U = 'https://main.deskrally.com';     W = $true  },
        @{ Why = 'bare origin, slash';      U = 'https://main.deskrally.com/';    W = $true  },
        @{ Why = 'https with /cp';          U = 'https://main.deskrally.com/cp';  W = $false },
        @{ Why = 'loopback https';          U = 'https://localhost:8443';         W = $false },
        @{ Why = 'loopback http';           U = 'http://127.0.0.1:8081';          W = $false },
        @{ Why = 'native root with port';   U = 'https://cp.example:8443';        W = $true  }
    )
    foreach ($c in $warnCases) {
        $w = $null -ne (Get-ControlPlaneBaseWarning $c.U)
        if ($w -ne $c.W) { throw "Assert-ControlPlaneGuardLogic: empty-path warning for '$($c.Why)' ($($c.U)) was $w, expected $($c.W)" }
    }
    Ok ("control-plane base guards: probe verdict + empty-path warning logic ({0} + {1} + {2} cases)" -f $cases.Count, $warnCases.Count, $refuseCases.Count)
}

# Fail the build unless $exe resolves its static imports from System32 only: the PE load-config
# DependentLoadFlags must be 0x800 (LOAD_LIBRARY_SEARCH_SYSTEM32, set by crates/agent-windows/build.rs).
# Both binaries can run from a folder the user can write (DeskRallySupport.exe from Downloads, and as
# the docs/53 elevated input helper), and import many non-KnownDLLs (pdh, wtsapi32, dxgi, ...). Measured
# 2026-10-28 with a garbage pdh.dll / wtsapi32.dll next to the exe: flag 0 (1.3.15 and the shipped
# support client) loaded the planted file (STATUS_INVALID_IMAGE_NOT_MZ / a "Bad Image" box); flag 0x800
# ignored it and ran. WATCHED FAILING against the 1.3.15 agent_host.exe before being trusted.
function Get-PeDependentLoadFlags {
    # Read DependentLoadFlags straight from the PE (no dumpbin: a check that needs a tool which may be
    # absent fails OPEN, Codex secfix r1). PE32+ only: the optional header's data directories start at
    # +112 and entry 10 is the load config; in IMAGE_LOAD_CONFIG_DIRECTORY64 the u16
    # DependentLoadFlags sits at +78 (after CSDVersion). A load config too short to carry it reads 0.
    param([string]$Exe)
    $b = [System.IO.File]::ReadAllBytes($Exe)
    $leaf = Split-Path -Leaf $Exe
    if ([BitConverter]::ToUInt16($b, 0) -ne 0x5A4D) { throw "${leaf}: not an MZ image" }
    $pe = [BitConverter]::ToUInt32($b, 0x3C)
    if ([BitConverter]::ToUInt32($b, $pe) -ne 0x00004550) { throw "${leaf}: no PE signature" }
    $coff = $pe + 4
    $sections = [BitConverter]::ToUInt16($b, $coff + 2)
    $optSize = [BitConverter]::ToUInt16($b, $coff + 16)
    $opt = $coff + 20
    if ([BitConverter]::ToUInt16($b, $opt) -ne 0x20B) { throw "${leaf}: not a PE32+ image" }
    $lcRva = [BitConverter]::ToUInt32($b, $opt + 112 + 10 * 8)
    if ($lcRva -eq 0) { throw "${leaf}: no load config directory" }
    $table = $opt + $optSize
    for ($i = 0; $i -lt $sections; $i++) {
        $sh = $table + 40 * $i
        $va = [BitConverter]::ToUInt32($b, $sh + 12)
        $vsize = [BitConverter]::ToUInt32($b, $sh + 8)
        if ($lcRva -ge $va -and $lcRva -lt ($va + $vsize)) {
            $off = [BitConverter]::ToUInt32($b, $sh + 20) + ($lcRva - $va)
            if ([BitConverter]::ToUInt32($b, $off) -lt 80) { return 0 }
            return [int][BitConverter]::ToUInt16($b, $off + 78)
        }
    }
    throw "${leaf}: the load config is not inside any section"
}

function Assert-DependentLoadFlag {
    param([string]$Exe)
    $flag = Get-PeDependentLoadFlags -Exe $Exe
    if ($flag -ne 0x800) {
        throw ("{0}: Dependent Load Flag is 0x{1:X} (want 0x800, System32 only); its static imports would load from its own folder" -f (Split-Path -Leaf $Exe), $flag)
    }
    Ok ("{0}: static imports resolve from System32 only (DependentLoadFlags 0x800)" -f (Split-Path -Leaf $Exe))
}
# Fail the build if $exe imports a CRT DLL. A bare VM has no vcruntime140.dll, so a dynamically
# linked agent dies at load with 0xC0000135 before it can log anything.
function Assert-StaticCrt {
    param([string]$Exe, [string]$Dumpbin)
    $deps = & $Dumpbin /dependents $Exe 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "dumpbin /dependents $Exe failed (exit $LASTEXITCODE): $deps" }
    # @() so a zero-match result is an empty array, not $null (StrictMode has no .Count on $null).
    #
    # THE TRAILING `\s*` IS LOAD-BEARING, and its absence made this guard incapable of failing.
    # dumpbin emits CRLF, so a line is "    VCRUNTIME140.dll<CR>". `\S*` stops at the `<CR>`, and in .NET
    # multiline mode `$` matches only immediately before the newline — so the pattern could never
    # reach it and EVERY binary passed. Measured 2026-09-06 against the real dumpbin output: the old
    # pattern matched 0, this one matches 8, starting with VCRUNTIME140.dll.
    #
    # What it was hiding: DeskRallySupport.exe was linked WITHOUT `+crt-static` (the support build
    # never set RUSTFLAGS, unlike the agent build) and therefore imported VCRUNTIME140.dll. On a
    # clean Windows 11 with no VC++ redistributable it did not start at all — 0xC0000135
    # STATUS_DLL_NOT_FOUND, no window, no message. That is the DOWNLOADABLE client, on the machine
    # of a customer who has never installed anything.
    $bad = @([regex]::Matches($deps, '(?im)^\s*(vcruntime\S*|msvcp\d\S*|ucrtbase\S*|api-ms-win-crt-\S*)\s*$') |
        ForEach-Object { $_.Groups[1].Value })
    if ($bad.Count -gt 0) {
        throw ("{0} links the CRT dynamically ({1}) — the +crt-static build did not take effect" -f
               (Split-Path -Leaf $Exe), ($bad -join ', '))
    }
    Ok ("static-CRT verified: {0} imports no CRT DLL" -f (Split-Path -Leaf $Exe))
}

# Fail the build if the application manifest is not in $exe's RESOURCE DIRECTORY.
#
# WHY THIS IS NOT A BYTE SCAN, and it is the whole point of the function: this repo already ships a
# resource whose bytes are in the file but NOT in the resource directory. The version resource's
# strings are findable with `strings -e l` while `GetFileVersionInfo` reads blank, because link.exe
# on the MSVC 14.50 preview here never merged them into `.rsrc`. So "I found the manifest text in
# the exe" proves nothing about whether Windows will ever read it. `mt.exe -inputresource` asks the
# loader's own question — read RT_MANIFEST id 1 out of the image — and fails when it is not there.
#
# What a missing manifest costs on the first-contact path: no comctl32 v6, so the code prompt's
# EDIT/BUTTON/STATIC controls render in the Windows-95 style on a customer's machine; no
# PerMonitorV2 from the manifest (support_main still sets it programmatically); and no explicit
# asInvoker, which leaves the exe to UAC's installer-detection heuristics.
#
# WATCHED FAILING, 2026-09-07, before being trusted (the standing rule after Assert-StaticCrt's
# regex was found incapable of failing): on the post-mt.exe binary this extracts 1003 chars with
# both markers and exits 0; on the same binary before the mt.exe step, mt.exe exits 31 with
# "general error c101008c: ... The specified resource type cannot be found in the image file".
function Assert-AppManifest {
    param([string]$Exe, [string]$Mt)
    $out = Join-Path ([System.IO.Path]::GetTempPath()) ("rmt-manifest-" + [guid]::NewGuid().ToString('N') + ".xml")
    try {
        $said = & $Mt -nologo "-inputresource:$Exe;#1" "-out:$out" 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $out)) {
            throw ("Assert-AppManifest FAILED: no RT_MANIFEST in {0}'s resource directory — the mt.exe embed did not take effect (mt.exe exit {1}): {2}" -f
                   (Split-Path -Leaf $Exe), $LASTEXITCODE, $said.Trim())
        }
        $xml = [System.IO.File]::ReadAllText($out)
        # Each marker is a DISTINCT promise the manifest makes; naming them separately means a
        # partially-correct manifest cannot pass by carrying only the easy one.
        $missing = @()
        if ($xml -notmatch 'Microsoft\.Windows\.Common-Controls') { $missing += 'comctl32 v6 dependency' }
        if ($xml -notmatch 'permonitorv2')                          { $missing += 'dpiAwareness permonitorv2' }
        if ($xml -notmatch 'asInvoker')                             { $missing += 'requestedExecutionLevel asInvoker' }
        if ($missing.Count -gt 0) {
            throw ("Assert-AppManifest FAILED: {0} has an RT_MANIFEST but it is missing: {1}" -f
                   (Split-Path -Leaf $Exe), ($missing -join ', '))
        }
        Ok ("app-manifest verified in the resource directory: {0} ({1} bytes, comctl32 v6 + permonitorv2 + asInvoker)" -f
            (Split-Path -Leaf $Exe), $xml.Length)
    } finally {
        if (Test-Path $out) { [System.IO.File]::Delete($out) }
    }
}

# Fail the build if the shipped config template's key set differs from the HelperConfig struct the
# agent actually deserializes. An extra key is dead configuration an operator will trust; a missing
# key is an install knob nobody knows exists.
function Assert-ConfigTemplateMatchesRust {
    param([string]$TemplatePath, [string]$ConfigRsPath)
    $rs = [System.IO.File]::ReadAllText($ConfigRsPath)
    $struct = [regex]::Match($rs, 'pub struct HelperConfig \{(?<body>.*?)\r?\n\}',
                             [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $struct.Success) { throw "could not find `pub struct HelperConfig` in $ConfigRsPath" }
    # @() so zero matches is an empty array, not $null (StrictMode has no .Count on $null).
    $rustFields = @([regex]::Matches($struct.Groups['body'].Value, '(?m)^\s+pub\s+(?<n>\w+)\s*:') |
        ForEach-Object { $_.Groups['n'].Value } | Sort-Object)
    if ($rustFields.Count -eq 0) { throw "parsed zero fields out of HelperConfig in $ConfigRsPath" }

    $tmpl = [System.IO.File]::ReadAllText($TemplatePath).TrimStart([char]0xFEFF) | ConvertFrom-Json
    $tmplKeys = @($tmpl.PSObject.Properties.Name | Sort-Object)

    $missing = @($rustFields | Where-Object { $tmplKeys -notcontains $_ })
    $extra   = @($tmplKeys  | Where-Object { $rustFields -notcontains $_ })
    if ($missing -or $extra) {
        throw ("config.template.json does not match HelperConfig: missing [{0}] extra [{1}]" -f
               ($missing -join ', '), ($extra -join ', '))
    }
    Ok ("config.template.json matches HelperConfig field-for-field ({0} fields: {1})" -f
        $rustFields.Count, ($rustFields -join ', '))
}

# Fail the build if the generated installer cannot SET a key the generated template advertises.
#
# Assert-ConfigTemplateMatchesRust proves one side of a triangle: the template matches the code.
# Nothing proved the third side -- install-agent.ps1, which is what actually writes config.json on a
# real machine. `require_session_policy` was advertised by the template, parsed by the agent, and
# documented in the shipped README as "what makes a per-group view-only mandate BINDING", while
# being unreachable from the installer: no parameter, no key in the hashtable. Every scripted
# install therefore landed with enforcement off, and all three artifacts individually looked right.
#
# The exemptions are decisions, not oversights, and each is checked by something else:
#   device_id, tenant_id   SERVER-MINTED at enrollment (M3). The installer must never write them,
#                          and the M3 guard further down fails the build if it tries.
#   identity_path          a test-only override for where the machine's private signing key lives.
#                          Exposing it invites a typo that puts the key outside the hardened agent
#                          root; production has no reason to move it.
function Assert-InstallerCoversTemplate {
    param([string]$TemplatePath, [string]$InstallerPath)
    # allow_cli_recording (the local recording broker's opt-in) and canvas_capture (the docs/52 GDI
    # escape hatch) are deliberately hand-edited only: a security opt-in and a diagnostic switch are
    # not install knobs. Both are listed in the template so they are documented.
    $exempt = @('device_id', 'tenant_id', 'identity_path', 'allow_cli_recording', 'canvas_capture')
    $tmpl = [System.IO.File]::ReadAllText($TemplatePath).TrimStart([char]0xFEFF) | ConvertFrom-Json
    # @() so a single remaining key is still an array (StrictMode has no .Count on a bare string).
    $required = @($tmpl.PSObject.Properties.Name | Where-Object { $exempt -notcontains $_ } | Sort-Object)
    if ($required.Count -eq 0) { throw "Assert-InstallerCoversTemplate: parsed zero keys from $TemplatePath" }
    $text = [System.IO.File]::ReadAllText($InstallerPath)
    # A key counts as settable when the installer assigns it into the config hashtable, either as a
    # literal member (`clipboard = $Clipboard`) or through the indexer the conditional keys use
    # (`$cfg["control_plane_url"] = ...`).
    $missing = @($required | Where-Object {
        $k = [regex]::Escape($_)
        (-not ($text -match ('(?m)^\s*{0}\s*=' -f $k))) -and
        (-not ($text -match ('\$cfg\[\s*["'']{0}["'']\s*\]\s*=' -f $k)))
    })
    if ($missing.Count -gt 0) {
        # The parentheses around the concatenation are load-bearing: -f binds TIGHTER than +, so
        # `"a{0}" + "b{1}" -f $x` formats ONLY the last fragment and ships the earlier ones with
        # their placeholders intact. An error message that prints a literal {0} is an error message
        # nobody can act on.
        throw (("install-agent.ps1 cannot set config key(s) that config.template.json advertises: " +
                "[{0}]. A key the template documents but the installer never writes is an install " +
                "knob that silently keeps its default on every scripted deployment.") -f ($missing -join ', '))
    }
    Ok ("install-agent.ps1 can set every non-exempt template key ({0}: {1}; exempt: {2})" -f
        $required.Count, ($required -join ', '), ($exempt -join ', '))
}

# Fail the build if the shipped installer would accept a MEANINGLESS required value.
#
# `[Parameter(Mandatory)]` rules out absent and empty -- measured, both 5.1 and 7 -- but it happily
# binds "   ". A whitespace enrollment token, or a URL with no scheme, installs an agent that can
# never connect and still reports healthy, which is the failure mode that is expensive precisely
# because it looks like success.
#
# This RUNS the shipped script rather than grepping it: a regex would pass against a validation
# block that was moved below the copy, which is the one way this guard could lie. -BinDir and
# -ConfigPath are pointed at a throwaway temp path so that even a regression that actuates cannot
# touch the real agent directories, and the guard then ASSERTS that path was never created.
#
# BUT PATH CONTAINMENT IS NOT ENOUGH, and this was learned the hard way on 2026-09-06. Before the
# validation existed, running this guard let install-agent.ps1 reach its "existing RmtAgent service
# found -- stopping + removing it" block, which does `sc.exe stop` + `sc.exe delete` on the REAL
# service. That is machine-global state, not something -BinDir can scope, and it de-registered the
# agent on the box running the build. So the guard also snapshots whether RmtAgent exists and fails
# LOUDLY, with the recovery command, if the run removed it -- turning a silent box-breaking side
# effect into a build error somebody can act on.
function Assert-InstallerRefusesMeaninglessValues {
    param([string]$InstallerPath)
    $svcBefore = [bool](Get-Service RmtAgent -ErrorAction SilentlyContinue)
    $cases = @(
        @{ Why = "whitespace -EnrollmentToken"; Sig = "wss://x/ws";  Cp = "https://x/cp"; Tok = "   " },
        @{ Why = "scheme-less -SignalingUrl";   Sig = "x.example/ws"; Cp = "https://x/cp"; Tok = "tok" },
        @{ Why = "whitespace -ControlPlaneUrl"; Sig = "wss://x/ws";  Cp = "  ";           Tok = "tok" }
    )
    foreach ($c in $cases) {
        $scratch = Join-Path ([IO.Path]::GetTempPath()) ("rmt-instguard-" + [guid]::NewGuid().ToString('N').Substring(0,8))
        $bin = Join-Path $scratch "bin"
        $cfg = Join-Path $scratch "cfg\config.json"
        $out = & pwsh -NoProfile -Command "& '$InstallerPath' -SignalingUrl '$($c.Sig)' -ControlPlaneUrl '$($c.Cp)' -EnrollmentToken '$($c.Tok)' -BinDir '$bin' -ConfigPath '$cfg'" 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            throw ("install-agent.ps1 ACCEPTED a $($c.Why): it must refuse before touching anything. " +
                   "Mandatory does not reject whitespace or a scheme-less URL; the script must " +
                   "validate the VALUE.")
        }
        if (Test-Path $scratch) {
            throw ("install-agent.ps1 refused a $($c.Why) but had already created $scratch. The " +
                   "validation must run BEFORE any copy, hardening or config write.")
        }
    }
    if ($svcBefore -and -not (Get-Service RmtAgent -ErrorAction SilentlyContinue)) {
        throw ("install-agent.ps1 got far enough to DELETE the RmtAgent service on this machine " +
               "while being handed deliberately invalid arguments. Its value validation must run " +
               "before the service stop/delete block. Re-register the agent with " +
               "'C:\rmt-agent-bin\agent_host.exe install' (the enrolled identity in " +
               "C:\rmt-agent\config.json is untouched).")
    }
    Ok ("install-agent.ps1 refuses meaningless required values, before actuating ({0} cases)" -f $cases.Count)
}

# Fail the build if a shipped .ps1 does not parse. It is about to be run, elevated, on a machine
# nobody is watching.
function Assert-PowerShellParses {
    param([string]$Path)
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        $detail = ($errors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join "; "
        throw "$(Split-Path -Leaf $Path) has PowerShell parse errors: $detail"
    }
    Ok ("{0} parse-checks clean" -f (Split-Path -Leaf $Path))
}

# Fail the build if a shipped .ps1 carries non-ASCII bytes without a UTF-8 BOM.
#
# Assert-PowerShellParses alone does NOT catch this: it runs in whatever PowerShell built the
# release (7.x, which assumes UTF-8), while the script is EXECUTED by Windows PowerShell 5.1 on the
# target — the only PowerShell present on a stock Windows install. 5.1 decodes a BOM-less file with
# the system ANSI codepage, so a UTF-8 em-dash arrives as mojibake that terminates a string literal
# early and the whole file fails to parse. The installer then aborts before doing anything, which is
# how a release that passed every host-side check can be 100% non-functional on a real machine.
function Assert-ShippedPs1Encoding {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    # @() so a zero-match result is an empty array, not $null (StrictMode has no .Count on $null).
    $nonAscii = @($bytes | Where-Object { $_ -gt 0x7F })
    if ($nonAscii.Count -gt 0 -and -not $hasBom) {
        # Parenthesized because -f binds tighter than +. Without the parens this formatted only the
        # SECOND fragment (which has no placeholders), so the thrown message read "{0} contains {1}
        # non-ASCII byte(s)" — naming neither the file nor the count, on the one failure that stops a
        # release from working at all on a real machine.
        throw (("{0} contains {1} non-ASCII byte(s) but has no UTF-8 BOM — Windows PowerShell 5.1 on " +
                "the target will mis-decode it and fail to parse the script") -f
               (Split-Path -Leaf $Path), $nonAscii.Count)
    }
    Ok ("{0} encoding is safe for Windows PowerShell 5.1 (bom={1}, non-ascii bytes={2})" -f
        (Split-Path -Leaf $Path), $hasBom, $nonAscii.Count)
}

# Fail the build if the shipped agent binary does not carry EXACTLY ONE pristine embedded stub slot.
#
# The downloadable guest stub (crates/agent-windows/src/stub.rs) self-configures by scanning its OWN
# binary for a 32-byte magic and reading the attend URI patched in after it. The placeholder is a
# `#[used]` static that must survive RELEASE optimization (opt-level 3 + LTO) as a SINGLE, unpatched
# copy — if the optimizer const-folds the reader's needle into a second plaintext magic, or drops the
# static, the whole feature breaks (make-stub refuses "ambiguous", or a configured stub cannot find
# its config). The Rust unit test only exercises the UNOPTIMIZED test binary, where those failures
# cannot even occur, so this is the only place the invariant is checked on the actual shipped
# artifact. The magic is derived from stub.rs's MAGIC_OBF (the source of truth) so the check can never
# drift from the code.
function Assert-NoDemoBinariesShipped {
    <#
      No insecure development demo may reach a release artifact (docs/25 F16).

      `agent/src/bin` holds ONLY dev tools — shell_server (a PowerShell over a loopback socket),
      backstage_server (file-browse and registry-read over a loopback socket) and ws_probe. The
      binaries that genuinely ship live in `crates/agent-windows/src/bin` (agent_host,
      stream_probe). Each demo now demands an explicit --insecure-dev and a per-run token, but the
      right place for a demo that hands out shells is "not in the download at all".

      THE DENYLIST IS DERIVED FROM THE DIRECTORY, not written out here, so a dev binary added later
      is covered the day it is added rather than the day someone remembers this guard. That is the
      difference between a defence and a defence that exists at one call site (docs/25 F16's
      sibling: shell_server was found and backstage_server was not, because the finding named one).

      It is a directory scan, so it still means something under -SkipRust: it inspects whatever is
      staged in dist/, including leftovers from an earlier full build.
    #>
    param(
        [Parameter(Mandatory)][string]$DistRoot,
        [Parameter(Mandatory)][string]$DemoBinDir
    )
    if (-not (Test-Path $DemoBinDir)) {
        throw "Assert-NoDemoBinariesShipped: $DemoBinDir not found — the denylist is derived from it, so a missing directory would silently disable this guard"
    }
    $demoNames = @(Get-ChildItem -Path $DemoBinDir -Filter '*.rs' -File |
        ForEach-Object { $_.BaseName })
    if ($demoNames.Count -eq 0) {
        throw "Assert-NoDemoBinariesShipped: parsed zero demo binary names from $DemoBinDir"
    }
    if (-not (Test-Path $DistRoot)) { return }   # nothing staged yet; nothing to violate

    $offenders = @(Get-ChildItem -Path $DistRoot -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $demoNames -contains $_.BaseName -and $_.Extension -in '.exe', '.pdb' })
    if ($offenders.Count -gt 0) {
        $list = ($offenders | ForEach-Object { $_.FullName }) -join "`n  "
        throw ("Assert-NoDemoBinariesShipped: an INSECURE DEV DEMO binary is staged in an artifact.`n  " +
               $list + "`nThese serve shells / file-browse / registry-read over a loopback port and " +
               "must never be distributed. Remove it from the staging step; do not add it to a denylist.")
    }
    Ok ("no demo binaries in dist ({0} names checked: {1})" -f $demoNames.Count, ($demoNames -join ', '))
}

function Assert-StubSlot {
    param([string]$Exe, [string]$StubRs)
    if (-not (Test-Path $StubRs)) { throw "Assert-StubSlot: $StubRs not found" }
    $rs = [System.IO.File]::ReadAllText($StubRs)
    $m = [regex]::Match($rs, 'const\s+MAGIC_OBF:\s*\[u8;\s*MAGIC_LEN\]\s*=\s*\[(?<body>[^\]]*)\]',
                        [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $m.Success) { throw "Assert-StubSlot: could not find MAGIC_OBF in $StubRs" }
    # @() so a zero-match result is an empty array, not $null (StrictMode has no .Count on $null).
    $obf = @([regex]::Matches($m.Groups['body'].Value, '0x[0-9a-fA-F]{2}') |
        ForEach-Object { [Convert]::ToInt32($_.Value, 16) })
    if ($obf.Count -ne 32) { throw "Assert-StubSlot: expected 32 MAGIC_OBF bytes, parsed $($obf.Count)" }
    $magic = [byte[]]($obf | ForEach-Object { $_ -bxor 0xA7 })  # XOR_KEY in stub.rs

    $bytes = [System.IO.File]::ReadAllBytes($Exe)
    # Latin1 maps each byte 1:1 to a char, so a native String.IndexOf is a fast byte-subsequence
    # search (a per-byte PowerShell loop over a 16 MB image would take the better part of a minute).
    $latin1 = [System.Text.Encoding]::GetEncoding('ISO-8859-1')
    $hay = $latin1.GetString($bytes)
    $needle = $latin1.GetString($magic)
    $count = 0; $first = -1; $idx = 0
    while (($idx = $hay.IndexOf($needle, $idx)) -ge 0) {
        if ($first -lt 0) { $first = $idx }
        $count++; $idx++
    }
    if ($count -ne 1) {
        throw ("{0} carries {1} embedded stub slot(s); expected exactly ONE (the placeholder must survive release optimization as a single copy — see stub.rs)" -f (Split-Path -Leaf $Exe), $count)
    }
    # The SHIPPED binary must be a pristine template: length 0 (unpatched). A non-zero length would
    # mean the release artifact was accidentally configured with a session's one-time code baked in.
    $len = [BitConverter]::ToUInt32($bytes, $first + 32)
    if ($len -ne 0) {
        throw ("{0} embedded stub slot has length {1}; a shipped template MUST be unpatched (length 0)" -f (Split-Path -Leaf $Exe), $len)
    }
    Ok ("stub slot verified: {0} carries exactly one pristine embedded slot at 0x{1:X}" -f (Split-Path -Leaf $Exe), $first)
}

# Resolve the WiX v4+ `wix` CLI: PATH first (the winget install adds it to the machine PATH), then the
# default WiX v7 location. Returns $null when WiX is absent — the MSI is then SKIPPED (a warning, not a
# failure), so a build box without WiX still produces the rest of dist/.
function Resolve-Wix {
    $cmd = Get-Command wix -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $default = Join-Path ${env:ProgramFiles} 'WiX Toolset v7.0/bin/wix.exe'
    if (Test-Path $default) { return $default }
    return $null
}

# Read column 1 of a one-column MSI query as a string[] (WindowsInstaller COM, read-only db). The caller
# wraps the result in @() so 0- and 1-row results are still arrays; returning a bare $out here (NOT a
# comma-wrapped `,$out`, which would nest the array and break -contains) lets PowerShell unroll it.
function Read-MsiColumn($db, [string]$sql) {
    try {
        $view = $db.OpenView($sql)
        $view.Execute()
        $out = @()
        while ($rec = $view.Fetch()) { $out += [string]$rec.StringData(1) }
        $out
    } catch {
        # A query against a table the MSI does NOT contain (e.g. no ServiceInstall table because the
        # .wxs registered no service) throws — read that as "no rows" so the guard reports the missing
        # service cleanly, rather than crashing with a raw COM error.
        @()
    }
}

# GUARD: the built MSI must actually package the agent AND register the service — an MSI whose .wxs
# silently dropped either would install nothing useful. Inspect the MSI's File and ServiceInstall tables
# directly rather than trusting `wix build` exit 0. Throws on a violation (the package suite records FAIL).
function Assert-MsiContents {
    param([string]$Msi)
    if (-not (Test-Path $Msi)) { throw "Assert-MsiContents: MSI not found at $Msi" }
    $installer = New-Object -ComObject WindowsInstaller.Installer
    try {
        $db = $installer.OpenDatabase($Msi, 0) # 0 = read-only
        $files = @(Read-MsiColumn $db 'SELECT `FileName` FROM `File`')
        $services = @(Read-MsiColumn $db 'SELECT `Name` FROM `ServiceInstall`')
    } finally {
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
    }
    # FileName is "short|long" (or just the long name); match the agent binary by substring.
    if (-not ($files -match 'agent_host\.exe')) {
        throw ("MSI does not package agent_host.exe (File table: {0})" -f ($files -join ', '))
    }
    if ($services -notcontains 'RmtAgent') {
        throw ("MSI does not register the RmtAgent service (ServiceInstall: {0})" -f ($services -join ', '))
    }
    Ok ("MSI verified: packages agent_host.exe and registers the RmtAgent service")
}

# --- Build identity: what is ACTUALLY staged, versus what HEAD says -------------------------------
# dist/MANIFEST.txt used to open with "generated <now>" and then list a byte count per file. Every
# statement in it was true and the combination was a lie: the header dated the MANIFEST, a reader
# took it to date the BUNDLE, and nothing in the file distinguished the two. A -SkipRust run
# regenerates the README, the config template, the installer and the manifest while leaving the
# agent binaries untouched -- so a bundle carrying a six-day-old agent_host.exe (one missing an LPE
# fix and a view-only/clipboard fix) advertised itself as built minutes ago, and whoever trusted the
# manifest installed it.
#
# The fix is to stop inferring and start measuring. A manifest's job is to describe what is IN the
# bundle, so these helpers read the binary's own embedded build identity, its mtime, and the commit
# HEAD was on when the manifest was written; the manifest then reports all three SEPARATELY, because
# conflating them is the entire defect.

# Run a git command that yields a single line. Returns $null on ANY failure -- git absent, not a
# checkout, a bad revision, or a non-zero exit.
#
# Nothing else in this script assumes git is on PATH, and crates/agent-core/build.rs makes exactly
# the same promise about the stamp it writes ("it must not require git"). A build box without git
# must still produce a dist/; it simply cannot claim the bundle is fresh, which is what the 'no-git'
# state below reports rather than guessing in either direction.
function Invoke-GitLine {
    param([string]$RepoRoot, [string[]]$GitArgs)
    try {
        $out = & git -C $RepoRoot @GitArgs 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        $line = @($out) | Where-Object { $_ } | Select-Object -First 1
        if (-not $line) { return $null }
        return ([string]$line).Trim()
    } catch {
        return $null
    }
}

# Read the AGENT_VERSION stamp out of a built binary. Returns every DISTINCT stamp found: normally
# exactly one, and an EMPTY array for a binary built before the stamp existed.
#
# crates/agent-core/src/version.rs defines AGENT_VERSION = concat!(CARGO_PKG_VERSION, "+",
# RMT_GIT_SHA), so a shipped .exe carries a literal like `0.0.1+9ee2636` in its read-only data -- or
# `0.0.1+unknown` (version::PLACEHOLDER_SHA) when git was unavailable at compile time. That literal
# is the only thing in the bundle that knows which SOURCE the binary came from. A file mtime only
# says when somebody last copied it, which is precisely how a stale bundle passed for fresh.
#
# Two things about the needle. First, the semver half is pinned to the workspace version read out of
# Cargo.toml, so a dependency's own "1.2.3+build" string is not a candidate; if Cargo.toml cannot be
# read the pattern widens to any three-part version and any resulting ambiguity is REPORTED rather
# than silently resolved. Second, the hex run can OVER-READ: rustc packs string literals into .rdata
# with no separator, so the bytes after the sha may themselves be hex. That can never produce a wrong
# verdict, because a git short sha is a PREFIX of the full commit id and the caller narrows the run
# back to a real commit longest-prefix-first; at worst it makes the reported sha a few characters too
# long on a box with no git to resolve it against.
function Get-EmbeddedAgentVersion {
    param([string]$Exe, [string]$RepoRoot)

    $semverPat = '[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}'
    $cargoToml = Join-Path $RepoRoot 'Cargo.toml'
    if (Test-Path $cargoToml) {
        $wm = [regex]::Match([System.IO.File]::ReadAllText($cargoToml),
                             '(?ms)^\[workspace\.package\].*?^version\s*=\s*"(?<v>[^"]+)"')
        if ($wm.Success) { $semverPat = [regex]::Escape($wm.Groups['v'].Value) }
    }

    $bytes = [System.IO.File]::ReadAllBytes($Exe)
    # Latin1 maps each byte 1:1 to a char, so this is a byte search driven by .NET's regex engine
    # rather than a per-byte PowerShell loop over an 18 MB image (Assert-StubSlot uses the same trick
    # and explains why the loop is unaffordable).
    $latin1 = [System.Text.Encoding]::GetEncoding('ISO-8859-1')
    $hay    = $latin1.GetString($bytes)

    # @() so a zero-match result is an empty array, not $null (StrictMode has no .Count on $null).
    # Returned WITHOUT a leading comma: the pipeline unrolls this to zero, one or many strings and
    # the caller re-wraps with @(). A `return ,$hits` here would arrive at the caller's @() as a
    # single ARRAY element, so $stamps[0] would be an array rather than a stamp.
    $hits = @([regex]::Matches($hay, ("{0}\+(?:unknown|[0-9a-f]{{7,40}})" -f $semverPat)) |
        ForEach-Object { $_.Value } | Select-Object -Unique)
    return $hits
}

# Everything the banner and the manifest need to say about the staged agent, MEASURED rather than
# assumed. This never throws: a box without git, or a binary with no stamp, still produces a dist/ --
# it just gets a State that is not 'fresh', which is exactly what -RequireFreshAgent refuses.
function Get-StagedAgentIdentity {
    param([string]$Exe, [string]$RepoRoot)

    $id = @{
        Exe          = $Exe
        Mtime        = (Get-Item -LiteralPath $Exe).LastWriteTime
        Stamp        = $null       # '0.0.1+9ee2636' as found in the binary, or the "unstamped" note
        StampNote    = ''          # set only when the scan found more than one candidate
        StampSource  = 'none'      # binary (authoritative) | image scan (fallback) | none
        Sha          = $null       # the hex half, narrowed to a real commit prefix where possible
        HeadFull     = $null
        HeadShort    = $null
        Branch       = $null
        State        = 'unknown'   # fresh | stale | unstamped | degraded | no-git
        Summary      = ''
        CommitsSince = -1
        SinceBasis   = 'none'      # commit (exact) | mtime (approximate) | none
    }
    $resolvedFull = $null

    $id.HeadFull  = Invoke-GitLine -RepoRoot $RepoRoot -GitArgs @('rev-parse', 'HEAD')
    $id.HeadShort = Invoke-GitLine -RepoRoot $RepoRoot -GitArgs @('rev-parse', '--short', 'HEAD')
    $id.Branch    = Invoke-GitLine -RepoRoot $RepoRoot -GitArgs @('rev-parse', '--abbrev-ref', 'HEAD')

    # ASK THE BINARY FIRST. `agent_host.exe version` prints AGENT_VERSION and exits, before it
    # installs a logging subscriber or reads anything, so this is authoritative: it returns the very
    # string the agent will report to signaling and the console's fleet view.
    #
    # This exists because scanning the image DOES NOT WORK on a release build, which the byte-scan
    # path below cannot tell you and which cost a false STALE on the first real binary it ever saw.
    # AGENT_VERSION is `concat!(CARGO_PKG_VERSION, "+", RMT_GIT_SHA)`, and at opt-level 3 rustc
    # materializes the 13-byte result as two overlapping 8-byte immediate MOVs in the code rather
    # than as one contiguous run in .rdata:
    #
    #     48 b8 '+4f56580'   mov rax, imm64        49 89 45 05   mov [r13+5], rax
    #     48 b8 '0.0.1+4f'   mov rax, imm64        49 89 45 00   mov [r13+0], rax
    #
    # so both halves are present in the file and never adjacent. Every synthetic fixture the scanner
    # was developed against had a contiguous literal and passed; the first optimized binary reported
    # `unstamped`, which would have flown the STALE banner over every genuine release forever and
    # trained the reader to ignore the one warning that matters.
    #
    # The scan is KEPT as a fallback, not deleted: it still answers for a binary that cannot be
    # executed here (a foreign architecture, a locked-down build box, or a pre-`version` binary
    # older than this change), and for those the over-read narrowing below is still the right logic.
    $stamps = @()
    try {
        $out = & $Exe version 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) {
            # Take the last non-empty line: `version` prints exactly one, but a stray line from a
            # future change must not silently become the stamp.
            $line = @($out | Where-Object { $_ -and $_.ToString().Trim() } |
                      ForEach-Object { $_.ToString().Trim() })[-1]
            if ($line -match '^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\+\S+$') {
                $stamps = @($line)
                $id.StampSource = 'binary (`agent_host version`)'
            }
        }
    } catch {
        # Cannot run it here. Fall through to the scan rather than failing the build: the identity
        # is a reporting concern, and refusing to package over it would be worse than reporting the
        # scan's answer.
    }
    if ($stamps.Count -eq 0) {
        $stamps = @(Get-EmbeddedAgentVersion -Exe $Exe -RepoRoot $RepoRoot)
        if ($stamps.Count -gt 0) { $id.StampSource = 'image scan (fallback)' }
    }

    if ($stamps.Count -eq 0) {
        # Never guess and never omit the line: the ABSENCE of a stamp is itself a fact about the
        # binary, and a manifest that quietly left the row out would read as "nothing to report".
        # AGENT_VERSION arrived in 4c075aa, so a binary without one predates that commit or came out
        # of a build that lost the literal.
        $id.Stamp = 'unstamped (pre-4c075aa or a degraded build)'
        $id.State = 'unstamped'
    } else {
        $id.Stamp = $stamps[0]
        if ($stamps.Count -gt 1) {
            $id.StampNote = ("ambiguous: {0} candidate stamps in the image ({1})" -f
                             $stamps.Count, ($stamps -join ', '))
        }
        $sha = $id.Stamp.Substring($id.Stamp.IndexOf('+') + 1)
        if ($sha -eq 'unknown') {
            # version::PLACEHOLDER_SHA. The binary runs fine; it just cannot say what it is, so
            # freshness is UNDETERMINED rather than false -- and -RequireFreshAgent still refuses it,
            # because a release must not ship a binary that cannot name its own source.
            $id.Sha   = $sha
            $id.State = 'degraded'
        } else {
            # Narrow the (possibly over-read) hex run back to a real commit, longest prefix first.
            # This is what turns an over-read '9ee2636dd' into a commit id the count below can
            # subtract from HEAD, instead of a false STALE.
            for ($len = $sha.Length; $len -ge 7; $len--) {
                $probe = $sha.Substring(0, $len)
                $full  = Invoke-GitLine -RepoRoot $RepoRoot `
                                        -GitArgs @('rev-parse', '--verify', '--quiet', "$probe^{commit}")
                if ($full) { $id.Sha = $probe; $resolvedFull = $full; break }
            }
            if (-not $id.Sha) { $id.Sha = $sha }
        }
    }

    if ($id.State -eq 'unknown') {
        if (-not $id.HeadFull) {
            $id.State = 'no-git'
        } elseif ($resolvedFull -and $resolvedFull -eq $id.HeadFull) {
            $id.State = 'fresh'
        } elseif (-not $resolvedFull -and $id.HeadFull.StartsWith($id.Sha)) {
            # The commit is not in this object database (a shallow or exported checkout) but the
            # stamp still prefixes HEAD, which is the whole comparison a short sha supports.
            $id.State = 'fresh'
        } else {
            $id.State = 'stale'
        }
    }

    # How much source has moved since this binary was built. The BASIS travels with the number,
    # because the two are not equally trustworthy: a resolved commit gives an exact `<commit>..HEAD`
    # range, whereas an mtime is a fallback that counts by COMMITTER date and reads a copied file's
    # timestamp as a build time. Saying which one produced the number is the difference between a
    # measurement and a guess wearing a measurement's clothes.
    $paths = @('--', 'crates', 'agent')
    if ($resolvedFull) {
        $count = Invoke-GitLine -RepoRoot $RepoRoot `
            -GitArgs (@('rev-list', '--count', ("{0}..HEAD" -f $resolvedFull)) + $paths)
        if ($count) { $id.CommitsSince = [int]$count; $id.SinceBasis = 'commit' }
    } elseif ($id.HeadFull) {
        $since = $id.Mtime.ToString('yyyy-MM-ddTHH:mm:sszzz')
        $count = Invoke-GitLine -RepoRoot $RepoRoot `
            -GitArgs (@('rev-list', '--count', 'HEAD', ("--since={0}" -f $since)) + $paths)
        if ($count) { $id.CommitsSince = [int]$count; $id.SinceBasis = 'mtime' }
    }

    switch ($id.State) {
        'fresh'     { $id.Summary = ("built from HEAD ({0})" -f $id.HeadShort) }
        'stale'     { $id.Summary = ("built from {0}, but HEAD is {1}" -f $id.Sha, $id.HeadShort) }
        'unstamped' { $id.Summary = 'carries no AGENT_VERSION stamp, so it cannot name its own source' }
        'degraded'  { $id.Summary = 'was built without git (RMT_GIT_SHA placeholder), so its source is unknown' }
        'no-git'    { $id.Summary = 'could not be compared to HEAD: git did not answer' }
        default     { $id.Summary = 'freshness undetermined' }
    }
    return $id
}

# Say out loud what is about to be packaged.
#
# Printed on EVERY run, not only the bad ones. Somebody reading a green build log should be able to
# see the agent's identity directly, rather than having to know that its ABSENCE means something --
# the original defect was exactly a missing statement being read as a reassuring one.
function Write-AgentIdentityBanner {
    param([hashtable]$Id, [bool]$Reused)

    $mtime = $Id.Mtime.ToString('yyyy-MM-ddTHH:mm:sszzz')
    $head  = if ($Id.HeadFull) { "{0} ({1})" -f $Id.HeadShort, $Id.Branch } else { '<git did not answer>' }
    if ($Id.State -eq 'fresh') {
        Ok ("staged agent_host.exe {0}; stamp {1}; built {2}" -f $Id.Summary, $Id.Stamp, $mtime)
        return
    }

    $lead = if ($Reused) {
        '-SkipRust: dist/agent was NOT rebuilt. THIS is what you are packaging:'
    } else {
        'the staged agent binary does not match HEAD:'
    }
    $since = if ($Id.CommitsSince -ge 0) {
        "{0} commit(s) have touched crates/ + agent/ since ({1} basis)" -f $Id.CommitsSince, $Id.SinceBasis
    } else {
        'commits touching crates/ + agent/ since: NOT COUNTED (git did not answer)'
    }
    Write-Host ""
    Warn "==================================================================================="
    Warn ("  {0}" -f $lead)
    Warn ("    staged agent_host.exe : {0}" -f $Id.Stamp)
    if ($Id.StampNote) { Warn ("                            {0}" -f $Id.StampNote) }
    Warn ("    binary mtime          : {0}" -f $mtime)
    Warn ("    repo HEAD             : {0}" -f $head)
    Warn ("    verdict               : {0} -- {1}" -f $Id.State.ToUpperInvariant(), $Id.Summary)
    Warn ("    {0}" -f $since)
    Warn "  dist/MANIFEST.txt will carry a STALE marker for this bundle, and so will the MSI it feeds."
    Warn "  Rebuild with: pwsh -File scripts/build-release.ps1    (no -SkipRust)"
    Warn "==================================================================================="
    Write-Host ""
}

$startedAt = Get-Date
Info "repo root: $RepoRoot"
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

# =================================================================================================
# 1. Rust agent (static CRT release)
# =================================================================================================
$AgentDist = Join-Path $Dist 'agent'
if ($SkipRust) {
    Warn "SkipRust: reusing existing dist/agent"
} else {
    # NOTE: dist/agent is deliberately NOT cleared here. This used to `Reset-Dir $AgentDist` before the
    # cargo build below, which meant an interrupted or failed build left dist/agent EMPTY — and the next
    # `verify-all.ps1` (package suite) or `ci-guard.ps1` then died on Assert-StubSlot's "agent_host.exe is
    # missing", a message that reads like a packaging break rather than "your build was cut short".
    # The reset now happens after cargo returns 0, immediately before the artifacts are staged.

    # libvpx (VP8 encode) is a NATIVE prerequisite — unlike the openh264 crate it replaced, it is
    # not vendored. Fail here with an actionable message rather than 3 minutes later with LNK1181.
    # The triplet MUST be x64-windows-static (/MT): this build uses +crt-static, and a /MD libvpx
    # fails to link with LNK2038. See docs/10-deployment.md section 1a.
    $VpxLib = if ($env:VPX_LIB_DIR) { $env:VPX_LIB_DIR } else { 'C:/vcpkg/installed/x64-windows-static/lib' }
    if (-not (Test-Path (Join-Path $VpxLib 'vpx.lib'))) {
        throw @"
libvpx not found: expected '$VpxLib/vpx.lib'.
Install it once with:
    vcpkg install libvpx:x64-windows-static
(the triplet MUST be x64-windows-static — a /MD build fails to link against +crt-static with
LNK2038). If your vcpkg lives elsewhere, set VPX_LIB_DIR / VPX_INCLUDE_DIR. See
docs/10-deployment.md section 1a.
"@
    }

    Info "building Rust agent (release, static CRT) — this compiles webrtc-rs + links libvpx and is slow"
    $prevRustflags = $env:RUSTFLAGS
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
    $prevUpdateOfficial = $env:DESKRALLY_UPDATE_OFFICIAL
    # The help identifies -RequireFreshAgent as the real release path. CI/local builds
    # preserve the caller's selection; own-feed conflicts fail in build.rs.
    if ($RequireFreshAgent) { $env:DESKRALLY_UPDATE_OFFICIAL = '1' }
    try {
        Invoke-Checked "cargo build --release agent_host + stream_probe" {
            cargo build --release --manifest-path (Join-Path $RepoRoot 'Cargo.toml') `
                -p rmt-agent-windows --bin agent_host --bin stream_probe
        }
    } finally {
        $env:RUSTFLAGS = $prevRustflags
        $env:DESKRALLY_UPDATE_OFFICIAL = $prevUpdateOfficial
    }

    # cargo returned 0, so the new artifacts exist: only NOW is it safe to drop the old ones. Reset
    # rather than overwrite, so a file that stops being produced does not linger in the package.
    Reset-Dir $AgentDist

    foreach ($exe in 'agent_host.exe', 'stream_probe.exe') {
        $src = Join-Path $Target "release/$exe"
        if (-not (Test-Path $src)) { throw "expected Rust artifact missing: $src" }
        Copy-Item $src (Join-Path $AgentDist $exe) -Force
    }
    Ok "agent binaries staged"

    # Static-CRT verification via dumpbin (PATH or the VS install vswhere reports).
    $dumpbin = Resolve-Dumpbin
    if ($dumpbin) {
        Info "static-CRT check using $dumpbin"
        foreach ($exe in 'agent_host.exe', 'stream_probe.exe') {
            Assert-StaticCrt -Exe (Join-Path $AgentDist $exe) -Dumpbin $dumpbin
        }
    } else {
        Warn "dumpbin NOT FOUND (no PATH entry, no vswhere/MSVC install) — the static-CRT check was NOT PERFORMED. Verify manually before deploying to a bare VM."
    }
}

# Agent config template, README, and installer are always (re)generated so they track this script.
New-Item -ItemType Directory -Force -Path $AgentDist | Out-Null

# The downloadable guest stub's placeholder must survive release optimization as ONE pristine copy in
# the SHIPPED agent_host.exe (the stub template). Run OUTSIDE the SkipRust block so the gate's package
# suite (build-release.ps1 -SkipRust) validates the staged binary too — the unit test only sees the
# unoptimized test binary, where the const-fold/LTO failures cannot appear. See Assert-StubSlot.
$StagedAgent = Join-Path $AgentDist 'agent_host.exe'
if (Test-Path $StagedAgent) {
    Assert-StubSlot -Exe $StagedAgent -StubRs (Join-Path $RepoRoot 'crates/agent-windows/src/stub.rs')
    # docs/53 / the 2026-10-28 planting finding: on every run, -SkipRust included, like the stub check.
    Assert-DependentLoadFlag -Exe $StagedAgent
} else {
    throw "Assert-StubSlot: $StagedAgent is missing — build the agent (drop -SkipRust) before packaging."
}

# What is ACTUALLY staged, read out of the binary itself. Computed HERE — after the check above has
# proven a binary is present, and before anything downstream describes the bundle — so the banner,
# the -RequireFreshAgent decision and dist/MANIFEST.txt all report one single measurement rather
# than three independent guesses that can disagree.
$AgentIdentity = Get-StagedAgentIdentity -Exe $StagedAgent -RepoRoot $RepoRoot
Write-AgentIdentityBanner -Id $AgentIdentity -Reused:([bool]$SkipRust)

# The refusal, for the one caller that needs it. See the .PARAMETER block at the top for why this is
# opt-in: the gate and the CI guard both run -SkipRust deliberately, so a hard failure by default
# would break every commit after a build. A release build passes this switch and gets the guarantee;
# everyone else gets the loud report above and the STALE marker in the manifest.
if ($RequireFreshAgent -and $AgentIdentity.State -ne 'fresh') {
    $sinceText = if ($AgentIdentity.CommitsSince -ge 0) {
        "{0} commit(s) have touched crates/ + agent/ since ({1} basis)" -f
            $AgentIdentity.CommitsSince, $AgentIdentity.SinceBasis
    } else {
        "commits since could not be counted"
    }
    # Parenthesized: -f binds tighter than + (see Assert-ShippedPs1Encoding for the same trap).
    throw (("-RequireFreshAgent: the staged agent binary is NOT built from HEAD [{0}] — {1}. " +
            "Staged stamp: {2}; mtime {3}; HEAD {4}. {5}. Re-run WITHOUT -SkipRust to rebuild it.") -f
           $AgentIdentity.State,
           $AgentIdentity.Summary,
           $AgentIdentity.Stamp,
           $AgentIdentity.Mtime.ToString('yyyy-MM-ddTHH:mm:sszzz'),
           ($(if ($AgentIdentity.HeadShort) { $AgentIdentity.HeadShort } else { '<unknown>' })),
           $sinceText)
}

# =================================================================================================
# The downloadable support client (docs/27 step 12). OPT-IN via -ControlPlaneUrl, so the gate and CI
# guard (which run without it) neither build it nor fire any new guard on its absence. dist/artifacts
# is populated ONLY when the origin measured out of the binary matches the one requested (and, under
# -Sign, only when signed + timestamped).
# =================================================================================================
$ArtifactDist = Join-Path $Dist 'artifacts'

# Self-test the control-plane guards BEFORE the support block below relies on them.
Assert-ControlPlaneGuardLogic
Assert-ControlPlaneProbeStringsMatchGo

if ($ProbeControlPlane -and $ControlPlaneUrl -eq '') {
    throw "-ProbeControlPlane needs -ControlPlaneUrl (the base to probe)."
}

if ($ControlPlaneUrl -ne '') {
    Info "Building the downloadable support client for origin: $ControlPlaneUrl"

    # A build baked for the WRONG origin is the failure this whole design exists to prevent, so refuse
    # to proceed if an ambient RMT_CONTROL_PLANE_URL disagrees with the one requested (rather than
    # silently letting the environment win).
    $ambient = $env:RMT_CONTROL_PLANE_URL
    if ($ambient -and $ambient.Trim() -ne '' -and $ambient.Trim() -ne $ControlPlaneUrl.Trim()) {
        throw "RMT_CONTROL_PLANE_URL in the environment ('$ambient') disagrees with -ControlPlaneUrl ('$ControlPlaneUrl'). Unset it or pass a matching value."
    }

    $baseRefusal = Get-ControlPlaneBaseRefusal $ControlPlaneUrl
    if ($baseRefusal) { throw $baseRefusal }
    $baseWarning = Get-ControlPlaneBaseWarning $ControlPlaneUrl
    if ($baseWarning) { Warn $baseWarning }
    if ($ProbeControlPlane) {
        Invoke-ControlPlaneProbe $ControlPlaneUrl
    } else {
        Warn "-ProbeControlPlane not given: the base URL was NOT proven to reach the control plane's API. Pass it for any build that will be published."
    }

    if (-not $SkipRust) {
        $prev = $env:RMT_CONTROL_PLANE_URL
        $env:RMT_CONTROL_PLANE_URL = $ControlPlaneUrl
        # docs/48 C: an explicit BAKED build, so a missing URL fails the compile instead of shipping
        # an "unconfigured" client, and a stray pass root key in the environment is refused.
        $prevMode = $env:DESKRALLY_BUILD_MODE
        $env:DESKRALLY_BUILD_MODE = 'baked'
        # +crt-static, exactly as the agent build above sets it. THIS WAS MISSING, and it is the one
        # binary that most needs it: the agent arrives via an installer on a machine somebody
        # administers, while this is downloaded and double-clicked by a customer whose machine has
        # never had a VC++ redistributable on it. Without the flag it imports VCRUNTIME140.dll and
        # dies at load with 0xC0000135 -- no window, no error, nothing to report to the technician.
        # Measured on a clean Windows 11 guest 2026-09-06. `Assert-StaticCrt` was supposed to catch
        # this and could not; see the regex note in that function.
        $prevRustflags = $env:RUSTFLAGS
        $env:RUSTFLAGS = '-C target-feature=+crt-static'
        try {
            Invoke-Checked "cargo build --release deskrally_support" {
                cargo build --release --manifest-path (Join-Path $RepoRoot 'Cargo.toml') `
                    -p rmt-agent-windows --bin deskrally_support
            }
        } finally {
            $env:RMT_CONTROL_PLANE_URL = $prev
            $env:DESKRALLY_BUILD_MODE = $prevMode
            $env:RUSTFLAGS = $prevRustflags
        }
    } else {
        Warn "SkipRust: not rebuilding DeskRallySupport.exe; reusing whatever is staged."
    }

    Reset-Dir $ArtifactDist
    $srcSupport = Join-Path $Target 'release/deskrally_support.exe'
    if (-not (Test-Path $srcSupport)) {
        throw "DeskRallySupport.exe not found at $srcSupport (drop -SkipRust to build it)."
    }
    $stagedSupport = Join-Path $ArtifactDist 'DeskRallySupport.exe'
    Copy-Item $srcSupport $stagedSupport -Force

    # Static-CRT like the agent: a public download must not depend on a VC++ redistributable.
    $dumpbin2 = Resolve-Dumpbin
    if ($dumpbin2) {
        Assert-StaticCrt -Exe $stagedSupport -Dumpbin $dumpbin2
    }
    Assert-DependentLoadFlag -Exe $stagedSupport

    # The application manifest (comctl32 v6 + PerMonitorV2 + asInvoker) is embedded HERE with mt.exe,
    # not at compile time — a second RT_MANIFEST from the .res conflicts with rustc's default and
    # blanks the version resource (see build.rs and the memory on the MSVC 14.50 resource quirk).
    $mt = Resolve-Mt
    $manifestSrc = Join-Path $RepoRoot 'crates/agent-windows/resources/deskrally_support.manifest'
    if ($mt -and (Test-Path $manifestSrc)) {
        $mtSaid = & $mt -nologo -manifest $manifestSrc "-outputresource:$stagedSupport;#1" 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            throw ("mt.exe returned {0} embedding the application manifest: {1}" -f $LASTEXITCODE, $mtSaid.Trim())
        }
        # mt.exe's exit code says it thinks it wrote the resource. Assert-AppManifest READS IT BACK
        # out of the image, because "the tool returned 0" is the same evidence Assert-StaticCrt had
        # while it was structurally incapable of failing (docs/28 section 8.2).
        Assert-AppManifest -Exe $stagedSupport -Mt $mt
    } elseif (-not $mt) {
        # Name WHICH failure. A build that silently skips this ships an unmanifested first-contact
        # binary, and "skipping manifest embed" read as a tidy no-op for as long as it existed.
        Warn "mt.exe NOT FOUND — DeskRallySupport.exe will ship with NO application manifest (no comctl32 v6, no manifest DPI, no explicit asInvoker). Install the Windows SDK to embed it."
    } else {
        throw "the application manifest is missing from the repo at $manifestSrc"
    }

    # Assert-BakedControlPlane: MEASURED, not asserted. A GUI-subsystem `& $exe` captures nothing
    # here, so run it via Start-Process with the output redirected to a file and read that.
    $measured = Get-BakedOrigin $stagedSupport
    if ($measured -ne $ControlPlaneUrl.Trim()) {
        throw "Assert-BakedControlPlane FAILED: DeskRallySupport.exe --deployment printed '$measured', expected '$ControlPlaneUrl'. The binary is baked for the wrong origin (or could not print it)."
    }
    Ok "Assert-BakedControlPlane: the binary reports origin '$measured'"

    # Assert-VersionResource: WARN unless signing (version + signing go together for SmartScreen).
    $desc = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($stagedSupport).FileDescription
    if ([string]::IsNullOrWhiteSpace($desc)) {
        $msg = "Assert-VersionResource: DeskRallySupport.exe has a BLANK Description (the version resource did not embed; see the MSVC 14.50 resource-merge note in build.rs)."
        if ($Sign) { throw "$msg A signed release must not ship a blank Description." } else { Warn $msg }
    } else {
        Ok "Assert-VersionResource: Description = '$desc'"
    }

    # The sidecar hash the page reads back and verify-download.ps1 checks. Carries the sha256 and, if
    # signed, the signer thumbprint.
    $sha = (Get-FileHash -Algorithm SHA256 $stagedSupport).Hash.ToLower()
    $shaLine = $sha
    if ($Sign) {
        Invoke-ReleaseSignature -ArtifactPath $stagedSupport
        $sig = Get-AuthenticodeSignature $stagedSupport
        if ($sig.Status -ne 'Valid') { throw "Assert-Signed: signature status is $($sig.Status)" }
        $thumb = $sig.SignerCertificate.Thumbprint
        # Re-hash after signing (the signature changes the bytes).
        $sha = (Get-FileHash -Algorithm SHA256 $stagedSupport).Hash.ToLower()
        $shaLine = "$sha  (signed by $thumb)"
        Ok "signed; thumbprint $thumb"
    }
    Write-Utf8NoBom (Join-Path $ArtifactDist 'DeskRallySupport.exe.sha256.txt') "$shaLine`r`n"
    Ok "staged dist/artifacts/DeskRallySupport.exe + .sha256.txt (sha256 $sha)"
} else {
    # No origin requested: leave dist/artifacts empty so nothing downstream offers an unbuilt download.
    if (Test-Path $ArtifactDist) { Reset-Dir $ArtifactDist }
}

# The template's key set is asserted against HelperConfig in crates/agent-windows/src/config.rs
# further down (Assert-ConfigTemplateMatchesRust): a template key the agent does not parse is dead
# configuration, and a HelperConfig field the template omits is an undocumented install knob.
# device_id and tenant_id are SERVER-MINTED at enrollment (M3) — they are present but blank, and
# `agent_host enroll` fills them in. Nothing may pre-set device_id.
$configTemplate = @'
{
  "signaling_url": "ws://YOUR-SIGNALING-HOST:8080/ws",
  "control_plane_url": "https://YOUR-CONTROL-PLANE:8443",
  "enrollment_token": "",
  "device_id": "",
  "tenant_id": "",
  "stun": [],
  "transfer_dir": "C:\\rmt-agent\\transfers",
  "grant_issuer_pubkey": "",
  "directive_pubkey": "",
  "update_signer_pubkey": "",
  "require_session_policy": false,
  "identity_path": "",
  "max_session_secs": 14400,
  "clipboard": "bidirectional",
  "allow_cli_recording": false,
  "canvas_capture": null,
  "quality": {
    "max_fps": 60,
    "adaptive": true
  }
}
'@
Write-Utf8NoBom (Join-Path $AgentDist 'config.template.json') $configTemplate

$agentReadme = @'
# RMT Agent

Static-CRT Windows agent. Runs as a LocalSystem service; a per-session SYSTEM helper streams the
desktop over WebRTC, injects input, and serves the backstage tooling protocol.

## Files
- `agent_host.exe`      the agent/service host
                        (`enroll` | `install` | `uninstall` | `run-service` | `stream`)
- `stream_probe.exe`    a controller-side probe (counts inbound RTP, can send input) for testing
- `config.template.json` template for `C:\rmt-agent\config.json`
- `install-agent.ps1`   copies the binaries, writes the config, **enrolls** (M3), installs + starts
                        the service

## Quick install (run elevated / as Administrator)
A stock Windows install ships execution policy `Restricted`, so invoke the script explicitly rather
than dot-slashing it (`./install-agent.ps1` fails with "running scripts is disabled on this system"):
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./install-agent.ps1 `
                    -SignalingUrl     "ws://relay.example:8080/ws" `
                    -ControlPlaneUrl  "https://cp.example:8443" `
                    -EnrollmentToken  "<one-shot token from the control plane>" `
                    -GrantIssuerPubkey "<64-hex-chars from GET /grant/pubkey>" `
                    -RequireSessionPolicy `
                    -Stun @("stun:stun.l.google.com:19302")
```
Other install-time knobs, all of which write the matching `config.json` key:
`-RequireSessionPolicy` (below), `-Clipboard bidirectional|to_technician|to_guest|disabled`,
`-MaxSessionSecs`, `-MaxBitrateBps`, `-MaxFps`, `-DisableAdaptive`. Run
`Get-Help ./install-agent.ps1 -Full` for the details. `quality.max_bitrate_bps` is written only when
`-MaxBitrateBps` is given, because it is a hard cap. Without it, sessions start at 3 Mbps and may rise to
20 Mbps, scaled for multiple displays. The agent ignores exactly 3000000, the value older installers wrote.

## Identity (M3) — why there is no `-DeviceId`
A `device_id` is what a session ticket authorizes the signaling server to broker to, so the agent
never chooses its own. The installer runs

```powershell
agent_host.exe enroll --control-plane-url <url> --token <token> --config C:\rmt-agent\config.json
```

which POSTs the control plane's public `POST /enroll/redeem` with a freshly generated Ed25519 public
key, and writes back the **server-minted** `device_id` + `tenant_id`, clearing the one-shot token.
The private seed lands in `C:\rmt-agent\identity.key` (ACL: SYSTEM + Administrators) and is what the
agent signs the signaling server's nonce with (`RMTAGENTAUTHv1`; see
`docs/11-agent-identity-contract.md`). Enrollment is terminal: an already-enrolled config is left
alone rather than burning another token use. If enrollment fails the installer aborts — it will not
leave behind an agent with a self-invented device id that no ticket can ever authorize.

## config.json fields (`C:\rmt-agent\config.json`)
- `signaling_url`  (required for streaming) the WebSocket rendezvous URL, e.g. `ws://host:8080/ws`.
- `control_plane_url`  base URL for first-run enrollment (`POST <url>/enroll/redeem`). `https://`
                   required, except a loopback host for local development. Present ⇒ this agent is
                   control-plane managed and will NOT invent a device id.
- `enrollment_token`  one-shot bearer secret; **cleared from disk** by a successful redemption.
- `device_id`      server-minted UUID. Leave blank — written by `enroll`. (Only an unmanaged
                   dev/LAN agent, i.e. no `control_plane_url`, mints one locally.)
- `tenant_id`      the tenant enrollment placed this machine in. Written by `enroll`; leave blank.
- `stun`           zero or more STUN URLs for WAN NAT traversal. Empty = LAN/loopback only.
- `transfer_dir`   root for file-transfer uploads/downloads. Default `C:\rmt-agent\transfers`.
- `grant_issuer_pubkey`  the control-plane's Ed25519 public key (hex, 64 chars). See docs/10 §4
                   step 1 for the four ways to obtain it — an ANONYMOUS `curl` of `/grant/pubkey`
                   is not one of them; that route is authenticated.
                   **SECURITY:** when set, backstage tooling requires a valid signed grant. When
                   BLANK, backstage is **DISABLED** on the installed service — it does NOT fall
                   back to a self-issued demo grant. (Only the `stream` dev CLI ever did that, and
                   an earlier version of this line said otherwise, which read as though leaving it
                   blank were merely insecure rather than non-functional.)
                   Pinning it is now load-bearing for TWO controls: backstage grants, and central
                   session revocation — an agent without it holds no session lease, so "End
                   session" in the console cannot reach it (docs/25 F03, docs/26).
- `directive_pubkey`  the control plane's FLEET DIRECTIVE key (hex, 64 chars; docs/65 D-C3), the
                   key remote reinstall/remove directives are signed with. Blank is normal: the agent
                   pins it from the enrollment response. Set it only to pre-pin at install. It must
                   differ from `grant_issuer_pubkey` and `update_signer_pubkey`; the agent refuses
                   it otherwise, and with no directive key pinned it refuses ALL directives.
- `update_signer_pubkey`  the RELEASE SIGNER's Ed25519 public key (hex, 64 chars), from
                   `rmt-update-sign gen-key` / `rmt-update-sign pubkey` (docs/21 §3).
                   **SECURITY:** this is NOT `grant_issuer_pubkey` and must never be set to the
                   same value. The control plane's key mints session-scoped, audited artifacts and
                   lives on the internet-facing box; the update key authorizes arbitrary code as
                   SYSTEM on every machine, permanently, and lives OFFLINE. The agent refuses every
                   update if the two are equal, and refuses every update when this is blank — there
                   is no permissive third state. Rotating it means visiting every machine.
- `require_session_policy`  when `true`, a session gets NO technician input until a
                   control-plane-signed session ACCESS policy verifies (docs/01 §5).
                   **SECURITY:** this is what makes a per-group view-only mandate BINDING. The
                   policy reaches the agent because the VIEWER forwards it, and the viewer is
                   exactly what the mandate constrains — with this `false`, a technician who
                   tampers with their own console simply omits the frame and keeps full control.
                   Needs `grant_issuer_pubkey` (there is nothing to verify against without it):
                   set BOTH for an enforcing deployment, or leave both blank/false. The installer's
                   `-RequireSessionPolicy` switch writes this; it REFUSES to run without
                   `-GrantIssuerPubkey`, because an agent with no issuer key can never verify a
                   policy and would strand every session in view-only.
- `identity_path`  override for `C:\rmt-agent\identity.key`. Leave blank in production.

## Manual streaming (no service; for testing)
```powershell
agent_host.exe stream --signaling ws://host:8080/ws [--stun stun:host:3478] [--fps 30] `
               [--identity C:\rmt-agent\identity.key --device <uuid> --tenant <uuid>]
```

## Uninstall
```powershell
agent_host.exe uninstall
```
'@
Write-Utf8NoBom (Join-Path $AgentDist 'README.md') $agentReadme

$installAgent = @'
<#
.SYNOPSIS
    Enroll this machine with the control plane and install the RMT agent as a Windows service.
    Run elevated (Administrator).
.DESCRIPTION
    1. Copies agent_host.exe + stream_probe.exe to -BinDir.
    2. Writes C:\rmt-agent\config.json from the supplied parameters.
    3. Runs `agent_host.exe enroll` (M3), which redeems the one-shot -EnrollmentToken against the
       control plane's public POST /enroll/redeem, pins this machine's freshly generated Ed25519
       public key, and writes back the SERVER-MINTED device_id + tenant_id.
    4. Runs `agent_host.exe install` to register + start the LocalSystem service.

    There is deliberately NO -DeviceId parameter. A device id is what a session ticket authorizes
    the signaling server to broker to, so it is minted server-side (migration 0008) and never
    chosen by the installer or the agent. If enrollment fails this script aborts before installing
    the service, rather than leaving an unauthenticatable agent behind.
.PARAMETER Unmanaged
    Skip enrollment entirely: a dev/LAN install with no control plane. The agent then mints a local
    dev device id on first run and its register_agent is NOT authenticated. Never use in production.
.PARAMETER RequireSessionPolicy
    Write `require_session_policy: true`. This is what makes a session ACCESS policy BINDING instead
    of advisory: the agent then refuses ALL technician input until a control-plane-signed policy
    verifies for the session.

    Without it, a per-group view-only mandate is enforced only by the console that is supposed to be
    constrained by it -- the policy reaches the agent because the VIEWER forwards it, so a technician
    running a patched console simply never sends the frame and keeps full control. Requires
    -GrantIssuerPubkey (there is nothing to verify a policy against without it); the two are checked
    together below and the combination is refused rather than shipped broken.
.PARAMETER UpdateSignerPubkey
    Write `update_signer_pubkey`: the RELEASE SIGNER's Ed25519 public key (64 hex chars), which the
    agent pins and every update manifest must be signed by (docs/21 §3). Produced by the offline
    signer: `rmt-update-sign gen-key -seed release-signing.key`, or `rmt-update-sign pubkey` for an
    existing one.

    **This is NOT -GrantIssuerPubkey, and passing the same value for both is refused below.** The
    control plane's key mints session-scoped, capability-bounded, audited artifacts and lives in a
    .env file on the internet-facing box. This key authorizes arbitrary code as SYSTEM on every
    managed machine, permanently, and it must live OFFLINE -- if it never touches the control plane,
    then compromising the control plane yields the ability to SERVE a manifest but not to SIGN one,
    which turns fleet-wide RCE into denial of updates.

    Blank (the default) means this agent refuses every update manifest. That is the safe default and
    the state of every machine installed before the feature existed; there is no permissive third
    value. Rotating this key means visiting every machine, because a changed key makes every
    enrolled agent refuse every update, silently, with no remote way back.
.PARAMETER Clipboard
    The machine's clipboard ceiling: bidirectional (default) | to_technician | to_guest | disabled.
    An administrator's off switch, per direction. Composes with -- never overrides -- the session's
    view-only state, which refuses both directions regardless of what is set here.
.PARAMETER MaxSessionSecs
    Longest a single remote-control session may run. Default 14400 (4 hours). A resource bound, not
    an authorization one.
.PARAMETER MaxBitrateBps
    An administrator's HARD bitrate cap: the most a technician may ask this agent to spend on the
    customer's uplink, applied even to a multi-display picture. Omit it (the default) to write no cap:
    sessions then start at 3 Mbps, adapt to loss, and may be raised to 20 Mbps, scaled for multiple displays.
    The value 3000000 is refused, because the agent reads it as the pre-1.3.25 installer default and not as a cap.
    Use 2900000 if a cap near 3 Mbps is wanted.
.PARAMETER MaxFps
    The machine's frame-rate ceiling. Default 60.
.PARAMETER DisableAdaptive
    Turn the adaptive rate controller off for every session on this machine -- the switch for a site
    where loss-based backoff misreads a lossy-but-uncongested link. Default: adaptive stays on.
#>
[CmdletBinding(DefaultParameterSetName="Managed")]
param(
    [Parameter(Mandatory=$true)][string]$SignalingUrl,
    [Parameter(Mandatory=$true, ParameterSetName="Managed")][string]$ControlPlaneUrl,
    [Parameter(Mandatory=$true, ParameterSetName="Managed")][string]$EnrollmentToken,
    [Parameter(Mandatory=$true, ParameterSetName="Unmanaged")][switch]$Unmanaged,
    [string]$MachineName = "",
    [string]$GrantIssuerPubkey = "",
    [string]$DirectivePubkey = "",
    [string]$UpdateSignerPubkey = "",
    [switch]$RequireSessionPolicy,
    [ValidateSet("bidirectional","to_technician","to_guest","disabled")]
    [string]$Clipboard = "bidirectional",
    [ValidateRange(60, 604800)][int]$MaxSessionSecs = 14400,
    [ValidateRange(100000, 100000000)][int]$MaxBitrateBps,
    [ValidateRange(1, 240)][int]$MaxFps = 60,
    [switch]$DisableAdaptive,
    [string[]]$Stun = @(),
    [string]$TransferDir = "C:\rmt-agent\transfers",
    [string]$BinDir = "C:\rmt-agent-bin",
    [string]$ConfigPath = "C:\rmt-agent\config.json"
)
$ErrorActionPreference = "Stop"
# Refuse a BLANK or SCHEMELESS required value, BEFORE anything is copied, written or enrolled.
#
# READ THE MEASUREMENT BEFORE EDITING THIS. The long-standing claim was that
# `[Parameter(Mandatory)]` prompts when a value is absent and that pressing Enter satisfies it with
# an empty string, producing an install that "succeeds" with an empty signaling_url. THAT IS
# REFUTED. Measured 2026-09-06: Windows PowerShell 5.1 and pwsh 7 both reject a prompted blank at
# the binder (ParameterArgumentValidationErrorEmptyStringNotAllowed), as they do an explicit "".
# (Limitation: the answers were piped to stdin rather than typed at a live console; the refusal is
# the binder's own validation, which does not depend on where the answer came from.)
#
# The all-nulls config that took a machine down did NOT come from here. This script ALWAYS writes
# transfer_dir, max_session_secs and quality with non-null defaults, and writes the two pubkeys as
# "" rather than null -- four fingerprints the broken file fails. That file is a Rust
# HelperConfig::default() serialization, and the writer was the agent crate's own unit suite minting
# a device_id into the hardcoded production path. Fixed at the source, in config.rs save_to.
#
# So this block is defence in depth, not that root cause -- and it closes a gap the binder really
# does leave open: WHITESPACE PASSES Mandatory. -EnrollmentToken "   " binds happily and installs an
# agent that can never redeem; a scheme-less URL does the same. Validate the VALUE, because the
# parameter attribute only rules out absent and empty, never meaningless.
#
# Placed ahead of even the elevation check so a bad install fails identically whether or not it was
# started elevated, and so build-release.ps1 can exercise the refusal without anything actuating.
function Assert-RequiredValue {
    param([string]$Name, [string]$Value, [string[]]$Schemes)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw ("$Name is blank or whitespace. Mandatory rules out absent and empty but binds " +
               "whitespace, which installs a service that can never connect and still reports " +
               "healthy. Re-run and pass a real value for $Name.")
    }
    if ($Schemes) {
        $v = $Value.Trim()
        $ok = @($Schemes | Where-Object { $v.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) })
        if ($ok.Count -eq 0) {
            throw ("$Name must start with one of: " + ($Schemes -join ", ") + " -- got '$v'. A " +
                   "value with no scheme is not a URL the agent can dial.")
        }
    }
}
Assert-RequiredValue -Name "-SignalingUrl" -Value $SignalingUrl -Schemes @("ws://", "wss://")
if (-not $Unmanaged) {
    Assert-RequiredValue -Name "-ControlPlaneUrl" -Value $ControlPlaneUrl -Schemes @("http://", "https://")
    Assert-RequiredValue -Name "-EnrollmentToken" -Value $EnrollmentToken
}
# Refused HERE, before the existing service is stopped or deleted (Codex 1.3.25 review): a refusal
# later in the script would leave an upgraded machine with no service.
if ($PSBoundParameters.ContainsKey('MaxBitrateBps') -and $MaxBitrateBps -eq 3000000) {
    throw "-MaxBitrateBps 3000000 is the legacy installer default, and the agent reads it as 'no cap'. Omit -MaxBitrateBps for no cap, or pass another value (for example 2900000) for a hard cap."
}


# Require elevation (service install, C:\rmt-agent, and the identity-key ACL all need admin).
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) { throw "install-agent.ps1 must be run as Administrator." }

# Refuse -RequireSessionPolicy without an issuer key, BEFORE anything is copied or written.
#
# require_session_policy means "no technician input until a control-plane-signed session ACCESS
# policy verifies". An agent with no grant_issuer_pubkey has nothing to verify a signature against,
# so no policy can ever verify and every session is stranded in view-only forever. The Rust field's
# own documentation says to set BOTH or neither. Refusing here costs the operator one re-run;
# shipping the combination costs them a machine that connects, paints a desktop, and silently
# ignores every click -- the kind of failure that gets diagnosed as "the product is broken".
if ($RequireSessionPolicy -and [string]::IsNullOrWhiteSpace($GrantIssuerPubkey)) {
    throw ("-RequireSessionPolicy needs -GrantIssuerPubkey: the agent verifies the session policy " +
           "against the control plane's Ed25519 key (GET /grant/pubkey), and without it NO policy " +
           "can ever verify, so every session would be stranded in view-only. Pass both, or neither.")
}

# Refuse the update signing key being the control plane's key, BEFORE anything is written.
#
# docs/21 §3 calls "the signing key is NOT the grant issuer key, and does NOT live on the control
# plane" the most important sentence in that document, and this is the copy-paste that quietly
# breaks it. The agent refuses this configuration too (rmt_agent::update::UpdateTrust::from_config),
# which is the check that actually protects an already-installed machine -- but an operator who only
# ever reads installer output would never see it. Failing here costs them one re-run; accepting it
# costs them the illusion of a signature check whose key sits in a .env file on the internet-facing
# box, which is the entire thing the split exists to prevent.
#
# Compared case-insensitively and trimmed: hex is case-insensitive, so a string comparison that
# missed "ABC..." against "abc..." would let the exact mistake through.
# docs/65 D-C3: the directive key is a THIRD, separate key. The agent refuses a directive key equal to
# either other key (and then refuses every directive); refuse it here so the mistake is loud at install.
if (-not [string]::IsNullOrWhiteSpace($DirectivePubkey)) {
    $dk = $DirectivePubkey.Trim().ToLowerInvariant()
    if ($dk -notmatch '^[0-9a-f]{64}$') { throw "-DirectivePubkey must be 64 hex characters." }
    if ($dk -eq $GrantIssuerPubkey.Trim().ToLowerInvariant() -or $dk -eq $UpdateSignerPubkey.Trim().ToLowerInvariant()) {
        throw ("-DirectivePubkey must NOT equal -GrantIssuerPubkey or -UpdateSignerPubkey (docs/65 D-C3): " +
               "a compromised grant signer must not be able to sign removal directives.")
    }
}
if (-not [string]::IsNullOrWhiteSpace($UpdateSignerPubkey) -and
    ($UpdateSignerPubkey.Trim().ToLowerInvariant() -eq $GrantIssuerPubkey.Trim().ToLowerInvariant())) {
    throw ("-UpdateSignerPubkey must NOT be the same key as -GrantIssuerPubkey. The control " +
           "plane's key mints session-scoped, audited artifacts and lives on the internet-facing " +
           "box; the update key authorizes arbitrary code as SYSTEM on every machine, permanently, " +
           "and must live OFFLINE (docs/21 §3). Generate a separate one with " +
           "'rmt-update-sign gen-key -seed release-signing.key'. The agent refuses this " +
           "combination too, so an install with both set the same would never apply an update.")
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# Stage binaries.
#
# HARDEN BEFORE COPYING. This directory holds the binary that runs as LocalSystem on every boot, and
# by default it sits at the root of C:, where it INHERITS the volume root's DACL. Measured on stock
# Windows 11 (`icacls C:\`): `NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)` — MODIFY for every
# authenticated user. Any standard user could replace agent_host.exe, or drop a DLL beside it, and
# own SYSTEM at the next service start.
#
# The config directory has had exactly this treatment, for exactly this reason, since the agent-root
# work; the BINARY directory never got it. Same measurement, same fix, one directory over.
#
# Order matters. Hardening first means the copy lands into an already-restricted directory, so there
# is no window in which a good binary sits in a world-writable place. The reparse-point refusal
# mirrors the config directory's: a junction planted here beforehand would otherwise redirect both
# the copy and the DACL onto a target the attacker chose.
# Replace the DACL and owner; additive grants retain explicit permissions planted before install.
function Set-AgentOnlyAcl([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "$Path is a reparse point - refusing to read, write or secure its target."
    }
    if ($item.PSIsContainer) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    } else {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$binItem = Get-Item -LiteralPath $BinDir -Force
if ($binItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw "$BinDir is a reparse point (junction/symlink) - refusing to install the service binary through it. Remove it and re-run."
}
Set-AgentOnlyAcl $BinDir
Write-Host "hardened $BinDir DACL to SYSTEM + Administrators" -ForegroundColor Green

# An earlier install leaves the RmtAgent service RUNNING, and its agent_host.exe holds THIS exact
# file open, so the copy below fails with "the process cannot access the file ... because it is being
# used by another process" (hit on the first real install). Stop + remove any existing service, and
# any lingering helper process, BEFORE the copy. A missing service is not an error (first install).
# The ENROLLED IDENTITY is untouched -- it lives in $ConfigPath under C:\rmt-agent, not the bin dir --
# so this is an in-place upgrade, not a re-enroll. Uses sc.exe rather than `agent_host uninstall` so
# we do NOT trigger the detached self-uninstaller, which would race this copy by deleting the bin dir.
if (Get-Service RmtAgent -ErrorAction SilentlyContinue) {
    Write-Host "existing RmtAgent service found -- stopping + removing it so its binary can be replaced" -ForegroundColor Yellow
    Stop-Service RmtAgent -Force -ErrorAction SilentlyContinue
    & sc.exe stop RmtAgent 2>&1 | Out-Null
    Get-Process agent_host -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    & sc.exe delete RmtAgent 2>&1 | Out-Null
    # A lingering handle keeps the service 'marked for deletion', which would then fail the later
    # `agent_host install`. Wait (bounded) for it to fully disappear.
    for ($i = 0; $i -lt 20 -and (Get-Service RmtAgent -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 300 }
}
Get-Process agent_host -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

foreach ($exe in "agent_host.exe","stream_probe.exe") {
    $destination = Join-Path $BinDir $exe
    if (Test-Path -LiteralPath $destination) { Set-AgentOnlyAcl $destination }
    Copy-Item -LiteralPath (Join-Path $here $exe) -Destination $destination -Force -ErrorAction Stop
    Set-AgentOnlyAcl $destination
}
$agentHost = Join-Path $BinDir "agent_host.exe"

# Write config.json (UTF-8, no BOM). device_id/tenant_id are intentionally ABSENT: `enroll` writes
# them from the control plane's response. An existing config's enrolled identity is preserved.
$cfgDir = Split-Path -Parent $ConfigPath
New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
Set-AgentOnlyAcl $cfgDir
if (Test-Path -LiteralPath $ConfigPath) { Set-AgentOnlyAcl $ConfigPath }
# Existing identity and config must be protected before they are read or used.
$identityPath = Join-Path $cfgDir 'identity.key'
if (Test-Path -LiteralPath $identityPath) { Set-AgentOnlyAcl $identityPath }

$existing = $null
if (Test-Path $ConfigPath) {
    $raw = [System.IO.File]::ReadAllText($ConfigPath).TrimStart([char]0xFEFF)
    try { $existing = $raw | ConvertFrom-Json } catch { $existing = $null }
}
#
# Every key config.template.json advertises is written here, INCLUDING the ones left at their
# defaults. Two reasons. The advertised-but-unwritable ones were the bug: `require_session_policy`
# was in the template, parsed by the agent and documented in the README as the thing that makes a
# view-only mandate binding, yet the installer had no parameter for it and never emitted the key --
# so every scripted install landed with enforcement off and nobody could tell by looking. And
# writing the defaults explicitly means `type C:\rmt-agent\config.json` ANSWERS the question "is
# this machine enforcing, and what is its clipboard set to" instead of requiring the reader to know
# which absent keys mean what. The values below are the agent's own defaults, so an explicit write
# changes no behaviour -- it only makes the behaviour legible.
#
# build-release.ps1's Assert-InstallerCoversTemplate fails the build if a template key stops being
# settable here, so this cannot drift back.
$cfg = [ordered]@{
    signaling_url          = $SignalingUrl
    stun                   = @($Stun)
    transfer_dir           = $TransferDir
    grant_issuer_pubkey    = $GrantIssuerPubkey
    directive_pubkey       = $DirectivePubkey
    update_signer_pubkey   = $UpdateSignerPubkey
    require_session_policy = [bool]$RequireSessionPolicy
    clipboard              = $Clipboard
    max_session_secs       = $MaxSessionSecs
    quality                = [ordered]@{
        max_fps         = $MaxFps
        adaptive        = (-not $DisableAdaptive)
    }
}
# quality.max_bitrate_bps is the EXCEPTION to "write every default": since agent 1.3.24 a written
# value is an administrator's hard cap. Through 1.3.24 this script wrote 3000000 on every machine,
# which capped the whole fleet at 3 Mbps. The agent now reads exactly 3000000 as that legacy default
# (LEGACY_INSTALLER_BITRATE_BPS), so this script refuses that value and writes the key only on request.
if ($PSBoundParameters.ContainsKey('MaxBitrateBps')) {
    # Exactly 3000000 was already refused before the service was touched.
    $cfg.quality['max_bitrate_bps'] = $MaxBitrateBps
}
# identity_path is the one template key deliberately NOT exposed as a parameter. It overrides where
# the machine's PRIVATE Ed25519 signing key lives, it exists so tests can point enrollment at a temp
# file, and production has no reason to move it: C:\rmt-agent is the directory this installer (and
# every service start) hardens to SYSTEM + Administrators, so a mistyped override would put the key
# somewhere with no such guarantee. Omitting the key leaves the agent on its hardened default.
if (-not $Unmanaged) {
    $cfg["control_plane_url"] = $ControlPlaneUrl
    $cfg["enrollment_token"]  = $EnrollmentToken
}
foreach ($keep in "device_id","tenant_id") {
    $v = $null
    if ($existing -and ($existing.PSObject.Properties.Name -contains $keep)) { $v = $existing.$keep }
    if (-not [string]::IsNullOrWhiteSpace($v)) {
        $cfg[$keep] = $v
        Write-Host "preserving already-enrolled $keep=$v" -ForegroundColor Yellow
    }
}
$json = $cfg | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($ConfigPath, $json, (New-Object System.Text.UTF8Encoding($false)))
Set-AgentOnlyAcl $ConfigPath
Write-Host "wrote $ConfigPath" -ForegroundColor Green

if ($RequireSessionPolicy) {
    Write-Host ("require_session_policy=true: sessions start VIEW-ONLY and stay there until a " +
        "control-plane-signed session policy verifies.") -ForegroundColor Green
} elseif (-not [string]::IsNullOrWhiteSpace($GrantIssuerPubkey)) {
    # Only warn when the deployment COULD enforce. An agent with no issuer key cannot verify a
    # policy at all, so telling that operator to turn enforcement on would be advice that breaks
    # their install (see the refusal at the top). This branch is the one where the operator has
    # everything needed and simply did not ask for it.
    Write-Warning ("require_session_policy is false: a session ACCESS policy is ADVISORY on this " +
        "machine. The policy reaches the agent only because the VIEWER forwards it, so a technician " +
        "running a tampered console can omit it and keep full control -- a per-group view-only " +
        "mandate is then not enforced. Pass -RequireSessionPolicy to make it binding.")
}

if ([string]::IsNullOrWhiteSpace($GrantIssuerPubkey)) {
    # Was: "backstage runs in INSECURE dev mode (self-issued demo grant)" — i.e. omitting this flag
    # silently switched the tool-panel authorization system OFF on an installed service. The agent
    # now fails CLOSED instead, so the accurate warning is that backstage is unavailable.
    Write-Warning ("grant_issuer_pubkey is blank: backstage (tool panels, shell, registry, file " +
        "transfer) will be DISABLED on this agent. Screen sharing and input still work. Pass " +
        "-GrantIssuerPubkey <hex> — the value GET /grant/pubkey serves — to enable it.")
}

if ([string]::IsNullOrWhiteSpace($UpdateSignerPubkey)) {
    # Write-Host, not Write-Warning: blank is the CORRECT default and the state of every machine
    # installed before this existed, so crying wolf here would train operators to ignore the
    # warnings above it. It is still worth saying out loud, because the failure it prevents is
    # silent -- an operator who later drops update-manifest.json on this machine gets nothing.
    Write-Host ("update_signer_pubkey is blank: this agent will REFUSE every update manifest " +
        "(docs/21 §3). That is the safe default. To enable updates, generate an OFFLINE release " +
        "signing key with 'rmt-update-sign gen-key -seed release-signing.key' and pass its public " +
        "half as -UpdateSignerPubkey. It must never be the same key as -GrantIssuerPubkey.") `
        -ForegroundColor DarkGray
}

# Enroll (M3). The agent's own subcommand owns the exchange, the key generation, and the key's ACL.
if ($Unmanaged) {
    Write-Warning "-Unmanaged: skipping enrollment. This agent mints a LOCAL dev device id and its registration is NOT authenticated. Dev/LAN only."
} else {
    $enrollArgs = @("enroll",
                    "--control-plane-url", $ControlPlaneUrl,
                    "--config",            $ConfigPath)
    if (-not [string]::IsNullOrWhiteSpace($MachineName)) { $enrollArgs += @("--name", $MachineName) }
    & $agentHost @enrollArgs
    if ($LASTEXITCODE -ne 0) {
        throw "agent_host enroll FAILED (exit $LASTEXITCODE) — service NOT installed. Fix the control-plane URL/token and re-run."
    }
    # Enrollment must have produced a server-minted device id; refuse to install a nameless agent.
    $after = [System.IO.File]::ReadAllText($ConfigPath).TrimStart([char]0xFEFF) | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace($after.device_id)) {
        throw "enroll reported success but $ConfigPath has no device_id — refusing to install."
    }
    Write-Host "enrolled as device $($after.device_id) in tenant $($after.tenant_id)" -ForegroundColor Green
}

# Install + start the service.
& $agentHost install
if ($LASTEXITCODE -ne 0) { throw "agent_host install FAILED (exit $LASTEXITCODE)" }
Write-Host "RMT agent installed. Service will stream once a controller connects via $SignalingUrl" -ForegroundColor Green

# Inbound firewall rule for the INSTALLED binary. The agent dials signaling OUTBOUND, but the
# peer-to-peer media/data path needs the controller to reach THIS agent's ICE candidates. With the
# Private profile defaulting to Block inbound and no TURN relay (ice_relay=0), a session brokers and
# then dies at ICE without this. Program-scoped so it is bound to this exact binary, and idempotent
# (removes any prior rule of the same name first). Non-fatal: enrollment already succeeded, so a
# firewall hiccup warns rather than aborting the install.
$fwName = 'RMT Agent (agent_host)'
try {
    Get-NetFirewallRule -DisplayName "$fwName*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $fwName       -Direction Inbound -Program $agentHost -Action Allow -Profile Any -Protocol UDP -ErrorAction Stop | Out-Null
    New-NetFirewallRule -DisplayName "$fwName TCP" -Direction Inbound -Program $agentHost -Action Allow -Profile Any -Protocol TCP -ErrorAction Stop | Out-Null
    Write-Host "added inbound firewall allow rules for $agentHost" -ForegroundColor Green
} catch {
    Write-Warning ("could not add the inbound firewall rule ({0}). A LAN/remote controller may not reach this agent until an inbound Allow rule exists for {1}." -f $_, $agentHost)
}
'@
Write-Utf8Bom (Join-Path $AgentDist 'install-agent.ps1') $installAgent
Ok "agent config template + README + installer generated"

# No INSECURE DEV DEMO binary may reach an artifact (docs/25 F16).
Assert-NoDemoBinariesShipped -DistRoot $Dist -DemoBinDir (Join-Path $RepoRoot 'agent/src/bin')

# The generated artifacts are checked against the code they claim to configure.
Assert-ConfigTemplateMatchesRust `
    -TemplatePath (Join-Path $AgentDist 'config.template.json') `
    -ConfigRsPath (Join-Path $RepoRoot 'crates/agent-windows/src/config.rs')
Assert-PowerShellParses (Join-Path $AgentDist 'install-agent.ps1')
Assert-ShippedPs1Encoding (Join-Path $AgentDist 'install-agent.ps1')
Assert-InstallerCoversTemplate `
    -TemplatePath  (Join-Path $AgentDist 'config.template.json') `
    -InstallerPath (Join-Path $AgentDist 'install-agent.ps1')
Assert-InstallerRefusesMeaninglessValues (Join-Path $AgentDist 'install-agent.ps1')

# M3: the installer must delegate identity to the agent's `enroll` subcommand and must never accept
# or write a caller-supplied device_id (a device id is what a session ticket authorizes).
$installerText = [System.IO.File]::ReadAllText((Join-Path $AgentDist 'install-agent.ps1'))
if ($installerText -notmatch '"enroll"') {
    throw "install-agent.ps1 does not invoke the agent's enroll subcommand"
}
if ($installerText -match '\$DeviceId\b') {
    throw "install-agent.ps1 has a DeviceId parameter — device ids are server-minted (M3)"
}
if ($installerText -match 'device_id\s*=\s*\$') {
    throw "install-agent.ps1 writes a caller-supplied device_id into config.json (M3 violation)"
}
Ok 'installer delegates identity to "agent_host enroll" and takes no -DeviceId'

# --- MSI installer (docs/01 §6): build dist/RmtAgent.msi from the staged agent + VERIFY its contents ---
# The MSI packages agent_host.exe and registers the RmtAgent service (packaging/msi/RmtAgent.wxs). Built
# only when WiX is available so a box without it still produces the rest of dist/; when it IS available
# the guard proves the MSI actually carries the agent + service. The gate's `package` suite runs this.
$wixCli = Resolve-Wix
if ($wixCli) {
    $Msi = Join-Path $Dist 'RmtAgent.msi'
    # build-msi.ps1 requires ProductVersion 1.3.N for agent 0.1.N (the auto-updater's mapping) and
    # defaults -Version to 1.3.0, so without this every staged agent but 0.1.0 failed the package
    # suite. Derive it from the staged agent itself.
    $stagedVersion = (& $StagedAgent version).Trim()
    if ($stagedVersion -notmatch '^0\.1\.(\d+)(\+[0-9a-f]+)?$') { throw "staged agent version '$stagedVersion' is not 0.1.N" }
    $MsiVersion = "1.3.$($Matches[1])"
    Invoke-Checked "build MSI (wix) $MsiVersion" {
        # An agent built with no update identity (no DESKRALLY_UPDATE_OFFICIAL / own feed, i.e. not
        # -RequireFreshAgent) packages as an auto-update-OFF MSI; build-msi refuses it otherwise.
        $msiArgs = @{ AgentExe = $StagedAgent; Version = $MsiVersion; Out = $Msi }
        if (@(& $StagedAgent msi-capabilities) -contains 'FEED=none') {
            if ($RequireFreshAgent) { throw 'a -RequireFreshAgent release agent has no update identity' }
            $msiArgs.ExpectedFeed = 'none'; $msiArgs.AllowNoPin = $true
        }
        & (Join-Path $PSScriptRoot 'build-msi.ps1') @msiArgs
    }
    Assert-MsiContents -Msi $Msi
    if ($Sign) { Invoke-ReleaseSignature -ArtifactPath $Msi }
} else {
    Warn "wix CLI not found — dist/RmtAgent.msi NOT built (install WiXToolset.WiXCLI to include it)"
}

# =================================================================================================
# 2. Go servers
# =================================================================================================
$ServersDist = Join-Path $Dist 'servers'
Reset-Dir $ServersDist

$goBuilds = @(
    @{ Name = 'signaling.exe';    Dir = (Join-Path $RepoRoot 'server/signaling');  Pkg = '.' },
    @{ Name = 'relay.exe';        Dir = (Join-Path $RepoRoot 'server/relay');      Pkg = '.' },
    @{ Name = 'controlplane.exe'; Dir = (Join-Path $RepoRoot 'control-plane');     Pkg = './cmd/controlplane' }
)
foreach ($b in $goBuilds) {
    $out = Join-Path $ServersDist $b.Name
    Push-Location $b.Dir
    try {
        Invoke-Checked ("go build {0}" -f $b.Name) {
            $env:CGO_ENABLED = '0'
            go build -o $out $b.Pkg
        }
    } finally { Pop-Location }
    if (-not (Test-Path $out)) { throw "expected server artifact missing: $out" }
}
Ok "server binaries staged"

# Control-plane migrations travel with the servers. A migration that fails to ship is a control
# plane that will not boot (or worse, boots against a half-migrated schema), so the staged set is
# compared against the source set and checked for numbering gaps.
$MigSrc  = Join-Path $RepoRoot 'control-plane/migrations'
$MigDist = Join-Path $ServersDist 'migrations'
New-Item -ItemType Directory -Force -Path $MigDist | Out-Null
Copy-Item (Join-Path $MigSrc '*.sql') $MigDist -Force

$srcNames    = @(Get-ChildItem $MigSrc  -Filter *.sql -File | Select-Object -ExpandProperty Name | Sort-Object)
$stagedNames = @(Get-ChildItem $MigDist -Filter *.sql -File | Select-Object -ExpandProperty Name | Sort-Object)
if ($srcNames.Count -eq 0) { throw "no migrations found in $MigSrc" }
$notStaged = $srcNames | Where-Object { $stagedNames -notcontains $_ }
if ($notStaged) { throw "migrations missing from dist: $($notStaged -join ', ')" }
if ($stagedNames.Count -ne $srcNames.Count) {
    throw "dist/servers/migrations has $($stagedNames.Count) files but source has $($srcNames.Count)"
}
# Numbering must be contiguous from 0001: a gap means a migration was lost or never committed.
for ($i = 0; $i -lt $stagedNames.Count; $i++) {
    $n = 0
    if (-not [int]::TryParse($stagedNames[$i].Substring(0, 4), [ref]$n)) {
        throw "migration $($stagedNames[$i]) does not start with a 4-digit sequence number"
    }
    if ($n -ne $i + 1) {
        throw ("migration numbering gap: expected {0:d4} but found {1}" -f ($i + 1), $stagedNames[$i])
    }
}
Ok ("control-plane migrations copied: {0} files, 0001..{1:d4} contiguous" -f $stagedNames.Count, $stagedNames.Count)

# =================================================================================================
# 3. Viewer (static bundle)
# =================================================================================================
$ViewerDist = Join-Path $Dist 'viewer'
if ($SkipViewer) {
    Warn "SkipViewer: reusing existing dist/viewer"
} else {
    Reset-Dir $ViewerDist
    $ViewerSrc = Join-Path $RepoRoot 'web/viewer'
    Push-Location $ViewerSrc
    try {
        if (-not (Test-Path (Join-Path $ViewerSrc 'node_modules'))) {
            Invoke-Checked "npm install (viewer deps)" { npm install }
        }
        # docs/66 2i: VITE_DEFAULT_ORIGIN is the default host's origin (the tenant-branded page's attribution link). This kit
        # build has no tenant branding unless the caller exports one or .env.production.local sets it; `none` = neutral.
        $hadOrigin = Test-Path Env:VITE_DEFAULT_ORIGIN
        if (-not $hadOrigin -and -not (Test-Path (Join-Path $ViewerSrc '.env.production.local'))) { $env:VITE_DEFAULT_ORIGIN = 'none' }
        try { Invoke-Checked "npm run build (tsc + vite)" { npm run build } }
        finally { if (-not $hadOrigin) { Remove-Item Env:VITE_DEFAULT_ORIGIN -ErrorAction SilentlyContinue } }
    } finally { Pop-Location }

    $builtBundle = Join-Path $ViewerSrc 'dist'
    if (-not (Test-Path (Join-Path $builtBundle 'index.html'))) {
        throw "viewer build produced no index.html at $builtBundle"
    }
    Copy-Item (Join-Path $builtBundle '*') $ViewerDist -Recurse -Force
    if (-not (Test-Path (Join-Path $ViewerDist 'index.html'))) {
        throw "viewer staging produced no index.html in $ViewerDist"
    }
    $viewerJs = @(Get-ChildItem $ViewerDist -Recurse -File -Filter *.js)
    if ($viewerJs.Count -eq 0) { throw "viewer bundle in $ViewerDist contains no JavaScript" }

    # Ship join.html as a byte-identical copy of index.html.
    #
    # The bundle is a single-page app with hand-rolled path routing (web/viewer/src/main.tsx): the
    # guest landing page is whatever is served at `/join`, and the app decides from
    # `window.location.pathname`. On the "serve it from any static host" deployment docs/10 §5
    # recommends there is NO SPA fallback, so `GET /join` — the exact URL the control plane hands
    # every attended guest as `join_url` — returned 404 and the whole attended-guest entry point was
    # dead in production while the checklist called it done. main.tsx already accepts `/join.html`,
    # so a copy costs one file and needs no server configuration at all. An operator who DOES have
    # an SPA fallback keeps working either way, because both paths render the same page.
    Copy-Item (Join-Path $ViewerDist 'index.html') (Join-Path $ViewerDist 'join.html') -Force
    Ok ("viewer bundle staged (index.html + join.html + {0} js file(s))" -f $viewerJs.Count)
}

# =================================================================================================
# 4. dist/README.md + MANIFEST.txt
# =================================================================================================
$distReadme = @'
# RMT — Release Distribution

Built by `scripts/build-release.ps1`. See `docs/10-deployment.md` for the full deployment guide.

## Layout
- `agent/`    Windows agent: `agent_host.exe` + `stream_probe.exe` (static CRT), `config.template.json`,
              `README.md`, `install-agent.ps1`. Install on a target machine (elevated).
- `servers/`  Backend: `signaling.exe` (:8080), `relay.exe` (:9000 TCP / :9001 WS),
              `controlplane.exe` (:8081, needs Postgres + migrations), and `migrations/*.sql`.
- `viewer/`   Static browser controller bundle (`index.html` + `join.html` + assets). Serve from any
              static host. `join.html` is a copy of `index.html`: the guest landing page the control
              plane links as `/join#<code>` needs an SPA fallback, and this makes the bundle work
              without one. If your host DOES rewrite unknown paths to `index.html`, keep it anyway —
              both paths render the same page.

## Fast start (native backend)
```powershell
servers/signaling.exe -addr :8080
servers/relay.exe -tcp :9000 -ws :9001
# control-plane in dev mode (no DB); production sets DATABASE_URL + applies servers/migrations
servers/controlplane.exe            # dev/in-memory; GET /grant/pubkey works for agent provisioning
```
Then install the agent on a target (see `agent/README.md`) and open the viewer.

Docker/compose alternative + TURN/coturn pointer: `docs/10-deployment.md`, `deploy/docker-compose.yml`.
'@
Write-Utf8NoBom (Join-Path $Dist 'README.md') $distReadme

# MANIFEST: what is IN the bundle -- component, file, size, and WHEN EACH FILE WAS BUILT.
#
# The old header was one line, "RMT release manifest - generated <now>", followed by a size per
# file. Read literally it dated the MANIFEST. Read the way everybody actually read it, it dated the
# BUNDLE, and nothing anywhere in the file distinguished the two. That gap is not academic: a
# -SkipRust run rewrites the README, the config template, the installer, the MSI and this manifest
# while leaving agent_host.exe exactly where it was, so a bundle whose agent predated an LPE fix by
# six days presented a header stamped a few seconds ago. Somebody trusting it installed it.
#
# So the header now states the two dates as two separate, labelled facts, adds the binary's own
# embedded build identity (the only thing in the bundle that knows what SOURCE it came from) and the
# commit HEAD was on, and -- when those disagree -- opens with an unmissable STALE block. Every file
# row carries its own mtime, and the stale binaries are flagged individually, so the fact survives
# both a skim of the top and a search of the middle.
$manifestLines = New-Object System.Collections.Generic.List[string]
$fileStamp = { param($dt) $dt.ToString('yyyy-MM-dd HH:mm:ss') }
$headText  = if ($AgentIdentity.HeadFull) {
    "{0}  (branch {1})" -f $AgentIdentity.HeadFull, $AgentIdentity.Branch
} else {
    'UNKNOWN -- git did not answer when this manifest was written'
}
$freshText = if ($AgentIdentity.State -eq 'fresh') {
    "OK -- {0}" -f $AgentIdentity.Summary
} else {
    "{0} -- {1}" -f $AgentIdentity.State.ToUpperInvariant(), $AgentIdentity.Summary
}

$manifestLines.Add("RMT release manifest")
$manifestLines.Add(("  manifest written    : {0}   (when THIS FILE was generated)" -f (Get-Date -Format o)))
$manifestLines.Add(("  repo HEAD           : {0}" -f $headText))
$manifestLines.Add(("  agent build identity: {0}   [source: {1}]" -f $AgentIdentity.Stamp, $AgentIdentity.StampSource))
if ($AgentIdentity.StampNote) {
    $manifestLines.Add(("                        {0}" -f $AgentIdentity.StampNote))
}
$manifestLines.Add(("  agent binaries built: {0}   (mtime of dist/agent/agent_host.exe -- NOT the line above)" -f
                   $AgentIdentity.Mtime.ToString('yyyy-MM-ddTHH:mm:sszzz')))
$manifestLines.Add(("  agent freshness     : {0}" -f $freshText))

$staleBundle = ($AgentIdentity.State -ne 'fresh')
if ($staleBundle) {
    $sinceLine = if ($AgentIdentity.CommitsSince -ge 0) {
        "  {0} commit(s) have touched crates/ + agent/ since ({1} basis)." -f
            $AgentIdentity.CommitsSince, $AgentIdentity.SinceBasis
    } else {
        "  Commits touching crates/ + agent/ since: NOT COUNTED (git did not answer)."
    }
    $manifestLines.Add("")
    $manifestLines.Add("  *** STALE AGENT BINARY -- THIS BUNDLE WAS NOT BUILT FROM HEAD ***")
    $manifestLines.Add($sinceLine)
    $manifestLines.Add("  'manifest written' and 'agent binaries built' above are different facts: a -SkipRust")
    $manifestLines.Add("  run refreshes every generated text file and the MSI while reusing the agent binaries")
    $manifestLines.Add("  already in dist/agent. Rows flagged STALE below are older than the source this")
    $manifestLines.Add("  manifest was written against -- including dist/RmtAgent.msi, which repackages them.")
    $manifestLines.Add("  Rebuild with: pwsh -File scripts/build-release.ps1    (no -SkipRust)")
}
$manifestLines.Add("")

$totalBytes = 0
foreach ($comp in 'agent','servers','viewer','artifacts') {
    $compPath = Join-Path $Dist $comp
    if (-not (Test-Path $compPath)) { continue }
    $files = @(Get-ChildItem -Recurse -File $compPath | Sort-Object FullName)
    if ($files.Count -eq 0) { $manifestLines.Add("[$comp]  (empty)"); $manifestLines.Add(""); continue }
    $oldest = ($files | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime
    $newest = ($files | Sort-Object LastWriteTime | Select-Object -Last  1).LastWriteTime
    $manifestLines.Add(("[{0}]  {1} file(s), staged {2} .. {3}" -f
                       $comp, $files.Count, (& $fileStamp $oldest), (& $fileStamp $newest)))
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($Dist.Length + 1)
        # Flag BOTH agent binaries, not just the one that was measured: they come out of a single
        # `cargo build` invocation, so agent_host.exe's verdict is stream_probe.exe's verdict too.
        $mark = if ($staleBundle -and $comp -eq 'agent' -and
                    ($f.Name -eq 'agent_host.exe' -or $f.Name -eq 'stream_probe.exe')) { '  <<< STALE' } else { '' }
        $manifestLines.Add(("  {0,-52} {1,12:N0} bytes  {2}{3}" -f
                           $rel, $f.Length, (& $fileStamp $f.LastWriteTime), $mark))
        $totalBytes += $f.Length
    }
    $manifestLines.Add("")
}

# Top-level artifacts. dist/RmtAgent.msi was absent from every previous manifest, which is the worst
# possible omission here: it is the file an operator double-clicks, it is REBUILT on every run
# (including -SkipRust, since the MSI step sits outside that branch), and it packages whatever
# agent_host.exe happened to be staged. So a stale agent got a freshly-dated MSI that no manifest
# mentioned. MANIFEST.txt itself is excluded because it is written after this list is built and any
# size printed for it would be last run's.
$rootFiles = @(Get-ChildItem -File $Dist | Where-Object { $_.Name -ne 'MANIFEST.txt' } | Sort-Object Name)
if ($rootFiles.Count -gt 0) {
    $manifestLines.Add(("[dist root]  {0} file(s)  (MANIFEST.txt itself omitted: it is written last)" -f $rootFiles.Count))
    foreach ($f in $rootFiles) {
        $mark = if ($staleBundle -and $f.Name -eq 'RmtAgent.msi') { '  <<< STALE (packages the agent binary above)' } else { '' }
        $manifestLines.Add(("  {0,-52} {1,12:N0} bytes  {2}{3}" -f
                           $f.Name, $f.Length, (& $fileStamp $f.LastWriteTime), $mark))
    }
    $manifestLines.Add("")
}

# TOTAL stays the three components only, so it keeps matching the BUILD SUMMARY printed below.
$manifestLines.Add(("TOTAL (agent + servers + viewer) {0:N0} bytes ({1:N1} MB)" -f $totalBytes, ($totalBytes / 1MB)))
Write-Utf8NoBom (Join-Path $Dist 'MANIFEST.txt') ($manifestLines -join "`r`n")

# =================================================================================================
# Summary
# =================================================================================================
$elapsed = (Get-Date) - $startedAt
Write-Host ""
Write-Host "=========================== BUILD SUMMARY ===========================" -ForegroundColor Cyan
foreach ($comp in 'agent','servers','viewer','artifacts') {
    $compPath = Join-Path $Dist $comp
    if (Test-Path $compPath) {
        # An EXISTING BUT EMPTY component directory is a normal state, not an impossible one:
        # a build without -ControlPlaneUrl deliberately empties dist/artifacts (see the else-branch
        # above) so nothing downstream offers an unbuilt download. Over zero files
        # `Measure-Object Length -Sum` yields no `Sum` property, and under StrictMode reading it is a
        # terminating error — so the whole build failed at the SUMMARY, after every guard had passed,
        # with "The property 'Sum' cannot be found on this object" and no clue which directory.
        # It stayed hidden while dist/artifacts did not exist at all (Test-Path skipped it) and
        # surfaced the moment a support-client build created it and a later plain build emptied it.
        $files = @(Get-ChildItem -Recurse -File $compPath -ErrorAction SilentlyContinue)
        $sz = 0
        if ($files.Count -gt 0) { $sz = ($files | Measure-Object Length -Sum).Sum }
        Write-Host ("  dist/{0,-9} {1,4} files  {2,8:N1} MB" -f $comp, $files.Count, ($sz / 1MB))
    }
}
Write-Host ("  TOTAL {0:N1} MB   elapsed {1:mm\:ss}" -f ($totalBytes / 1MB), $elapsed) -ForegroundColor Green
Write-Host "  dist -> $Dist" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan
