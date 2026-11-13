<#
.SYNOPSIS
  Verify the LIVE support download end-to-end (docs/27 step 18, docs/28 §4).

.DESCRIPTION
  The one guard that measures the file the public actually gets. It GETs the live URL and checks:
    * 200, Content-Type application/octet-stream, the exact-filename Content-Disposition, and a
      Content-Length that matches the served bytes;
    * the SHA-256 of the downloaded bytes equals the served .sha256.txt sidecar AND the value baked
      into the served viewer bundle (so page, sidecar, and file all agree);
    * running the downloaded exe with `--deployment` prints the origin it was published to (so a
      binary baked for a DIFFERENT origin is caught).

  Until this has PASSED for a deployment, VITE_SUPPORT_DOWNLOAD_URL must stay unset and the /join
  download block must not render. A guard that has never been seen to fail has not been verified — so
  the runbook (docs/20) records deliberately breaking each link and confirming this catches it.

  NOTHING IN THIS REPO HAS RUN THIS AGAINST A LIVE DEPLOYMENT YET (signing + publish are deferred).
  Paste its output into docs/20 before any claim about the live download.

.PARAMETER BaseUrl
  The deployment origin, e.g. https://main.deskrally.com (no trailing slash needed).

.PARAMETER ExpectedOrigin
  The control-plane base the binary must report from `--deployment`. Defaults to BaseUrl + '/cp' (the
  Compose/Caddy layout: Caddy sends only /cp/* to the control plane). A bare origin was baked once and
  every support code failed with a 405; pass this explicitly for a layout without the /cp prefix.

.PARAMETER RunExe
  Also download and run the exe with --deployment to read back its baked origin. Windows only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $BaseUrl,
    [string] $ExpectedOrigin = '',
    [switch] $RunExe
)

$ErrorActionPreference = 'Stop'
$base = $BaseUrl.TrimEnd('/')
if ($ExpectedOrigin -eq '') { $ExpectedOrigin = $base + '/cp' }
$fail = @()
function Check($cond, $msg) { if ($cond) { Write-Host "[ ok ] $msg" -ForegroundColor Green } else { Write-Host "[FAIL] $msg" -ForegroundColor Red; $script:fail += $msg } }

$exeUrl = "$base/download/DeskRallySupport.exe"
$shaUrl = "$base/download/DeskRallySupport.exe.sha256.txt"

$tmp    = [System.IO.Path]::GetTempFileName()
$exeRun = $null
$outFile = $null
try {
    # --- 1. The exe response: status, headers, bytes -------------------------------------------
    Write-Host "GET $exeUrl"
    $resp = Invoke-WebRequest -Uri $exeUrl -OutFile $tmp -PassThru -MaximumRedirection 0
    Check ($resp.StatusCode -eq 200) "status 200 (got $($resp.StatusCode))"
    $ctype = "$($resp.Headers['Content-Type'])"
    Check ($ctype -like 'application/octet-stream*') "Content-Type application/octet-stream (got '$ctype')"
    $disp = "$($resp.Headers['Content-Disposition'])"
    Check ($disp -like '*attachment*' -and $disp -like '*DeskRallySupport.exe*') "Content-Disposition names the exe (got '$disp')"
    $served = (Get-Item $tmp).Length
    $clen = [int64]("0$($resp.Headers['Content-Length'])")
    Check ($clen -eq $served) "Content-Length ($clen) matches served bytes ($served)"
    $enc = "$($resp.Headers['Content-Encoding'])"
    Check ([string]::IsNullOrEmpty($enc)) "no Content-Encoding on the exe (got '$enc')"

    $downloadHash = (Get-FileHash -Algorithm SHA256 $tmp).Hash.ToLower()
    Write-Host "downloaded sha256 = $downloadHash"

    # --- 2. The sidecar hash matches the downloaded bytes --------------------------------------
    Write-Host "GET $shaUrl"
    $sideResp = Invoke-WebRequest -Uri $shaUrl -MaximumRedirection 0
    $sideDisp = "$($sideResp.Headers['Content-Disposition'])"
    Check (-not ($sideDisp -like '*attachment*')) "sidecar is NOT served as an attachment (got '$sideDisp')"
    $sidecarHash = (($sideResp.Content -split '\s+')[0]).ToLower()
    Check ($sidecarHash -eq $downloadHash) "served .sha256.txt ($sidecarHash) matches the downloaded file"

    # --- 3. The hash baked into the served bundle matches -------------------------------------
    # Absent or unfetchable JS is a hard failure: the bundle assertion cannot be skipped.
    try {
        $index = (Invoke-WebRequest -Uri "$base/join" -MaximumRedirection 0).Content
        $js = [regex]::Matches($index, 'src="([^"]+\.js)"') |
              ForEach-Object { $_.Groups[1].Value } |
              Select-Object -First 1
        Check ($js) "found viewer bundle JS src in /join"
        if ($js) {
            $jsUrl = if ($js -like 'http*') { $js } elseif ($js.StartsWith('/')) { "$base$js" } else { "$base/$js" }
            try {
                $bundle = (Invoke-WebRequest -Uri $jsUrl -MaximumRedirection 0).Content
                Check ($bundle.ToLower().Contains($downloadHash)) "the served bundle bakes the same sha256 the file hashes to"
            } catch {
                Check $false "could not fetch the viewer bundle at $jsUrl : $_"
            }
        }
    } catch {
        Check $false "could not fetch /join to check the baked hash: $_"
    }

    # --- 4. The exe reports the origin it was published to ------------------------------------
    # Never execute if any preceding check failed; non-Windows with -RunExe is a hard failure.
    if ($RunExe) {
        if (-not $IsWindows) {
            Check $false "-RunExe requires Windows; verification is incomplete on this platform"
        } elseif ($fail.Count -gt 0) {
            Write-Host "[skip] -RunExe: not executing because earlier checks failed" -ForegroundColor Yellow
        } else {
            $outFile = [System.IO.Path]::GetTempFileName()
            $exeRun  = "$tmp.exe"; Copy-Item $tmp $exeRun -Force
            Start-Process -FilePath $exeRun -ArgumentList '--deployment' -Wait -NoNewWindow -RedirectStandardOutput $outFile | Out-Null
            $origin = (Get-Content -Raw $outFile -ErrorAction SilentlyContinue)
            if ($origin) { $origin = $origin.Trim() }
            Check ($origin -eq $ExpectedOrigin) "the downloaded exe reports origin '$origin' (expected '$ExpectedOrigin')"
        }
    }
} finally {
    if ($exeRun)  { Remove-Item $exeRun  -ErrorAction SilentlyContinue }
    if ($outFile) { Remove-Item $outFile -ErrorAction SilentlyContinue }
    Remove-Item $tmp -ErrorAction SilentlyContinue
}

Write-Host ""
if ($fail.Count -gt 0) {
    Write-Host "VERIFY-DOWNLOAD FAILED ($($fail.Count)):" -ForegroundColor Red
    $fail | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
Write-Host "VERIFY-DOWNLOAD PASSED for $base" -ForegroundColor Green
