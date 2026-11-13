<#
.SYNOPSIS
  No-skip verification harness for the whole product. A SKIP IS A FAILURE.

.DESCRIPTION
  A green `cargo test` / `go test` in this repo has historically meant "nothing ran": the live
  cross-language e2e tests self-skip (Rust prints `SKIP:` and returns green; Go `t.Skip`s without
  TEST_DATABASE_URL) and there is no CI to start the servers they need. This script closes that gap.

  It stands up the real dependencies (on DELIBERATELY uncontended ports — this box runs a torrent
  client on :8080; see $SigPort/$RelayTcpPort/$PwCpPort):
    * Postgres on 127.0.0.1:5433 (reused if already running; started if down; NEVER stopped by us)
    * relay      on :19000 (TCP) / :19001 (WS)
    * signaling  on :18080 (DEV/insecure flags — the Rust + non-secure Playwright e2e wire shape)
  ...then runs EVERY suite and scans each suite's output for skip markers, treating any skip as a
  hard failure (except known hardware gates — see $GatedSkipRegex / -StrictGated). The Playwright
  suite runs LAST with our signaling/relay torn down: it self-manages its own stack, and is handed
  the same uncontended ports via RMT_E2E_* + CONTROL_PLANE_ORIGIN (e2e/ports.ts).

  Suites covered (all must RUN, not skip):
    1. Go: control-plane  (TEST_DATABASE_URL set → pgx/RLS integration tests execute, not skip)
    2. Go: server/signaling
    3. Go: server/relay
    4. Rust: whole workspace, unit + live e2e (SIGNALING_WS_URL/RELAY_TCP_ADDR pointed at our servers)
    4b. Web: TypeScript typecheck (tsc --noEmit)
    5. Web: vitest unit suite (npm test)
    5b. Packaging: build-release.ps1's own guards (-SkipRust -SkipViewer) — the config-template /
        HelperConfig field match, the shipped installer's parse + encoding, migration contiguity.
        Added because those guards existed and were never run by anything, so a release that could
        not be built at all went unnoticed for two loops.
    6. Web: Playwright e2e (npm run test:e2e) — self-managed stack, run after our servers stop

.PARAMETER SkipBuild
  Reuse already-built server/agent binaries instead of rebuilding them.

.PARAMETER Only
  Comma-separated subset of suite keys to run: cp-go, sig-go, relay-go, rust, typecheck, vitest, package,
  playwright.
  Dependencies (servers) are still started as needed. Default: all.

.PARAMETER StrictGated
  Treat KNOWN environment-gated skips (see $GatedSkipRegex) as hard failures too. Off by default:
  a test that fundamentally needs hardware/a live desktop this box cannot provide headless is
  reported as GATED, not silently passed — but does not red the build. A SILENT skip (a runnable
  test that did not run) is ALWAYS a failure regardless of this switch — that is the whole point.

.NOTES
  Exit code 0 ONLY if every selected suite ran with zero failures and zero NON-gated skips.
#>
[CmdletBinding()]
param(
  [switch]$SkipBuild,
  [string]$Only = "",
  [switch]$StrictGated
)

# Skips that are NOT false-greens but genuine environment gates: a test that requires hardware or a
# live/interactive desktop a headless CI box cannot provide. Only e2e_stream's live DXGI capture
# qualifies today — DXGI Desktop Duplication delivers no frame unless the process is on the active
# console desktop (see docs/07 "Capture/DXGI must run in the interactive session"), and the
# synthetic-capturer WebRTC video test (transport-webrtc) already exercises the same encode→RTP path.
# EVERYTHING else that skips is a hard failure.
# `-update-pass-vectors`: TestGenerateDeploymentPassVectors is a golden-vector GENERATOR that skips
# by design unless asked to rewrite the vectors (docs/48); the comparison test beside it always runs.
$GatedSkipRegex = 'first live capture failed|DxgiCapturer::new\(\) failed|run with -update-pass-vectors|--- SKIP: TestGenerateDeploymentPassVectors'

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

# --- Keep the display awake for the whole run ----------------------------------------------------
# e2e_stream captures the LIVE desktop through DXGI Desktop Duplication, which stops delivering
# frames once the monitor powers off — even though the session stays unlocked and Active. This box
# blanks its monitor after 180 s (powercfg SUB_VIDEO/VIDEOIDLE), so an unattended run would gate that
# suite for a reason that has nothing to do with the code, and the skip message's "locked console?"
# guess sent one investigation down the wrong path entirely.
#
# ES_DISPLAY_REQUIRED holds the display on. It is a THREAD-level request, so it outlives this script
# whenever the script does not own the process — dot-sourced, or run from a wrapper in a live pwsh
# session. It is therefore released in the `finally` that wraps the whole body below (PowerShell runs
# a finally on `exit` and on a terminating error alike), NOT by a statement before the exits: this
# script has six `throw`s in its preflight, and every one of them would skip such a statement and
# leave the monitor pinned on for the life of that terminal.
#
# A cursor nudge first, because the flag prevents a FUTURE sleep but does not wake a display that is
# already off.
#
# The whole acquire is best-effort: failing to hold the display must degrade to "e2e_stream might
# gate", never take down the harness. That includes Add-Type — with $ErrorActionPreference='Stop' a
# compilation failure here would abort every suite over a convenience feature.
$DisplayHeld   = $false
$ES_CONTINUOUS = [uint32]2147483648   # NB: the literal 0x80000000 parses as a NEGATIVE Int32.
try {
    Add-Type -Namespace RmtVerify -Name Power -MemberDefinition @'
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SetThreadExecutionState(uint esFlags);
    [DllImport("user32.dll")]
    public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, System.UIntPtr dwExtraInfo);
'@
    $ES_DISPLAY_REQUIRED = [uint32]2
    [RmtVerify.Power]::mouse_event([uint32]1, 0, 0, 0, [UIntPtr]::Zero)  # MOUSEEVENTF_MOVE, (0,0)
    [void][RmtVerify.Power]::SetThreadExecutionState($ES_CONTINUOUS -bor $ES_DISPLAY_REQUIRED)
    $DisplayHeld = $true
} catch {
    Write-Warning "could not hold the display awake ($_); e2e_stream may gate if the monitor sleeps"
}

try {

# --- Config -----------------------------------------------------------------------------------
$PgHost = "127.0.0.1"
$PgPort = 5433
$PgDb   = "rmt_test"
$DbUrl  = "postgres://postgres@${PgHost}:${PgPort}/${PgDb}?sslmode=disable"

# DELIBERATELY off the common :8080/:8081/:9000 defaults. This host runs other software that
# squats :8080 (a torrent client's WebUI), which silently made every live e2e test skip with
# "signaling not reachable" — the exact false-green this harness exists to catch. We serve the
# Rust suite here and pass the same ports to Playwright via RMT_E2E_* (see e2e/ports.ts).
$SigPort      = 18080
$RelayTcpPort = 19000
$RelayWsPort  = 19001
$PwCpPort     = 18081   # control-plane port Playwright's secure specs bind (DEV mode, no DB)
# Where the reusable Postgres lives if we have to start one. RELOCATED 2026-08-01 off %TEMP% to a
# DURABLE path: the old scratchpad location lived under %TEMP% and an external temp-cleaner repeatedly
# wiped pgsql\share + pgsql\lib mid-session (see docs/07). This dir is outside %TEMP%, so it persists.
$PgScratch = if ($env:RMT_PG_SCRATCH) { $env:RMT_PG_SCRATCH } else { Join-Path $HOME 'rmt-pg' }

$SignalingDir = Join-Path $RepoRoot "server\signaling"
$RelayDir     = Join-Path $RepoRoot "server\relay"
$CpDir        = Join-Path $RepoRoot "control-plane"
$ViewerDir    = Join-Path $RepoRoot "web\viewer"
$SignalingExe = Join-Path $SignalingDir "signaling.exe"
$RelayExe     = Join-Path $RelayDir "relay.exe"
$CpExe        = Join-Path $CpDir "controlplane.exe"
$AgentExe     = Join-Path $RepoRoot "target\debug\agent_host.exe"

$LogDir = Join-Path $env:TEMP "rmt-verify-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$SelectedSuites = if ($Only.Trim()) { @($Only.Split(",") | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ }) } else { @() }
function Want([string]$key) { return ($SelectedSuites.Count -eq 0) -or ($SelectedSuites -contains $key) }

# A MISTYPED -Only key used to match no suite, run NOTHING, and then report "ALL SUITES GREEN" with
# PASS=0 — a green run that means nothing ran, which is the exact false green this harness exists to
# catch. Validate the keys up front instead of discovering it from a suspiciously fast pass.
$KnownSuites = @("cp-go", "sig-go", "relay-go", "rust", "typecheck", "vitest", "package", "playwright")
$unknown = @($SelectedSuites | Where-Object { $KnownSuites -notcontains $_ })
if ($unknown.Count -gt 0) {
  throw ("-Only contains unknown suite key(s): {0}. Known keys: {1}" -f ($unknown -join ", "), ($KnownSuites -join ", "))
}

# Rust test builds overflow the PDB LNK1140 limit with full debuginfo across the WebRTC-heavy e2e
# exes; strip debuginfo and disable incremental for the test build (per docs/07 build hygiene).
$env:RUSTFLAGS = "-C debuginfo=0"
$env:CARGO_INCREMENTAL = "0"

# --- Result accounting ------------------------------------------------------------------------
$Results = New-Object System.Collections.ArrayList
function Record($name, $status, $detail) {
  [void]$Results.Add([pscustomobject]@{ Suite = $name; Status = $status; Detail = $detail })
  $color = switch ($status) { "PASS" { "Green" } "GATED" { "Yellow" } "FAIL" { "Red" } "SKIP" { "Red" } default { "Yellow" } }
  Write-Host ("  [{0}] {1} — {2}" -f $status, $name, $detail) -ForegroundColor $color
}

function Section($title) {
  Write-Host ""
  Write-Host ("=" * 92) -ForegroundColor Cyan
  Write-Host ("== {0}" -f $title) -ForegroundColor Cyan
  Write-Host ("=" * 92) -ForegroundColor Cyan
}

# --- Process management -----------------------------------------------------------------------
$Bg = New-Object System.Collections.ArrayList
function StartServer($name, $exe, [string[]]$srvArgs, $workdir, $envextra) {
  $log = Join-Path $LogDir "$name.log"
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $exe
  foreach ($a in $srvArgs) { [void]$psi.ArgumentList.Add($a) }
  $psi.WorkingDirectory = $workdir
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  if ($envextra) { foreach ($k in $envextra.Keys) { $psi.EnvironmentVariables[$k] = $envextra[$k] } }
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  # Drain stdout/stderr to a log file so a full pipe can't deadlock the child.
  Register-ObjectEvent -InputObject $p -EventName OutputDataReceived -Action { if ($EventArgs.Data) { Add-Content -LiteralPath $Event.MessageData -Value $EventArgs.Data } } -MessageData $log | Out-Null
  Register-ObjectEvent -InputObject $p -EventName ErrorDataReceived  -Action { if ($EventArgs.Data) { Add-Content -LiteralPath $Event.MessageData -Value $EventArgs.Data } } -MessageData $log | Out-Null
  [void]$p.Start()
  $p.BeginOutputReadLine()
  $p.BeginErrorReadLine()
  [void]$Bg.Add([pscustomobject]@{ Name = $name; Proc = $p; Log = $log })
  Write-Host ("  started {0} (pid {1}) → {2}" -f $name, $p.Id, $log) -ForegroundColor DarkGray
  return $p
}

function StopServers {
  foreach ($s in $Bg) {
    try { if (-not $s.Proc.HasExited) { $s.Proc.Kill($true) } } catch {}
  }
  Get-EventSubscriber | Unregister-Event -ErrorAction SilentlyContinue
  $Bg.Clear()
}

# Only clean executables belonging to this checkout, never the installed service or another repo.
function CleanupStaleTestProcs {
  $ownedExecutables = @($SignalingExe, $RelayExe, $CpExe, $AgentExe)
  # Cargo's target directory may be a junction to a shared build volume. Process.Path
  # can use that physical path rather than the checkout's junction path.
  $targetDir = Get-Item -LiteralPath (Join-Path $RepoRoot "target") -ErrorAction SilentlyContinue
  if ($targetDir -and $targetDir.LinkType -eq "Junction") {
    foreach ($destination in $targetDir.Target) {
      $ownedExecutables += Join-Path $destination "debug\agent_host.exe"
    }
  }
  foreach ($n in @("signaling", "relay", "controlplane", "agent_host")) {
    Get-Process $n -ErrorAction SilentlyContinue | ForEach-Object {
      try {
        if ($_.Path -and $ownedExecutables -contains $_.Path) {
          $_.Kill()
          Write-Host ("  killed stale test {0} (pid {1})" -f $n, $_.Id) -ForegroundColor DarkGray
        }
      } catch {}
    }
  }
  # Vite must belong to THIS viewer checkout as well as the expected port.
  Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue |
    Where-Object {
      $_.CommandLine -match [regex]::Escape($ViewerDir) -and
      $_.CommandLine -match "vite" -and $_.CommandLine -match "5173"
    } |
    ForEach-Object {
      try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; Write-Host ("  killed stale vite (pid {0})" -f $_.ProcessId) -ForegroundColor DarkGray } catch {}
    }
}

function TestTcp($tcpHost, $port, $timeoutMs = 800) {
  try {
    $c = New-Object System.Net.Sockets.TcpClient
    $iar = $c.BeginConnect($tcpHost, $port, $null, $null)
    $ok = $iar.AsyncWaitHandle.WaitOne($timeoutMs)
    if ($ok -and $c.Connected) { $c.Close(); return $true }
    $c.Close(); return $false
  } catch { return $false }
}

function WaitTcp($tcpHost, $port, $timeoutMs = 15000) {
  $deadline = (Get-Date).AddMilliseconds($timeoutMs)
  while ((Get-Date) -lt $deadline) {
    if (TestTcp $tcpHost $port 500) { return $true }
    Start-Sleep -Milliseconds 250
  }
  return $false
}

# --- Output scanning: the heart of "a skip is a failure" --------------------------------------
# Returns @{ Skips = @(...); Fails = @(...) } of offending lines.
function ScanGo($outText) {
  $skips = @(); $fails = @()
  foreach ($line in ($outText -split "`r?`n")) {
    if ($line -match "^\s*--- SKIP:") { $skips += $line.Trim() }
    if ($line -match "^\s*--- FAIL:") { $fails += $line.Trim() }
    if ($line -match "^FAIL\b" -and $line -notmatch "no test files") { $fails += $line.Trim() }
    # A package that built no tests at all is suspect for a suite we expect to have tests.
  }
  return @{ Skips = $skips; Fails = $fails }
}

function ScanRust($outText) {
  $skips = @(); $fails = @()
  $lines = @($outText -split "`r?`n")
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if ($line -match "SKIP:") { $skips += $line.Trim() }
    if ($line -match "test result: FAILED") { $fails += $line.Trim() }
    if ($line -match "^\s*error(\[|:)") { $fails += $line.Trim() }
    if ($line -match "panicked at") {
      # WHY THIS RULE EXISTS, and why it is NOT simply "any panic fails":
      #
      # A panic on a background/detached task does NOT fail a `cargo test` run — the harness
      # swallows it, `cargo` exits 0 and every `test result:` line still reads `ok`. This rule is
      # the ONLY thing that surfaces such a swallowed panic (a real bug in a spawned task that
      # never propagates to a test verdict), so it must keep firing on them. Loosening it to
      # "ignore panics when the run otherwise passed" would blind the gate to exactly what it is
      # here to catch.
      #
      # There is ONE documented, measured exception: a teardown-only CANCELLATION race in the
      # VENDORED `webrtc-sctp` crate. When a `#[tokio::test]`'s runtime is dropped with an SCTP
      # association still live, `write_loop`'s `spawn_blocking(...).await.unwrap()`
      # (webrtc-sctp-0.10.0/src/association/mod.rs:515) unwraps a `JoinError::Cancelled` and
      # panics on a runtime worker DURING SHUTDOWN — after the test's assertions have all passed.
      # It is third-party code, it cannot affect a verdict, and it was measured 0/4 reproducible.
      #
      # It is suppressed ONLY when BOTH facts hold: the panic LOCATION (this line) is that vendored
      # SCTP site, AND the panic PAYLOAD (this line for pre-1.73 Rust, or the NEXT line for the
      # current two-line format) is a task cancellation. Requiring BOTH means a panic anywhere in
      # our own code still fails, AND a NON-cancellation panic even in that same vendored file still
      # fails — so a genuine SCTP defect is never masked, only the shutdown-cancel is. If a
      # webrtc-sctp upgrade moves or changes this site, the carve-out stops matching and the panic
      # re-surfaces for re-evaluation, which is the correct fail-safe direction.
      $next = if (($i + 1) -lt $lines.Count) { $lines[$i + 1] } else { "" }
      $atSctpTeardown = ($line -match "webrtc-sctp") -and ($line -match "association") -and ($line -match "mod\.rs")
      $isCancellation = ($line -match "[Cc]ancelled") -or ($next -match "[Cc]ancelled")
      # Second documented exception (2026-10-30): expected-panic GUARD TESTS. These unit tests exist
      # to assert that production code PANICS in unit builds — their names state the contract — and
      # the harness still prints the panic to stderr although the test PASSES and cargo exits 0.
      # Suppressed ONLY when the panicking THREAD NAME (quoted in this very line) is one of the named
      # guard tests: any other thread's panic still fails, and a rename stops the carve-out matching
      # so the panic re-surfaces for re-evaluation — the same fail-safe direction as the SCTP rule.
      $isExpectedGuardPanic = ($line -match "thread 'input::backend_tests::real_backend_panics_before_os_call_in_unit_tests'") -or
                              ($line -match "thread 'shared_capture::tests::production_constructors_refuse_real_injector_in_unit_tests'")
      # Third documented exception (2026-11-02): SIMULATED CRASHES in the fleet-removal recovery tests (docs/65 §7).
      # Those tests inject a panic at a chosen journal save / side effect ("simulated crash after ...") and catch it,
      # to prove the helper resumes truthfully after power loss; the harness still prints each panic. Suppressed ONLY
      # when BOTH hold: the panicking thread is a `directive_removal::tests::` test AND the payload (next line, or
      # this line in the old one-line format) is exactly a "simulated crash after ..." message. Any other panic in
      # those tests, or that message from any other thread, still fails.
      $isSimulatedRemovalCrash = ($line -match "thread 'directive_removal::tests::[a-z0-9_]+'") -and
                                 (($next -match "^\s*simulated crash after (journal save #\d+|[a-z_]+)\s*$") -or
                                  ($line -match "simulated crash after (journal save #\d+|[a-z_]+)\s*$"))
      if (-not (($atSctpTeardown -and $isCancellation) -or $isExpectedGuardPanic -or $isSimulatedRemovalCrash)) { $fails += $line.Trim() }
    }
  }
  return @{ Skips = $skips; Fails = $fails }
}

function ScanVitest($outText) {
  $skips = @(); $fails = @()
  foreach ($line in ($outText -split "`r?`n")) {
    # vitest summary lines: "Tests  N passed | M skipped (T)" etc.
    if ($line -match "Tests\s.*\bskipped\b") {
      if ($line -notmatch "0 skipped") { $skips += $line.Trim() }
    }
    if ($line -match "Tests\s.*\bfailed\b") {
      if ($line -notmatch "\b0 failed") { $fails += $line.Trim() }
    }
  }
  return @{ Skips = $skips; Fails = $fails }
}

function ScanPlaywright($outText) {
  $skips = @(); $fails = @()
  foreach ($line in ($outText -split "`r?`n")) {
    # list reporter summary: "N passed", "M skipped", "K failed" — and per-test "SKIP" reasons.
    if ($line -match "(\d+)\s+skipped" ) {
      if ($Matches[1] -ne "0") { $skips += $line.Trim() }
    }
    if ($line -match "(\d+)\s+failed") {
      if ($Matches[1] -ne "0") { $fails += $line.Trim() }
    }
    if ($line -match "SKIP( IS NOT A PASS)?:|skipReason") { $skips += $line.Trim() }
  }
  return @{ Skips = $skips; Fails = $fails }
}

# Run a command, tee output to a log, return @{ Code; Text; Log }.
function RunCmd($name, $scriptblock) {
  $log = Join-Path $LogDir "$name.out.txt"
  Write-Host ("  running {0} → {1}" -f $name, $log) -ForegroundColor DarkGray
  # A suite may signal failure by EXIT CODE or by THROWING. The `package` suite throws:
  # `build-release.ps1` reports a violated guard with `throw`, and with $ErrorActionPreference='Stop'
  # an uncaught one here does NOT produce "[FAIL] Packaging guards" — it aborts the whole harness on
  # the spot, so the remaining suites never run, no SUMMARY is printed, and the operator is left
  # reading a PowerShell stack trace instead of a verdict. (Still a non-zero exit, so never a false
  # green — but a diagnosis this harness exists to hand over, lost.) Measured 2026-08-13 while
  # mutation-testing the packaging guard. Catch it and let Verdict record a FAIL like anything else.
  $out = ""
  $code = 0
  try {
    $out = & $scriptblock 2>&1 | Tee-Object -FilePath $log | Out-String
    $code = $LASTEXITCODE
  } catch {
    $out = "$_"
    Add-Content -LiteralPath $log -Value $out
    if ($code -eq 0) { $code = 1 }
  }
  return @{ Code = $code; Text = $out; Log = $log }
}

# Apply a scan result + exit code into a recorded verdict. Skips are partitioned into HARD skips
# (a runnable test that didn't run — the false-green this harness exists to catch) and GATED skips
# (known hardware/desktop gates listed in $GatedSkipRegex). Hard skips always fail; gated skips are
# reported as GATED and only fail under -StrictGated.
function Verdict($name, $run, $scan) {
  $gated = @($scan.Skips | Where-Object { $_ -match $GatedSkipRegex })
  $hard  = @($scan.Skips | Where-Object { $_ -notmatch $GatedSkipRegex })
  $nFail = $scan.Fails.Count

  if ($hard.Count -gt 0) {
    foreach ($s in ($hard | Select-Object -First 8)) { Write-Host ("      SKIP> {0}" -f $s) -ForegroundColor Red }
    Record $name "SKIP" ("{0} skip(s) detected — a skip is a failure (log: {1})" -f $hard.Count, $run.Log)
    return
  }
  if ($nFail -gt 0 -or $run.Code -ne 0) {
    foreach ($s in ($scan.Fails | Select-Object -First 8)) { Write-Host ("      FAIL> {0}" -f $s) -ForegroundColor Red }
    Record $name "FAIL" ("exit={0}, {1} failure line(s) (log: {2})" -f $run.Code, $nFail, $run.Log)
    return
  }
  if ($gated.Count -gt 0) {
    foreach ($s in ($gated | Select-Object -First 8)) { Write-Host ("      GATED> {0}" -f $s) -ForegroundColor Yellow }
    if ($StrictGated) {
      Record $name "FAIL" ("{0} gated skip(s), -StrictGated set (log: {1})" -f $gated.Count, $run.Log)
    } else {
      Record $name "GATED" ("passed; {0} environment-gated skip(s) not runnable headless (log: {1})" -f $gated.Count, $run.Log)
    }
    return
  }
  Record $name "PASS" ("exit=0, no skips (log: {0})" -f $run.Log)
}

# =============================================================================================
# 0. Preflight: Postgres
# =============================================================================================
Section "Preflight: clean stale test processes + Postgres on ${PgHost}:${PgPort}"
CleanupStaleTestProcs
if (TestTcp $PgHost $PgPort 800) {
  Write-Host "  Postgres already up — reusing it (will NOT stop it)." -ForegroundColor Green
} else {
  Write-Host "  Postgres down — attempting documented restart (data persists on disk)." -ForegroundColor Yellow
  $pgCtl = Join-Path $PgScratch "pgsql\bin\pg_ctl.exe"
  $pgData = Join-Path $PgScratch "pgdata"
  if (Test-Path $pgCtl) {
    & $pgCtl -D $pgData -o "-p $PgPort" -l (Join-Path $PgScratch "pg.log") start
    if (-not (WaitTcp $PgHost $PgPort 15000)) {
      throw "Could not bring up Postgres on ${PgHost}:${PgPort}. Start it manually (see docs/07-session-handoff.md)."
    }
    Write-Host "  Postgres started." -ForegroundColor Green
  } else {
    throw "Postgres is down and pg_ctl not found at $pgCtl. Start Postgres manually (see docs/07-session-handoff.md)."
  }
}

# =============================================================================================
# 1. Build server + agent binaries
# =============================================================================================
if (-not $SkipBuild) {
  Section "Build: Go servers + Rust agent_host"
  $goBuilds = @(
    @{ Name = "signaling"; Dir = $SignalingDir; Out = $SignalingExe; Target = "." },
    @{ Name = "relay";     Dir = $RelayDir;     Out = $RelayExe;     Target = "." },
    @{ Name = "controlplane"; Dir = $CpDir;     Out = $CpExe;        Target = ".\cmd\controlplane" }
  )
  foreach ($b in $goBuilds) {
    Write-Host ("  go build {0}..." -f $b.Name) -ForegroundColor DarkGray
    Push-Location $b.Dir
    & go build -o $b.Out $b.Target
    $bc = $LASTEXITCODE
    Pop-Location
    if ($bc -ne 0) { throw ("go build {0} failed (exit {1})" -f $b.Name, $bc) }
  }
  # BOTH binaries, explicitly. The Playwright specs spawn agent_host as the guest AND stream_probe as
  # the controller (the attended policy-install e2e needs a controller that can send
  # Control::InstallSessionPolicy, which the browser viewer only does on its own connect path). Listing
  # stream_probe here rather than relying on the workspace test build to leave one behind: a spec that
  # cannot find its binary SKIPS, and this gate counts a skip as a FAILURE, so the dependency has to be
  # stated where the build happens.
  Write-Host "  cargo build agent_host + stream_probe (debug, for Playwright)..." -ForegroundColor DarkGray
  # WITH the harness features: the real-agent Playwright specs (pass26/30/34, multi-tech,
  # backstage_place, secure-transport, default-TTL, viewer_chrome live-session) drive agent_host's
  # test switches and refuse a featureless build. Found 2026-10-30: this line had no features, so
  # every real-agent spec failed the moment the gate's own build overwrote a featured one.
  & cargo build -p rmt-agent-windows --bin agent_host --bin stream_probe --features test-harness,secure-test
  if ($LASTEXITCODE -ne 0) { throw "cargo build agent_host + stream_probe failed" }
} else {
  Write-Host "  -SkipBuild: reusing existing binaries." -ForegroundColor Yellow
}

# =============================================================================================
# 2. Start relay + signaling (DEV/insecure) for the Rust e2e wire shape
# =============================================================================================
Section "Start dependencies: relay :$RelayTcpPort, signaling :$SigPort (insecure dev flags)"
StartServer "relay" $RelayExe @("-tcp", ":$RelayTcpPort", "-ws", ":$RelayWsPort") $RelayDir $null | Out-Null
if (-not (WaitTcp "127.0.0.1" $RelayTcpPort 15000)) { StopServers; throw "relay did not come up on :$RelayTcpPort" }
StartServer "signaling" $SignalingExe @("-addr", ":$SigPort", "-insecure-no-ticket-verification", "-insecure-no-agent-auth") $SignalingDir $null | Out-Null
if (-not (WaitTcp "127.0.0.1" $SigPort 15000)) { StopServers; throw "signaling did not come up on :$SigPort" }
Write-Host "  relay + signaling up." -ForegroundColor Green

try {
  # ===========================================================================================
  # 3. Go suites
  # ===========================================================================================
  if (Want "cp-go") {
    Section "Go: control-plane (TEST_DATABASE_URL set → pgx/RLS tests MUST run)"
    $env:TEST_DATABASE_URL = $DbUrl
    # -timeout: the package is ~1,550 tests and passed Go's 10-minute default (~600 s) with stage 1b.
    $run = RunCmd "cp-go" { Push-Location $CpDir; go test ./... -count=1 -timeout 30m -v; Pop-Location }
    Verdict "Go control-plane" $run (ScanGo $run.Text)
    Remove-Item Env:\TEST_DATABASE_URL -ErrorAction SilentlyContinue
  }
  if (Want "sig-go") {
    Section "Go: server/signaling"
    $run = RunCmd "sig-go" { Push-Location $SignalingDir; go test ./... -count=1 -v; Pop-Location }
    Verdict "Go signaling" $run (ScanGo $run.Text)
  }
  if (Want "relay-go") {
    Section "Go: server/relay"
    $run = RunCmd "relay-go" { Push-Location $RelayDir; go test ./... -count=1 -v; Pop-Location }
    Verdict "Go relay" $run (ScanGo $run.Text)
  }

  # ===========================================================================================
  # 4. Rust workspace (unit + live e2e) — pointed at our running servers
  # ===========================================================================================
  if (Want "rust") {
    Section "Rust: workspace unit + live e2e (SIGNALING_WS_URL/RELAY_TCP_ADDR → our servers)"
    $env:SIGNALING_WS_URL = "ws://127.0.0.1:$SigPort/ws"
    $env:RELAY_TCP_ADDR = "127.0.0.1:$RelayTcpPort"
    $run = RunCmd "rust" { cargo test --workspace -- --nocapture }
    Verdict "Rust workspace" $run (ScanRust $run.Text)
    Remove-Item Env:\SIGNALING_WS_URL -ErrorAction SilentlyContinue
    Remove-Item Env:\RELAY_TCP_ADDR -ErrorAction SilentlyContinue

    # 4b. The `h264` cargo feature is the ALTERNATE VideoEncoder behind the codec seam (openh264),
    # kept so "the seam has two structurally-different implementations" is a fact, not a claim. The
    # default workspace build above compiles NONE of it, so without this step it rots silently — a
    # broken h264.rs would stay green forever. `--lib` restricts to unit tests (the h264 encoder
    # tests + the trait-object test's h264 arm, which drives both encoders through `dyn VideoEncoder`);
    # they need no signaling/relay servers, so this is order-independent of the live e2e above.
    Section "Rust: h264 alternate-encoder feature (--features h264 --lib) — keeps the codec seam honest"
    $run = RunCmd "rust-h264" { cargo test -p rmt-transport-webrtc --features h264 --lib -- --nocapture }
    Verdict "Rust h264 alt-encoder" $run (ScanRust $run.Text)
  }

  # ===========================================================================================
  # 4b. TypeScript typecheck
  # ===========================================================================================
  #
  # Added loop 82, after a type error in a NEW test file passed all eight suites green. Nothing in
  # the gate ran `tsc`: vitest strips types without checking them, and Playwright drives the vite DEV
  # server, which does the same. Only `npm run build` typechecks, and the gate never calls it. So the
  # one class of defect the compiler catches for free was the one class the gate could not see.
  #
  # It runs BEFORE vitest deliberately — "this does not typecheck" is a cheaper and more precise
  # thing to read than whatever the untyped value does at runtime three suites later.
  if (Want "typecheck") {
    Section "Web: TypeScript typecheck (tsc --noEmit)"
    $run = RunCmd "typecheck" { Push-Location $ViewerDir; npx tsc --noEmit -p tsconfig.json; Pop-Location }
    Verdict "Web typecheck" $run @{ Skips = @() }
  }

  # ===========================================================================================
  # 5. Vitest unit suite
  # ===========================================================================================
  if (Want "vitest") {
    Section "Web: vitest unit suite (npm test)"
    # --no-file-parallelism: run test files sequentially so timing-sensitive tests are not starved
    # of a macrotask tick under the harness's heavy concurrent load (the failure mode that flaked
    # file_transfer/v3_wiring's async-SHA waits). The suite is ~1.3s, so the serialization is cheap.
    $run = RunCmd "vitest" { Push-Location $ViewerDir; npx vitest run --no-file-parallelism; Pop-Location }
    Verdict "Web vitest" $run (ScanVitest $run.Text)
  }

  # ===========================================================================================
  # 5b. Packaging guards — build-release.ps1's own assertions, run as a test suite
  # ===========================================================================================
  #
  # Added loop 17, after `build-release.ps1` was found BROKEN and had been since loop 15: two
  # `HelperConfig` fields (`max_session_secs`, `quality`) were added without the shipped
  # `config.template.json` ever gaining them, and the script's own
  # `Assert-ConfigTemplateMatchesRust` guard caught it the moment anyone ran it — which nobody had
  # for two loops, because THIS harness never ran it. The guards were fine; they simply were not
  # applied, which is the same failure shape as a defence that exists at one call site and not its
  # siblings.
  #
  # `-SkipRust -SkipViewer` deliberately: the cargo/npm builds are already covered by the suites
  # above, and skipping them turns a ~2-minute rebuild into a couple of seconds. What still runs is
  # exactly the set of checks nothing else performs — the config-template/HelperConfig field match,
  # the shipped installer's PowerShell parse and its 5.1-safe encoding, the "installer must delegate
  # identity to `agent_host enroll`" guard, and migration-numbering contiguity.
  #
  # There is no output to scan for skips: the script's contract is that it THROWS on a violated
  # guard, so the exit code is the whole verdict.
  if (Want "package") {
    Section "Packaging: build-release.ps1 guards (config template, installer, migrations)"
    $run = RunCmd "package" {
      & (Join-Path $PSScriptRoot 'build-release.ps1') -SkipRust -SkipViewer
    }
    Verdict "Packaging guards" $run @{ Skips = @() }
  }
}
finally {
  # Playwright self-manages its own stack (incl. an enforcing signaling on :8180); free :8080/:9000.
  Section "Tear down harness servers (Playwright self-manages its stack)"
  StopServers
  Start-Sleep -Milliseconds 500
}

# =============================================================================================
# 6. Playwright e2e (self-managed) — run with our servers stopped
# =============================================================================================
if (Want "playwright") {
  Section "Web: Playwright e2e (npm run test:e2e) — self-managed stack"
  if (-not (Test-Path $AgentExe)) {
    Record "Web Playwright" "FAIL" "agent_host.exe missing at $AgentExe (needed by specs) — build it"
  } else {
    # A Vite dev server started by an earlier run (or a developer) would be REUSED by Playwright
    # with a stale /cp proxy target; kill it so Playwright starts one with our CONTROL_PLANE_ORIGIN.
    CleanupStaleTestProcs
    # Move the :8080/:8081 specs onto the uncontended ports (e2e/ports.ts reads these); point the
    # Vite /cp proxy at the same control-plane port so secure_grant's browser reaches it.
    $env:RMT_E2E_SIG_PORT = "$SigPort"
    $env:RMT_E2E_CP_PORT = "$PwCpPort"
    $env:CONTROL_PLANE_ORIGIN = "http://127.0.0.1:$PwCpPort"

    # e2e/real_auth.spec.ts needs its OWN database, and this is the only place that can give it one.
    #
    # It exercises the branch nothing else does — a control plane with DATABASE_URL SET, i.e. the
    # real authenticator — by running the operator's own three commands: migrate, bootstrap, serve.
    # It cannot share $PgDb: the Go tests reset that schema to a CURATED subset of migrations with no
    # schema_migration ledger, so `migrate` there answers ErrNeedsBaseline and `cp_create_tenant`
    # (migration 0006) does not exist. A separate database is the isolation, not a nicety.
    #
    # Created here rather than in the spec because Node has no Postgres client in this project, and
    # adding one to the viewer to create a database would be a strange dependency.
    $psql = Join-Path $PgScratch "pgsql\bin\psql.exe"
    $E2eDb = "rmt_e2e_auth"
    if (Test-Path $psql) {
      $exists = & $psql -h $PgHost -p $PgPort -U postgres -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$E2eDb'" 2>$null
      if ("$exists".Trim() -ne "1") {
        & $psql -h $PgHost -p $PgPort -U postgres -d postgres -c "CREATE DATABASE $E2eDb" 2>&1 | Out-Null
        Write-Host "  created $E2eDb for the real-auth e2e." -ForegroundColor Green
      }
      $env:E2E_DATABASE_URL = "postgres://postgres@${PgHost}:${PgPort}/${E2eDb}?sslmode=disable"
    } else {
      Write-Host "  psql not found at $psql — real_auth.spec.ts will report why it cannot run." -ForegroundColor Yellow
    }
    # REBUILD the harness agent HERE, not only in the early build section: the Rust suite's
    # `cargo test` builds package bins as a side effect and overwrites agent_host.exe WITHOUT the
    # harness features, so every real-agent spec would get an exe with no `multi-stream` and fail at
    # registration (found 2026-10-30 — the ordering bug predated the missing-features bug).
    Write-Host "  cargo build agent_host + stream_probe (test-harness, for the real-agent specs)..." -ForegroundColor DarkGray
    & cargo build -p rmt-agent-windows --bin agent_host --bin stream_probe --features test-harness,secure-test
    if ($LASTEXITCODE -ne 0) { throw "playwright-prep cargo build failed" }
    $run = RunCmd "playwright" { Push-Location $ViewerDir; npm run test:e2e; Pop-Location }
    Verdict "Web Playwright" $run (ScanPlaywright $run.Text)
  }
}

# =============================================================================================
# Summary
# =============================================================================================
Section "SUMMARY"
$Results | Format-Table -AutoSize | Out-String | Write-Host
$nPass  = ($Results | Where-Object Status -eq "PASS").Count
$nGated = ($Results | Where-Object Status -eq "GATED").Count
$nFail  = ($Results | Where-Object Status -eq "FAIL").Count
$nSkip  = ($Results | Where-Object Status -eq "SKIP").Count
Write-Host ("Logs: {0}" -f $LogDir) -ForegroundColor DarkGray
Write-Host ("PASS={0}  GATED={1}  FAIL={2}  SKIP={3}" -f $nPass, $nGated, $nFail, $nSkip) -ForegroundColor White

# Zero suites is never success. Belt-and-braces alongside the -Only validation above: any future
# path that selects nothing (a filter, an early return) must fail loudly rather than print GREEN.
if ($Results.Count -eq 0) {
  Write-Host "VERIFICATION FAILED — no suites ran at all. A run that executes nothing is not a pass." -ForegroundColor Red
  exit 1
}
if ($nFail -eq 0 -and $nSkip -eq 0) {
  # Stamp the green run so `ci-guard.ps1` can tell "the cheap checks are green" from "this tree has
  # actually been certified". Without a stamp the guard has no way to notice that source changed
  # after the last real gate, and a long green streak on the cheap checks reads as a verified tree.
  # Written ONLY on green, and only for a FULL run: a `-Only` subset certifies nothing, and a stamp
  # from one would be a lie the guard would then repeat.
  if ($SelectedSuites.Count -eq 0) {
    try {
      $stampPath = Join-Path $PSScriptRoot ".verify-all-green.local.json"
      Set-Content -LiteralPath $stampPath -Encoding UTF8 -Value ([pscustomobject]@{
        finished_utc = (Get-Date).ToUniversalTime().ToString("s")
        pass = $nPass; gated = $nGated; fail = $nFail; skip = $nSkip
        strict_gated = [bool]$StrictGated
        log_dir = $LogDir
      } | ConvertTo-Json)
      Write-Host ("  green stamp written: {0}" -f $stampPath) -ForegroundColor DarkGray
    } catch { Write-Warning "could not write the green stamp: $_" }
  } else {
    Write-Host "  (-Only subset: no green stamp written — a subset certifies nothing)" -ForegroundColor DarkGray
  }
  if ($nGated -gt 0) {
    Write-Host "GREEN — every runnable test passed. $nGated suite(s) carry environment-gated skips (see GATED above; run -StrictGated to enforce, or run those on real hardware/an interactive desktop)." -ForegroundColor Green
  } else {
    Write-Host "ALL SUITES GREEN — every selected suite RAN with no skips." -ForegroundColor Green
  }
  exit 0
} else {
  Write-Host "VERIFICATION FAILED — a skip (that is not a known hardware gate) counts as a failure. See logs above." -ForegroundColor Red
  exit 1
}

} finally {
    # Release the ES_DISPLAY_REQUIRED hold taken at the top, on EVERY path out of the body above:
    # `exit` (PowerShell runs finally blocks on exit), a preflight `throw`, or any terminating error.
    # A plain statement before the exits looked equivalent and was not — the six preflight throws
    # skipped it, pinning the monitor on for the life of the calling terminal whenever this script
    # does not own the process (dot-sourced, or run from a wrapper).
    if ($DisplayHeld) {
        try { [void][RmtVerify.Power]::SetThreadExecutionState($ES_CONTINUOUS) } catch { }
    }
}
