"""
Tests for verify-download.ps1.

All tests use a local loopback HTTP server; no network, no production access, no real exe execution.
All temp files are handled by the script's own GetTempFileName calls.
Start-Process is mocked in RunExe tests so no downloaded binary is ever launched.
"""
import contextlib
import hashlib
import http.server
import os
import subprocess
import sys
import tempfile
import threading
import unittest

SCRIPT     = os.path.join(os.path.dirname(__file__), 'verify-download.ps1')
PWSH       = 'pwsh'
# Override with DESKRALLY_TEST_TMP when the system temp directory is unsuitable (e.g. a full C:).
TMPBASE_VD = os.environ.get('DESKRALLY_TEST_TMP') or tempfile.gettempdir()

_FAKE_EXE   = b'MZ' + b'\x00' * 62          # 64 bytes, not a runnable PE
_FAKE_HASH  = hashlib.sha256(_FAKE_EXE).hexdigest().lower()
_SIDECAR    = (_FAKE_HASH + '  DeskRallySupport.exe\n').encode()
_BUNDLE_JS  = ('var h="' + _FAKE_HASH + '";').encode()
_JOIN_HTML  = b'<html><head><script src="/assets/main.js"></script></head></html>'
_JOIN_NO_JS = b'<html><body>no bundle scripts here</body></html>'


@contextlib.contextmanager
def _mock_server(responses):
    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            entry = responses.get(self.path)
            if entry is None:
                self.send_response(404); self.end_headers(); return
            status, hdrs, body = entry
            self.send_response(status)
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_): pass

    srv = http.server.HTTPServer(('127.0.0.1', 0), _H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f'http://127.0.0.1:{port}'
    finally:
        srv.shutdown()
        srv.server_close()


def _ps(url, *extra):
    """Run the script directly; -NoProfile prevents profile interference; timeout bounds the suite."""
    return subprocess.run(
        [PWSH, '-NoProfile', '-NonInteractive', '-File', SCRIPT, '-BaseUrl', url, *extra],
        capture_output=True, text=True, timeout=60,
    )


def _run_with_wrapper(wrapper_content, timeout=60):
    """Write wrapper_content to a temp .ps1 and run it under -NoProfile.

    Used to inject function mocks (e.g. Start-Process) before invoking the real script with &, which can see parent-scope mocks.
    Wrappers explicitly propagate the script exit code.
    """
    tmpdir = TMPBASE_VD if sys.platform == 'win32' else tempfile.gettempdir()
    os.makedirs(tmpdir, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode='w', suffix='.ps1', dir=tmpdir,
        delete=False, prefix='tvd_wrap_',
    ) as f:
        f.write(wrapper_content)
        wp = f.name
    try:
        return subprocess.run(
            [PWSH, '-NoProfile', '-NonInteractive', '-File', wp],
            capture_output=True, text=True, timeout=timeout,
        )
    finally:
        try:
            os.unlink(wp)
        except OSError:
            pass


def _good():
    exe_hdrs = {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': 'attachment; filename="DeskRallySupport.exe"',
        'Content-Length': str(len(_FAKE_EXE)),
    }
    return {
        '/download/DeskRallySupport.exe':            (200, exe_hdrs, _FAKE_EXE),
        '/download/DeskRallySupport.exe.sha256.txt': (200, {'Content-Type': 'text/plain'}, _SIDECAR),
        '/join':           (200, {'Content-Type': 'text/html'}, _JOIN_HTML),
        '/assets/main.js': (200, {'Content-Type': 'application/javascript'}, _BUNDLE_JS),
    }


def setUpModule():
    if not os.path.isfile(SCRIPT):
        raise unittest.SkipTest(f'script not found: {SCRIPT}')
    probe = subprocess.run(
        [PWSH, '-NoProfile', '-Command', 'exit 0'],
        capture_output=True, timeout=30,
    )
    if probe.returncode != 0:
        raise unittest.SkipTest('pwsh not available')


class TestVerifyDownload(unittest.TestCase):

    def test_failed_verification_preserves_caller_finally(self):
        responses = _good()
        del responses['/assets/main.js']
        script_fwd = SCRIPT.replace('\\', '/')
        with _mock_server(responses) as url:
            wrapper = (
                "try {\n"
                f"  & '{script_fwd}' -BaseUrl '{url}'\n"
                "  $code = $LASTEXITCODE\n"
                "} finally { Write-Output 'CALLER_CLEANUP_EXECUTED' }\n"
                "exit $code\n"
            )
            result = _run_with_wrapper(wrapper)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('CALLER_CLEANUP_EXECUTED', result.stdout)
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', result.stdout)

    # ------------------------------------------------------------------
    # Happy path
    # ------------------------------------------------------------------

    def test_successful_verification(self):
        with _mock_server(_good()) as url:
            r = _ps(url)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('VERIFY-DOWNLOAD PASSED', r.stdout)

    # ------------------------------------------------------------------
    # Missing or unfetchable bundle
    # ------------------------------------------------------------------

    def test_exe_missing_fails(self):
        """Exe URL returning 404 must cause non-zero exit (unfetchable exe)."""
        responses = _good()
        del responses['/download/DeskRallySupport.exe']
        with _mock_server(responses) as url:
            r = _ps(url)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)

    def test_join_unfetchable_fails(self):
        """/join returning 404 must fail hard — the bundle hash cannot be verified."""
        responses = _good()
        del responses['/join']   # handler returns 404
        with _mock_server(responses) as url:
            r = _ps(url)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('[FAIL]', r.stdout)
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)

    def test_bundle_fetch_failure_fails(self):
        """Bundle JS URL returning 404 must fail hard, not warn."""
        responses = _good()
        del responses['/assets/main.js']   # handler returns 404 for this path
        with _mock_server(responses) as url:
            r = _ps(url)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('[FAIL]', r.stdout)
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)

    def test_missing_js_fails(self):
        """No <script src> in /join HTML must fail hard, not warn."""
        responses = _good()
        responses['/join'] = (200, {'Content-Type': 'text/html'}, _JOIN_NO_JS)
        with _mock_server(responses) as url:
            r = _ps(url)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('[FAIL]', r.stdout)
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)

    # ------------------------------------------------------------------
    # Hash / sidecar failures
    # ------------------------------------------------------------------

    def test_hash_mismatch_fails(self):
        """Sidecar hash that does not match the downloaded bytes must fail."""
        responses = _good()
        bad = ('ab' * 32 + '  DeskRallySupport.exe\n').encode()
        responses['/download/DeskRallySupport.exe.sha256.txt'] = (
            200, {'Content-Type': 'text/plain'}, bad,
        )
        with _mock_server(responses) as url:
            r = _ps(url)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('[FAIL]', r.stdout)
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)

    def test_sidecar_missing_fails(self):
        """Sidecar URL returning 404 must fail — sidecar is a required check."""
        responses = _good()
        del responses['/download/DeskRallySupport.exe.sha256.txt']
        with _mock_server(responses) as url:
            r = _ps(url)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)

    # ------------------------------------------------------------------
    # RunExe guard: Start-Process must not be called after any failure.
    # Both platform branches of the guard are tested separately.
    # ------------------------------------------------------------------

    # Each entry: (scenario_name, responses_factory).
    # exe_missing and sidecar_missing cause Invoke-WebRequest to throw (ErrorActionPreference=Stop),
    # so the script exits via exception rather than via the $fail.Count branch; Start-Process is
    # still unreachable and the launch_log must remain absent.
    _RUNEXE_FAILURE_SCENARIOS = [
        ('exe_missing',
         lambda: {k: v for k, v in _good().items()
                  if k != '/download/DeskRallySupport.exe'}),
        ('sidecar_missing',
         lambda: {k: v for k, v in _good().items()
                  if k != '/download/DeskRallySupport.exe.sha256.txt'}),
        ('sidecar_hash_mismatch',
         lambda: {**_good(),
                  '/download/DeskRallySupport.exe.sha256.txt': (
                      200, {'Content-Type': 'text/plain'},
                      ('ab' * 32 + '  DeskRallySupport.exe\n').encode())}),
        ('bundle_hash_mismatch',
         lambda: {**_good(),
                  '/assets/main.js': (200, {'Content-Type': 'application/javascript'},
                                      b'var h="deadbeefdeadbeef";')}),
        ('join_missing',
         lambda: {k: v for k, v in _good().items() if k != '/join'}),
        ('bundle_missing',
         lambda: {k: v for k, v in _good().items() if k != '/assets/main.js'}),
        ('bad_exe_content_type',
         lambda: {**_good(),
                  '/download/DeskRallySupport.exe': (
                      200,
                      {'Content-Type': 'text/plain',
                       'Content-Disposition': 'attachment; filename="DeskRallySupport.exe"',
                       'Content-Length': str(len(_FAKE_EXE))},
                      _FAKE_EXE)}),
    ]

    @unittest.skipUnless(sys.platform == 'win32', 'Windows only: tests the $fail.Count skip guard')
    def test_runexe_not_started_after_any_failure(self):
        """On Windows, Start-Process must not be called for any failure scenario.

        Parameterized over: exe missing, sidecar missing, sidecar hash mismatch,
        bundle hash mismatch, /join missing, bundle JS missing, wrong Content-Type.
        The mock records any call to launch_log; an absent log proves Start-Process was never called.
        """
        os.makedirs(TMPBASE_VD, exist_ok=True)
        script_fwd = SCRIPT.replace('\\', '/')

        for name, make_responses in self._RUNEXE_FAILURE_SCENARIOS:
            with self.subTest(scenario=name):
                launch_log = os.path.join(TMPBASE_VD, f'tvd_launch_{name}_{os.getpid()}.txt')
                self.addCleanup(
                    lambda p=launch_log: os.unlink(p) if os.path.exists(p) else None)
                if os.path.exists(launch_log):
                    os.unlink(launch_log)
                lp_fwd = launch_log.replace('\\', '/')

                with _mock_server(make_responses()) as url:
                    wrapper = (
                        "function Start-Process {\n"
                        "    param([string]$FilePath, [string[]]$ArgumentList, [switch]$Wait,\n"
                        "          [switch]$NoNewWindow, [string]$RedirectStandardOutput)\n"
                        f"    Add-Content -Path '{lp_fwd}' -Value $FilePath\n"
                        "    if ($RedirectStandardOutput) {"
                        " [System.IO.File]::WriteAllText($RedirectStandardOutput, '') }\n"
                        "}\n"
                        f"& '{script_fwd}' -BaseUrl '{url}' -RunExe\nexit $LASTEXITCODE\n"
                    )
                    r = _run_with_wrapper(wrapper)

                self.assertNotEqual(r.returncode, 0,
                    f'[{name}] expected non-zero exit\n' + r.stdout + r.stderr)
                self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)
                self.assertFalse(
                    os.path.exists(launch_log),
                    f'[{name}] Start-Process was called but must not be when checks failed',
                )

    @unittest.skipUnless(sys.platform == 'win32', 'Windows only: mocked Start-Process success path')
    def test_runexe_success_mocked(self):
        """When all checks pass and -RunExe is set, Start-Process is called exactly once.

        The mock records calls to launch_log and writes the expected origin to the output file
        so the script's origin check passes without running any real binary.
        """
        expected_origin = 'test-mocked-origin'
        os.makedirs(TMPBASE_VD, exist_ok=True)
        launch_log = os.path.join(TMPBASE_VD, f'tvd_launch_ok_{os.getpid()}.txt')
        self.addCleanup(lambda: os.unlink(launch_log) if os.path.exists(launch_log) else None)
        if os.path.exists(launch_log):
            os.unlink(launch_log)
        script_fwd = SCRIPT.replace('\\', '/')
        lp_fwd     = launch_log.replace('\\', '/')
        with _mock_server(_good()) as url:
            wrapper = (
                "function Start-Process {\n"
                "    param([string]$FilePath, [string[]]$ArgumentList, [switch]$Wait,\n"
                "          [switch]$NoNewWindow, [string]$RedirectStandardOutput)\n"
                f"    Add-Content -Path '{lp_fwd}' -Value $FilePath\n"
                f"    if ($RedirectStandardOutput) {{"
                f" [System.IO.File]::WriteAllText($RedirectStandardOutput, '{expected_origin}') }}\n"
                "}\n"
                f"& '{script_fwd}' -BaseUrl '{url}' -RunExe -ExpectedOrigin '{expected_origin}'\nexit $LASTEXITCODE\n"
            )
            r = _run_with_wrapper(wrapper)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('VERIFY-DOWNLOAD PASSED', r.stdout)
        self.assertTrue(os.path.exists(launch_log), 'Start-Process was not called but should have been')
        with open(launch_log) as f:
            calls = [line.strip() for line in f if line.strip()]
        self.assertEqual(len(calls), 1, f'Expected exactly one Start-Process call, got {len(calls)}: {calls}')

    @unittest.skipUnless(sys.platform == 'win32', 'Windows only: mocked Start-Process wrong-origin path')
    def test_runexe_wrong_origin_fails(self):
        """When all checks pass but the exe writes a different origin, the script exits 1.

        Start-Process is mocked to write 'wrong-origin' to the output file while
        -ExpectedOrigin 'expected-origin' is passed.  Line 109 of verify-download.ps1
        checks ($origin -eq $ExpectedOrigin); removing that Check would let an exe
        reporting the wrong origin exit 0 — this test detects that regression.
        """
        os.makedirs(TMPBASE_VD, exist_ok=True)
        launch_log = os.path.join(TMPBASE_VD, f'tvd_launch_wrongorigin_{os.getpid()}.txt')
        self.addCleanup(lambda: os.unlink(launch_log) if os.path.exists(launch_log) else None)
        if os.path.exists(launch_log):
            os.unlink(launch_log)
        script_fwd = SCRIPT.replace('\\', '/')
        lp_fwd     = launch_log.replace('\\', '/')
        with _mock_server(_good()) as url:
            wrapper = (
                "function Start-Process {\n"
                "    param([string]$FilePath, [string[]]$ArgumentList, [switch]$Wait,\n"
                "          [switch]$NoNewWindow, [string]$RedirectStandardOutput)\n"
                f"    Add-Content -Path '{lp_fwd}' -Value $FilePath\n"
                "    if ($RedirectStandardOutput) {"
                " [System.IO.File]::WriteAllText($RedirectStandardOutput, 'wrong-origin') }\n"
                "}\n"
                f"& '{script_fwd}' -BaseUrl '{url}' -RunExe -ExpectedOrigin 'expected-origin'\nexit $LASTEXITCODE\n"
            )
            r = _run_with_wrapper(wrapper)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('[FAIL]', r.stdout)
        self.assertIn("[FAIL] the downloaded exe reports origin 'wrong-origin' (expected 'expected-origin')", r.stdout)
        self.assertTrue(os.path.exists(launch_log), 'Wrong-origin check must reach the mocked executable')
        with open(launch_log) as f:
            self.assertEqual(len(f.read().splitlines()), 1, 'Expected exactly one mocked executable launch')
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)

    def test_sidecar_served_as_attachment_fails(self):
        """Sidecar response with Content-Disposition: attachment must fail.

        Line 71 of verify-download.ps1 checks that the sidecar is NOT served as
        an attachment.  Deleting that line would allow this case to pass silently.
        """
        responses = _good()
        responses['/download/DeskRallySupport.exe.sha256.txt'] = (
            200,
            {
                'Content-Type': 'text/plain',
                'Content-Disposition': 'attachment; filename="DeskRallySupport.exe.sha256.txt"',
            },
            _SIDECAR,
        )
        with _mock_server(responses) as url:
            r = _ps(url)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('[FAIL] sidecar is NOT served as an attachment', r.stdout)
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)

    def test_exe_with_content_encoding_fails(self):
        """An exe response carrying Content-Encoding must fail the Content-Encoding check.

        Uses 'identity' (not 'gzip') so Invoke-WebRequest does not auto-decompress and
        throw before reaching line 62's Check call, ensuring the [FAIL] path is exercised.
        """
        responses = _good()
        exe_hdrs = {
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': 'attachment; filename="DeskRallySupport.exe"',
            'Content-Length': str(len(_FAKE_EXE)),
            'Content-Encoding': 'identity',
        }
        responses['/download/DeskRallySupport.exe'] = (200, exe_hdrs, _FAKE_EXE)
        with _mock_server(responses) as url:
            r = _ps(url)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('[FAIL] no Content-Encoding on the exe', r.stdout)
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)

    def test_exe_missing_content_disposition_fails(self):
        """Exe served with no Content-Disposition header must fail with the disposition check.

        Line 57 of verify-download.ps1 checks that $disp matches '*attachment*' and
        '*DeskRallySupport.exe*'.  Deleting that line would let an exe with no
        Content-Disposition header pass silently.
        """
        responses = _good()
        responses['/download/DeskRallySupport.exe'] = (
            200,
            {
                'Content-Type': 'application/octet-stream',
                'Content-Length': str(len(_FAKE_EXE)),
            },
            _FAKE_EXE,
        )
        with _mock_server(responses) as url:
            r = _ps(url)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('[FAIL] Content-Disposition names the exe', r.stdout)
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)

    def test_runexe_fails_on_non_windows(self):
        """-RunExe on a non-Windows host must always fail with the platform error.

        Start-Process is mocked so that a regression removing the $IsWindows guard would write to
        launch_log rather than attempting to execute the fake MZ bytes as a real process.
        """
        tmpdir = TMPBASE_VD if sys.platform == 'win32' else tempfile.gettempdir()
        launch_log = os.path.join(tmpdir, f'tvd_launch_nonwin_{os.getpid()}.txt')
        self.addCleanup(lambda: os.unlink(launch_log) if os.path.exists(launch_log) else None)
        if os.path.exists(launch_log):
            os.unlink(launch_log)
        script_fwd = SCRIPT.replace('\\', '/')
        lp_fwd = launch_log.replace('\\', '/')

        with _mock_server(_good()) as url:
            wrapper = (
                "Set-Variable -Name IsWindows -Value $false -Force\n"
                "function Start-Process {\n"
                "    param([string]$FilePath, [string[]]$ArgumentList, [switch]$Wait,\n"
                "          [switch]$NoNewWindow, [string]$RedirectStandardOutput)\n"
                f"    Add-Content -Path '{lp_fwd}' -Value $FilePath\n"
                "    if ($RedirectStandardOutput) {"
                " [System.IO.File]::WriteAllText($RedirectStandardOutput, '') }\n"
                "}\n"
                f"& '{script_fwd}' -BaseUrl '{url}' -RunExe\nexit $LASTEXITCODE\n"
            )
            r = _run_with_wrapper(wrapper)

        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('-RunExe requires Windows', r.stdout)
        self.assertNotIn('[skip]', r.stdout)
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)
        self.assertFalse(
            os.path.exists(launch_log),
            f'Start-Process was called but must not be on non-Windows; log: {launch_log}',
        )


    def test_exe_status_201_fails(self):
        """Exe served with HTTP 201 must fail the status-200 check (line 53).

        Invoke-WebRequest does not throw on a 201 response, so line 53's Check
        is reached and must emit '[FAIL] status 200' and exit 1.
        Mutation: removing that Check lets a 201 response pass all subsequent
        header/hash/bundle checks and exit 0 — this test detects that regression.
        """
        responses = _good()
        exe_hdrs = {
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': 'attachment; filename="DeskRallySupport.exe"',
            'Content-Length': str(len(_FAKE_EXE)),
        }
        responses['/download/DeskRallySupport.exe'] = (201, exe_hdrs, _FAKE_EXE)
        with _mock_server(responses) as url:
            r = _ps(url)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('[FAIL] status 200', r.stdout)
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)

    def test_content_length_mismatch_fails(self):
        """Content-Length header reporting twice the actual byte count must fail.

        verify-download.ps1 line 59-60 reads $resp.Headers['Content-Length'] and
        checks it equals $served (the actual byte count).  A server advertising
        twice the real length must cause exit 1 and '[FAIL] Content-Length'.

        Uses a wrapper mock so Invoke-WebRequest does not throw before reaching
        the Check: the mock writes the real 64 bytes to -OutFile and returns a
        synthetic response object with Content-Length=128, letting the script's
        own Check produce the [FAIL] output.
        """
        script_fwd = SCRIPT.replace('\\', '/')
        byte_vals = ', '.join(str(b) for b in _FAKE_EXE)
        with _mock_server(_good()) as url:
            wrapper = (
                f"$fakeExeBytes = [byte[]]@({byte_vals})\n"
                "function Invoke-WebRequest {\n"
                "    param([string]$Uri, [string]$OutFile, [switch]$PassThru, [int]$MaximumRedirection)\n"
                "    if (($Uri -like '*/DeskRallySupport.exe') -and $PassThru -and $OutFile) {\n"
                "        [System.IO.File]::WriteAllBytes($OutFile, $fakeExeBytes)\n"
                "        return [PSCustomObject]@{\n"
                "            StatusCode = 200\n"
                "            Headers = @{\n"
                "                'Content-Type'        = 'application/octet-stream'\n"
                "                'Content-Disposition' = 'attachment; filename=\"DeskRallySupport.exe\"'\n"
                "                'Content-Length'      = '128'\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "    Microsoft.PowerShell.Utility\\Invoke-WebRequest @PSBoundParameters\n"
                "}\n"
                f"& '{script_fwd}' -BaseUrl '{url}'\n"
                "exit $LASTEXITCODE\n"
            )
            r = _run_with_wrapper(wrapper)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('[FAIL] Content-Length', r.stdout)
        self.assertNotIn('VERIFY-DOWNLOAD PASSED', r.stdout)


if __name__ == '__main__':
    unittest.main()
