"""Loopback-only native binary/proxy smoke test. Does not exercise PostgreSQL or a remote session."""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def status(url):
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def ready(url, process):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f'Process exited during startup ({process.returncode})')
        try:
            if status(url) == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    raise RuntimeError(f'Timed out waiting for {url}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('--caddy', type=Path, required=True)
    args = parser.parse_args()
    package = args.package.resolve()
    suffix = '.exe' if os.name == 'nt' else ''
    binary = package / 'bin' / f'controlplane{suffix}'
    # Never inherit a real deployment's credentials or developer-mode switches into the probe.
    env = {k: v for k, v in os.environ.items() if not k.startswith((
        'CP_', 'SIGNALING_', 'RECORDING_', 'DIRECTIVE_', 'GRANT_', 'DATABASE_', 'TOTP_', 'MIGRATE_'))}
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
    refused = subprocess.run([str(binary)], env=env, capture_output=True, text=True, timeout=15, **options)
    if refused.returncode == 0 or 'DATABASE_URL' not in refused.stderr:
        raise RuntimeError('Production startup did not refuse a missing database URL')
    for service, extra in (('controlplane', ['migrate', '-h']), ('signaling', ['-h']), ('relay', ['-h'])):
        result = subprocess.run([str(package / 'bin' / f'{service}{suffix}'), *extra], env=env,
                                capture_output=True, timeout=15, **options)
        if result.returncode:
            raise RuntimeError(f'{service} command-line probe failed')
    cp_port, proxy_port = port(), port()
    env.update(CP_INSECURE_DEV='1', CP_LISTEN=f'127.0.0.1:{cp_port}', CP_INSECURE_DEV_GRANT_SEED='12' * 32)
    env.update(SITE_ADDRESS=f'http://127.0.0.1:{proxy_port}', VIEWER_ROOT=(package / 'viewer').as_posix(),
               DOWNLOAD_ROOT=(package / 'download').as_posix())
    children = []
    with tempfile.TemporaryDirectory(prefix='deskrally-smoke-') as temporary:
        log_path = Path(temporary) / 'smoke.log'
        config = Path(temporary) / 'Caddyfile'
        original = (ROOT / 'deploy/native/Caddyfile').read_text()
        config.write_text('{\n admin off\n auto_https off\n}\n' + original.replace('127.0.0.1:8081', f'127.0.0.1:{cp_port}'))
        with log_path.open('w') as log:
            try:
                cp = subprocess.Popen([str(binary)], env=env, stdout=log, stderr=log, **options)
                children.append(cp)
                ready(f'http://127.0.0.1:{cp_port}/healthz', cp)
                proxy = subprocess.Popen([str(args.caddy.resolve()), 'run', '--config', str(config), '--adapter', 'caddyfile'],
                                         env=env, stdout=log, stderr=log, **options)
                children.append(proxy)
                base = f'http://127.0.0.1:{proxy_port}'
                ready(base + '/docs', proxy)
                for route, expected in (('/docs', 200), ('/console', 200), ('/cp/healthz', 200),
                                        ('/cp/internal/presence', 404), ('/download/missing.exe', 404)):
                    actual = status(base + route)
                    if actual != expected:
                        raise RuntimeError(f'{route}: expected {expected}, got {actual}')
                print('PASS: production startup refusal, native CLI, loopback dev health, public docs/console, API prefix, internal-route denial, missing-download 404')
                print('Not covered: PostgreSQL, Windows service installation, Linux runtime, TLS issuance, TURN or a remote session.')
            except Exception:
                log.flush()
                print(log_path.read_text())
                raise
            finally:
                for child in reversed(children):
                    if child.poll() is None:
                        child.terminate()
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()


if __name__ == '__main__':
    main()
