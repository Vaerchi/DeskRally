"""Exercise literal configuration, argument boundaries and exit propagation without real services."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeLaunchers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='deskrally native launcher ')
        cls.package = Path(cls.temp.name)
        (cls.package / 'config').mkdir()
        (cls.package / 'bin').mkdir()
        for name in ('run-service.ps1', 'run-service.sh'):
            shutil.copyfile(ROOT / 'deploy/native' / name, cls.package / name)
        cls.runners = []
        pwsh = shutil.which('pwsh')
        if os.name == 'nt' and pwsh:
            probe = cls.package / 'probe.go'
            probe.write_text('package main\nimport("encoding/json";"os")\n'
                             'func main(){ json.NewEncoder(os.Stdout).Encode(map[string]any{'
                             '"args":os.Args[1:],"value":os.Getenv("TEST_LITERAL")});os.Exit(7) }\n')
            subprocess.run(['go', 'build', '-o', str(cls.package / 'bin/controlplane.exe'), str(probe)], check=True)
            cls.runners.append([pwsh, '-NoLogo', '-NoProfile', '-File', str(cls.package / 'run-service.ps1')])
        bash = shutil.which('bash')
        git_bash = Path('C:/Program Files/Git/bin/bash.exe')
        if os.name == 'nt' and git_bash.exists():
            bash = str(git_bash)
        if bash:
            helper = cls.package / 'probe.py'
            helper.write_text('import json, os, sys\nprint(json.dumps({"args":sys.argv[1:],'
                              '"value":os.environ.get("TEST_LITERAL")}))\nsys.exit(7)\n')
            binary = cls.package / 'bin/controlplane'
            binary.write_text(f'#!/bin/sh\nexec "{Path(sys.executable).as_posix()}" "{helper.as_posix()}" "$@"\n')
            binary.chmod(0o755)
            cls.runners.append([bash, str(cls.package / 'run-service.sh')])
        if not cls.runners:
            raise unittest.SkipTest('No supported native shell available')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_literal_secrets_arguments_and_exit_status(self):
        literal = 'spaces = $HOME $(echo unsafe) `echo unsafe` "quotes"'
        (self.package / 'config/controlplane.env').write_bytes(f'# comment\r\nTEST_LITERAL={literal}\r\n'.encode())
        for runner in self.runners:
            with self.subTest(runner=runner[0]):
                result = subprocess.run(runner + ['controlplane', 'migrate', '--dir', 'folder with spaces'], capture_output=True, text=True)
                self.assertEqual(result.returncode, 7, result.stderr)
                payload = json.loads(result.stdout)
                self.assertEqual(payload['value'], literal)
                self.assertEqual(payload['args'], ['migrate', '--dir', 'folder with spaces'])

    def test_duplicate_and_malformed_keys_are_rejected(self):
        for config in ('TEST_LITERAL=a\nTEST_LITERAL=b\n', 'export TEST_LITERAL=a\n', 'BAD-KEY=value\n'):
            (self.package / 'config/controlplane.env').write_text(config)
            for runner in self.runners:
                with self.subTest(config=config, runner=runner[0]):
                    result = subprocess.run(runner + ['controlplane'], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn('"args"', result.stdout)


if __name__ == '__main__':
    unittest.main()
