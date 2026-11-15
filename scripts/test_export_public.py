"""Offline integration/unit tests; each case uses a disposable local git repository."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("public_export", Path(__file__).with_name("export-public.py"))
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.dest = self.root / "out"
        self.git("init", "--quiet")
        self.policy = {"version": 1, "include": ["src/"], "exclude": ["src/hidden/", "**/*.pyc"]}

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], stderr=subprocess.DEVNULL)

    def write(self, path, data):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def commit(self):
        self.write(exporter.POLICY, json.dumps(self.policy).encode())
        self.git("add", ".")
        # Identity is synthetic and confined to this invocation; no git config changes.
        self.git("-c", "user.name=Export Test", "-c", "user.email=export@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture")
        return self.git("rev-parse", "HEAD").decode().strip()

    def run_export(self, allow=None, revision="HEAD"):
        with contextlib.redirect_stderr(io.StringIO()) as report:
            try:
                return exporter.export(self.repo, revision, self.dest, allow)
            finally:
                self.report = report.getvalue()

    def test_selection_manifest_and_immutable_policy(self):
        self.write("src/main.txt", b"hello\n")
        self.write("src/hidden/data.txt", b"excluded")
        self.write("src/cache.pyc", b"excluded")
        self.write("other.txt", b"excluded")
        revision = self.commit()
        self.write("src/main.txt", b"uncommitted")
        self.write(exporter.POLICY, b"not json")
        manifest = json.loads(self.run_export(revision=revision))
        self.assertEqual(manifest, {"source_revision": revision, "files": [{
            "path": "src/main.txt", "source_revision": revision,
            "sha256": hashlib.sha256(b"hello\n").hexdigest()}]})
        self.assertEqual((self.dest / "src/main.txt").read_bytes(), b"hello\n")
        self.assertEqual(sorted(p.relative_to(self.dest).as_posix() for p in self.dest.rglob("*") if p.is_file()),
                         [exporter.MANIFEST, "src/main.txt"])

    def test_nonempty_destination(self):
        self.commit()
        self.dest.mkdir()
        sentinel = self.dest / "keep.txt"
        sentinel.write_text("keep")
        with self.assertRaises(ValueError):
            self.run_export()
        self.assertEqual(sentinel.read_text(), "keep")

    def test_destination_inside_source(self):
        self.commit()
        self.dest = self.repo / "out"
        with self.assertRaises(ValueError):
            self.run_export()
        self.assertFalse(self.dest.exists())

    def test_secret_and_personal_findings_redacted(self):
        literal = b"synthetic-test-value"
        self.write("src/bad.txt", b'password="' + literal + b'"\nWIN11LAB\nvaerchi\n')
        self.commit()
        with self.assertRaises(ValueError):
            self.run_export()
        self.assertIn("src/bad.txt:1:literal-credential", self.report)
        self.assertIn("src/bad.txt:2:private-machine", self.report)
        self.assertIn("src/bad.txt:3:personal-identity", self.report)
        self.assertNotIn(literal.decode(), self.report)

    def test_exact_allow_and_unused(self):
        self.write("src/key.hex", b"a" * 64 + b"\n")
        self.commit()
        allow = self.root / "review.txt"
        allow.write_text("src/key.hex:long-hex\n", encoding="utf-8")
        self.run_export(allow)
        self.dest = self.root / "second"
        allow.write_text("src/key.hex:long-hex\nsrc/absent.txt:private-machine\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.run_export(allow)
        self.assertIn("unused-allow-entry", self.report)

    def test_allow_does_not_accept_another_path(self):
        self.write("src/other.hex", b"a" * 64)
        self.commit()
        allow = self.root / "review.txt"
        allow.write_text("src/key.hex:long-hex\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.run_export(allow)
        self.assertIn("src/other.hex:1:long-hex: [blocked", self.report)

    def test_nonregular_selected_input(self):
        self.commit()
        # Store an ordinary blob, then record it as a symlink without requiring OS symlink privilege.
        self.write("link-target.txt", b"target")
        oid = self.git("hash-object", "-w", "link-target.txt").decode().strip()
        self.git("update-index", "--add", "--cacheinfo", "120000", oid, "src/link")
        self.git("-c", "user.name=Export Test", "-c", "user.email=export@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "symlink")
        with self.assertRaises(ValueError):
            self.run_export()
        self.assertFalse(self.dest.exists())

    def test_pattern_rules_and_forbidden_names(self):
        samples = {
            "private-key": b"-----BEGIN RSA PRIVATE KEY-----",
            "long-base64": b"Z" * 100,
            "credential-url": b"postgres://example:synthetic@localhost/db",
            "private-path": b"R:\\example\\file",
            "personal-workspace": b"/home/example/source",
        }
        self.dest.mkdir()
        for rule, data in samples.items():
            (self.dest / (rule + ".txt")).write_bytes(data)
        (self.dest / ".env").write_bytes(b"")
        findings = exporter.scan(self.dest, b"")
        for rule in samples:
            self.assertTrue(any(p == rule + ".txt" and r == rule for p, _, r in findings), rule)
        self.assertIn((".env", 0, "forbidden-file"), findings)

    def test_prefix_and_glob_exclusion(self):
        policy = {"include": ["web/", "exact.txt"], "exclude": ["**/*evidence*/", "**/*.pyc"]}
        for path in ("web/evidence-pass/file.txt", "web/nested/evidence/file.txt", "web/cache.pyc"):
            self.assertFalse(exporter.selected(path, policy))
        self.assertTrue(exporter.selected("web/viewer/main.js", policy))
        self.assertTrue(exporter.selected("exact.txt", policy))
        self.assertFalse(exporter.selected("exact.txt/child", policy))
        self.assertFalse(exporter.selected("unknown.txt", policy))

    def test_exclude_exception_is_exact_example_paths_only(self):
        self.policy = {"version": 1, "include": ["src/"], "exclude": ["**/.env.*", "**/*.env"],
                       "exclude_exceptions": ["src/.env.example"]}
        self.write("src/.env.example", b"KEY=\n")
        self.write("src/.env.local", b"excluded")
        self.write("src/other/.env.example", b"excluded: not listed exactly")
        self.write("src/main.txt", b"hello\n")
        self.commit()
        # The selection exception alone is not enough: the output scan still flags the name.
        with self.assertRaises(ValueError):
            self.run_export()
        self.assertIn("src/.env.example:0:forbidden-file", self.report)
        allow = self.root / "review.txt"
        allow.write_text("src/.env.example:forbidden-file\n", encoding="utf-8")
        self.dest = self.root / "second"
        manifest = json.loads(self.run_export(allow))
        self.assertEqual(sorted(f["path"] for f in manifest["files"]), ["src/.env.example", "src/main.txt"])

    def test_exclude_exception_rejects_globs_and_non_templates(self):
        self.write("src/main.txt", b"hello\n")
        for bad in (["src/*.example"], ["src/.env"], "src/.env.example", [""]):
            with self.subTest(bad=bad):
                self.policy = {"version": 1, "include": ["src/"], "exclude": ["**/.env*"],
                               "exclude_exceptions": bad}
                self.commit()
                with self.assertRaises(ValueError):
                    self.run_export()
                self.assertFalse(self.dest.exists())


if __name__ == "__main__":
    unittest.main()
