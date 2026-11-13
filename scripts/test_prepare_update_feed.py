"""Release preparation failure boundaries; no production or private key access."""
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import prepare_update_feed as feed

TEST_ORIGIN = "https://updates.example.test:8443"
TEST_PUBLISHER = "CN=Test Publisher, O=Test"


class UpdateFeedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.binary = self.root / "input.exe"
        self.binary.write_bytes(b"test executable bytes")
        self.output = self.root / "output"

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self, **overrides):
        args = dict(component="client", binary=self.binary, version="0.5.0", output=self.output,
                    origin=TEST_ORIGIN, publisher=TEST_PUBLISHER,
                    verify=lambda path, publisher: {"version": "0.5.0.0", "original": "DeskRallyClient.exe",
                                         "product": "DeskRally"})
        args.update(overrides)
        return feed.stage(**args)

    def test_identity_argument_rules(self):
        base = ["client", "--binary", "test.exe", "--version", "0.5.0", "--output", "out"]
        for extra in ([], ["--origin", TEST_ORIGIN], ["--publisher", TEST_PUBLISHER],
                      ["--official", "--origin", TEST_ORIGIN],
                      ["--official", "--publisher", TEST_PUBLISHER]):
            with self.subTest(extra=extra), self.assertRaises(SystemExit):
                feed.parse_args(base + extra)
        own = feed.parse_args(base + ["--origin", TEST_ORIGIN, "--publisher", TEST_PUBLISHER])
        self.assertEqual((own["origin"], own["publisher"]), (TEST_ORIGIN, TEST_PUBLISHER))
        identity = json.loads((Path(feed.__file__).resolve().parents[1] /
                               "packaging/official-update-identity.json").read_text())
        official = feed.parse_args(base + ["--official"])
        self.assertEqual((official["origin"], official["publisher"]),
                         (identity["feed"], identity["publisher"]))

    def test_invalid_identity_rejected_before_staging(self):
        for origin in ("", "http://example.test", "https://", "https://user@host",
                       "https://host/path", "https://host/", "https://host?q=1",
                       "https://host#x", "https://host\\path", "https://two hosts",
                       "https://host:99999", "https://host:0", "https://host\x00evil",
                       "https://host\x01evil", "https://host\x7fevil"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                self.prepare(origin=origin)
        for publisher in ("", " ", "CN=one\nCN=two", "CN=one\rCN=two", 'CN="quoted"', "CN=a\x00b", "CN=a\tb"):
            with self.subTest(publisher=publisher), self.assertRaises(ValueError):
                self.prepare(publisher=publisher)
        self.assertFalse(self.output.exists())

    def test_client_feed_matches_staged_bytes(self):
        result = self.prepare()
        manifest = json.loads(Path(result["manifest"]).read_text())
        self.assertEqual(manifest["url"], TEST_ORIGIN + "/download/client/releases/0.5.0/DeskRallyClient.exe")
        self.assertEqual(manifest["sha256"], feed.hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(manifest["size"], self.binary.stat().st_size)
        self.assertEqual(Path(result["payload"]).read_bytes(), self.binary.read_bytes())

    def test_configured_publisher_reaches_authenticode(self):
        evidence = {"version": "0.5.0.0", "original": "DeskRallyClient.exe", "product": "DeskRally"}
        with patch.object(feed, "authenticode", return_value=evidence) as verify:
            result = self.prepare(verify=None)
        verify.assert_called_once_with(Path(result["payload"]), TEST_PUBLISHER)

    def test_untrusted_candidate_never_publishes_manifest(self):
        def reject(path, publisher):
            self.assertEqual(publisher, TEST_PUBLISHER)
            self.assertEqual(path.read_bytes(), self.binary.read_bytes())
            raise ValueError("signature rejected")
        with self.assertRaisesRegex(ValueError, "signature rejected"):
            self.prepare(verify=reject)
        self.assertFalse((self.output / "client/manifest.json").exists())

    def test_actual_version_and_product_required(self):
        for info in ({"version": "0.4.0.0"}, {"version": "0.5.0.0", "product": "Other"}):
            with self.subTest(info=info), tempfile.TemporaryDirectory(dir=self.root) as dest:
                with self.assertRaises(ValueError):
                    self.prepare(output=Path(dest)/"out", verify=lambda _, publisher: info)
                self.assertFalse((Path(dest)/"out/client/manifest.json").exists())

    def test_existing_output_not_overwritten(self):
        result = self.prepare()
        before = Path(result["manifest"]).read_bytes()
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(Path(result["manifest"]).read_bytes(), before)

    def test_path_injection_and_nonrelease_versions_rejected(self):
        for version in ("../1.2.3", "01.2.3", "1.2.3/next", "1.2.3-rc1", "1.2.3\n", "1.2.3+unknown"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.prepare(version=version)
        self.assertFalse(self.output.exists())

    def test_agent_requires_separate_signing_material(self):
        with self.assertRaisesRegex(ValueError, "offline signer"):
            self.prepare(component="agent")
        self.assertFalse(self.output.exists())

    def test_limits_before_copy(self):
        with patch.object(feed, "MAX_BINARY", 1), self.assertRaisesRegex(ValueError, "size"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_agent_signer_verification_failure_never_exposes_manifest(self):
        def run(args, **kwargs):
            if args[1] == "version":
                return SimpleNamespace(stdout="0.5.0")
            if args[1] == "sign":
                Path(args[args.index("-out")+1]).write_text("{}")
                return SimpleNamespace(returncode=0)
            raise subprocess.CalledProcessError(1, args)
        with patch.object(feed.subprocess, "run", side_effect=run):
            with self.assertRaises(subprocess.CalledProcessError):
                self.prepare(component="agent", signer="offline-signer.exe", seed=self.root/"private.key",
                             public_key="ab"*32)
        self.assertFalse((self.output/"agent/canary/manifest.json").exists())

    def test_agent_signer_must_bind_exact_release(self):
        def run(args, **kwargs):
            if args[1] == "version":
                return SimpleNamespace(stdout="0.5.0")
            if args[1] == "sign":
                wrong = {"claims": {"release": {"sha256": "00"*32}}}
                Path(args[args.index("-out")+1]).write_text(json.dumps(wrong))
            return SimpleNamespace(returncode=0)
        with patch.object(feed.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(ValueError, "requested release"):
                self.prepare(component="agent", signer="offline-signer.exe", seed=self.root/"private.key",
                             public_key="ab"*32)
        self.assertFalse((self.output/"agent/canary/manifest.json").exists())

    def test_private_seed_cannot_be_in_public_tree(self):
        with self.assertRaisesRegex(ValueError, "private seed"):
            self.prepare(component="agent", signer="offline-signer.exe", seed=self.output/"private.key",
                         public_key="ab"*32)
        self.assertFalse(self.output.exists())

    def test_signature_validation_and_rotating_leaf(self):
        valid = {"status": "Valid", "subject": TEST_PUBLISHER, "timestamp": True,
                 "version": "0.5.0.0"}
        for changes, accepted in (({}, True), ({"status": "NotSigned"}, False),
                                  ({"subject": "Another publisher"}, False),
                                  ({"timestamp": False}, False)):
            info = dict(valid, **changes)
            with self.subTest(changes=changes), patch.object(feed.subprocess, "run") as run:
                run.return_value.stdout = json.dumps(info)
                if accepted:
                    self.assertEqual(feed.authenticode(self.binary, TEST_PUBLISHER), info)
                else:
                    with self.assertRaises(ValueError):
                        feed.authenticode(self.binary, TEST_PUBLISHER)
                self.assertEqual(run.call_args.kwargs["env"]["DESKRALLY_UPDATE_ARTIFACT"], str(self.binary))


if __name__ == "__main__":
    unittest.main()
