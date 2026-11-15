"""Prepare public update artifacts locally; never upload signing keys or deploy.

Authenticode is checked on the staged bytes. Agent manifests additionally use
the existing offline Ed25519 signer. Publish payloads before their manifests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\+[0-9a-f]{7,40})?\Z")
MAX_BINARY = 128 * 1024 * 1024


def validate_identity(origin, publisher):
    if not isinstance(origin, str) or not origin.startswith("https://"):
        raise ValueError("Origin must be exactly https://host[:port]")
    if re.search(r"[\x00-\x1f\x7f]", origin):
        raise ValueError("Origin must be exactly https://host[:port]")
    host = origin[8:]
    if not host or re.search(r'[/@?#\\\s"]', host):
        raise ValueError("Origin must be exactly https://host[:port]")
    try:
        parts = urlsplit(origin)
        if not parts.hostname or parts.path or parts.query or parts.fragment:
            raise ValueError("Invalid origin")
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid origin port")
    except ValueError as error:
        raise ValueError("Origin must be exactly https://host[:port]") from error
    if not isinstance(publisher, str) or not publisher.strip() or re.search(r'[\x00-\x1f\x7f"]', publisher):
        raise ValueError("Publisher must be non-empty, one line, without double quotes")
    return origin, publisher


def resolve_identity(official=False, origin=None, publisher=None):
    if official:
        if origin is not None or publisher is not None:
            raise ValueError("--official cannot be combined with --origin or --publisher")
        identity = json.loads((Path(__file__).resolve().parents[1] /
                               "packaging/official-update-identity.json").read_text(encoding="utf-8"))
        origin, publisher = identity["feed"], identity["publisher"]
    elif origin is None or publisher is None:
        raise ValueError("Supply --official or both --origin and --publisher")
    return validate_identity(origin, publisher)


def release_version(value):
    if not VERSION.fullmatch(value):
        raise ValueError("Expected a release version, optionally followed by a git hash")
    return value.split("+", 1)[0]


def authenticode(path, publisher):
    if not isinstance(publisher, str) or not publisher.strip():
        raise ValueError("A non-empty publisher is required")
    # Pass paths as child environment data, never as PowerShell source text.
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    env["DESKRALLY_UPDATE_ARTIFACT"] = str(path)
    command = r"""
$ErrorActionPreference='Stop'
$s=Get-AuthenticodeSignature -LiteralPath $env:DESKRALLY_UPDATE_ARTIFACT
$v=(Get-Item -LiteralPath $env:DESKRALLY_UPDATE_ARTIFACT).VersionInfo
[pscustomobject]@{status=[string]$s.Status;subject=$s.SignerCertificate.Subject;
 timestamp=($null -ne $s.TimeStamperCertificate);version=$v.FileVersion;
 product=$v.ProductName;original=$v.OriginalFilename} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        env=env, capture_output=True, text=True, check=True, timeout=60,
    )
    evidence = json.loads(result.stdout)
    if (evidence.get("status") != "Valid" or evidence.get("subject") != publisher
            or evidence.get("timestamp") is not True):
        raise ValueError("A valid timestamped DeskRally publisher signature is required")
    # Azure Artifact Signing leaf certificates rotate every few days. Pinning
    # one leaf thumbprint would strand updates at the next certificate rotation.
    return evidence


def stage(component, binary, version, output, *, origin, publisher, signer=None, seed=None,
          public_key=None, minimum="0.0.1", ring="canary", verify=None):
    origin, publisher = validate_identity(origin, publisher)
    core = release_version(version)
    if component not in ("client", "agent") or ring not in ("canary", "early", "general"):
        raise ValueError("Unknown component or ring")
    binary, output = Path(binary).resolve(strict=True), Path(output).resolve()
    limit = min(MAX_BINARY, 32 * 1024 * 1024) if component == "client" else MAX_BINARY
    if not binary.is_file() or not 0 < binary.stat().st_size <= limit:
        raise ValueError("Invalid binary size")
    if component == "agent":
        release_version(minimum)
        if not signer or not seed or not public_key or not re.fullmatch(r"[0-9a-f]{64}", public_key):
            raise ValueError("Agent feed requires offline signer, seed file, and pinned public key")
        if Path(seed).resolve().is_relative_to(output):
            raise ValueError("The private seed must be outside the public output directory")
    # A fresh directory makes a failed preparation incapable of replacing a live
    # manifest. The caller chooses what is published after reviewing the output.
    output.mkdir(parents=True, exist_ok=False)
    name = "DeskRallyClient.exe" if component == "client" else "agent_host.exe"
    relative = Path(component) / "releases" / core / name
    payload = output / relative
    payload.parent.mkdir(parents=True)
    with binary.open("rb") as src, payload.open("xb") as dst:
        count = 0
        while chunk := src.read(1024 * 1024):
            count += len(chunk)
            if count > limit:
                raise ValueError("Binary grew beyond the size limit")
            dst.write(chunk)
        dst.flush()
        os.fsync(dst.fileno())
    evidence = authenticode(payload, publisher) if verify is None else verify(payload, publisher)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    url = origin + "/download/" + relative.as_posix()
    if component == "client":
        actual = str(evidence.get("version", ""))
        if actual not in (core, core + ".0"):
            raise ValueError("Signed client file version does not match requested release")
        if evidence.get("original") != name or evidence.get("product") != "DeskRally":
            raise ValueError("Signed file is not the DeskRally desktop client")
        manifest = {"version": core, "sha256": digest, "size": count, "url": url}
        destination = output / "client" / "manifest.json"
        pending = destination.with_suffix(".pending.json")
        pending.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        pending.replace(destination)
    else:
        actual = subprocess.run([str(payload), "version"], capture_output=True,
                                text=True, check=True, timeout=15).stdout.strip()
        if actual != version:
            raise ValueError("Signed agent build identity does not match requested release")
        destination = output / "agent" / ring / "manifest.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        pending = destination.with_suffix(".pending.json")
        subprocess.run([str(signer), "sign", "-seed", str(seed), "-version", version,
                        "-binary", str(payload), "-url", url, "-min-upgradable-from", minimum,
                        "-valid-days", "30", "-out", str(pending)], check=True, timeout=30,
                       capture_output=True)
        subprocess.run([str(signer), "verify", "-in", str(pending), "-pubkey", public_key],
                       check=True, timeout=30, capture_output=True)
        manifest = json.loads(pending.read_text(encoding="utf-8"))
        if manifest["claims"]["release"] != {"sha256": digest, "version": version,
                                              "url": url, "min_upgradable_from": minimum}:
            raise ValueError("Offline signer did not produce the requested release")
        pending.replace(destination)
    return {"component": component, "version": version, "sha256": digest,
            "payload": str(payload), "manifest": str(destination), "url": url}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=("agent", "client"))
    parser.add_argument("--official", action="store_true")
    parser.add_argument("--origin")
    parser.add_argument("--publisher")
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--signer", type=Path)
    parser.add_argument("--seed", type=Path)
    parser.add_argument("--public-key")
    parser.add_argument("--minimum", default="0.0.1")
    parser.add_argument("--ring", choices=("canary", "early", "general"), default="canary")
    args = vars(parser.parse_args(argv))
    try:
        args["origin"], args["publisher"] = resolve_identity(
            args.pop("official"), args["origin"], args["publisher"])
    except ValueError as error:
        parser.error(str(error))
    return args


def main():
    print(json.dumps(stage(**parse_args()), indent=2))


if __name__ == "__main__":
    main()
