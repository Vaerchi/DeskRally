"""Export an immutable, explicitly selected source tree; findings block success."""
import argparse
import fnmatch
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


POLICY = "packaging/public-export.json"
MANIFEST = "EXPORT-MANIFEST.json"
spec = importlib.util.spec_from_file_location(
    "release_inventory", Path(__file__).with_name("release-source-inventory.py"))
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)
PATTERNS = dict(inventory.PATTERNS)
PATTERNS.update({
    "private-key": rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----",
    "long-hex": rb"(?i)(?<![a-z0-9])[a-f0-9]{64,}(?![a-z0-9])",
    "long-base64": rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])",
    "literal-credential": rb'''(?i)\b(?:password|token|secret)\s*[:=]\s*(?:["'][^"'\r\n]+["']|[A-Za-z0-9_+/!@.-]{4,})''',
    "credential-url": rb"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:[^\s/@]+@",
    "connection-credential": rb"(?i)\b(?:pwd|password)\s*=\s*[^;\s]+",
    "private-machine": rb"(?i)\b(?:Ed's|Work Laptop|WIN11LAB|DRACCEPT)\b",
    "private-path": rb"(?i)(?:[FR]:[/\\]|C:[/\\]Users[/\\])",
})


def safe_path(path):
    p = PurePosixPath(path)
    return (bool(path) and not p.is_absolute() and str(p) == path
            and all(part not in (".", "..") and ":" not in part
                    and "\\" not in part and not re.search(r"[\x00-\x1f]", part)
                    and not part.endswith((".", " "))
                    and part.split(".")[0].upper() not in
                    {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(10)],
                     *[f"LPT{i}" for i in range(10)]} for part in p.parts))


def matches(path, entry):
    # A trailing slash denotes a prefix, including globbed directory prefixes.
    if entry.endswith("/"):
        return any(fnmatch.fnmatchcase("/".join(path.split("/")[:i]) + "/", entry)
                   or (entry.startswith("**/") and fnmatch.fnmatchcase(
                       "/".join(path.split("/")[:i]) + "/", entry[3:]))
                   for i in range(1, len(path.split("/"))))
    return fnmatch.fnmatchcase(path, entry) or (
        entry.startswith("**/") and fnmatch.fnmatchcase(path, entry[3:]))


def selected(path, policy):
    # exclude_exceptions: exact paths of blank configuration templates (".example") that an exclude
    # pattern such as "**/.env.*" would otherwise drop. Exact paths only, never globs.
    return (any(matches(path, p) for p in policy["include"])
            and (path in policy.get("exclude_exceptions", [])
                 or not any(matches(path, p) for p in policy["exclude"])))


def scan(destination, manifest_bytes):
    findings = set()
    for target in sorted(destination.rglob("*")):
        if target.is_symlink():
            raise ValueError("Output contains a non-regular path")
        if target.is_dir():
            continue
        path = target.relative_to(destination).as_posix()
        data = target.read_bytes()
        name = target.name.lower()
        if (name == ".env" or name.startswith(".env.") or name.endswith(".env")
                or target.suffix.lower() in {".pfx", ".p12", ".key", ".pem", ".jks", ".keystore"}):
            findings.add((path, 0, "forbidden-file"))
        for rule, pattern in PATTERNS.items():
            for hit in re.finditer(pattern, data):
                # Only generated manifest digests have an intrinsic blob exemption.
                if path == MANIFEST and data == manifest_bytes and rule in {"long-hex", "long-base64"}:
                    continue
                findings.add((path, data.count(b"\n", 0, hit.start()) + 1, rule))
    return sorted(findings)


def read_allowances(path):
    if path is None:
        return set()
    entries = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        file, sep, rule = line.rpartition(":")
        if not sep or not safe_path(file) or rule not in {*PATTERNS, "forbidden-file"}:
            raise ValueError("Invalid allow-findings entry (expected exact file:rule)")
        if line in entries:
            raise ValueError("Duplicate allow-findings entry")
        entries.add(line)
    return entries


def export(source, revision, destination, allow_findings=None):
    source = source.resolve(strict=True)
    # Check unresolved ancestors as well: never follow destination symlinks.
    destination = destination.absolute()
    if any(p.is_symlink() for p in (destination, *destination.parents)):
        raise ValueError("Refusing destination symlink")
    destination = destination.resolve()
    if destination == source or source in destination.parents:
        raise ValueError("Destination must be outside source")
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise ValueError("Destination must be new or empty")
    allowed = read_allowances(allow_findings)

    def git(*args):
        return subprocess.check_output(["git", "-C", str(source), *args], stderr=subprocess.DEVNULL)

    if Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve() != source:
        raise ValueError("Source must be the repository root")
    commit = git("rev-parse", "--verify", "--end-of-options", revision + "^{commit}").decode().strip()
    entries = {}
    for entry in git("ls-tree", "-rz", "--full-tree", commit).split(b"\0"):
        if entry:
            meta, raw = entry.split(b"\t", 1)
            entries[raw.decode("utf-8")] = meta.decode().split()
    if POLICY not in entries or entries[POLICY][0] not in {"100644", "100755"} or entries[POLICY][1] != "blob":
        raise ValueError("Missing regular export policy at selected revision")
    policy = json.loads(git("cat-file", "blob", entries[POLICY][2]))
    if (policy.get("version") != 1 or any(not isinstance(policy.get(k), list)
            or not all(isinstance(p, str) and p for p in policy[k]) for k in ("include", "exclude"))):
        raise ValueError("Invalid export policy")
    exceptions = policy.get("exclude_exceptions", [])
    if (not isinstance(exceptions, list) or not all(
            isinstance(p, str) and p.endswith(".example") and not any(c in p for c in "*?[")
            for p in exceptions)):
        raise ValueError("Invalid export policy")
    files = []
    seen = set()
    for path, (mode, kind, oid) in sorted(entries.items()):
        if not selected(path, policy):
            continue
        if not safe_path(path) or path.casefold() == MANIFEST.casefold():
            raise ValueError("Unsafe or reserved export path")
        if path.casefold() in seen:
            raise ValueError("Case-colliding export paths")
        seen.add(path.casefold())
        if mode not in {"100644", "100755"} or kind != "blob":
            raise ValueError("Refusing non-regular selected input")
        files.append((path, oid, mode))
    destination.mkdir(parents=True, exist_ok=True)
    records = []
    for path, oid, mode in files:
        content = git("cat-file", "blob", oid)
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(content)
        if mode == "100755":
            target.chmod(0o755)
        records.append({"path": path, "sha256": hashlib.sha256(content).hexdigest(),
                        "source_revision": commit})
    manifest = (json.dumps({"source_revision": commit, "files": records}, indent=2) + "\n").encode()
    (destination / MANIFEST).write_bytes(manifest)
    findings = scan(destination, manifest)
    used = {f"{path}:{rule}" for path, _, rule in findings} & allowed
    blocked = [(path, line, rule) for path, line, rule in findings if f"{path}:{rule}" not in allowed]
    for path, line, rule in findings:
        status = "accepted" if f"{path}:{rule}" in allowed else "blocked"
        print(f"{path}:{line}:{rule}: [{status}; content redacted]", file=sys.stderr)
    for entry in sorted(allowed - used):
        print(f"{entry}: unused-allow-entry", file=sys.stderr)
    if blocked or allowed - used:
        raise ValueError("Export blocked; output is an unapproved review tree")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--allow-findings", type=Path)
    args = parser.parse_args()
    try:
        export(args.source, args.revision, args.destination, args.allow_findings)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Avoid echoing exception text from OS/git/JSON, which can contain source data.
        print("Export failed (" + type(error).__name__ + "); review findings and inputs.", file=sys.stderr)
        return 1
    print("Export passed; review manifest, licenses and source before publication.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
