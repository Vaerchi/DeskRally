"""Offline release inventory. Reports locations, never matching secret values; does not publish/copy.

Only tracked application inputs from the selected revision are inspected. Internal planning/history,
operator scripts and local state are excluded by construction. Findings require human disposition;
zero matches is not proof that a source tree is safe to publish.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOTS = ("agent/", "crates/", "control-plane/", "server/", "web/viewer/",
         "clients/windows/", "android/", "third_party/", "packaging/")
TOP = {"Cargo.toml", "Cargo.lock"}
PATTERNS = {
    "private-key": rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----",
    "credential-token": rb"\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16})\b",
    "personal-identity": rb"(?i)\b(?:nuckols|vaerchi|edgar|colosolutions|fmrteam)\b",
    "personal-workspace": rb"(?i)(?:[CF]:[/\\](?:Users|DeskRally|Visual Studio Projects)|/home/(?!runner\b)[a-z0-9_-]+/)",
    "deployment-host": rb"(?i)(?:main|loam|vc|turn)\.deskrally\.com|bridge\.computercontrolservice\.com",
    "private-network": rb"\b(?:192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b",
    "credential-assignment-review": rb"(?i)(?:password|secret|token|seed)\s*[:=]\s*[\"'][^\"'\r\n]{8,}[\"']",
}
FORBIDDEN_SUFFIXES = {".pfx", ".p12", ".key", ".exe", ".dll", ".pdb", ".zip", ".tar", ".gz"}


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def objects(root, entries):
    # One sequential git process instead of starting a process per file.
    with subprocess.Popen(["git", "-C", str(root), "cat-file", "--batch"],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE) as reader:
        try:
            for entry in entries:
                if not entry:
                    continue
                meta, raw_path = entry.split(b"\t", 1)
                mode, kind, oid = meta.decode().split()
                path = raw_path.decode("utf-8")
                content = b""
                if (path in TOP or path.startswith(ROOTS)) and kind == "blob":
                    reader.stdin.write(oid.encode() + b"\n")
                    reader.stdin.flush()
                    header = reader.stdout.readline().split()
                    if len(header) != 3 or header[1] != b"blob":
                        raise RuntimeError("Cannot read selected blob: " + path)
                    content = reader.stdout.read(int(header[2]))
                    if reader.stdout.read(1) != b"\n":
                        raise RuntimeError("Truncated git object: " + path)
                yield path, mode, kind, oid, content
        finally:
            reader.stdin.close()
            reader.wait()


def inventory(root, revision):
    commit = git(root, "rev-parse", "--verify", revision + "^{commit}").decode().strip()
    tracked = git(root, "ls-tree", "-rz", "--full-tree", commit).split(b"\0")
    selected, excluded = [], []
    for path, mode, kind, oid, content in objects(root, tracked):
        if path not in TOP and not path.startswith(ROOTS):
            excluded.append(path)
            continue
        # Read immutable git objects, never local ignored/untracked files or symlink targets.
        findings = []
        if mode not in ("100644", "100755") or kind != "blob":
            findings.append({"kind": "non-regular-file", "line": 0})
        if Path(path).suffix.lower() in FORBIDDEN_SUFFIXES:
            findings.append({"kind": "binary-or-key-review", "line": 0})
        for label, pattern in PATTERNS.items():
            for match in re.finditer(pattern, content):
                findings.append({"kind": label, "line": content.count(b"\n", 0, match.start()) + 1})
        selected.append({"path": path, "mode": mode, "git_blob": oid,
                         "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content),
                         "findings": findings})
    return {"revision": commit, "selected_files": len(selected), "excluded_files": len(excluded),
            "files_requiring_review": sum(bool(f["findings"]) for f in selected),
            "files": selected, "excluded_paths": excluded,
            "publication_approved": False,
            "limitations": "Heuristic inventory only. No credential values are emitted. Fixtures may match; classify each finding. Binary metadata, rights, dependency notices, history, runtime tests and rotation remain separate gates."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--revision", default="HEAD")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = inventory(args.source, args.revision)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("revision", "selected_files", "excluded_files", "files_requiring_review", "publication_approved")}))


if __name__ == "__main__":
    main()
