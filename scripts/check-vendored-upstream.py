#!/usr/bin/env python3
"""Report upstream releases newer than the base of each vendored crate (third_party/UPSTREAM.json).

DeskRally carries modified copies of some crates, so upstream security fixes do not arrive through cargo. Run this
periodically (it needs network access to crates.io) and before each release. Exit codes:
  0  every vendored crate is on its newest upstream release
  1  at least one newer upstream release exists (review it; see the crate's DESKRALLY-CHANGES.md)
  2  the check could not run (bad manifest, network or API error)

Also run `cargo audit` (RustSec) and read the advisories for these crate names: a vendored copy is not covered by
`cargo audit`'s version matching, because it builds from a path.
"""
import json
import sys
import urllib.request
from pathlib import Path

USER_AGENT = "deskrally-vendored-upstream-check (https://github.com/Vaerchi/DeskRally)"


def parse_version(text: str) -> tuple:
    core = text.split("+", 1)[0].split("-", 1)[0]
    return tuple(int(p) for p in core.split("."))


def upstream_versions(name: str) -> list:
    req = urllib.request.Request(f"https://crates.io/api/v1/crates/{name}/versions",
                                 headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    out = []
    for v in data.get("versions", []):
        num = v.get("num", "")
        if v.get("yanked") or "-" in num.split("+", 1)[0]:
            continue  # skip yanked and pre-releases
        out.append(num)
    return out


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        manifest = json.loads((root / "third_party" / "UPSTREAM.json").read_text(encoding="utf-8"))
        crates = manifest["crates"]
    except (OSError, ValueError, KeyError) as e:
        print(f"cannot read third_party/UPSTREAM.json: {e}")
        return 2
    behind = False
    for c in crates:
        name, base = c["name"], c["base_version"]
        try:
            newer = sorted((v for v in upstream_versions(name) if parse_version(v) > parse_version(base)),
                           key=parse_version)
        except Exception as e:  # network, HTTP or JSON error: say so, never report "up to date"
            print(f"{name}: could not query crates.io: {e}")
            return 2
        if newer:
            behind = True
            print(f"{name}: base {base}; newer upstream: {', '.join(newer)} (review, then rebase; see {c['change_log']})")
        else:
            print(f"{name}: base {base} is the newest upstream release")
    return 1 if behind else 0


if __name__ == "__main__":
    sys.exit(main())
