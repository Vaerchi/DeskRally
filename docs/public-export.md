# Public source export

The exporter produces a history-free review tree from one immutable commit. Only
paths selected by `packaging/public-export.json` at that commit are copied;
exclusions win. Include entries are exact paths or directory prefixes ending in
`/`. Exclusions also support case-sensitive shell globs. The policy's `notes`
records a decision for every current top-level directory. New top-level paths
are denied until reviewed. Selected symlinks and submodules are refused.

Run these commands in a development environment with Python 3 and Git available:

```sh
python -m unittest discover -s scripts -p test_export_public.py
python scripts/export-public.py --source . --revision <reviewed-commit> --destination <new-directory-outside-repository>
```

The destination must be absent or empty and outside the repository. The exporter
never copies history, runs source code, installs dependencies, signs or publishes.
It reads the policy and selected blobs through Git, not the working tree.
Use the reviewed exporter and inventory scanner together from this checkout.

`EXPORT-MANIFEST.json` records each exported file's path, SHA-256 and source
commit, without absolute source paths. Files retain their source bytes. The
manifest itself is generated metadata and is not included in its own hash list.
Only its generated digests are exempt from long-blob checks.

The output tree is scanned using all release inventory patterns plus private
machine/path, literal credential, credential URL, long blob and forbidden filename
rules. Reports contain `file:line:rule` and a fully redacted preview; matching
values are never printed. A nonzero exit means the tree is unapproved. Failed
trees remain available for review; use a fresh empty destination on each retry.
The manifest is an inventory, not an approval certificate.

For a known benign finding, review the exact output file, then put one exact
`relative/path:rule` per line in a separate reviewed allow-findings file. Blank
lines and lines beginning with `#` are ignored. Wildcards are not supported.
Pass it with `--allow-findings <review-file>`. An allowance accepts all hits of
that rule in that one file; it must match at least one hit or the export fails.
Review every occurrence before accepting a pair. The public update key may need
`packaging/update-signer-pubkey.hex:long-hex`; this is not preapproved by the tool.

Before publication, review the complete diff, inventory, accepted findings,
dependency notices and license coverage. Scans are heuristic and can miss
secrets or flag benign fixtures, lockfile hashes and embedded assets. Do not
bulk-accept findings to obtain a passing exit status.

## Outstanding publication gates

Existing documentation is deliberately denied until the reviewed wave A/B/C
decision list is made available inside this worktree. Add each approved doc as an
exact path; never include a docs prefix, waves D/E, or INTERNAL documents.
All fixture/testdata directories are conservatively excluded pending review.
Build completeness and source license coverage also require review: this tool
does not grant Apache-2.0 rights or replace third-party licenses. A root Apache-2.0
license and any required notices must be provided and reviewed before publishing.
