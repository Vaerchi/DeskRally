# Private release preparation

## Completed initial batch

- New private repository with fresh history.
- Original project website and visitor documentation prepared and moved to the separate DeskRally-Website repository.
- Public user guides and technical references are maintained by the website, using reviewed snapshots of the canonical product documentation.

## Before importing application code

- Select a stable current source revision and export only explicit source/build/test paths.
- Exclude internal handoffs, private audit records, personal screenshots, local secrets, workspaces, build output, and existing Git history.
- Preserve required third-party licenses and notices. Remove unnecessary vendored CI token assignments.
- Replace personal paths and deployment defaults with portable configuration or documentation examples.
- Review certificate subjects and publisher policy carefully: make identity portable without disabling signature verification or other trust checks.
- Establish what to do with deployment-specific public keys. Private signing material must never enter this repository.
- Add working generic build/setup instructions and run the application checks against the exported tree.
- Scan source and generated distributions for secrets and identifying information before each migration batch.

## Before publishing the product source

- Complete the application migration and verify the published source can be built as documented.
- Rotate the exposed historical lab credential and address any reused credentials. A fresh repository does not revoke credentials.
- Apply the selected Apache 2.0 license to original work and preserve required third-party attribution; complete the dependency review in `LICENSING.md`.
- Establish a private security-reporting route and contribution guidance.
- Review the exported source and release assets, then give the website the public product repository URL.
- Coordinate the website documentation snapshot with the selected product release.

The product repository is private during release preparation. The separate website publishes the reviewed introductory and technical documentation. Application source migration continues through reviewed batches.
