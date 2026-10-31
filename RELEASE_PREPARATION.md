# Private release preparation

## Completed initial batch

- New private repository with fresh history.
- Original project website and visitor documentation, written without private operational notes.
- Portrait-free rally artwork and synthetic console illustration.
- Website links checked; responsive rendering and documentation search checked.

## Before importing application code

- Select a stable current source revision and export only explicit source/build/test paths.
- Exclude internal handoffs, private audit records, personal screenshots, local secrets, workspaces, build output, and existing Git history.
- Preserve required third-party licenses and notices. Remove unnecessary vendored CI token assignments.
- Replace personal paths and deployment defaults with portable configuration or documentation examples.
- Review certificate subjects and publisher policy carefully: make identity portable without disabling signature verification or other trust checks.
- Establish what to do with deployment-specific public keys. Private signing material must never enter this repository.
- Add working generic build/setup instructions and run the application checks against the exported tree.
- Scan source and generated distributions for secrets and identifying information before each migration batch.

## Before making the repository or site public

- Complete the application migration and verify the published source can be built as documented.
- Rotate the exposed historical lab credential and address any reused credentials. A fresh repository does not revoke credentials.
- Select the project license and preserve required attribution.
- Establish a private security-reporting route and contribution guidance.
- Review all pages and exported assets, then add the public GitHub URL to the website.
- Configure the project apex/www domains deliberately; avoid changing an existing application route.
- Enable indexing for the final public website if desired.

The website and repository remain private during this preparation. No historical private documentation or application source is included in this initial batch.
