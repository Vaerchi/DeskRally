# Cloudflare Pages hosting

The project website is a static site suitable for Cloudflare Pages Free. It uses no Pages Functions, paid databases, or other paid runtime services. The GitHub repository can remain private.

## Selected deployment mode: Direct Upload

The reviewed website is authorized for public publication; the GitHub repository stays private. Cloudflare rejected its Git integration with error 8000011, so this project uses Direct Upload instead. Do not reinstall or remove the account's Git integration as a workaround: other sites may use it.

Build with `python3 build.py`, then deploy the generated `dist/` with Wrangler using an authorized Cloudflare credential supplied through the process environment. Never place the token in source, command arguments, build output, or documentation. No automatic GitHub deployment is configured.

A Direct Upload project cannot later be converted to a Git-integrated project. Future automation can use Wrangler from an appropriately secured CI workflow, or a new Git-integrated Pages project after the account's installation problem has been resolved.

The current public site permits indexing. The `404.html` remains non-indexable. Any future private preview needs separate access protection; do not assume that a private GitHub repository or a noindex directive is authentication.

## Git integration reference (not configured for this project)

In Cloudflare, choose Workers & Pages, create a Pages application, and connect the private DeskRally GitHub repository. Grant the GitHub integration access only to this repository if possible.

Use these build settings:

| Setting | Value |
| --- | --- |
| Production branch | `main` |
| Framework preset | None |
| Root directory | `website` |
| Build command | `python3 build.py` |
| Build output directory | `dist` |

The generator uses only Python's standard library. No environment secrets are needed to build the website. Do not copy application credentials or signing material into Pages.

`wrangler.jsonc` declares the static output and a suggested project name. If that name is unavailable, choose another name in the dashboard and update the configuration to match. Configure the Git integration before using Wrangler for manual deployments; do not create a separate Direct Upload project if Git integration is wanted.

## Keep the draft private

A private GitHub repository does not make a Pages deployment private. Before publishing a draft, configure Cloudflare Access for its production hostname and preview hostnames, allowing only the intended reviewer. Preview-only protection does not protect the production `pages.dev` hostname. Check every enabled hostname while signed out.

If indexing restrictions are added to a draft, they are indexing preferences, not authentication. Keep the existing private review preview until protected Cloudflare hosting has been verified.

The `_headers` file is copied into `dist/` and adds static-response security headers. The generator also emits a branded `404.html`, so missing documentation paths are not silently treated as the homepage.

## Project domains

After the protected Pages deployment has been verified, add `deskrally.com` and `www.deskrally.com` through the Pages custom-domain flow. Use the records Cloudflare supplies. The apex domain must use a Cloudflare-managed zone for Pages apex hosting. Inspect existing records before changing them; application subdomains must remain untouched.

If the final public website uses the apex as its canonical address, configure a permanent redirect from `www` after both hostnames are working. Keep draft Access rules in place until the website is intentionally released publicly.

## Public launch checks

- Confirm repository access and website access independently.
- Review visitor content, assets, and generated output for identifying information or secrets.
- Add a GitHub link only when the public source repository is ready.
- Remove draft indexing restrictions only when public indexing is intended. The current public site allows indexing; check HTML metadata, `robots.txt`, and headers before changing that behavior.
- Keep analytics and optional third-party content disabled unless deliberately added and documented.
- Verify TLS, root and www routing, documentation paths, search, static headers, and real 404 responses after deployment.
- Review the account's Free plan and applicable limits without enabling a paid plan.

Official references:

- https://developers.cloudflare.com/pages/get-started/git-integration/
- https://developers.cloudflare.com/pages/platform/limits/
- https://developers.cloudflare.com/pages/configuration/headers/
- https://developers.cloudflare.com/pages/configuration/custom-domains/
- https://developers.cloudflare.com/pages/configuration/preview-deployments/
