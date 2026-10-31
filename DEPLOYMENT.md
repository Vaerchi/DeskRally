# Project website deployment

The project website is public on Cloudflare Pages using static assets only. No paid services or plan upgrades were enabled for this launch.

- Primary domain: https://deskrally.com
- Alternate domain: https://www.deskrally.com
- Pages address: https://deskrally.pages.dev
- Deployment mode: Direct Upload, with no automatic Git deployment configured.
- Source directory: `website/`; build with `python3 build.py` and deploy only `website/dist/`.

Both custom domains are active in Cloudflare, and valid HTTPS plus the expected homepage content were verified using public DNS answers. The local resolver retained older negative answers during verification; this does not affect the Pages address.

The account's existing Cloudflare Pages Git integration returned error 8000011, so it was left untouched. See `website/CLOUDFLARE.md` for deployment and future automation notes. No credentials are stored in this repository.

The GitHub repository remains private. Apache 2.0 is selected for original project work; application source migration and third-party review remain separate release-preparation tasks.
