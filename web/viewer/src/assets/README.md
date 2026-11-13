# Bundled brand assets

The public support and sign-in pages use `rally-route.svg`: an original, static SVG road map with contour lines, a lime route, and a checkered finish flag. It contains no portrait, personal information, external fonts, or embedded raster image. Vite hashes the asset for cache invalidation.

`RallyIdentity.tsx` uses the shared road mark and welcome panel. Its text stays in HTML for responsive layout and accessibility; the artwork is decorative. `logo.png`, browser icons, Windows icons and Android launchers are generated from `brand/identity.json` by `scripts/update-brand-assets.ps1`. Tenant-uploaded logos remain separate.

The retired portrait and historical login mockups have been removed from this branch and preserved in a private archive outside the repository at the owner's request. Older Git history still contains those assets; this change does not rewrite history.
