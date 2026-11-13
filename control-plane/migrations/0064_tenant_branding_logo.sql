-- tenant_branding.logo_data_uri — an optional per-tenant logo shown in the console header, stored as a
-- validated raster-image data URI (docs/01 §9, "custom logos"). Empty = no logo (use the product
-- default/text name). Additive, forward-only: a NOT NULL default keeps existing rows valid with no
-- backfill, same posture as 0028's text columns. The control plane validates the value
-- (NormalizeBranding/ValidateLogoDataURI) to a bounded raster data URI before it is ever stored, so the
-- column never holds script-bearing SVG or arbitrary text. RLS is inherited from the table (0028).
ALTER TABLE tenant_branding ADD COLUMN logo_data_uri text NOT NULL DEFAULT '';
