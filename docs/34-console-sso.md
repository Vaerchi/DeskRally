# Console single sign-on (Microsoft Entra ID), phase 1

Phase 1 lets console users sign in with Microsoft Entra ID through their organization's own app
registration. Password + TOTP sign-in keeps working unchanged.

Phase 1 does not include:
- "require SSO" (password login can't be turned off yet);
- desktop-client SSO. The desktop app blocks navigation to Microsoft's pages, so Test sign-in, Link
  and "Sign in with Microsoft" are disabled there with a note; use the console in a browser;
- SAML;
- other providers.

The data layer, Entra client, handlers and UI were implementation-reviewed.

## Operator prerequisites (per deployment)
- **Migration 0057** (`controlplane migrate`) adds:
  - `tenant_oidc`;
  - `app_user.oidc_issuer` / `oidc_subject`;
  - `user_session.login_method` / `oidc_connection_version`;
  - `oidc_login_attempt` and `oidc_pending_mfa`.
- **`CP_TENANT_HOST_SUFFIX=.example.com`** in the control plane's environment. The SSO routes are
  mounted ONLY when it is set. Every tenant's host must be `<slug>` + suffix, and the redirect URI is
  built from it, never from the request.
- **`TOTP_ENCRYPTION_KEY`** must already be set; it also encrypts the client secret and the PKCE
  verifier.
- **Caddy:** no change. The callback is `https://<slug>.example.com/cp/auth/oidc/callback` under the
  existing `/cp` proxy, and the CP sets `no-store` and `no-referrer` on it.

## Tenant owner setup (Entra admin center)
1. **App registrations → New registration.**
   - Single tenant ("Accounts in this organizational directory only").
   - Redirect URI (Web): the value shown in DeskRally → Security → Single sign-on, e.g.
     `https://console.example.com/cp/auth/oidc/callback`.
2. **Certificates & secrets → New client secret.** Copy its value.
3. **Optional, to let Entra MFA satisfy DeskRally's 2FA:** the ID token must carry `amr`.
   - `amr` is NOT in the portal's "Add optional claim" picker. Add it in the app's **Manifest**, under
     `optionalClaims.idToken`: `{"name": "amr", "source": null, "essential": false,
     "additionalProperties": []}`.
   - Then run **Test sign-in** in a browser. The return URL ends `amr_present=true` or `false`.
   - **Guest accounts** (for example a personal Microsoft account added to the directory) usually get
     no `amr`: their MFA happens at their home provider. They keep entering the DeskRally code. That
     is expected, and the code page says why (`?why=no_amr`).
4. **In DeskRally → Security → Single sign-on (owner, authenticator code required):**
   - Directory (tenant) ID;
   - Application (client) ID;
   - the client secret;
   - Enabled;
   - optionally "Trust Entra MFA".
5. **Test sign-in** (owner) verifies the whole flow without signing in or linking.
6. **Each user** links their Microsoft account under **My account → Microsoft sign-in → Link** (needs an
   authenticator code). After that, "Sign in with Microsoft" appears on the tenant's login page.

## Security properties (what the code enforces)
- **Linking:** a user links an identity only while signed in with password + TOTP. Email is never used
  to choose an account; the binding is `(issuer, sub)`.
- **Fixed endpoints:** Entra endpoints are fixed per tenant GUID. There is no discovery fetch, the
  HTTP client is pinned to `login.microsoftonline.com`, it follows no redirects, and bodies are capped.
- **ID-token checks:**
  - RS256 only;
  - iss, aud, azp, nonce, exp/iat/nbf (2 min skew), tid and ver 2.0 are checked;
  - PKCE S256, single-use state bound to an HttpOnly attempt cookie.
- **One MFA policy for both login methods:** an enrolled TOTP or the tenant's "require 2FA" requires
  TOTP after Microsoft sign-in, unless "Trust Entra MFA" is on AND the token's `amr` says `mfa`.
- **Fencing:**
  - Changing the connection bumps its version, revokes OIDC sessions, and clears links when the
    client or tenant id changes.
  - Disable, unlink, user disable and credential changes are fenced against in-flight logins and links
    by row locks in one global order.
  - Stale authority is re-checked at commit.
- **IdP-side changes do not propagate in phase 1:** a session lives until it expires (12 h max / 30 min
  idle). To cut access at once, disable the user in DeskRally.
