-- 0080 — "Remember this app for 30 days" for Microsoft (OIDC) sign-in.
--
-- Until now only the password form could issue a remembered session (0053, IssueRemembered): a "Sign in
-- with Microsoft" login always got an ordinary 12 h / 30 min idle session, even in the Windows Hello
-- unlocked desktop app with the box ticked (Ed, 2026-11-09: Hello still asked him to sign in).
--
-- The choice is made at /auth/oidc/start and has to survive the round trip to Microsoft. It is kept on
-- the server-side login attempt, never in a parameter the callback could be handed: the attempt is
-- bound to the browser's HttpOnly attempt-key cookie and to the state, and consumed once. The pending
-- MFA step (oidc_pending_mfa) reads it from the attempt it references, so it needs no column.
--
-- Only a sign-in may ask for it: a link or test attempt runs inside an existing session and issues none.
ALTER TABLE oidc_login_attempt ADD COLUMN IF NOT EXISTS remember boolean NOT NULL DEFAULT false;

ALTER TABLE oidc_login_attempt DROP CONSTRAINT IF EXISTS oidc_attempt_remember_login_only;
ALTER TABLE oidc_login_attempt ADD CONSTRAINT oidc_attempt_remember_login_only
    CHECK (NOT remember OR mode = 'login');

COMMENT ON COLUMN oidc_login_attempt.remember IS
    'The sign-in asked for a remembered session (30 days absolute, 7 days idle), as the password form''s '
    'remember_device does. Set at /auth/oidc/start only for the Windows Hello unlocked desktop app; '
    'login attempts only (0080).';
