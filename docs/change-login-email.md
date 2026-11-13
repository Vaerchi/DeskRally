# Change a login email

In **My account**, use **Change login email**:

1. Enter the new email address and enter it again to confirm.
2. Enter your current password.
3. Select **Change login email**. The confirmation shows the address to use for
   future sign-ins. Your password stays the same.

This updates the existing account. Its tenant, user ID, roles, authenticator app,
machines, and historical activity remain attached to that account. No tenant
recreation or agent re-enrollment is needed. Other sign-ins are signed out; the
browser performing the change receives a replacement session.

The address cannot already belong to another user in the same tenant. The same
address in a different tenant is allowed. Email matching follows the existing
case-sensitive login convention. This feature changes the login identifier;
it does not send email or verify ownership of a mailbox. Check the address before
saving. Accounts without a local password cannot use this password-based flow.

## API and security

`POST /me/email` accepts `current_password` and `new_email`. The authenticated
principal supplies the tenant and user; callers cannot specify another account.
The existing CSRF, authentication, tenant and IP policy middleware applies.
Password verification has a separate throttle budget from login.

Storage compares the credential version observed during password verification
before committing the email and a new credential epoch atomically. A concurrent
credential change rejects the stale operation. Duplicate or rejected changes
leave both the email and credential epoch intact. No schema migration is needed.

The password hash is retained, all prior login sessions are revoked, and the
replacement session and CSRF cookies use the new credential version. A login
that raced the change with old account data cannot use its stale session.
An `auth.email_changed` audit event records the old and new addresses without
recording the password. Authentication failure and post-commit operational
errors are reported separately so the caller knows if the address already changed.

The browser form is covered by success, duplicate, password rejection, typo,
double-submit, expired-session, and narrow-screen tests. Go tests exercise real
middleware and PostgreSQL under the restricted application role, including
tenant isolation, credential races, and preservation of account identity.

## Recovery and operation

If an error explicitly says the email **was changed**, sign in using the new
address and existing password. For a forgotten password, use the existing
administrator-assisted password-reset process; do not create a replacement
tenant or edit password hashes directly.

This feature is served by the website and the existing desktop web shell. It
does not require a new agent installer or code-signing certificate.
