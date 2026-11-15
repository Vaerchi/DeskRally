/**
 * My Account panel (docs/01 §10 credential gap): lets the authenticated user change their own
 * password and manage their TOTP second factor from the console, without leaving the browser.
 *
 * Account credentials:
 *   - Login email: new address + current password (POST /me/email), preserving account identity.
 *   - Password change: current + new password (POST /me/password). On success the server rotates all
 *     sessions and issues a fresh session cookie; the browser stays logged in automatically.
 *   - TOTP enrollment: step-up (password for first time, current code for re-enrollment) →
 *     server returns the secret + otpauth URI → user confirms with a fresh code (POST /auth/totp/confirm).
 *
 * Both sections are deliberately thin: validation lives on the server, this panel owns only
 * in-flight state, error surfacing, and the transient secret display.
 *
 * Security notes:
 *   - SEC-001: the TOTP secret is never written to the DOM as selectable text. The primary path is
 *     a "Copy secret" button; the raw text is hidden behind a <details> reveal for manual entry only.
 *     The secret is cleared from React state immediately when the user cancels or confirmation succeeds,
 *     so it does not persist in the DOM beyond the enrollment window.
 *   - SEC-005: all three async submit handlers use a useRef inFlight latch checked synchronously
 *     before the first await, so a fast double-tap cannot queue two concurrent requests.
 */

import { type FormEvent, useCallback, useRef, useState } from "react";
import type { ConsoleApi } from "../lib/console_api";
import { MicrosoftAccountSection } from "./MicrosoftAccountSection";

export interface MyAccountPanelProps {
  api: ConsoleApi;
}

type TOTPPhase =
  | "idle"      // show the enroll button
  | "step-up"   // show password / TOTP-code step-up form
  | "pending"   // secret held in state, waiting for confirmation code
  | "confirmed"; // enrollment complete, show success (secret already cleared)

export function MyAccountPanel({ api }: MyAccountPanelProps) {
  const [newEmail, setNewEmail] = useState("");
  const [confirmEmail, setConfirmEmail] = useState("");
  const [emailPassword, setEmailPassword] = useState("");
  const [changingEmail, setChangingEmail] = useState(false);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [changedEmail, setChangedEmail] = useState<string | null>(null);
  const emailInFlight = useRef(false);

  const handleChangeEmail = useCallback(async (e: FormEvent) => {
    e.preventDefault();
    if (emailInFlight.current) return;
    setChangedEmail(null);
    if (newEmail.trim() !== confirmEmail.trim()) {
      setEmailError("Email addresses do not match.");
      return;
    }
    if (!newEmail.trim() || !emailPassword) return;
    emailInFlight.current = true;
    setChangingEmail(true);
    setEmailError(null);
    try {
      const email = await api.changeEmail(emailPassword, newEmail.trim());
      setChangedEmail(email);
      setNewEmail("");
      setConfirmEmail("");
    } catch (err) {
      setEmailError(err instanceof Error ? err.message : String(err));
    } finally {
      setEmailPassword("");
      emailInFlight.current = false;
      setChangingEmail(false);
    }
  }, [api, newEmail, confirmEmail, emailPassword]);

  // --- password change state ---
  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [changingPw, setChangingPw] = useState(false);
  const [pwError, setPwError] = useState<string | null>(null);
  const [pwSuccess, setPwSuccess] = useState(false);
  const pwInFlight = useRef(false); // SEC-005: sync latch prevents double-submit race

  // --- TOTP enrollment state ---
  const [totpPhase, setTotpPhase] = useState<TOTPPhase>("idle");
  const [totpStepUpPw, setTotpStepUpPw] = useState("");
  const [totpStepUpCode, setTotpStepUpCode] = useState("");
  const [enrolling, setEnrolling] = useState(false);
  // SEC-001: secret held only in state, never written to DOM as selectable text except via
  // an explicit <details> reveal the user must open; cleared on cancel or confirmation success.
  const [totpSecret, setTotpSecret] = useState("");
  const [totpUri, setTotpUri] = useState("");
  const [secretCopied, setSecretCopied] = useState(false);
  const [confirmCode, setConfirmCode] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [totpError, setTotpError] = useState<string | null>(null);
  const enrollInFlight = useRef(false); // SEC-005
  const confirmInFlight = useRef(false); // SEC-005

  // -----------------------------------------------------------------------
  // Password change
  // -----------------------------------------------------------------------

  const clearPwSuccess = useCallback(() => setPwSuccess(false), []);

  const handleChangePassword = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      if (pwInFlight.current) return; // SEC-005: sync guard before first await
      if (newPw !== confirmPw) {
        setPwError("New passwords do not match.");
        return;
      }
      if (newPw === "") return;
      pwInFlight.current = true;
      setChangingPw(true);
      setPwError(null);
      setPwSuccess(false);
      try {
        await api.changePassword(currentPw, newPw);
        setCurrentPw("");
        setNewPw("");
        setConfirmPw("");
        setPwSuccess(true);
      } catch (err) {
        setPwError(err instanceof Error ? err.message : String(err));
      } finally {
        pwInFlight.current = false;
        setChangingPw(false);
      }
    },
    [api, currentPw, newPw, confirmPw],
  );

  // -----------------------------------------------------------------------
  // TOTP enrollment
  // -----------------------------------------------------------------------

  const handleEnrollSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      if (enrollInFlight.current) return; // SEC-005
      enrollInFlight.current = true;
      setEnrolling(true);
      setTotpError(null);
      try {
        const result = await api.enrollTotp({
          password: totpStepUpPw || undefined,
          code: totpStepUpCode || undefined,
        });
        setTotpSecret(result.secret);
        setTotpUri(result.otpauth_uri);
        setTotpStepUpPw("");
        setTotpStepUpCode("");
        setConfirmCode("");
        setSecretCopied(false);
        setTotpPhase("pending");
      } catch (err) {
        setTotpError(err instanceof Error ? err.message : String(err));
      } finally {
        enrollInFlight.current = false;
        setEnrolling(false);
      }
    },
    [api, totpStepUpPw, totpStepUpCode],
  );

  const handleConfirmSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      if (!confirmCode || confirmInFlight.current) return; // SEC-005
      confirmInFlight.current = true;
      setConfirming(true);
      setTotpError(null);
      try {
        await api.confirmTotp(confirmCode);
        // SEC-001: clear secret from state immediately after success
        setTotpSecret("");
        setTotpUri("");
        setConfirmCode("");
        setTotpPhase("confirmed");
      } catch (err) {
        setTotpError(err instanceof Error ? err.message : String(err));
      } finally {
        confirmInFlight.current = false;
        setConfirming(false);
      }
    },
    [api, confirmCode],
  );

  const resetTotpFlow = useCallback(() => {
    setTotpPhase("idle");
    setTotpStepUpPw("");
    setTotpStepUpCode("");
    // SEC-001: always clear secret when leaving the enrollment flow
    setTotpSecret("");
    setTotpUri("");
    setConfirmCode("");
    setSecretCopied(false);
    setTotpError(null);
  }, []);

  const handleCopySecret = useCallback(() => {
    if (!totpSecret) return;
    void navigator.clipboard?.writeText(totpSecret).then(
      () => setSecretCopied(true),
      () => setSecretCopied(false),
    );
  }, [totpSecret]);

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------

  return (
    <section className="panel panel--account" data-testid="account-panel">
      <MicrosoftAccountSection api={api} />
      <form className="panel__form" onSubmit={(e) => void handleChangeEmail(e)} data-testid="change-email-form">
        <span className="panel__toolbar-title">Change login email</span>
        <p className="panel__note">
          Use the new email to sign in with your existing password. Your permissions and machines stay the same.
          Other sign-ins will be signed out; this browser stays signed in.
        </p>
        <label className="panel__toolbar-field">
          New login email
          <input type="email" className="panel__input" autoComplete="email" required maxLength={254}
            value={newEmail} disabled={changingEmail} data-testid="new-login-email"
            onChange={(e) => { setNewEmail(e.target.value); setChangedEmail(null); setEmailError(null); }} />
        </label>
        <label className="panel__toolbar-field">
          Confirm new email
          <input type="email" className="panel__input" autoComplete="off" required maxLength={254}
            value={confirmEmail} disabled={changingEmail} data-testid="confirm-login-email"
            onChange={(e) => { setConfirmEmail(e.target.value); setChangedEmail(null); setEmailError(null); }} />
        </label>
        <label className="panel__toolbar-field">
          Current password
          <input type="password" className="panel__input" autoComplete="current-password" required
            value={emailPassword} disabled={changingEmail} data-testid="email-current-password"
            onChange={(e) => { setEmailPassword(e.target.value); setChangedEmail(null); setEmailError(null); }} />
        </label>
        <button type="submit" className="panel__action" data-testid="change-email-submit"
          disabled={changingEmail || !newEmail.trim() || !confirmEmail.trim() || !emailPassword}>
          {changingEmail ? "Changing…" : "Change login email"}
        </button>
        {changedEmail && <span className="panel__toolbar-note" role="status" data-testid="change-email-success">
          Login email changed to {changedEmail}. Use it the next time you sign in.
        </span>}
        {emailError && <span className="panel__toolbar-error" role="alert" data-testid="change-email-error">
          {emailError}
        </span>}
      </form>
      {/* ---- Password change ---- */}
      <form className="panel__form" onSubmit={(e) => void handleChangePassword(e)} data-testid="change-password-form">
        <span className="panel__toolbar-title">Change password</span>
        <label className="panel__toolbar-field">
          Current password
          <input
            type="password"
            className="panel__input"
            value={currentPw}
            onChange={(e) => { setCurrentPw(e.target.value); clearPwSuccess(); }}
            autoComplete="current-password"
            disabled={changingPw}
            data-testid="current-password"
          />
        </label>
        <label className="panel__toolbar-field">
          New password
          <input
            type="password"
            className="panel__input"
            value={newPw}
            onChange={(e) => { setNewPw(e.target.value); clearPwSuccess(); }}
            autoComplete="new-password"
            disabled={changingPw}
            data-testid="new-password"
          />
        </label>
        <label className="panel__toolbar-field">
          Confirm new password
          <input
            type="password"
            className="panel__input"
            value={confirmPw}
            onChange={(e) => { setConfirmPw(e.target.value); clearPwSuccess(); }}
            autoComplete="new-password"
            disabled={changingPw}
            data-testid="confirm-password"
          />
        </label>
        <button
          type="submit"
          className="panel__action"
          disabled={changingPw || currentPw === "" || newPw === "" || confirmPw === ""}
          data-testid="change-password-submit"
        >
          {changingPw ? "Changing…" : "Change password"}
        </button>
        {pwSuccess && (
          <span className="panel__toolbar-note" role="status" data-testid="change-password-success">
            Password changed. All previous sessions were signed out; this session is now using the new credential.
          </span>
        )}
        {pwError && (
          <span className="panel__toolbar-error" role="alert" data-testid="change-password-error">
            {pwError}
          </span>
        )}
      </form>

      {/* ---- TOTP enrollment ---- */}
      <div className="panel__form" data-testid="totp-section">
        <span className="panel__toolbar-title">Authenticator app (TOTP)</span>

        {totpPhase === "idle" && (
          <>
            <p className="panel__note">
              Add or update a TOTP second factor. Your authenticator app (Google Authenticator, Authy, 1Password, etc.)
              will generate a 6-digit code at login. Required if your tenant enforces two-factor authentication.
            </p>
            <button
              className="panel__action"
              onClick={() => setTotpPhase("step-up")}
              data-testid="totp-enroll-open"
            >
              Set up authenticator
            </button>
          </>
        )}

        {totpPhase === "step-up" && (
          <form onSubmit={(e) => void handleEnrollSubmit(e)} data-testid="totp-stepup-form">
            <p className="panel__note">
              To arm a new TOTP secret you must prove your identity first. Enter your <strong>current
              password</strong> if this is your first enrollment, or your <strong>current TOTP code</strong>{" "}
              if you are replacing an existing factor.
            </p>
            <label className="panel__toolbar-field">
              Current password (first enrollment)
              <input
                type="password"
                className="panel__input"
                value={totpStepUpPw}
                onChange={(e) => setTotpStepUpPw(e.target.value)}
                autoComplete="current-password"
                disabled={enrolling}
                data-testid="totp-stepup-password"
              />
            </label>
            <label className="panel__toolbar-field">
              Current TOTP code (re-enrollment only)
              <input
                type="text"
                inputMode="numeric"
                className="panel__input"
                value={totpStepUpCode}
                onChange={(e) => setTotpStepUpCode(e.target.value)}
                autoComplete="one-time-code"
                disabled={enrolling}
                data-testid="totp-stepup-code"
              />
            </label>
            <div className="panel__actions-row">
              <button
                type="submit"
                className="panel__action"
                disabled={enrolling || (totpStepUpPw === "" && totpStepUpCode === "")}
                data-testid="totp-stepup-submit"
              >
                {enrolling ? "Generating secret…" : "Generate secret"}
              </button>
              <button
                type="button"
                className="panel__action"
                onClick={resetTotpFlow}
                disabled={enrolling}
                data-testid="totp-cancel"
              >
                Cancel
              </button>
            </div>
            {totpError && (
              <span className="panel__toolbar-error" role="alert" data-testid="totp-error">
                {totpError}
              </span>
            )}
          </form>
        )}

        {totpPhase === "pending" && (
          <>
            <p className="panel__note">
              Add this secret to your authenticator app using the <strong>Copy secret</strong> button or
              the manual reveal below, then enter a confirmation code.
            </p>
            {/* SEC-001: primary interaction is clipboard copy — secret not in DOM as selectable text */}
            <button
              className="panel__action"
              onClick={handleCopySecret}
              data-testid="totp-copy-secret"
            >
              {secretCopied ? "Copied!" : "Copy secret"}
            </button>
            <details>
              <summary>Show secret text (for manual entry into authenticator)</summary>
              <p className="panel__mono panel__code" data-testid="totp-secret">
                {totpSecret}
              </p>
            </details>
            <details>
              <summary>Show full otpauth URI (scan or import manually)</summary>
              <p className="panel__mono panel__code" data-testid="totp-uri">
                {totpUri}
              </p>
            </details>
            <form onSubmit={(e) => void handleConfirmSubmit(e)} data-testid="totp-confirm-form">
              <label className="panel__toolbar-field">
                Confirmation code (6 digits from your app)
                <input
                  type="text"
                  inputMode="numeric"
                  className="panel__input"
                  value={confirmCode}
                  onChange={(e) => setConfirmCode(e.target.value)}
                  autoComplete="one-time-code"
                  disabled={confirming}
                  data-testid="totp-confirm-code"
                />
              </label>
              <div className="panel__actions-row">
                <button
                  type="submit"
                  className="panel__action"
                  disabled={confirming || confirmCode === ""}
                  data-testid="totp-confirm-submit"
                >
                  {confirming ? "Confirming…" : "Confirm enrollment"}
                </button>
                <button
                  type="button"
                  className="panel__action"
                  onClick={resetTotpFlow}
                  disabled={confirming}
                  data-testid="totp-cancel"
                >
                  Cancel
                </button>
              </div>
              {totpError && (
                <span className="panel__toolbar-error" role="alert" data-testid="totp-error">
                  {totpError}
                </span>
              )}
            </form>
          </>
        )}

        {totpPhase === "confirmed" && (
          <>
            <p className="panel__note" role="status" data-testid="totp-confirmed">
              TOTP enrollment complete. Your authenticator app will now generate a code required at each login.
            </p>
            <button className="panel__action" onClick={resetTotpFlow} data-testid="totp-enroll-again">
              Set up again
            </button>
          </>
        )}
      </div>
    </section>
  );
}
