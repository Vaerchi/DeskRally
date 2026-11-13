import type { FetchLike } from "./controlplane";

/** App-scoped auth boundary. An old request must not sign out a newer login. */
export class AuthSession {
  private generation = 0;
  private expired = false;

  constructor(private readonly onExpired: () => void, private readonly fetchImpl: FetchLike = (input, init) => fetch(input, init)) {}

  get epoch(): number { return this.generation; }
  isCurrent(epoch: number): boolean { return !this.expired && epoch === this.generation; }

  expire(): void {
    if (this.expired) return;
    this.expired = true;
    this.generation++;
    this.onExpired();
  }

  signedIn(): void {
    this.generation++;
    this.expired = false;
  }

  readonly fetch: FetchLike = async (input, init) => {
    const epoch = this.generation;
    const response = await this.fetchImpl(input, init);
    // A rejected login is a form error, not expiry of an authenticated session. Inside a session, a
    // wrong code or password on a step-up (TOTP enroll/confirm, password change, /auth/step-up, reset
    // link) is 403 from the control plane, so only a real session failure reaches the 401 below.
    const path = new URL(input, "http://local.invalid").pathname;
    const publicRequest = ["/auth/login", "/auth/logout", "/auth/password/redeem", "/grant/pubkey"]
      .some((suffix) => path.endsWith(suffix));
    if (!publicRequest && response.status === 401 && this.isCurrent(epoch)) this.expire();
    return response;
  };
}
