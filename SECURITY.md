# Security policy

DeskRally is remote-access software: its agent can run as SYSTEM on other people's computers. We treat
security reports as our highest priority and thank everyone who reports responsibly.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a
vulnerability**. Only the maintainers can see the report.

Include as much of the following as you can:

- the affected component (agent, control plane, signaling, console, support client, installer, deployment
  files) and version or commit;
- what an attacker needs first (network position, an account, a role, local access);
- steps to reproduce, or a proof of concept;
- the impact you expect.

Do not put real credentials, enrollment tokens or other people's data in a report. Test only against systems you
own or are authorised to test, and never against a deployment run by someone else without their permission.

## What happens next

- We aim to acknowledge a report within five working days.
- We confirm whether the issue is real and how serious it is, and keep you informed while we fix it.
- We coordinate a disclosure date with you. By default we publish an advisory once a fixed release is available.
- With your permission, we credit you in the advisory.

## Supported versions

Security fixes go into the latest release of the agent, the server and the support client. Self-hosted operators
should stay on the latest release. The agent can update itself from a feed the operator controls.

## Scope

All code in this repository is in scope, along with the release artefacts built from it, including the default
deployment configuration in `deploy/`.

Out of scope:

- a deployment someone else operates, which is the responsibility of its operator;
- findings that need an already-compromised administrator account or server and give nothing beyond that
  access;
- the limits listed in [docs/security-model.md](docs/security-model.md#known-limits), unless you find a way
  around them that the page doesn't describe.

## How DeskRally is secured

See [docs/security-model.md](docs/security-model.md). It covers tenant isolation, sign-in, signed access grants,
consent, the audit trail, transport encryption, signed updates and how the project is tested.
