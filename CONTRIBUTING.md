# Contributing to DeskRally

Thank you for helping. Bug reports, fixes, documentation and new features are all welcome.

## Before you start

- **Security problems** go through the private route in [SECURITY.md](SECURITY.md), not public issues.
- **Bugs.** Open an issue with the version, what you did, what you expected and what happened. Remove host
  names, addresses, tokens and screenshots of other people's screens.
- **Larger changes** (a new feature, protocol change or database migration) start best with an issue describing
  the problem and your proposed approach, so the design can be agreed before you write much code.

## Building and testing

[README.md](README.md) describes the layout and how to build each component.

Before opening a pull request:

- Run the tests for the parts you changed. To run everything, use `scripts/verify-all.ps1`. It treats a skipped
  test as a failure, so install the prerequisites it names rather than skipping them.
- Add or update tests for any change in behaviour. A test should fail without your change.
- Keep tenant isolation intact. New tenant-scoped tables need a `tenant_id`, a row-level security policy and
  tests run as the application role.
- Never commit secrets, private keys, real enrollment tokens, real host names or personal data. Use
  `example.com` and the documentation address ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

## Pull requests

- Keep each pull request to one change, and explain in the description why it is needed.
- Follow the existing style of the code you touch: `cargo fmt` and `cargo clippy` for Rust, `gofmt` for Go, and
  `npm run typecheck` and `npm test` in `web/viewer` for the console.
- Update the documentation in `docs/` when behaviour visible to users or operators changes.

## Sign your work (DCO)

Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/). Add a
`Signed-off-by` line to each commit to certify that you wrote the change or have the right to submit it:

```
git commit -s -m "Describe the change"
```

No separate contributor licence agreement is required.

## Licence

DeskRally is licensed under the [Apache License 2.0](LICENSE). By contributing, you agree that your contribution
is licensed under the same terms (section 5 of the licence).

The name "DeskRally" and its logo are trademarks and are not covered by the code licence. A fork is welcome, but
a product that is distributed under a different name must not present itself as DeskRally.
