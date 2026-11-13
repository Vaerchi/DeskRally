# DeskRally

DeskRally is self-hosted remote support and remote access software. A Windows agent streams the desktop
over WebRTC to a browser console. The server side has a control plane, a signaling service, a relay and
a TURN server, and it runs in Docker or natively on Linux or Windows.

## Layout

| Path | What it is |
|------|------------|
| `crates/` | Rust workspace: wire protocol, crypto, agent core, Windows agent, WebRTC transport |
| `agent/` | Backstage: the agent's headless shell and tooling, carried over the session transport |
| `third_party/` | Modified copies of `webrtc-ice` and `webrtc-sctp`; see each `DESKRALLY-CHANGES.md` |
| `control-plane/` | Go control plane: accounts, tenants, machines, sessions, audit (PostgreSQL with row-level security) |
| `server/` | Go signaling and relay services |
| `web/viewer/` | Browser console and viewer (React, TypeScript, Vite) |
| `clients/windows/` | Windows attended-support client |
| `android/` | Android technician app (Trusted Web Activity wrapping the console) |
| `packaging/` | MSI and release packaging |
| `deploy/` | Docker Compose, Caddy, TURN and native-install deployment files |
| `docs/` | Design and operations documents; `docs/guides/` has the server and client deployment guides |

## Building

- **Agent (Windows):** `cargo build --release -p rmt-agent-windows`. It links libvpx (video) and libopus
  (audio) statically: `vcpkg install libvpx:x64-windows-static opus:x64-windows-static`. Elsewhere the
  distro libopus serves (`libopus-dev`, with `OPUS_LIB_DIR` set to the directory holding `libopus.a`).
  libvpx must be **1.16.0** on every platform: the bindings are verified against it and a test refuses any
  other encoder ABI, so build it from source where the distro ships another (`VPX_LIB_DIR`,
  `VPX_INCLUDE_DIR`). The Windows-only crates compile empty off Windows.
- **Server:** `go build ./...` in `control-plane/`, `server/signaling/` and `server/relay/`.
- **Console:** `npm ci && npm run build` in `web/viewer/`.

Tests: `cargo test --workspace`, `go test ./...` in each Go module, and `npm test` in `web/viewer/`.
The control plane's PostgreSQL tests run against the database named by `TEST_DATABASE_URL`. Signaling's
real-control-plane tests need the fixture binary first: `go build -o cptestfixture ./cmd/cptestfixture` in
`control-plane/` (name it `cptestfixture.exe` on Windows).

To deploy a server, start with `docs/guides/server-deployment.md`.

## Security and contributing

How DeskRally is secured, and its current limits: `docs/security-model.md`. To report a vulnerability privately,
see `SECURITY.md`. To contribute, see `CONTRIBUTING.md`.

## License

Apache License 2.0; see `LICENSE` and `NOTICE`. Third-party components keep their own licenses.
"DeskRally" and its logo are trademarks and are not licensed by the Apache License.
