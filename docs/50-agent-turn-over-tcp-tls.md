# docs/50: Agent TURN over TCP and TLS

**Status (2026-10-20):** built on main and VM-accepted with UDP blocked (§6). It ships in the next agent release.

## 1. The gap

- **What the agent gets:** every session hands it the TURN servers signaling issues (`SIGNALING_TURN_URLS`). The production set is UDP 3478, TCP 3478 and TLS 443 (`deploy/.env.example`).
- **What it could use:** `webrtc-ice` 0.11 gathers relay candidates over UDP only. Its `gather_candidates_relay` logs "Unable to handle URL" for every `?transport=tcp` and `turns:` URL; the TCP/TLS branches are a TODO ported from Pion.
- **Consequence:** an agent on a network that blocks outbound UDP (common on corporate and guest networks) has no relay candidate at all. A session to it fails whenever no direct path exists, even though the browser on the other side can reach TURN over TLS on 443.
- **Network constraint:** a successful UDP TURN connection, including through NAT hairpinning, does not validate TCP/TLS fallback on networks that block UDP.

**Upstream has not fixed it.** The same TODO and the same skip are still in `webrtc-ice` 0.17.2 (2026-07-20), so an upgrade would not help.

## 2. Design

**A minimal vendored patch** (`third_party/webrtc-ice`, MIT/Apache-2.0):
- Commit ec51eb2 is the pristine 0.11.0 crate source; the next commit adds the hook, so the patch reviews as its own diff.
- `src/relay_dialer.rs`: a `RelayStreamDialer` trait and a process-wide `OnceLock` registration.
- `gather_candidates_relay`: for `proto == tcp` with a registered dialer, it asks the dialer for the TURN server connection and then runs the **unchanged** TURN client over it.
- No dialer registered: exactly upstream behaviour (negative-control test).

**The transport** (`crates/transport-webrtc/src/turn_stream.rs`):
- **`StreamConn`** presents one TCP or TLS stream as the packet `Conn` the TURN client expects, like Pion's `STUNConn`:
  - each send writes one STUN message or ChannelData frame, padding ChannelData to 4 bytes (RFC 8656 §12.5);
  - receives are delimited by the frame headers and delivered one at a time, padding removed;
  - unread bytes persist across calls, so a cancelled receive loses nothing;
  - writes go through one writer task that owns the write half and writes whole frames, so no caller can be cancelled halfway through a frame. A send only enqueues; on a full queue (256 frames) it drops the frame, as a full UDP buffer would;
  - reads go through one reader task that owns the read half and hands over whole frames (a full inbound queue is TCP backpressure, not a drop);
  - `close` only signals: both tasks stop at once, even when the server has stopped reading, and drop their halves, which closes the socket. The connection is terminal from then on;
  - a frame that is neither STUN nor ChannelData cannot be resynchronised and is an error, as is a frame larger than the caller's buffer.
- **`TurnStreamDialer`** handles `turn:…?transport=tcp` over plain TCP and `turns:…?transport=tcp` over TLS. The connect and the handshake are each bounded at 3 s.
- **`install()`** registers it once, before the first peer connection is built.

**What does not change:** the relayed address stays UDP toward the peer (RFC 8835 §3.4); only the agent-to-TURN leg moves. TURN credentials, their issuance, and the browser side are untouched.

## 3. Security

- **Trust:** TLS trust is `tls_trust::client_config()`, the same roots as every other agent HTTPS/WSS dial. If those roots cannot be loaded, `turns:` is disabled (logged) and plain TCP still works.
- **Name check:** the certificate is verified against the URL's host name, never the resolved address. A certificate for another name is refused (test).
- **Wire contents:** nothing new is sent. The TURN long-term credential already travelled in TURN messages over UDP; TLS now protects it on that leg.
- **Hostile server input:**
  - a non-TURN frame closes the relay;
  - an oversize frame is refused, never truncated;
  - frames are bounded by their 16-bit length fields.

## 4. Cost

- **Allocations:** per session the agent now makes up to three allocations instead of one: UDP, TCP and TLS, when all are issued. The extra two are short-lived TCP/TLS connections to our own coturn, released with the session.
- **Gathering time (corrected in review):** the agent gathers NON-trickle, so it sends its SDP only once every relay worker has finished.
  - Where our TURN is reachable, a TCP or TLS allocation completes in well under a second.
  - Where a firewall silently DROPS the TCP or TLS port, the session start waits up to 3 s for the connect. A handshake that stalls after connecting can add another 3 s.
  - The UDP relay on a UDP-blocked network already waited for its own retransmissions before this change.
  - Trickling the agent's candidates would remove the wait. That is a separate change to the signaling exchange.

## 5. Tests

- **Unit** (`turn_stream::tests`, 12):
  - frame layout for STUN, ChannelData and garbage;
  - write padding;
  - a stream split into single bytes;
  - wire padding, and garbage as an error;
  - a short buffer refused;
  - a cancelled receive keeps its bytes;
  - close returns at once while the server is not reading, and the connection is then terminal;
  - a pending receive ends on close;
  - on a real TCP socket, close CLOSES the socket while the conn is still referenced (both halves are owned by tasks that exit on close). The same holds with the inbound queue full and a malformed frame behind it;
  - a slow reader gets 100 frames whole and in order;
  - a full queue drops instead of blocking.
- **Integration** (`tests/turn_tcp.rs`), against the `turn` crate's TURN server, served over the same framing:
  - TCP and TLS allocations relay datagrams **both ways** with a UDP peer, past the client's switch from Send indications to ChannelData (asserted), using never-aligned lengths;
  - TLS: a wrong-name certificate is refused, and missing roots fail cleanly;
  - **the patched ICE path:** an agent configured with only `turn:…?transport=tcp` gathers a relay candidate on the TURN server's relay address.
- **Negative control** (`tests/turn_tcp_unregistered.rs`, a separate binary because the hook is process-global): with no dialer, the same configuration yields no relay candidate.
- **Mutants:**
  - disabling the gather hook is killed;
  - not stripping read-side padding is killed;
  - `close` not signalling is killed by both close tests;
  - the reader task ignoring close while reading is killed (socket test);
  - an unguarded framing-error send is killed by the full-queue socket test. Its first version sent one frame too many and never reached the error path: that "kill" was misread from a log grep, and Codex caught it;
  - removing write-side padding is **equivalent** for this client, because the `turn` crate's `ChannelData::encode` already pads. The padding is kept as defence in depth and has its own unit test.

## 6. VM acceptance with outbound UDP blocked: PASSED (2026-10-20)

**Setup:**
- coturn 4.6.3 (TCP 3478, TLS 5349, lab CA) on a Linux test server;
- test signaling issuing ONLY TCP/TLS TURN;
- the acceptance VM with ALL outbound UDP blocked. A UDP STUN request got no reply there, while the host got one.

**Results:**
- **1.3.6 (negative control):** negotiation timed out; coturn saw no connection from the VM.
- **9d94ec5:** 893 VP8 packets in 20 s. coturn logged TCP and TLS connections from the VM, and a TLSv1.3 allocation with that session (ALLOCATE, CREATE_PERMISSION and CHANNEL_BIND all succeeded).

**Still unmeasured:** production coturn on `turns:…:443` itself. The lab used port 5349 with a lab CA; production uses a public certificate and the same code path.