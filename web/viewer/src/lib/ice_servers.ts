/**
 * Static ICE servers for a session — now **none**.
 *
 * The signaling server issues this session's STUN/TURN in its `ice_servers` message, which arrives
 * before `brokered` and therefore before ICE gathering begins (see `transport.ts`). A self-hosted
 * deployment configures `SIGNALING_STUN_URLS` / `SIGNALING_TURN_URLS`, and those are the servers
 * that should be used.
 *
 * This previously returned Google's public STUN for any non-loopback URL. Two reasons that is the
 * wrong default now: it sends every session's connectivity checks to a third party the operator
 * never chose, and it masked a missing deployment configuration as a working one — the connection
 * succeeded via public STUN right up until it met a NAT that needed the TURN nobody had noticed was
 * absent.
 */
export function iceServersFor(_signalingUrl: string): RTCIceServer[] {
  return [];
}
