package main

// Session-ticket verification (M2 / ADR-002 session brokering).
//
// The control plane's POST /sessions mints an Ed25519-signed session ticket
// (control-plane/ticket.go); the viewer presents it in `connect_request`, and this file verifies
// it before the broker pairs the peers. The signature covers a canonical v1 binary preimage.
//
// !!! The canonical bytes built here MUST stay BYTE-IDENTICAL to control-plane/ticket.go's
// ticketSigningBytes (domain tag "RMTTICKETv1\x00", u8 version, u32 big-endian length-prefixed
// strings, i64 big-endian times). Both modules pin the SAME golden fixture
// (ticket_test.go ↔ control-plane/ticket_test.go), so any drift breaks a test loudly. !!!

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// ticketDomainTag is the 12-byte domain-separation tag: ASCII "RMTTICKETv1" + one 0x00 byte.
// Distinct from the backstage-grant tag ("RMTGRANTv1\x00\x00") by construction.
var ticketDomainTag = []byte("RMTTICKETv1\x00")

// ticketVersion is the legacy control version; observers use version 2.
const ticketVersion = 1

// ticketMaxClockSkewMs bounds how far ahead of this server's clock a ticket may claim to have been
// issued. Without it, a control plane (or a clock-skewed one) could mint a ticket dated far in the
// future whose exp_ms is correspondingly far away, stretching the 2-minute window arbitrarily.
const ticketMaxClockSkewMs = 60_000

// TicketClaims mirrors the control plane's TicketClaims JSON exactly.
type TicketClaims struct {
	V             int    `json:"v"`
	SessionID     string `json:"session_id"`
	TechnicianID  string `json:"technician_id"`
	TenantID      string `json:"tenant_id"`
	DeviceID      string `json:"device_id"`
	IssuedAtMs    int64  `json:"iat_ms"`
	ExpiresAtMs   int64  `json:"exp_ms"`
	Access        string `json:"access,omitempty"`
	accessPresent bool
}

// Preserve field presence so even an explicit empty access is refused on V1.
func (c *TicketClaims) UnmarshalJSON(data []byte) error {
	type plain TicketClaims
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*c = TicketClaims(decoded)
	// encoding/json matches struct fields case-insensitively, so "Access" or "ACCESS" also fill
	// Access: presence must be detected the same way (Codex signaling review v1).
	for key := range fields {
		if strings.EqualFold(key, "access") {
			c.accessPresent = true
		}
	}
	return nil
}

// SignedSessionTicket mirrors the control plane's envelope: claims + hex Ed25519 signature over
// their canonical v1 preimage.
type SignedSessionTicket struct {
	Claims TicketClaims `json:"claims"`
	Sig    string       `json:"sig"`
}

// ticketSigningBytes rebuilds the canonical v1 preimage — the byte-identical twin of
// control-plane/ticket.go's ticketSigningBytes.
func ticketSigningBytes(c TicketClaims) []byte {
	buf := append([]byte{}, ticketDomainTag...)
	buf = append(buf, byte(c.V))
	lp := func(s string) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		buf = append(buf, l[:]...)
		buf = append(buf, s...)
	}
	lp(c.SessionID)
	lp(c.TechnicianID)
	lp(c.TenantID)
	lp(c.DeviceID)
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(c.IssuedAtMs))
	buf = append(buf, t[:]...)
	binary.BigEndian.PutUint64(t[:], uint64(c.ExpiresAtMs))
	buf = append(buf, t[:]...)
	if c.V == 2 {
		lp(c.Access)
	}
	return buf
}

// errTicketInvalid is the single verification failure — callers report a generic rejection so a
// probing client learns nothing about WHICH check failed; the detail goes to the server log only.
var errTicketInvalid = errors.New("ticket invalid")

// verifyTicket checks a connect_request's ticket: present, version 1, a valid signature over the
// canonical bytes, unexpired at nowMs, carrying a tenant binding, and bound to the requested
// target device. Returns a wrapped errTicketInvalid describing the failing check (for logs), nil
// when the ticket is good.
//
// The TENANT binding is load-bearing, not decoration. `device_id` is only per-tenant unique in the
// control plane's schema, so a ticket minted by tenant B for a device id owned by tenant A would
// otherwise authorize brokering to A's agent. Two things close that:
//
//   - the control plane makes `machine.device_id` GLOBALLY unique and mints it server-side at
//     enrollment redemption (migrations/0008_machine_device_unique.sql, handleRedeemEnrollment),
//     so only the tenant that actually owns an agent can ever mint a ticket naming its device id;
//   - a ticket with an EMPTY tenant claim is rejected here, and verifyTicketTenant additionally
//     requires the claim to match the tenant the target agent registered under, whenever the agent
//     declared one.
func verifyTicket(pub ed25519.PublicKey, ticket *SignedSessionTicket, nowMs int64, target string) error {
	if ticket == nil {
		return fmt.Errorf("%w: no ticket in connect_request", errTicketInvalid)
	}
	switch ticket.Claims.V {
	case ticketVersion:
		if ticket.Claims.Access != "" || ticket.Claims.accessPresent {
			return fmt.Errorf("%w: v1 must not carry access", errTicketInvalid)
		}
	case 2:
		if ticket.Claims.Access != "view_only" {
			return fmt.Errorf("%w: v2 requires view_only access", errTicketInvalid)
		}
	default:
		return fmt.Errorf("%w: unsupported version %d", errTicketInvalid, ticket.Claims.V)
	}
	sig, err := hex.DecodeString(ticket.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature", errTicketInvalid)
	}
	if !ed25519.Verify(pub, ticketSigningBytes(ticket.Claims), sig) {
		return fmt.Errorf("%w: bad signature", errTicketInvalid)
	}
	if nowMs > ticket.Claims.ExpiresAtMs {
		return fmt.Errorf("%w: expired at %d (now %d)", errTicketInvalid, ticket.Claims.ExpiresAtMs, nowMs)
	}
	if ticket.Claims.IssuedAtMs > nowMs+ticketMaxClockSkewMs {
		return fmt.Errorf("%w: issued at %d, more than %dms ahead of now (%d)",
			errTicketInvalid, ticket.Claims.IssuedAtMs, ticketMaxClockSkewMs, nowMs)
	}
	if ticket.Claims.TenantID == "" {
		return fmt.Errorf("%w: ticket carries no tenant binding", errTicketInvalid)
	}
	// A ticket has to be individually identifiable to be single-use (spentTickets below).
	if ticket.Claims.SessionID == "" {
		return fmt.Errorf("%w: ticket carries no session id", errTicketInvalid)
	}
	// Loop 91: the technician claim is now ADVERTISED on `brokered` and ends up in the hashed
	// preimage of every audit event the agent seals for this session. `technician_id` was in the
	// signed preimage from the start but never checked here, so a control plane that minted one with
	// an empty technician produced a ticket that verified and then attributed a whole session's audit
	// trail to nobody — a chain that looks authentic and names no one. Refuse it at the same seam
	// that refuses an empty session id, rather than discovering it at ingest time as a 403.
	if ticket.Claims.TechnicianID == "" {
		return fmt.Errorf("%w: ticket carries no technician id", errTicketInvalid)
	}
	if ticket.Claims.DeviceID != target {
		// target is the connect_request field: attacker-sized (up to the 64 KiB read cap), and a
		// holder of ANY valid ticket reaches this line with a mismatching one. The error is logged,
		// so both ids are clipped here; the comparison above uses the full values.
		return fmt.Errorf("%w: ticket for device %q, connect_request targets %q",
			errTicketInvalid, clipForLog(ticket.Claims.DeviceID), clipForLog(target))
	}
	return nil
}

// verifyTicketTenant checks the ticket's tenant claim against the tenant the TARGET AGENT declared
// at register_agent. An agent that declares no tenant (the pre-M2 registration shape) cannot be
// cross-checked here — its protection is the control plane's globally-unique, server-minted device
// ids — so an undeclared tenant passes. A DECLARED tenant must match exactly: a ticket minted in
// another tenant can then never be brokered to this agent, whatever the device id says.
//
// Called only after verifyTicket, so the ticket is non-nil and its tenant claim non-empty.
func verifyTicketTenant(ticket *SignedSessionTicket, agentTenant string) error {
	if agentTenant == "" {
		return nil
	}
	if ticket.Claims.TenantID != agentTenant {
		// Both tenants are unbounded strings (a signed claim; a register_agent field in dev mode);
		// the error is logged, so clip them. The comparison above uses the full values.
		return fmt.Errorf("%w: ticket for tenant %q, target agent registered under tenant %q",
			errTicketInvalid, clipForLog(ticket.Claims.TenantID), clipForLog(agentTenant))
	}
	return nil
}

// spentTickets makes a session ticket SINGLE-USE WITHIN THIS PROCESS. Verification alone leaves a
// ticket an unbound bearer credential: whoever holds it can broker session after session until
// exp_ms, so one leaked ticket (a log line, a proxy, a browser history entry) is unlimited access to
// that device for the rest of its TTL. Recording the session id the control plane minted the ticket
// for reduces that to exactly the one rendezvous the technician was authorized for.
//
// "Within this process" is the honest scope and is why it is only HALF the enforcement: two
// replicas hold two maps, and a restart holds none, so each would honour the same ticket again.
// ticketredeem.go adds the ledger that spans both — this map remains the fast path in front of it,
// and the only line of defence that still works when the control plane is unreachable.
//
// Bounded by the tickets' own expiry: an entry can be dropped once the ticket it names is expired,
// because verifyTicket already refuses it from then on. Only signature-verified tickets ever reach
// here, so the map cannot be inflated by an unauthenticated client.
type spentTickets struct {
	mu    sync.Mutex
	spent map[string]int64 // ticket session id -> that ticket's exp_ms
}

func newSpentTickets() *spentTickets {
	return &spentTickets{spent: make(map[string]int64)}
}

// consume records sessionID as spent and reports whether it was previously unspent. The check and
// the record are one atomic step, so two concurrent replays cannot both win.
func (s *spentTickets) consume(sessionID string, expMs, nowMs int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, exp := range s.spent {
		if nowMs > exp {
			delete(s.spent, id)
		}
	}
	if _, ok := s.spent[sessionID]; ok {
		return false
	}
	s.spent[sessionID] = expMs
	return true
}
