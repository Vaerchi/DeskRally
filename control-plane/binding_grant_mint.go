package controlplane

// Session BINDING GRANTS (docs/69 §3.1): the control plane telling the AGENT which console key may
// prove itself in one session. The console generates an ephemeral Ed25519 key, sends its public half
// with the session request, and receives this grant back; it installs the grant over the Control
// channel, and the agent verifies it against the same pinned GrantIssuer key as a backstage grant or a
// session policy. From then on the agent knows the session id, the technician and the console key from
// a source the signaling server cannot forge, and demands a signature from that key over both ends'
// live DTLS fingerprints (RMTSESSBINDv1) before it sends a picture or accepts input.
//
// The canonical preimage is a cross-language contract with the agent's Rust verifier;
// TestBindingGrantGoldenVectorV1 pins the bytes.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// bindingGrantDomainTag: ASCII "RMTBINDGv1" + two 0x00 bytes (12 bytes, like every other tag signed
// by the GrantIssuer key). TestDomainTagsArePairwiseDistinct keeps it apart from the others.
var bindingGrantDomainTag = []byte("RMTBINDGv1\x00\x00")

// bindingGrantVersion is the preimage layout version, signed after the tag.
const bindingGrantVersion byte = 1

type bindingGrantClaims struct {
	SessionID     string             `json:"session_id"`
	DeviceID      string             `json:"device_id"`
	TenantID      string             `json:"tenant_id"`
	TechnicianID  string             `json:"technician_id"`
	Access        SessionAccessLevel `json:"access"`
	ConsolePubkey string             `json:"console_pubkey"`
	IssuedAtMs    int64              `json:"issued_at_ms"`
	ExpiresAtMs   int64              `json:"expires_at_ms"`
}

// SignedBindingGrant is the claims plus an Ed25519 signature (hex) over their canonical bytes.
type SignedBindingGrant struct {
	Claims bindingGrantClaims `json:"claims"`
	Sig    string             `json:"sig"`
}

// JSON is the wire form the console forwards to the agent unchanged.
func (g SignedBindingGrant) JSON() (string, error) {
	b, err := json.Marshal(g)
	return string(b), err
}

// bindingGrantSigningBytes builds the canonical v1 preimage:
//
//	tag(12) || u8 version || session(16) || device(16) || tenant(16) || technician(16)
//	|| lp(access) || console_pubkey(32) || i64 issued_at_ms || i64 expires_at_ms
func bindingGrantSigningBytes(c bindingGrantClaims) ([]byte, error) {
	ids := [4]struct{ name, v string }{
		{"session_id", c.SessionID}, {"device_id", c.DeviceID}, {"tenant_id", c.TenantID}, {"technician_id", c.TechnicianID},
	}
	var raw [4][16]byte
	for i, f := range ids {
		b, err := uuidBytes(f.v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
		raw[i] = b
	}
	if !c.Access.Valid() {
		return nil, fmt.Errorf("access %q is not a known level", c.Access)
	}
	pub, err := parseConsolePubkey(c.ConsolePubkey)
	if err != nil {
		return nil, err
	}
	var w canonicalWriter
	w.buf = append(w.buf, bindingGrantDomainTag...)
	w.u8(bindingGrantVersion)
	for _, b := range raw {
		w.raw16(b)
	}
	w.lpStr(string(c.Access))
	w.buf = append(w.buf, pub...)
	w.i64(c.IssuedAtMs)
	w.i64(c.ExpiresAtMs)
	return w.buf, nil
}

// parseConsolePubkey accepts exactly 64 lowercase-or-uppercase hex characters (a 32-byte Ed25519 key).
func parseConsolePubkey(h string) ([]byte, error) {
	if len(h) != 2*ed25519.PublicKeySize {
		return nil, fmt.Errorf("console_pubkey must be %d hex characters", 2*ed25519.PublicKeySize)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("console_pubkey is not hex")
	}
	return b, nil
}

// MintBindingGrant signs a binding grant. The console key is normalised to lowercase hex so the JSON
// and the signed bytes always describe the same key.
func (gi *GrantIssuer) MintBindingGrant(sessionID, deviceID, tenantID, technicianID string, access SessionAccessLevel,
	consolePubkeyHex string, issuedAtMs, expiresAtMs int64) (SignedBindingGrant, error) {
	pub, err := parseConsolePubkey(consolePubkeyHex)
	if err != nil {
		return SignedBindingGrant{}, err
	}
	c := bindingGrantClaims{
		SessionID: sessionID, DeviceID: deviceID, TenantID: tenantID, TechnicianID: technicianID,
		Access: access, ConsolePubkey: hex.EncodeToString(pub), IssuedAtMs: issuedAtMs, ExpiresAtMs: expiresAtMs,
	}
	msg, err := bindingGrantSigningBytes(c)
	if err != nil {
		return SignedBindingGrant{}, err
	}
	return SignedBindingGrant{Claims: c, Sig: hex.EncodeToString(ed25519.Sign(gi.priv, msg))}, nil
}
