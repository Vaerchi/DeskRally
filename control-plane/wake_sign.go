package controlplane

// Signed wake orders (docs/70-wake-on-lan.md section 5.2). The RMTWAKEv1 domain tag
// differs from RMTDIRECTIVEv1 so signatures cannot cross between the two formats.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"unicode/utf8"
)

const (
	wakeDomainTag = "RMTWAKEv1\x00\x00\x00\x00\x00\x00\x00"
	wakeVersion   = 1
	wakeMaxTTL    = 60_000
	wakeClockSkew = 30_000
)

// WakeClaims is the signed content of one wake order.
type WakeClaims struct {
	TenantID       string `json:"tenant_id"`
	RelayDeviceID  string `json:"relay_device_id"`
	RelayKeySHA256 string `json:"relay_key_sha256"`
	WakeChallenge  string `json:"wake_challenge"`
	RequestID      string `json:"request_id"`
	TargetMAC      string `json:"target_mac"`
	IPv4Network    string `json:"ipv4_network"`
	GatewayMAC     string `json:"gateway_mac"`
	IssuedAtMs     int64  `json:"issued_at_ms"`
	ExpiresAtMs    int64  `json:"expires_at_ms"`
}

type signedWake struct {
	Claims WakeClaims `json:"claims"`
	Sig    string     `json:"sig"`
}

func wakeHex(s string, size int) ([]byte, error) {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != size || hex.EncodeToString(raw) != s {
		return nil, fmt.Errorf("expected %d bytes of lowercase hex", size)
	}
	return raw, nil
}

func wakeUUID(s string) ([16]byte, error) {
	id, err := uuidBytes(s)
	if err == nil && strings.ToLower(s) != s {
		err = errors.New("expected lowercase UUID")
	}
	return id, err
}

func wakeMAC(s string) (net.HardwareAddr, error) {
	mac, err := net.ParseMAC(s)
	if err != nil || len(mac) != 6 || mac.String() != s || mac[0]&1 != 0 || s == "00:00:00:00:00:00" {
		return nil, errors.New("expected a canonical nonzero unicast MAC")
	}
	return mac, nil
}

// wakePreimage builds the canonical RMTWAKEv1 preimage.
func wakePreimage(c WakeClaims) ([]byte, error) {
	tenant, err := wakeUUID(c.TenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant_id: %w", err)
	}
	if c.RelayDeviceID == "" || !utf8.ValidString(c.RelayDeviceID) || uint64(len(c.RelayDeviceID)) > math.MaxUint32 {
		return nil, errors.New("relay_device_id must be nonempty, length-prefixed UTF-8")
	}
	fp, err := wakeHex(c.RelayKeySHA256, 32)
	if err != nil {
		return nil, fmt.Errorf("relay_key_sha256: %w", err)
	}
	challenge, err := wakeHex(c.WakeChallenge, 16)
	if err != nil {
		return nil, fmt.Errorf("wake_challenge: %w", err)
	}
	request, err := wakeUUID(c.RequestID)
	if err != nil {
		return nil, fmt.Errorf("request_id: %w", err)
	}
	target, err := wakeMAC(c.TargetMAC)
	if err != nil {
		return nil, fmt.Errorf("target_mac: %w", err)
	}
	network, err := netip.ParsePrefix(c.IPv4Network)
	if err != nil || !network.Addr().Is4() || network.Bits() < 16 || network.Bits() > 30 || network.Masked().String() != c.IPv4Network {
		return nil, errors.New("ipv4_network must be a canonical IPv4 network with prefix 16..30")
	}
	gateway, err := wakeMAC(c.GatewayMAC)
	if err != nil {
		return nil, fmt.Errorf("gateway_mac: %w", err)
	}

	var w canonicalWriter
	w.buf = append(w.buf, wakeDomainTag...)
	w.u8(wakeVersion)
	w.raw16(tenant)
	w.lpStr(c.RelayDeviceID)
	w.buf = append(w.buf, fp...)
	w.buf = append(w.buf, challenge...)
	w.raw16(request)
	w.buf = append(w.buf, target...)
	addr := network.Addr().As4()
	w.buf = append(w.buf, addr[:]...)
	w.u8(byte(network.Bits()))
	w.buf = append(w.buf, gateway...)
	w.i64(c.IssuedAtMs)
	w.i64(c.ExpiresAtMs)
	return w.buf, nil
}

func validWakeLifetime(issued, expires int64) bool {
	// Once ordered, unsigned subtraction gives the full positive difference.
	return expires > issued && uint64(expires)-uint64(issued) <= wakeMaxTTL
}

// SignWake validates and signs a wake order, returning its wire JSON.
func SignWake(priv ed25519.PrivateKey, c WakeClaims) (artifact []byte, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid wake signing key length")
	}
	msg, err := wakePreimage(c)
	if err != nil {
		return nil, err
	}
	if !validWakeLifetime(c.IssuedAtMs, c.ExpiresAtMs) {
		return nil, errors.New("wake lifetime must be positive and at most 60000 ms")
	}
	return json.Marshal(signedWake{Claims: c, Sig: hex.EncodeToString(ed25519.Sign(priv, msg))})
}
