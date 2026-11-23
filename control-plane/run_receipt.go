package controlplane

// Agent-signed run receipts (docs/72-toolbox-run-receipts.md section 4.3).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
)

const runReceiptDomainTag = "RMTRUNRCPTv1\x00\x00\x00\x00"
const runReceiptVersion = 1

// RunReceiptClaims is the signed content of one agent run receipt.
type RunReceiptClaims struct {
	TenantID     string `json:"tenant_id"`
	DeviceID     string `json:"device_id"`
	SessionID    string `json:"session_id"`
	RequestID    string `json:"request_id"`
	Shell        string `json:"shell"`
	RunAs        string `json:"run_as"`
	ExecSHA256   string `json:"exec_sha256"`
	Outcome      string `json:"outcome"`
	ExitCode     *int32 `json:"exit_code"`
	Truncated    bool   `json:"truncated"`
	FinishedAtMs int64  `json:"finished_at_ms"`
}

type signedRunReceipt struct {
	Claims RunReceiptClaims `json:"claims"`
	Sig    string           `json:"sig"`
}

type runReceiptError string

const (
	runReceiptKey       runReceiptError = "key"
	runReceiptEnvelope  runReceiptError = "envelope"
	runReceiptSignature runReceiptError = "signature"
)

func (e runReceiptError) Error() string { return fmt.Sprintf("run receipt refused: %s", string(e)) }

func runReceiptPreimage(c RunReceiptClaims) ([]byte, error) {
	tenant, err := wakeUUID(c.TenantID)
	if err != nil {
		return nil, runReceiptEnvelope
	}
	session, err := wakeUUID(c.SessionID)
	if err != nil {
		return nil, runReceiptEnvelope
	}
	request, err := wakeUUID(c.RequestID)
	if err != nil || !utf8.ValidString(c.DeviceID) || len(c.DeviceID) > 256 {
		return nil, runReceiptEnvelope
	}
	execHash, err := wakeHex(c.ExecSHA256, 32)
	if err != nil {
		return nil, runReceiptEnvelope
	}

	var shell, runAs, outcome byte
	switch c.Shell {
	case "powershell":
		shell = 1
	case "cmd":
		shell = 2
	default:
		return nil, runReceiptEnvelope
	}
	switch c.RunAs {
	case "system":
		runAs = 1
	case "user":
		runAs = 2
	default:
		return nil, runReceiptEnvelope
	}
	switch c.Outcome {
	case "exited":
		outcome = 1
	case "timed_out":
		outcome = 2
	case "start_failed":
		outcome = 3
	default:
		return nil, runReceiptEnvelope
	}
	var exitCode int32
	if outcome == 3 {
		if c.ExitCode != nil || c.Truncated {
			return nil, runReceiptEnvelope
		}
	} else {
		if c.ExitCode == nil {
			return nil, runReceiptEnvelope
		}
		exitCode = *c.ExitCode
	}

	var w canonicalWriter
	w.buf = append(w.buf, runReceiptDomainTag...)
	w.u8(runReceiptVersion)
	w.raw16(tenant)
	w.lpStr(c.DeviceID)
	w.raw16(session)
	w.raw16(request)
	w.u8(shell)
	w.u8(runAs)
	w.buf = append(w.buf, execHash...)
	w.u8(outcome)
	w.i32(exitCode)
	var flags byte
	if c.Truncated {
		flags = 1
	}
	w.u8(flags)
	w.i64(c.FinishedAtMs)
	return w.buf, nil
}

// VerifyRunReceipt validates the wire JSON and verifies its re-encoded claims with the pinned key.
func VerifyRunReceipt(pub ed25519.PublicKey, artifact []byte) (*RunReceiptClaims, error) {
	if !usableEd25519Key(pub) {
		return nil, runReceiptKey
	}
	c, msg, sig, err := decodeRunReceipt(artifact)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return nil, runReceiptSignature
	}
	return c, nil
}

func decodeRunReceipt(artifact []byte) (*RunReceiptClaims, []byte, []byte, error) {
	envelope, ok := strictSignedJSONObject(artifact, "claims sig", "")
	if !ok || !utf8.Valid(artifact) {
		return nil, nil, nil, runReceiptEnvelope
	}
	fields, ok := strictSignedJSONObject(envelope["claims"],
		"tenant_id device_id session_id request_id shell run_as exec_sha256 outcome exit_code truncated finished_at_ms",
		"exit_code")
	if !ok {
		return nil, nil, nil, runReceiptEnvelope
	}
	var receipt signedRunReceipt
	if json.Unmarshal(artifact, &receipt) != nil || !validSignedJSONString(fields["device_id"]) {
		return nil, nil, nil, runReceiptEnvelope
	}
	c := receipt.Claims
	if string(fields["finished_at_ms"]) != strconv.FormatInt(c.FinishedAtMs, 10) ||
		(c.ExitCode != nil && string(fields["exit_code"]) != strconv.FormatInt(int64(*c.ExitCode), 10)) {
		return nil, nil, nil, runReceiptEnvelope
	}
	sig, err := wakeHex(receipt.Sig, ed25519.SignatureSize)
	if err != nil {
		return nil, nil, nil, runReceiptEnvelope
	}
	msg, err := runReceiptPreimage(c)
	if err != nil {
		return nil, nil, nil, err
	}
	return &c, msg, sig, nil
}

// Match PublicIdentity's point-decoding and weak-key checks. Go's Ed25519 API
// exposes only a boolean verification result, so validate the public point here.
func usableEd25519Key(pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	encoded := bytes.Clone(pub)
	encoded[31] &= 127
	for l, r := 0, len(encoded)-1; l < r; l, r = l+1, r-1 {
		encoded[l], encoded[r] = encoded[r], encoded[l]
	}
	one := big.NewInt(1)
	p := new(big.Int).Sub(new(big.Int).Lsh(one, 255), big.NewInt(19))
	y := new(big.Int).Mod(new(big.Int).SetBytes(encoded), p)
	y2 := new(big.Int).Mod(new(big.Int).Mul(y, y), p)
	if y.Sign() == 0 || y2.Cmp(one) == 0 {
		return false // order divides four
	}
	// The Edwards equation gives x² = (y²-1)/(1+d*y²), d = -121665/121666.
	d := new(big.Int).ModInverse(big.NewInt(121666), p)
	d.Mul(d, big.NewInt(-121665))
	denominator := new(big.Int).Mul(d, y2)
	denominator.Add(denominator, one)
	inverse := new(big.Int).ModInverse(denominator, p)
	if inverse == nil {
		return false
	}
	x2 := new(big.Int).Sub(y2, one)
	x2.Mod(x2.Mul(x2, inverse), p)
	sum := new(big.Int).Mod(new(big.Int).Add(x2, y2), p)
	// Doubling an order-eight point gives y=0, which requires x²+y²=0.
	return sum.Sign() != 0 && big.Jacobi(x2, p) == 1
}

// Require the exact set of object fields. encoding/json otherwise accepts
// missing, duplicate and case-insensitive struct keys.
func strictSignedJSONObject(raw []byte, fields, nullable string) (map[string]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	out := make(map[string]json.RawMessage)
	for dec.More() {
		token, err := dec.Token()
		name, ok := token.(string)
		if err != nil || !ok || out[name] != nil {
			return nil, false
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil || (name != nullable && bytes.Equal(value, []byte("null"))) {
			return nil, false
		}
		out[name] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	want := strings.Fields(fields)
	if len(out) != len(want) {
		return nil, false
	}
	for _, name := range want {
		if out[name] == nil {
			return nil, false
		}
	}
	return out, true
}

// encoding/json replaces lone UTF-16 surrogates with U+FFFD. Preserve the
// exact decoded string by refusing that spelling, as serde_json does.
func validSignedJSONString(raw []byte) bool {
	var high bool
	for len(raw) > 0 {
		if raw[0] == '\\' && len(raw) >= 6 && raw[1] == 'u' {
			unit, err := strconv.ParseUint(string(raw[2:6]), 16, 16)
			if err != nil || high != (unit >= 0xdc00 && unit <= 0xdfff) {
				return false
			}
			high = unit >= 0xd800 && unit <= 0xdbff
			raw = raw[6:]
			continue
		}
		if high {
			return false
		}
		if raw[0] == '\\' {
			raw = raw[1:]
		}
		raw = raw[1:]
	}
	return true
}


