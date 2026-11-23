package controlplane

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Binding-grant fixture (docs/69). The issuer, technician, session and machine come from the
// session-policy golden fixture; the tenant and console key are fixed here. The Rust verifier pins the
// same values to the same hex.
const (
	goldenBindTenantID      = "44444444-4444-4444-4444-444444444444"
	goldenBindConsolePubHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)

const (
	goldenBindPreimageHex = "524d5442494e444776310000012222222222222222222222222222222233333333333333333333333333333333444444444444444444444444444444441111111111111111111111111111111100000007636f6e74726f6cd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a00000192cc09140000000192cc16cfa0"
	goldenBindSigHex      = "dcbe7c5d96ce5e0debfff6c97cb4f1545409329c6f84e5ba6183cc82e1b002b86c5d4a8fcd898127199929a7c593b9c7cc81810fd70d3dd1c6735e7eccd76701"
)

func goldenBindClaims() bindingGrantClaims {
	return bindingGrantClaims{
		SessionID: goldenSessionID, DeviceID: goldenMachineID, TenantID: goldenBindTenantID,
		TechnicianID: goldenTechnicianID, Access: SessionAccessControl, ConsolePubkey: goldenBindConsolePubHex,
		IssuedAtMs: goldenIssuedAtMs, ExpiresAtMs: goldenExpiresAtMs,
	}
}

func TestBindingGrantGoldenVectorV1(t *testing.T) {
	iss := goldenPolicyIssuer(t)
	msg, err := bindingGrantSigningBytes(goldenBindClaims())
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if got := hex.EncodeToString(msg); got != goldenBindPreimageHex {
		t.Fatalf("canonical preimage drift (the agent will reject every binding grant):\n got  %s\n want %s", got, goldenBindPreimageHex)
	}
	g, err := iss.MintBindingGrant(goldenSessionID, goldenMachineID, goldenBindTenantID, goldenTechnicianID,
		SessionAccessControl, goldenBindConsolePubHex, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if g.Sig != goldenBindSigHex {
		t.Fatalf("sig drift:\n got  %s\n want %s", g.Sig, goldenBindSigHex)
	}
	js, err := g.JSON()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("go-minted binding grant JSON (Rust fixture): %s", js)
}

func TestBindingGrantSignatureVerifiesAndCoversEveryField(t *testing.T) {
	iss := goldenPolicyIssuer(t)
	g, err := iss.MintBindingGrant(goldenSessionID, goldenMachineID, goldenBindTenantID, goldenTechnicianID,
		SessionAccessViewOnly, strings.ToUpper(goldenBindConsolePubHex), goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatal(err)
	}
	if g.Claims.ConsolePubkey != goldenBindConsolePubHex {
		t.Fatalf("console key not normalised to lowercase: %s", g.Claims.ConsolePubkey)
	}
	pub, _ := hex.DecodeString(iss.PublicKeyHex())
	sig, _ := hex.DecodeString(g.Sig)
	verify := func(c bindingGrantClaims) bool {
		msg, err := bindingGrantSigningBytes(c)
		return err == nil && ed25519.Verify(pub, msg, sig)
	}
	if !verify(g.Claims) {
		t.Fatal("a freshly minted grant does not verify")
	}
	for name, mutate := range map[string]func(*bindingGrantClaims){
		"session":    func(c *bindingGrantClaims) { c.SessionID = goldenBindTenantID },
		"device":     func(c *bindingGrantClaims) { c.DeviceID = goldenBindTenantID },
		"tenant":     func(c *bindingGrantClaims) { c.TenantID = goldenSessionID },
		"technician": func(c *bindingGrantClaims) { c.TechnicianID = goldenBindTenantID },
		"access":     func(c *bindingGrantClaims) { c.Access = SessionAccessControl },
		"console":    func(c *bindingGrantClaims) { c.ConsolePubkey = strings.Repeat("ab", 32) },
		"issued":     func(c *bindingGrantClaims) { c.IssuedAtMs++ },
		"expires":    func(c *bindingGrantClaims) { c.ExpiresAtMs++ },
	} {
		c := g.Claims
		mutate(&c)
		if verify(c) {
			t.Errorf("changing the %s still verifies: the field is not covered by the signature", name)
		}
	}
	var back SignedBindingGrant
	js, _ := g.JSON()
	if err := json.Unmarshal([]byte(js), &back); err != nil || back != g {
		t.Fatalf("JSON round trip changed the grant: %v", err)
	}
}

func TestBindingGrantRefusesMalformedInput(t *testing.T) {
	iss := goldenPolicyIssuer(t)
	mint := func(session, key string, access SessionAccessLevel) error {
		_, err := iss.MintBindingGrant(session, goldenMachineID, goldenBindTenantID, goldenTechnicianID, access, key,
			goldenIssuedAtMs, goldenExpiresAtMs)
		return err
	}
	for name, err := range map[string]error{
		"short key":      mint(goldenSessionID, goldenBindConsolePubHex[:62], SessionAccessControl),
		"non-hex key":    mint(goldenSessionID, strings.Repeat("zz", 32), SessionAccessControl),
		"empty key":      mint(goldenSessionID, "", SessionAccessControl),
		"synthetic id":   mint("dev-1", goldenBindConsolePubHex, SessionAccessControl),
		"unknown access": mint(goldenSessionID, goldenBindConsolePubHex, "admin"),
	} {
		if err == nil {
			t.Errorf("%s: minted", name)
		}
	}
}
