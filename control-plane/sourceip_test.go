package controlplane

// Source-address persistence (sourceip.go): the value written to user_session / audit_event /
// session_record must be the TRUSTED derivation (the allow-list's resolveClientIP), never a header an
// untrusted peer chose, and never a non-IP. One scenario runs against both the in-memory fakes and
// Postgres (fake/pg parity); the pg leg skips without TEST_DATABASE_URL (a skip is a failure for us).

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sipBackend is what the shared scenario needs from a fixture, kept to closures so the fake and pg
// fixtures need no common type.
type sipBackend struct {
	srv      *Server
	tenant   string // login slug
	email    string
	password string
	deviceID string
	// sessionRow reads user_session.source_ip / user_agent for the session behind a login cookie
	// ("" for NULL).
	sessionRow func(t *testing.T, token string) (ip, ua string)
	recordIP   func(t *testing.T, id string) string
	audit      func(t *testing.T) []MgmtAuditEvent
}

type sipReq struct {
	remote, xff, ua string
}

func (b sipBackend) do(t *testing.T, method, path string, body any, rq sipReq, csrf string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		buf, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, strings.NewReader(string(buf)))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.RemoteAddr = rq.remote
	if rq.xff != "" {
		r.Header.Set("X-Forwarded-For", rq.xff)
	}
	if rq.ua != "" {
		r.Header.Set("User-Agent", rq.ua)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	if csrf != "" {
		r.Header.Set(CSRFHeaderName, csrf)
	}
	rec := httptest.NewRecorder()
	b.srv.Handler().ServeHTTP(rec, r)
	return rec
}

// loginAndStart logs in then starts a session, both from the same simulated peer, and returns what was
// persisted for the login session, the login audit event, the session record and the session.start event.
func (b sipBackend) loginAndStart(t *testing.T, rq sipReq) (sessIP, sessUA, loginEvIP, recIP, startEvIP string) {
	t.Helper()
	rec := b.do(t, "POST", "/auth/login", loginRequest{Tenant: b.tenant, Email: b.email, Password: b.password}, rq, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", rec.Code, rec.Body.String())
	}
	cookie := sessionCookieFrom(rec)
	csrfCookie, csrfTok := csrfFrom(t, rec)
	sessIP, sessUA = b.sessionRow(t, cookie.Value)

	sr := b.do(t, "POST", "/sessions", startSessionRequest{MachineID: b.deviceID}, rq, csrfTok, cookie, csrfCookie)
	if sr.Code != http.StatusCreated {
		t.Fatalf("start session = %d: %s", sr.Code, sr.Body.String())
	}
	var body struct {
		Session SessionRecord `json:"session"`
	}
	if err := json.Unmarshal(sr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	recIP = b.recordIP(t, body.Session.ID)
	// ListEvents is newest first: the first hit per action is this step's.
	sawLogin, sawStart := false, false
	for _, e := range b.audit(t) {
		if e.Action == "auth.login" && !sawLogin {
			sawLogin, loginEvIP = true, e.SourceIP
		}
		if e.Action == "session.start" && !sawStart {
			sawStart, startEvIP = true, e.SourceIP
		}
	}
	if !sawLogin || !sawStart {
		t.Fatalf("audit trail lacks auth.login (%v) or session.start (%v)", sawLogin, sawStart)
	}
	return
}

func runSourceIPScenario(t *testing.T, b sipBackend) {
	const ua = "Mozilla/5.0 (X11; Linux) SourceIPTest/1.0"
	check := func(name string, rq sipReq, want string) {
		t.Helper()
		sessIP, sessUA, loginIP, recIP, startIP := b.loginAndStart(t, rq)
		for what, got := range map[string]string{
			"user_session.source_ip": sessIP, "auth.login audit": loginIP,
			"session_record.source_ip": recIP, "session.start audit": startIP,
		} {
			if got != want {
				t.Errorf("%s: %s = %q, want %q", name, what, got, want)
			}
		}
		if sessUA != ua {
			t.Errorf("%s: user_session.user_agent = %q, want %q", name, sessUA, ua)
		}
	}

	// 1. No proxy trust configured: the peer's address, whatever X-Forwarded-For claims.
	check("default+spoofed XFF", sipReq{remote: "198.51.100.7:5555", xff: "6.6.6.6", ua: ua}, "198.51.100.7")

	// 2. IPv6 peer.
	check("ipv6 peer", sipReq{remote: "[2001:db8::42]:443", ua: ua}, "2001:db8::42")

	// 3. Trusted proxy (CP_TRUSTED_PROXIES): the rightmost hop, which may be IPv6.
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	b.srv.SetTrustedProxies([]*net.IPNet{trusted})
	t.Cleanup(func() { SetTrustedProxyNets(nil); SetTrustProxyForClientIP(false) })
	check("trusted proxy, ipv6 client", sipReq{remote: "10.1.2.3:9999", xff: "6.6.6.6, 2001:db8::1", ua: ua}, "2001:db8::1")
	check("trusted proxy, ipv4 client", sipReq{remote: "10.1.2.3:9999", xff: "203.0.113.50", ua: ua}, "203.0.113.50")

	// 4. Proxy trust IS configured, but this peer is not a trusted proxy: its header is ignored.
	check("untrusted peer, spoofed XFF", sipReq{remote: "203.0.113.9:1234", xff: "6.6.6.6", ua: ua}, "203.0.113.9")
	check("untrusted ipv6 peer, spoofed XFF", sipReq{remote: "[2001:db8:ffff::9]:1234", xff: "6.6.6.6", ua: ua}, "2001:db8:ffff::9")

	// 5. A trusted proxy forwarding garbage falls back to the proxy's own (valid) address, never the garbage.
	check("trusted proxy, garbage XFF", sipReq{remote: "10.1.2.3:9999", xff: "not-an-ip", ua: ua}, "10.1.2.3")
}

func sipTestFixtureFake(t *testing.T) sipBackend {
	t.Helper()
	f := newPass12Fixture(t)
	return sipBackend{
		srv: f.srv, tenant: p12TenantAlpha,
		email: p12AliceEmail, password: p12AlicePw, deviceID: f.m1.DeviceID,
		sessionRow: func(t *testing.T, token string) (string, string) {
			s, err := f.sessions.Store.GetByTokenHash(context.Background(), HashToken(token))
			if err != nil {
				t.Fatalf("session lookup: %v", err)
			}
			return s.SourceIP, s.UserAgent
		},
		recordIP: func(t *testing.T, id string) string {
			r, err := f.srv.SessionRecords.GetSession(context.Background(), p12TenantAlpha, id)
			if err != nil {
				t.Fatalf("GetSession: %v", err)
			}
			return r.SourceIP
		},
		audit: func(t *testing.T) []MgmtAuditEvent { return f.auditEventsFor(t, p12TenantAlpha) },
	}
}

func sipTestFixturePg(t *testing.T) sipBackend {
	t.Helper()
	f := newPass13PgFixture(t)
	return sipBackend{
		srv: f.srv, tenant: p13TenantAlpha,
		email: p13AliceEmail, password: p13AlicePw, deviceID: f.m1DevID,
		sessionRow: func(t *testing.T, token string) (ip, ua string) {
			if err := f.suPool.QueryRow(context.Background(),
				`SELECT COALESCE(host(source_ip),''), COALESCE(user_agent,'') FROM user_session WHERE token_hash=$1`,
				HashToken(token)).Scan(&ip, &ua); err != nil {
				t.Fatalf("user_session row: %v", err)
			}
			return
		},
		recordIP: func(t *testing.T, id string) (ip string) {
			if err := f.suPool.QueryRow(context.Background(),
				`SELECT COALESCE(host(source_ip),'') FROM session_record WHERE id=$1`, id).Scan(&ip); err != nil {
				t.Fatalf("session_record row: %v", err)
			}
			return
		},
		audit: func(t *testing.T) []MgmtAuditEvent { return f.auditEventsFor(t, f.alphaTid) },
	}
}

func TestSourceIPIsTheTrustedDerivation(t *testing.T) { runSourceIPScenario(t, sipTestFixtureFake(t)) }

func TestPgSourceIPIsTheTrustedDerivation(t *testing.T) { runSourceIPScenario(t, sipTestFixturePg(t)) }

// A value that is not an IP is stored as NULL, never as text. The middleware only ever produces valid
// addresses, so the guard is exercised through the context directly, on both store flavours.
func TestSourceIPNonIPIsNullNotStored(t *testing.T) {
	bad := context.WithValue(context.Background(), sourceCtxKey{}, requestSource{ip: "garbage; DROP TABLE", userAgent: "ua"})
	if got := sourceIPFrom(bad); got != "" {
		t.Fatalf("sourceIPFrom(non-IP) = %q, want empty", got)
	}
	if got := sourceIPFrom(context.Background()); got != "" {
		t.Fatalf("sourceIPFrom(no request) = %q, want empty", got)
	}
	st := NewInMemoryMgmtAuditStore()
	e := &MgmtAuditEvent{Action: "x.y"}
	if err := st.RecordEvent(bad, "t1", e); err != nil || e.SourceIP != "" {
		t.Fatalf("fake RecordEvent: err=%v SourceIP=%q, want empty", err, e.SourceIP)
	}
	rs := NewInMemorySessionRecordStore()
	rec := &SessionRecord{MachineID: "m", TechnicianID: "u", SourceIP: "300.1.1.1"}
	if err := rs.StartSession(context.Background(), "t1", rec); err != nil {
		t.Fatal(err)
	}
	got, _ := rs.GetSession(context.Background(), "t1", rec.ID)
	if got.SourceIP != "" {
		t.Fatalf("fake record SourceIP = %q, want empty", got.SourceIP)
	}
	ss := NewInMemorySessionStore()
	sess := &Session{TokenHash: []byte("h"), SourceIP: "999.1.1.1"}
	if err := ss.Insert(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
}

func TestPgSourceIPNonIPIsNullNotStored(t *testing.T) {
	f := newPass13PgFixture(t)
	ctx := context.Background()
	bad := context.WithValue(ctx, sourceCtxKey{}, requestSource{ip: "garbage", userAgent: "ua"})
	e := &MgmtAuditEvent{Action: "x.y"}
	if err := f.srv.MgmtAudit.RecordEvent(bad, f.alphaTid, e); err != nil {
		t.Fatalf("RecordEvent with a non-IP context value must still succeed (as NULL): %v", err)
	}
	e2 := &MgmtAuditEvent{Action: "x.z"}
	if err := f.srv.MgmtAudit.RecordEvent(ctx, f.alphaTid, e2); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{e.ID, e2.ID} {
		var isNull bool
		if err := f.suPool.QueryRow(ctx, `SELECT source_ip IS NULL FROM audit_event WHERE id=$1`, id).Scan(&isNull); err != nil || !isNull {
			t.Fatalf("audit_event %s source_ip IS NULL = %v (err %v), want true", id, isNull, err)
		}
	}
	now := time.Now().UTC()
	sess := &Session{TenantID: f.alphaTid, UserID: f.aliceUID, TokenHash: []byte("tok-nonip-0123456789abcdef0123456"),
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeen: now, SourceIP: "999.1.1.1"}
	if err := NewPgSessionStore(f.appPool).Insert(ctx, sess); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	var ipNull, uaNull bool
	if err := f.suPool.QueryRow(ctx, `SELECT source_ip IS NULL, user_agent IS NULL FROM user_session WHERE id=$1`, sess.ID).Scan(&ipNull, &uaNull); err != nil || !ipNull || !uaNull {
		t.Fatalf("user_session source_ip/user_agent NULL = %v/%v (err %v), want true/true", ipNull, uaNull, err)
	}
}

func TestSanitizeUserAgent(t *testing.T) {
	if got := sanitizeUserAgent("a\x00b\x01c\xffd\n"); got != "abcd" {
		t.Fatalf("control/invalid bytes kept: %q", got)
	}
	long := strings.Repeat("é", 400) // 2 bytes each
	got := sanitizeUserAgent(long)
	if len(got) > maxStoredUserAgent || len(got) < maxStoredUserAgent-1 || strings.ContainsRune(got, 0xFFFD) {
		t.Fatalf("truncation: len=%d", len(got))
	}
}

// The console/API sees it: GET /audit/export carries source_ip, and an event written outside a request
// has none.
func TestAuditExportCarriesSourceIP(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "the-real-password", RoleOwner)
	audit := NewInMemoryMgmtAuditStore()
	f.srv.MgmtAudit, f.auth.MgmtAudit = audit, audit
	b := sipBackend{srv: f.srv}
	rec := b.do(t, "POST", "/auth/login", loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "the-real-password"},
		sipReq{remote: "192.0.2.77:1"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d", rec.Code)
	}
	if err := audit.RecordEvent(context.Background(), "tenant-1", &MgmtAuditEvent{Action: "job.noreq"}); err != nil {
		t.Fatal(err)
	}
	ex := b.do(t, "GET", "/audit/export", nil, sipReq{remote: "192.0.2.77:1"}, "", sessionCookieFrom(rec))
	if ex.Code != http.StatusOK {
		t.Fatalf("export = %d: %s", ex.Code, ex.Body.String())
	}
	seen := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(ex.Body.String()), "\n") {
		var e MgmtAuditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		seen[e.Action] = e.SourceIP
		if e.Action == "job.noreq" && strings.Contains(line, "source_ip") {
			t.Errorf("event without a request carries a source_ip key: %s", line)
		}
	}
	if seen["auth.login"] != "192.0.2.77" || seen["job.noreq"] != "" {
		t.Fatalf("export source_ips = %v", seen)
	}
}

// Service-to-service routes (signaling -> control plane, everything under /internal/) record no source:
// their TCP peer is signaling's container address, which production once wrote on a session.end. The
// same peer on an ordinary route is still recorded, and so is a trusted proxy's forwarded client.
func TestServiceRoutesRecordNoSourceAddress(t *testing.T) {
	s := &Server{}
	var gotIP, gotUA string
	h := s.sourceIPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP, gotUA = sourceIPFrom(r.Context()), userAgentFrom(r.Context())
	}))
	for _, c := range []struct {
		path, wantIP, wantUA string
	}{
		{"/internal/sessions/abc/ended", "", ""},
		{"/internal/devices/d1/help-request", "", ""},
		{"/internal", "", ""},
		{"/sessions/abc/end", "172.18.0.5", "signaling/1.0"},
		{"/internalish", "172.18.0.5", "signaling/1.0"}, // only the /internal/ tree is a service route
	} {
		req := httptest.NewRequest(http.MethodPost, c.path, nil)
		req.RemoteAddr = "172.18.0.5:41000"
		req.Header.Set("User-Agent", "signaling/1.0")
		gotIP, gotUA = "unset", "unset"
		h.ServeHTTP(httptest.NewRecorder(), req)
		if gotIP != c.wantIP || gotUA != c.wantUA {
			t.Errorf("%s: source %q user agent %q, want %q %q", c.path, gotIP, gotUA, c.wantIP, c.wantUA)
		}
	}
}
