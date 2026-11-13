package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// The relay is a deliberately dumb, E2E-blind data plane (ADR-002 / ADR-004).
// Wire protocol for both transports:
//
//   1. The connecting peer first announces its RelayToken (a UUID).
//        - Raw TCP: a single newline-terminated line, e.g. "6f...c9\n".
//        - WebSocket: the first (text) message frame is the token.
//   2. Everything after the token is opaque payload, forwarded verbatim to
//      whichever peer presents the same token. The relay never decrypts and
//      never inspects it.

const (
	maxTokenLen           = 128              // generous cap; a UUID is 36 bytes
	defaultWait           = 30 * time.Second // how long an unpaired half-connection is held
	defaultMaxConnections = 1024             // bounded even when launched without a deployment template
)

// Empty configuration is bounded. A malformed limit must not silently disable admission.
// Zero remains an explicit operator opt-in to unlimited operation for isolated development.
func relayConnectionLimit(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return defaultMaxConnections, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("RELAY_MAX_CONNECTIONS must be a non-negative integer (0 explicitly disables the limit)")
	}
	return n, nil
}

func main() {
	tcpAddr := flag.String("tcp", ":9000", "raw TCP listen address (empty to disable)")
	wsAddr := flag.String("ws", ":9001", "WebSocket listen address (empty to disable)")
	wsPath := flag.String("ws-path", "/relay", "WebSocket upgrade path")
	pairWait := flag.Duration("pair-timeout", defaultWait, "how long to hold an unpaired half-connection")
	flag.Parse()

	maxConns, err := relayConnectionLimit(os.Getenv("RELAY_MAX_CONNECTIONS"))
	if err != nil {
		log.Fatal(err)
	}

	broker := NewBroker(*pairWait, maxConns)

	if maxConns > 0 {
		log.Printf("relay: admission limit %d concurrent connections (RELAY_MAX_CONNECTIONS)", maxConns)
	} else {
		log.Printf("WARNING: relay admission explicitly disabled by RELAY_MAX_CONNECTIONS=0")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)

	if *tcpAddr != "" {
		ln, err := net.Listen("tcp", *tcpAddr)
		if err != nil {
			log.Fatalf("tcp listen %s: %v", *tcpAddr, err)
		}
		log.Printf("relay: raw TCP listener on %s", *tcpAddr)
		go func() { errCh <- serveTCP(ctx, ln, broker) }()
	}

	if *wsAddr != "" {
		srv := newWSServer(*wsAddr, *wsPath, broker)
		log.Printf("relay: WebSocket listener on %s%s", *wsAddr, *wsPath)
		go func() { errCh <- serveWS(ctx, srv) }()
	}

	select {
	case <-ctx.Done():
		log.Printf("relay: shutting down")
	case err := <-errCh:
		if err != nil {
			log.Fatalf("relay: listener failed: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Raw TCP transport
// ---------------------------------------------------------------------------

func serveTCP(ctx context.Context, ln net.Listener, broker *Broker) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // graceful shutdown
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() { //nolint:staticcheck // temporary accept blip
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return err
		}
		go handleTCP(conn, broker)
	}
}

func handleTCP(conn net.Conn, broker *Broker) {
	if !broker.TryAcquire() {
		_ = conn.Close()
		return
	}
	defer broker.Release()

	// Bound only the token handshake with a deadline; the relayed session
	// itself must not be time-limited.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Enforce the token cap DURING the read, not after it.
	//
	// `normalizeToken` rejects anything over maxTokenLen, but it only sees the line once ReadString
	// has already buffered it — and ReadString grows without bound until it finds a '\n'. So a
	// pre-auth peer (this handshake is the first thing on the connection; nothing has authenticated)
	// could stream arbitrarily many bytes with no newline and the relay would accumulate all of
	// them. The 10s deadline above bounds the TIME, not the volume, and it is per connection: a
	// handful of connections at ordinary bandwidth is a lot of memory for an unauthenticated peer to
	// command.
	//
	// A LimitReader makes the cap structural — the read cannot exceed it, so the check in
	// normalizeToken becomes a second line of defence rather than the only one. +1 byte of slack so
	// a token of exactly maxTokenLen followed by '\n' still reads cleanly and is judged by
	// normalizeToken, keeping the accept/reject boundary exactly where it already was.
	hs := bufio.NewReader(io.LimitReader(conn, maxTokenLen+1))
	line, err := hs.ReadString('\n')
	// A full-but-newline-less read returns io.EOF with the bytes in `line`; hand those to
	// normalizeToken so an over-length token is REJECTED rather than mistaken for a read error —
	// same outcome, but the reason stays true.
	if err != nil && line == "" {
		_ = conn.Close()
		return
	}
	token, ok := normalizeToken(line)
	if !ok {
		_ = conn.Close()
		return
	}

	// Clear the handshake deadline: relayed sessions can be long-lived.
	_ = conn.SetReadDeadline(time.Time{})

	// The limit applied to the HANDSHAKE only — the relayed session that follows is deliberately
	// unbounded. `hs` may hold bytes it already read past the newline; splice those back in front of
	// the raw connection so the session sees an unbroken byte stream. Reading the session THROUGH
	// the exhausted LimitReader instead would end it at EOF the moment the handshake budget ran out,
	// silently capping every relayed session at ~128 bytes.
	//
	// Take only what is ALREADY BUFFERED (`Buffered()`), never `io.ReadAll`: ReadAll would keep
	// reading until the LimitReader's budget is spent, which on a stream that has simply gone quiet
	// after the token blocks the handshake until the peer sends more — a hang introduced by the very
	// fix that bounds the read. Buffered() cannot block, and is bounded by maxTokenLen+1.
	leftover := make([]byte, hs.Buffered())
	if len(leftover) > 0 {
		if _, rerr := io.ReadFull(hs, leftover); rerr != nil {
			_ = conn.Close()
			return
		}
	}
	s := &bufConn{Conn: conn, r: bufio.NewReader(io.MultiReader(bytes.NewReader(leftover), conn))}
	if err := broker.Handle(token, s); err != nil {
		log.Printf("relay tcp %s: %v", redactToken(token), err)
	}
	_ = conn.Close()
}

// bufConn presents a net.Conn as a stream whose reads come from a bufio.Reader
// (so any bytes buffered past the token newline are not lost) while writes and
// closes go straight to the underlying connection.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// ---------------------------------------------------------------------------
// WebSocket transport
// ---------------------------------------------------------------------------

var upgrader = websocket.Upgrader{
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
	// The relay is a shared, tenant-agnostic data plane; origin enforcement
	// belongs at the auth/control plane, not here. Accept any origin.
	CheckOrigin: func(*http.Request) bool { return true },
}

// wsRelayHandler returns an http.Handler that checks admission BEFORE the
// WebSocket upgrade (SEC-001 fix). Extracting it from newWSServer lets tests
// exercise the exact production handler via httptest.NewServer.
func wsRelayHandler(path string, broker *Broker) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		// Admission check BEFORE the WebSocket upgrade so refused connections
		// do not complete the HTTP 101 handshake (SEC-001: upgrade is cheap,
		// but a 503 is cheaper and avoids allocating gorilla buffers first).
		if !broker.TryAcquire() {
			http.Error(w, "relay at capacity", http.StatusServiceUnavailable)
			return
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			broker.Release() // upgrade failed; free the slot before returning
			return           // Upgrade already wrote an error response
		}
		defer broker.Release()
		handleWS(ws, broker)
	})
	return mux
}

// wsReadHeaderTimeout bounds how long a client may take to send its HTTP
// request headers. It is a var only so a test can shorten it.
var wsReadHeaderTimeout = 10 * time.Second

// wsMaxHeaderBytes caps the request header block read before the handler runs.
const wsMaxHeaderBytes = 16 << 10

// newWSServer bounds the pre-upgrade HTTP phase. Connections that never finish
// their request headers would otherwise hold a goroutine and file descriptor
// indefinitely, and the admission slot (TryAcquire) is only taken after the
// headers parse, so RELAY_MAX_CONNECTIONS does not bound them. ReadTimeout,
// WriteTimeout and IdleTimeout are deliberately unset: relayed sessions are
// long-lived, and handleWS applies its own post-upgrade token deadline.
func newWSServer(addr, path string, broker *Broker) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           wsRelayHandler(path, broker),
		ReadHeaderTimeout: wsReadHeaderTimeout,
		MaxHeaderBytes:    wsMaxHeaderBytes,
	}
}

func serveWS(ctx context.Context, srv *http.Server) error {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func handleWS(ws *websocket.Conn, broker *Broker) {
	// Admission slot already acquired by the HTTP handler in newWSServer before
	// the WebSocket upgrade; do not acquire again here.
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Bound the untrusted token message before ReadMessage buffers it. Like the TCP
	// handshake, accept at most maxTokenLen+1 raw bytes, including any whitespace.
	// Overlong padding is intentionally rejected; normalizeToken still checks syntax.
	ws.SetReadLimit(int64(maxTokenLen) + 1)

	mt, msg, err := ws.ReadMessage()
	if err != nil || (mt != websocket.TextMessage && mt != websocket.BinaryMessage) {
		_ = ws.Close()
		return
	}
	token, ok := normalizeToken(string(msg))
	if !ok {
		_ = ws.Close()
		return
	}
	_ = ws.SetReadDeadline(time.Time{})

	// The token cap must not limit the opaque payload messages relayed after pairing.
	ws.SetReadLimit(0)

	s := &wsConn{ws: ws}
	if err := broker.Handle(token, s); err != nil {
		log.Printf("relay ws %s: %v", redactToken(token), err)
	}
	_ = ws.Close()
}

// wsConn adapts a gorilla WebSocket connection to a byte stream by mapping
// reads/writes onto message frames. Frame boundaries are irrelevant to the
// relay: it forwards an opaque byte stream.
type wsConn struct {
	ws *websocket.Conn
	r  io.Reader // current in-progress frame reader, or nil
}

func (c *wsConn) Read(p []byte) (int, error) {
	for {
		if c.r == nil {
			mt, r, err := c.ws.NextReader()
			if err != nil {
				return 0, err
			}
			if mt != websocket.BinaryMessage && mt != websocket.TextMessage {
				continue // skip control frames handled by the library
			}
			c.r = r
		}
		n, err := c.r.Read(p)
		if errors.Is(err, io.EOF) {
			c.r = nil // frame drained; fetch the next on the following call
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	w, err := c.ws.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	n, err := w.Write(p)
	if err != nil {
		_ = w.Close()
		return n, err
	}
	return n, w.Close()
}

func (c *wsConn) Close() error { return c.ws.Close() }

// ---------------------------------------------------------------------------
// Token handling
// ---------------------------------------------------------------------------

// redactToken returns a short, non-reversible fingerprint (first 8 hex chars of
// sha256) of a RelayToken for log lines. The token is the pairing secret: anyone
// who can present a still-parked token is spliced to the legitimate peer, so it
// must never be written to logs. The fingerprint still lets an operator
// correlate lines for one session.
func redactToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "tok:" + hex.EncodeToString(sum[:4])
}

// normalizeToken trims surrounding whitespace/newline framing and validates
// that the announced token is a well-formed UUID. It returns the canonical
// token and whether it is acceptable.
func normalizeToken(raw string) (string, bool) {
	t := strings.TrimSpace(raw)
	if len(t) == 0 || len(t) > maxTokenLen {
		return "", false
	}
	if !isUUID(t) {
		return "", false
	}
	return strings.ToLower(t), true
}

// isUUID reports whether s looks like a canonical 8-4-4-4-12 hex UUID. The
// relay stays dependency-light, so this is a hand-rolled check rather than a
// UUID library.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !isHexDigit(r) {
				return false
			}
		}
	}
	return true
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}
