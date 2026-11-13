package main

// The WebSocket handshake must be bounded DURING the first read — not by normalizeToken after
// gorilla has already buffered the whole frame — and the bound must not leak into the opaque
// relayed session that follows.
//
// PREMISE, declared locally: handleWS is the first thing that runs on a fresh WebSocket. Nothing
// has authenticated at that point — the token IS the credential — so whatever ReadMessage is
// willing to buffer, an anonymous peer can make it buffer. Before the fix, gorilla's readLimit was
// zero (no limit), so an over-declared 4 GiB text frame would be accumulated up to the 10s
// handshake deadline; normalizeToken's `len(t) > maxTokenLen` check only ran on the assembled
// message. The 10s deadline bounds TIME, not VOLUME.
//
// The oversize test uses a RAW RFC 6455 frame whose header declares 64 KiB and WITHHOLDS the body,
// so a bounded server (gorilla's advanceFrame short-circuits at the header: readLength > readLimit
// → CloseMessageTooBig, errReadLimit) closes at once, while the unbounded server sits waiting for
// body bytes that never come and only unblocks when the 10s handshake deadline fires. Time-to-close
// is the discriminator that a full-payload test could not provide.
//
// The valid-token legs are the negative control for the fix: they must relay a payload that is an
// order of magnitude past the handshake cap in BOTH directions, otherwise the cap has leaked into
// the session and every relayed stream is silently truncated at ~128 bytes.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// newRelayWSServer starts an httptest.Server whose /relay endpoint is the same upgrader +
// handleWS pipeline used in production. The server is torn down on test cleanup so no goroutine
// or listener outlives the test.
func newRelayWSServer(t *testing.T, pairTimeout time.Duration) (string, *Broker) {
	t.Helper()
	broker := NewBroker(pairTimeout, 0)
	var handlers sync.WaitGroup
	mux := http.NewServeMux()
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		handlers.Add(1)
		defer handlers.Done()
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		handleWS(ws, broker)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		// Client cleanups were registered later and have already closed hijacked sockets.
		done := make(chan struct{})
		go func() { handlers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(pairTimeout + 2*time.Second):
			t.Error("relay handlers did not finish after client cleanup")
		}
	})
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return "ws://" + u.Host + "/relay", broker
}

// dialRawWS completes the WebSocket HTTP upgrade over a raw TCP socket and hands the socket back
// so the caller can write hand-crafted RFC 6455 frames. The socket is registered for cleanup so
// no half-open peer survives the test.
func dialRawWS(t *testing.T, wsURL string) net.Conn {
	t.Helper()
	u, err := url.Parse(wsURL)
	if err != nil {
		t.Fatalf("parse ws url: %v", err)
	}
	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	req := "GET " + u.Path + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("upgrade write: %v", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	// Read the response headers up to the blank line. httptest + gorilla will not push any frame
	// bytes onto the socket before we send our first frame, so the reader's buffer will be empty
	// at the end of the headers and reading directly from `conn` afterwards is safe.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("upgrade status: %v", err)
	}
	if !strings.Contains(status, " 101 ") {
		t.Fatalf("unexpected upgrade status: %q", strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("upgrade headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	if br.Buffered() != 0 {
		t.Fatalf("unexpected %d bytes buffered past upgrade headers", br.Buffered())
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn
}

// writeClientFrame writes a single client-to-server WebSocket frame. Client frames MUST be masked
// (RFC 6455 §5.3); an unmasked client frame is a protocol violation that gorilla will reject on
// its own, which would mask the very read-limit behaviour we are trying to observe. `writeBody`
// controls whether the payload bytes are actually written after the header — used by the oversize
// test to declare a large length and withhold the body.
func writeClientFrame(conn net.Conn, fin bool, opcode byte, declaredLen uint64, payload []byte, writeBody bool) error {
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})
	var b0 byte = opcode & 0x0F
	if fin {
		b0 |= 0x80
	}
	hdr := []byte{b0}
	switch {
	case declaredLen < 126:
		hdr = append(hdr, 0x80|byte(declaredLen))
	case declaredLen < 65536:
		hdr = append(hdr, 0x80|126)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(declaredLen))
		hdr = append(hdr, l[:]...)
	default:
		hdr = append(hdr, 0x80|127)
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], declaredLen)
		hdr = append(hdr, l[:]...)
	}
	mask := []byte{0x11, 0x22, 0x33, 0x44}
	hdr = append(hdr, mask...)
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	if !writeBody || len(payload) == 0 {
		return nil
	}
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	_, err := conn.Write(masked)
	return err
}

// Require the size-limit close code, not just any connection error or protocol rejection.
func assertHandshakeTooBig(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatalf("read size-limit close: %v", err)
	}
	if header[0] != 0x88 || header[1]&0x80 != 0 || header[1] < 2 || header[1] >= 126 {
		t.Fatalf("expected unmasked close frame, got %x", header)
	}
	body := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatal(err)
	}
	if code := binary.BigEndian.Uint16(body); code != websocket.CloseMessageTooBig {
		t.Fatalf("close code=%d, want size limit %d", code, websocket.CloseMessageTooBig)
	}
}

// Withhold the body so normalizeToken cannot supply a false-positive rejection.
func TestHandshakeWSRejectsOversizeDeclaredFrameDuringRead(t *testing.T) {
	wsURL, _ := newRelayWSServer(t, 2*time.Second)
	conn := dialRawWS(t, wsURL)
	if err := writeClientFrame(conn, true, 0x01, 64*1024, nil, false); err != nil {
		t.Fatal(err)
	}
	assertHandshakeTooBig(t, conn)
}

// The first two fragments fit (128 total); the final declared two bytes exceed129.
// Withholding those two bytes distinguishes cumulative read limiting from syntax rejection.
func TestHandshakeWSRejectsFragmentedTokenOverlimit(t *testing.T) {
	wsURL, _ := newRelayWSServer(t, 2*time.Second)
	conn := dialRawWS(t, wsURL)
	fragment := bytes.Repeat([]byte("A"), 64)
	if err := writeClientFrame(conn, false, 0x01, 64, fragment, true); err != nil {
		t.Fatal(err)
	}
	if err := writeClientFrame(conn, false, 0x00, 64, fragment, true); err != nil {
		t.Fatal(err)
	}
	if err := writeClientFrame(conn, true, 0x00, 2, nil, false); err != nil {
		t.Fatal(err)
	}
	assertHandshakeTooBig(t, conn)
}

// TestHandshakeWSInvalidEmptyTokenRejected is the direct positive-control for token validation:
// an empty text frame is well under any size cap but is not a valid token, so the server must
// close instead of splicing anything.
func TestHandshakeWSInvalidEmptyTokenRejected(t *testing.T) {
	wsURL, _ := newRelayWSServer(t, 5*time.Second)
	d := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	ws, _, err := d.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()

	if err := ws.WriteMessage(websocket.TextMessage, []byte("")); err != nil {
		t.Fatalf("write empty token: %v", err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatal("empty token was accepted")
	} else {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("empty token was held instead of rejected")
		}
	}
}

// TestHandshakeWSValidTokensRelayLargePayload is the negative control for the fix: after the
// token is accepted, the size cap MUST be lifted, and payloads far larger than maxTokenLen must
// cross intact in BOTH directions. If SetReadLimit stays at maxTokenLen+1 after handshake, this
// leg would fail on the first oversize frame — silently capping every relayed session.
//
// The two-peer variant also exercises Text and Binary token framings against each other, since
// the production wire allows either (handleWS accepts both message types for the token).
func TestHandshakeWSValidTokensRelayLargePayload(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fragmented bool
	}{{"single", false}, {"fragmented", true}} {
		t.Run(tc.name, func(t *testing.T) {
			wsURL, _ := newRelayWSServer(t, 5*time.Second)
			const token = "6f1c9a2e-4b7d-4c8e-9a1f-2d3e4b5c6a7b"

			dialWithToken := func(mt int) *websocket.Conn {
				t.Helper()
				d := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
				ws, _, err := d.Dial(wsURL, nil)
				if err != nil {
					t.Fatalf("dial: %v", err)
				}
				_ = ws.SetWriteDeadline(time.Now().Add(3 * time.Second))
				wire := []byte(token)
				if mt == websocket.TextMessage {
					wire = []byte(strings.Repeat(" ", maxTokenLen+1-len(token)) + token)
				}
				if tc.fragmented && mt == websocket.TextMessage {
					if err := writeClientFrame(ws.UnderlyingConn(), false, 0x01, 64, wire[:64], true); err != nil {
						_ = ws.Close()
						t.Fatal(err)
					}
					if err := writeClientFrame(ws.UnderlyingConn(), true, 0x00, uint64(len(wire)-64), wire[64:], true); err != nil {
						_ = ws.Close()
						t.Fatal(err)
					}
				} else if err := ws.WriteMessage(mt, wire); err != nil {
					_ = ws.Close()
					t.Fatal(err)
				}
				_ = ws.SetWriteDeadline(time.Time{})
				return ws
			}

			a := dialWithToken(websocket.TextMessage)
			t.Cleanup(func() { _ = a.Close() })
			b := dialWithToken(websocket.BinaryMessage)
			t.Cleanup(func() { _ = b.Close() })

			payload := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x01}, 16*1024) // 64 KiB, >> maxTokenLen
			relayOneWay := func(t *testing.T, dir string, from, to *websocket.Conn) {
				t.Helper()
				_ = from.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := from.WriteMessage(websocket.BinaryMessage, payload); err != nil {
					t.Fatalf("%s: write %d bytes: %v", dir, len(payload), err)
				}
				_ = from.SetWriteDeadline(time.Time{})

				_ = to.SetReadDeadline(time.Now().Add(5 * time.Second))
				got := make([]byte, 0, len(payload))
				for len(got) < len(payload) {
					_, r, err := to.NextReader()
					if err != nil {
						t.Fatalf("%s: NextReader after %d/%d bytes: %v", dir, len(got), len(payload), err)
					}
					buf, err := io.ReadAll(r)
					got = append(got, buf...)
					if err != nil && !errors.Is(err, io.EOF) {
						t.Fatalf("%s: read after %d/%d bytes: %v", dir, len(got), len(payload), err)
					}
				}
				_ = to.SetReadDeadline(time.Time{})
				if !bytes.Equal(got, payload) {
					t.Fatalf("%s: relayed bytes differ from what was sent (len got=%d want=%d)",
						dir, len(got), len(payload))
				}
			}

			relayOneWay(t, "a->b", a, b)
			relayOneWay(t, "b->a", b, a)

		})
	}
}
