package main

// The relay's token handshake must be bounded DURING the read, and bounding it must not truncate
// the relayed session that follows.
//
// PREMISE, declared locally: `handleTCP` is the first thing that runs on a fresh connection. Nothing
// has authenticated at that point — the token IS the credential — so whatever this function is
// willing to buffer, an anonymous peer can make it buffer. `normalizeToken` rejects anything over
// `maxTokenLen`, but it only ever saw the line AFTER `bufio.Reader.ReadString('\n')` had already
// accumulated it, and ReadString grows until it finds a newline. The 10s handshake deadline bounds
// the TIME, not the volume.
//
// The second half of this test exists because the obvious fix breaks the product: if the session
// keeps reading through the exhausted LimitReader it hits EOF the moment the handshake budget runs
// out, so a bounded handshake would silently cap every relayed session at ~128 bytes. A test that
// only asserted the bound would call that a success. Both legs, therefore.

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// serveOne runs handleTCP against one side of a net.Pipe, as the accept loop would.
func serveOne(conn net.Conn, broker *Broker) {
	go handleTCP(conn, broker)
}

func TestHandshakeIsBoundedButTheSessionIsNot(t *testing.T) {
	// --- Leg 1: an endless newline-less handshake is refused, not buffered ------------------------
	//
	// This leg deliberately uses a REAL TCP socket rather than net.Pipe. net.Pipe is synchronous and
	// unbuffered, so a large client write blocks on the server reading it, and the client's own
	// write deadline then expires no matter what the server does — the assertion would pass against
	// the unbounded code too. (Confirmed by mutation: the first version of this test passed with the
	// LimitReader removed.) Over TCP the kernel buffers, the write completes, and the server's
	// behaviour is the only thing left to observe.
	//
	// The discriminator is TIME TO CLOSE. Bounded: the reader stops at maxTokenLen+1, normalizeToken
	// rejects an over-length token, and the connection closes at once. Unbounded: the server keeps
	// consuming, finds no newline, and holds the connection until the 10s handshake deadline — so an
	// anonymous peer commands a goroutine, a socket and a growing buffer for ten seconds a time.
	broker := NewBroker(time.Second, 0)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		handleTCP(c, broker)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	junk := bytes.Repeat([]byte("A"), 64*1024) // no '\n' anywhere
	_ = client.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = client.Write(junk) // may partially fail once the server hangs up; that is fine

	// A bounded server has already closed. Allow far more slack than it needs, but stay well under
	// the 10s handshake deadline that is the unbounded path's only stopping condition.
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	buf := make([]byte, 1)
	_, rerr := client.Read(buf)
	elapsed := time.Since(start)
	if rerr == nil {
		t.Fatal("server sent data in response to a junk handshake")
	}
	if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
		t.Fatalf("the relay held an unauthenticated, newline-less handshake open for %v: it buffered "+
			"64 KiB and is still waiting for a newline (bounded reads close immediately)", elapsed)
	}
	_ = client.Close()

	// --- Leg 2: a normal session still relays payloads far larger than the handshake bound --------
	// This is the negative control for the fix: it must bound the HANDSHAKE, not the session.
	broker2 := NewBroker(2 * time.Second, 0)
	aClient, aServer := net.Pipe()
	bClient, bServer := net.Pipe()
	serveOne(aServer, broker2)
	serveOne(bServer, broker2)

	const token = "6f1c9a2e-4b7d-4c8e-9a1f-2d3e4b5c6a7b\n"
	// Pipe writes block until read, so drive both handshakes from goroutines.
	awaitWrite(t, startWrite(aClient, []byte(token)))
	awaitWrite(t, startWrite(bClient, []byte(token)))

	// A payload an order of magnitude past maxTokenLen must cross intact.
	payload := bytes.Repeat([]byte("xyz123"), 4096) // 24 KiB >> maxTokenLen (128)
	w := startWrite(aClient, payload)

	got := make([]byte, len(payload))
	_ = bClient.SetReadDeadline(time.Now().Add(5 * time.Second))
	n := 0
	for n < len(got) {
		m, err := bClient.Read(got[n:])
		if err != nil {
			t.Fatalf("relayed session truncated after %d of %d bytes (%v) — the handshake bound leaked "+
				"into the session", n, len(got), err)
		}
		n += m
	}
	awaitWrite(t, w)
	if !bytes.Equal(got, payload) {
		t.Fatal("relayed bytes differ from what was sent")
	}
	_ = aClient.Close()
	_ = bClient.Close()
}
