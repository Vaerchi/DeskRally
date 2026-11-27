package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// A quiet peer (a browser console that sends nothing after joining) must keep receiving pings, so its
// pong refreshes the server's read deadline instead of the socket being reaped (2026-11-27). The loop
// must also stop when the connection's handler exits.
func TestPingLoopPingsUntilDone(t *testing.T) {
	serverConn := make(chan *websocket.Conn, 1)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		serverConn <- c
	}))
	defer srv.Close()

	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var pings atomic.Int32
	client.SetPingHandler(func(string) error { pings.Add(1); return nil })
	go func() {
		for {
			if _, _, err := client.ReadMessage(); err != nil { // control frames are handled inside reads
				return
			}
		}
	}()

	conn := <-serverConn
	defer conn.Close()
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() { pingLoop(conn, 20*time.Millisecond, done); close(stopped) }()

	deadline := time.Now().Add(5 * time.Second)
	for pings.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := pings.Load(); got < 3 {
		t.Fatalf("pings received = %d, want >= 3", got)
	}
	close(done)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("pingLoop did not stop after done was closed")
	}
}

func TestPingLoopDisabledForNonPositiveInterval(t *testing.T) {
	finished := make(chan struct{})
	go func() { pingLoop(nil, 0, make(chan struct{})); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("pingLoop with interval 0 must return at once")
	}
}
