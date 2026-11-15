package controlplane

// The control plane's public listener settings (docs/66 2d.2, 2e.2).
//
// The control plane listens ONCE, on plain HTTP behind Caddy (there is no separate public listener), so these
// bounds apply to that one listener. They are the CP's own limits and hold for any client that can reach it;
// Caddy's timeouts sit in front and do not replace them.
//
//   - HTTP/1.1 ONLY: TLSNextProto is an empty non-nil map (no h2 upgrade even if a TLS listener is ever put
//     in front directly) and no h2c handler is installed, so the connection cap bounds concurrent requests
//     (no multiplexed streams).
//   - ReadHeaderTimeout 5 s, ReadTimeout 5 s (the whole request, headers and body), MaxHeaderBytes 16 KiB.
//     Routes with legitimately long uploads (central recording) extend their own read deadline per route
//     through http.ResponseController, as they already did.
//   - a connection cap (default 1024) from an in-repo counting listener: golang.org/x/net is not a dependency
//     of this module and one small type does not justify adding it.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

// Public listener defaults.
const (
	DefaultMaxConns          = 1024
	DefaultReadHeaderTimeout = 5 * time.Second
	DefaultReadTimeout       = 5 * time.Second
	DefaultIdleTimeout       = 60 * time.Second
	MaxRequestHeaderBytes    = 16 << 10
)

// PublicServerConfig tunes NewPublicServer. Zero values mean the defaults above.
type PublicServerConfig struct {
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

// NewPublicServer builds the http.Server with the HTTP/1.1-only, bounded settings.
func NewPublicServer(addr string, h http.Handler, cfg PublicServerConfig) *http.Server {
	or := func(v, d time.Duration) time.Duration {
		if v <= 0 {
			return d
		}
		return v
	}
	protos := new(http.Protocols)
	protos.SetHTTP1(true) // HTTP/1.1 only: no HTTP/2 and no unencrypted HTTP/2 (h2c)
	return &http.Server{
		Protocols:         protos,
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: or(cfg.ReadHeaderTimeout, DefaultReadHeaderTimeout),
		ReadTimeout:       or(cfg.ReadTimeout, DefaultReadTimeout),
		// 60 s: sized for the largest legitimate response (a 10 000-event audit export), as before.
		WriteTimeout:   or(cfg.WriteTimeout, 60*time.Second),
		IdleTimeout:    or(cfg.IdleTimeout, DefaultIdleTimeout),
		MaxHeaderBytes: MaxRequestHeaderBytes,
		// The accepted connection is captured into every request context so the public-exchange bound can CLOSE it
		// actively (publicbounds.go): a handler that stalls without I/O is otherwise beyond every deadline.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connCtxKey{}, c)
		},
		// Empty, non-nil: HTTP/2 is disabled for any TLS listener; nothing here speaks h2c.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
}

// LimitListener caps simultaneous connections at n: Accept blocks while n are open, which leaves further
// connections in the kernel backlog instead of spending a goroutine and a file descriptor on each.
func LimitListener(l net.Listener, n int) net.Listener {
	if n <= 0 {
		n = DefaultMaxConns
	}
	return &limitListener{Listener: l, sem: make(chan struct{}, n), done: make(chan struct{})}
}

type limitListener struct {
	net.Listener
	sem       chan struct{}
	closeOnce sync.Once
	done      chan struct{}
}

func (l *limitListener) acquire() bool {
	select {
	case <-l.done:
		return false
	case l.sem <- struct{}{}:
		return true
	}
}

func (l *limitListener) release() { <-l.sem }

func (l *limitListener) Accept() (net.Conn, error) {
	if !l.acquire() {
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		l.release()
		return nil, err
	}
	return &limitListenerConn{Conn: c, release: l.release}, nil
}

func (l *limitListener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.done) })
	return err
}

type limitListenerConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (c *limitListenerConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}

// connCtxKey carries the request's net.Conn in its context (see NewPublicServer).
type connCtxKey struct{}
