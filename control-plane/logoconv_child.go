package controlplane

// The logo-convert CHILD and its PARENT supervisor (docs/66 2b.3).
//
// CHILD: `controlplane logo-convert` (cmd/controlplane/main.go calls RunLogoConvertChild). It has no database
// handle, no secrets and no network use: the parent starts it with an EMPTY environment. It first applies its
// own resource limits (applyChildLimits: Linux RLIMIT_AS 256 MiB + RLIMIT_CPU 3 s; Windows a Job Object with a
// 256 MiB process memory limit and a 3 s process CPU limit; an unsupported platform refuses), THEN reads the
// raw upload from stdin, and writes the derived PNG to stdout. Failure is a non-zero exit status and one fixed
// code on stderr (never a message derived from the input). If the limits cannot be applied the child exits
// without reading anything: conversion fails CLOSED.
//
// PARENT (LogoConverter): runs the child with a hard 3 s WALL-TIME deadline after which the PROCESS is killed
// (not a goroutine) and waited on; stdout is read through a 128 KiB cap and stderr keeps at most 256 bytes;
// the output is re-verified (valid PNG, inside 512x256, at most 64 KiB) before it is returned. Capacity is a
// bounded queue: 2 running, 8 waiting, the next one is refused (the handler answers 429). A permit is held
// until the child has actually EXITED, so a stuck decode is killed by the deadline and only then frees
// capacity, and two stuck decodes cannot disable conversion beyond that deadline.
//
// The working directory is the OS temporary directory (the child never opens a file); it is not enforced
// read-only, which no portable API offers. On Windows Go adds SYSTEMROOT to an otherwise empty environment.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// ErrLogoBusy: the conversion queue (2 running + 8 waiting) is full. The handler answers 429.
var ErrLogoBusy = errors.New("logo conversion is busy; retry shortly")

// ErrLogoTimeout: the child exceeded its wall-time deadline and was killed.
var ErrLogoTimeout = &LogoError{Code: "E_TIME", Msg: "the image took too long to process; try a simpler image"}

// ErrLogoUnsupported: this build or platform cannot run the child under resource limits, so uploads are
// refused rather than decoded unbounded.
var ErrLogoUnsupported = errors.New("logo upload is not supported on this deployment")

// Child resource limits.
const (
	logoChildMemoryBytes = 256 << 20
	logoChildCPUSeconds  = 3
)

// RunLogoConvertChild is the body of `controlplane logo-convert`. It returns the process exit code.
func RunLogoConvertChild(stdin io.Reader, stdout, stderr io.Writer) int {
	fail := func(code string, exit int) int {
		_, _ = io.WriteString(stderr, code)
		return exit
	}
	if err := applyChildLimits(); err != nil {
		return fail("E_LIMITS", 4)
	}
	raw, over, err := readLimited(stdin, LogoMaxInputBytes)
	if err != nil {
		return fail("E_READ", 3)
	}
	if over {
		return fail(ErrLogoTooBigInput.Code, 3)
	}
	out, err := ConvertLogo(raw)
	if err != nil {
		var le *LogoError
		if errors.As(err, &le) {
			return fail(le.Code, 3)
		}
		return fail("E_INTERNAL", 5)
	}
	if _, err := stdout.Write(out); err != nil {
		return fail("E_WRITE", 5)
	}
	return 0
}

// exitStatus is the child's exit code, or -1 when it was not a normal exit.
func exitStatus(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// LogoConverter supervises the child. The zero value is not usable: use NewLogoConverter.
type LogoConverter struct {
	// Command builds the child's command. nil = this executable with the single argument "logo-convert".
	Command func() *exec.Cmd
	// Deadline is the wall-time limit (default 3 s).
	Deadline time.Duration
	// Hooks for tests: called around the child's life (start before the process is created, exit after it
	// has been waited for), always while the permit is held.
	OnStart func()
	OnExit  func()

	sem     chan struct{}
	maxWait int32
	waiting atomic.Int32
	started atomic.Int64
	killed  atomic.Int64

	limitsFailed atomic.Bool
}

// NewLogoConverter builds a converter admitting `running` concurrent conversions and `waiting` queued ones.
func NewLogoConverter(running, waiting int) *LogoConverter {
	if running <= 0 {
		running = 2
	}
	if waiting < 0 {
		waiting = 8
	}
	return &LogoConverter{sem: make(chan struct{}, running), maxWait: int32(waiting)}
}

// Supported reports whether this platform can run the child under limits (see applyChildLimits).
// A child that reports E_LIMITS (the limit could not be applied at RUNTIME: Job Object assignment refused, setrlimit
// failed) latches support off for the life of the process, so the capability stops being advertised and the
// route answers 501 instead of a generic 5xx (repair B5).
func (c *LogoConverter) Supported() bool { return childLimitsSupported && !c.limitsFailed.Load() }

// Stats: children started and children killed by the deadline or the output cap (tests, metrics).
func (c *LogoConverter) Stats() (started, killed int64) { return c.started.Load(), c.killed.Load() }

func (c *LogoConverter) deadline() time.Duration {
	if c.Deadline > 0 {
		return c.Deadline
	}
	return LogoDefaultDeadline * time.Second
}

func (c *LogoConverter) command() (*exec.Cmd, error) {
	if c.Command != nil {
		return c.Command(), nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, "logo-convert")
	return cmd, nil
}

// admit takes a running slot, queueing up to maxWait callers, or refuses.
func (c *LogoConverter) admit(ctx context.Context) error {
	select {
	case c.sem <- struct{}{}:
		return nil
	default:
	}
	if c.waiting.Add(1) > c.maxWait {
		c.waiting.Add(-1)
		return ErrLogoBusy
	}
	defer c.waiting.Add(-1)
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// capWriter keeps at most limit bytes and trips `over` (and fires onOver once) beyond it.
type capWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	limit  int
	over   bool
	onOver func()
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := w.limit - w.buf.Len(); room > 0 {
		if len(p) <= room {
			w.buf.Write(p)
		} else {
			w.buf.Write(p[:room])
			w.over = true
		}
	} else if len(p) > 0 {
		w.over = true
	}
	if w.over && w.onOver != nil {
		f := w.onOver
		w.onOver = nil
		go f()
	}
	return len(p), nil
}

// discardTail keeps the first limit bytes and silently drops the rest (stderr).
type discardTail struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
}

func (w *discardTail) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := w.limit - w.buf.Len(); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		w.buf.Write(p[:room])
	}
	return len(p), nil
}

// Convert runs one conversion. Errors that are the Owner's to fix are *LogoError; ErrLogoBusy and
// ErrLogoUnsupported are capacity and platform; anything else is an infrastructure failure.
func (c *LogoConverter) Convert(ctx context.Context, raw []byte) ([]byte, error) {
	if !c.Supported() {
		return nil, ErrLogoUnsupported
	}
	if len(raw) == 0 {
		return nil, ErrLogoUnreadable
	}
	if len(raw) > LogoMaxInputBytes {
		return nil, ErrLogoTooBigInput
	}
	if err := c.admit(ctx); err != nil {
		return nil, err
	}
	// The permit is released only after the child has EXITED (below), never before.
	defer func() { <-c.sem }()
	return c.runChild(raw)
}

func (c *LogoConverter) runChild(raw []byte) ([]byte, error) {
	cmd, err := c.command()
	if err != nil {
		return nil, err
	}
	cmd.Env = []string{} // an EMPTY environment: no secrets, no configuration
	cmd.Dir = os.TempDir()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	var killOnce sync.Once
	kill := func() {
		killOnce.Do(func() {
			c.killed.Add(1)
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		})
	}
	out := &capWriter{limit: logoStdoutCap, onOver: kill}
	errw := &discardTail{limit: logoStderrCap}
	cmd.Stdout, cmd.Stderr = out, errw

	if c.OnStart != nil {
		c.OnStart()
	}
	c.started.Add(1)
	if err := cmd.Start(); err != nil {
		if c.OnExit != nil {
			c.OnExit()
		}
		return nil, err
	}
	var timedOut atomic.Bool
	timer := time.AfterFunc(c.deadline(), func() { timedOut.Store(true); kill() })
	go func() {
		_, _ = stdin.Write(raw)
		_ = stdin.Close()
	}()
	waitErr := cmd.Wait() // the child has exited (killed or finished) when this returns
	timer.Stop()
	if c.OnExit != nil {
		c.OnExit()
	}

	out.mu.Lock()
	body, over := append([]byte(nil), out.buf.Bytes()...), out.over
	out.mu.Unlock()
	errw.mu.Lock()
	code := errw.buf.String()
	errw.mu.Unlock()

	if waitErr != nil {
		// ONLY the child's own first action emits E_LIMITS (RunLogoConvertChild applies its limits BEFORE it reads
		// stdin, exit status 4); nothing an image can provoke reaches that line. The exit status is checked too, so a
		// crashing decoder's stderr can never be mistaken for it (r2-2).
		if code == "E_LIMITS" && exitStatus(waitErr) == 4 {
			c.limitsFailed.Store(true)
			return nil, ErrLogoUnsupported
		}
		if timedOut.Load() {
			return nil, ErrLogoTimeout
		}
		if le := logoErrorByCode(code); le != nil {
			return nil, le
		}
		return nil, errors.New("logo conversion failed")
	}
	if over {
		return nil, errors.New("logo conversion failed")
	}
	if err := VerifyConvertedLogo(body); err != nil {
		return nil, err
	}
	return body, nil
}
