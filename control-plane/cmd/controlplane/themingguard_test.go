package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	controlplane "rmt/controlplane"
)

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, format)
}

func (l *logSink) n() int { l.mu.Lock(); defer l.mu.Unlock(); return len(l.lines) }

func counter(n int64, err error) func(context.Context) (int64, error) {
	return func(context.Context) (int64, error) { return n, err }
}

func TestThemingOffNoAssignmentsStarts(t *testing.T) {
	var s logSink
	if err := themingOffGuard(context.Background(), nil, counter(0, nil), "", s.logf, time.Hour); err != nil {
		t.Fatalf("no assignments: %v", err)
	}
	// Even with the escape hatch set, nothing to warn about when no assignment exists.
	if err := themingOffGuard(context.Background(), nil, counter(0, nil), controlplane.ThemingEscapeValue, s.logf, time.Hour); err != nil || s.n() != 0 {
		t.Fatalf("escape hatch without assignments: %v, %d log lines", err, s.n())
	}
}

func TestThemingOffWithAnActiveAssignmentRefusesToStart(t *testing.T) {
	var s logSink
	for _, escape := range []string{"", "yes", "I-UNDERSTAND", "i-understand "} {
		err := themingOffGuard(context.Background(), nil, counter(2, nil), escape, s.logf, time.Hour)
		if !errors.Is(err, controlplane.ErrThemingOffWithAssignments) || !strings.Contains(err.Error(), "release the assignments first") {
			t.Fatalf("escape %q: %v, want the refusal", escape, err)
		}
	}
	if s.n() != 0 {
		t.Fatal("a refusal must not start the warning loop")
	}
}

func TestEscapeHatchStartsAndWarnsRepeatedly(t *testing.T) {
	var s logSink
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := themingOffGuard(ctx, nil, counter(1, nil), controlplane.ThemingEscapeValue, s.logf, 30*time.Millisecond); err != nil {
		t.Fatalf("escape hatch: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.n() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.n() < 3 || !strings.Contains(s.lines[0], "WARNING") {
		t.Fatalf("warning not repeated: %d lines %v", s.n(), s.lines)
	}
	cancel()
}

// A database failure keeps the existing startup behaviour (an error the caller treats as fatal): never fail-open.
func TestThemingOffGuardDatabaseFailureIsAnError(t *testing.T) {
	var s logSink
	err := themingOffGuard(context.Background(), nil, counter(0, errors.New("connection refused")), controlplane.ThemingEscapeValue, s.logf, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "migration 0071") {
		t.Fatalf("db failure: %v", err)
	}
}

// With the policy ENABLED the guard is not consulted (the live-among check covers that mode).
func TestThemingOffGuardIsSkippedWhenThePolicyIsOn(t *testing.T) {
	clearHostEnv(t)
	t.Setenv("CP_HOST_THEMING", "on")
	t.Setenv("CP_EDGE_SECRET", testSecret)
	p, err := buildHostPolicy(".deskrally.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := themingOffGuard(context.Background(), p, counter(5, nil), "", func(string, ...any) {}, time.Hour); err != nil {
		t.Fatalf("policy on: %v", err)
	}
}
