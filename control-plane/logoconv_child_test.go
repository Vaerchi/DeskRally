package controlplane

// docs/66 2b.3: the logo child in a REAL process. The test binary doubles as the child: TestMain dispatches
// `logo-convert` to the production entry point (RunLogoConvertChild, the same function cmd/controlplane calls)
// and a few `logo-test-*` modes that misbehave on purpose. Nothing here fakes the process boundary.

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "gate-client": // the docs/66 release gate's timing client (releasegate_client_test.go)
			os.Exit(runGateClient(os.Stdin, os.Stdout))
		case "logo-convert":
			os.Exit(RunLogoConvertChild(os.Stdin, os.Stdout, os.Stderr))
		case "logo-test-hang": // never answers
			time.Sleep(time.Hour)
		case "logo-test-slow": // the real conversion, after a delay (queue tests)
			time.Sleep(450 * time.Millisecond)
			os.Exit(RunLogoConvertChild(os.Stdin, os.Stdout, os.Stderr))
		case "logo-test-memhog": // the production limits, then try to hold 400 MiB
			if err := applyChildLimits(); err != nil {
				os.Stderr.WriteString("E_LIMITS")
				os.Exit(4)
			}
			b := make([]byte, 400<<20)
			for i := 0; i < len(b); i += 4096 {
				b[i] = 1
			}
			// Survived the allocation: answer like a successful conversion, so an UNLIMITED child is a visible
			// failure of the test (a nil error), not merely a garbled one.
			img := image.NewNRGBA(image.Rect(0, 0, 8, 8))
			_ = png.Encode(os.Stdout, img)
			os.Exit(0)
		case "logo-test-spin": // the production limits, then burn CPU forever
			if err := applyChildLimits(); err != nil {
				os.Exit(4)
			}
			for x := 0; ; x++ {
				_ = x
			}
		case "logo-test-env": // report the environment to the file named by argv[2]
			_ = os.WriteFile(os.Args[2], []byte(strings.Join(os.Environ(), "\n")+"|"), 0o600)
			os.Exit(0)
		case "logo-test-limits-fail": // the child could not apply its limits at runtime
			os.Stderr.WriteString("E_LIMITS")
			os.Exit(4)
		case "logo-test-fake-limits": // says E_LIMITS but is NOT the limit-installation failure (exit status 5)
			os.Stderr.WriteString("E_LIMITS")
			os.Exit(5)
		case "logo-test-flood": // more than 128 KiB on stdout
			os.Stdout.Write(bytes.Repeat([]byte("x"), 1<<20))
			time.Sleep(time.Hour)
		}
	}
	os.Exit(m.Run())
}

func selfCmd(args ...string) func() *exec.Cmd {
	return func() *exec.Cmd { return exec.Command(os.Args[0], args...) }
}

func testConverter(running, waiting int, args ...string) *LogoConverter {
	c := NewLogoConverter(running, waiting)
	c.Command = selfCmd(args...)
	return c
}

func goodLogo(t testing.TB) []byte {
	return solidPNG(t, 300, 100, color.NRGBA{R: 53, G: 101, B: 74, A: 255})
}

func TestChildConvertsALogoEndToEnd(t *testing.T) {
	c := testConverter(2, 8, "logo-convert")
	out, err := c.Convert(t.Context(), goodLogo(t))
	if err != nil {
		t.Fatal(err)
	}
	if w, h := outDims(t, out); w != 300 || h != 100 {
		t.Errorf("%dx%d", w, h)
	}
	if err := VerifyConvertedLogo(out); err != nil {
		t.Error(err)
	}
}

func TestChildRefusalsComeBackAsTheFixedCodes(t *testing.T) {
	c := testConverter(2, 8, "logo-convert")
	for name, tc := range map[string]struct {
		raw  []byte
		want *LogoError
	}{
		"svg":       {[]byte("<svg/>"), ErrLogoFormat},
		"bomb":      {bombPNG(30000, 30000), ErrLogoDimensions},
		"truncated": {goodLogo(t)[:50], ErrLogoUnreadable},
		"noisy":     {noisePNG(t, 150, 150), ErrLogoTooBigOutput},
	} {
		_, err := c.Convert(t.Context(), tc.raw)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v want %v", name, err, tc.want)
		}
	}
	// The parent refuses what it can see itself without spending a process.
	started, _ := c.Stats()
	if _, err := c.Convert(t.Context(), nil); !errors.Is(err, ErrLogoUnreadable) {
		t.Errorf("empty: %v", err)
	}
	if _, err := c.Convert(t.Context(), make([]byte, LogoMaxInputBytes+1)); !errors.Is(err, ErrLogoTooBigInput) {
		t.Errorf("oversize: %v", err)
	}
	if s2, _ := c.Stats(); s2 != started {
		t.Errorf("a refusal the parent could see spent a child process")
	}
}

func TestChildHasAnEmptyEnvironment(t *testing.T) {
	t.Setenv("CP_SECRET_FOR_TEST", "hunter2")
	t.Setenv("DATABASE_URL", "postgres://secret")
	file := t.TempDir() + "/env.txt"
	c := testConverter(1, 0, "logo-test-env", file)
	_, _ = c.Convert(t.Context(), goodLogo(t)) // errors: the helper emits no PNG
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	env := string(b)
	for _, leak := range []string{"hunter2", "CP_SECRET", "DATABASE_URL", "PATH="} {
		if strings.Contains(env, leak) {
			t.Errorf("the child inherited %q: %s", leak, env)
		}
	}
	// Windows adds SYSTEMROOT to an otherwise empty environment; nothing else may be there.
	for _, line := range strings.Split(strings.TrimSuffix(env, "|"), "\n") {
		if line == "" || strings.HasPrefix(strings.ToUpper(line), "SYSTEMROOT=") {
			continue
		}
		t.Errorf("unexpected variable in the child: %q", line)
	}
}

func TestChildThatNeverAnswersIsKilledAtTheDeadline(t *testing.T) {
	c := testConverter(2, 8, "logo-test-hang")
	c.Deadline = 400 * time.Millisecond
	start := time.Now()
	_, err := c.Convert(t.Context(), goodLogo(t))
	el := time.Since(start)
	if !errors.Is(err, ErrLogoTimeout) {
		t.Fatalf("got %v, want the timeout", err)
	}
	if el < 350*time.Millisecond || el > 3*time.Second {
		t.Errorf("killed after %v, want about 400 ms", el)
	}
	if _, killed := c.Stats(); killed != 1 {
		t.Errorf("killed = %d", killed)
	}
	// The permit came back: a second conversion is admitted at once (not queued behind a corpse).
	c.Command = selfCmd("logo-convert")
	if _, err := c.Convert(t.Context(), goodLogo(t)); err != nil {
		t.Errorf("after a kill: %v", err)
	}
}

func TestOutputOverTheCapKillsTheChild(t *testing.T) {
	c := testConverter(1, 0, "logo-test-flood")
	c.Deadline = 5 * time.Second
	start := time.Now()
	_, err := c.Convert(t.Context(), goodLogo(t))
	if err == nil {
		t.Fatal("a 1 MiB stdout was accepted")
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("flood not cut: %v", time.Since(start))
	}
	if _, killed := c.Stats(); killed != 1 {
		t.Errorf("killed = %d", killed)
	}
}

// A bomb that gets past the dimension gate (here: a memory hog standing in for a decoder bug) dies under the
// child's own limit, and the parent survives and reports a plain failure. Linux: RLIMIT_AS. Windows: the Job
// Object memory limit. A platform without a limit refuses uploads instead (asserted below).
func TestChildDiesUnderItsMemoryLimitAndTheParentSurvives(t *testing.T) {
	c := testConverter(1, 0, "logo-test-memhog")
	c.Deadline = 10 * time.Second
	if !c.Supported() {
		if _, err := c.Convert(t.Context(), goodLogo(t)); !errors.Is(err, ErrLogoUnsupported) {
			t.Fatalf("unsupported platform must refuse: %v", err)
		}
		t.Skip("no child limits on this platform: uploads are refused (asserted)")
	}
	out, err := c.Convert(t.Context(), goodLogo(t))
	if err == nil {
		t.Fatalf("the memory hog finished (%q): the limit is not applied", out)
	}
	var le *LogoError
	if errors.As(err, &le) {
		t.Errorf("an infrastructure death must not look like an Owner error: %v", err)
	}
}

func TestChildIsStoppedByTheCPULimit(t *testing.T) {
	if testing.Short() {
		t.Skip("burns 3 s of CPU")
	}
	c := testConverter(1, 0, "logo-test-spin")
	c.Deadline = 20 * time.Second // far beyond the 3 s CPU limit: the LIMIT must end it
	start := time.Now()
	_, err := c.Convert(t.Context(), goodLogo(t))
	el := time.Since(start)
	if err == nil || errors.Is(err, ErrLogoTimeout) {
		t.Fatalf("got %v: the wall-time kill ended it, not the CPU limit", err)
	}
	if el > 12*time.Second {
		t.Errorf("took %v", el)
	}
}

func TestQueueAdmitsTwoRunsEightWaitsAndRefusesTheRest(t *testing.T) {
	c := testConverter(2, 8, "logo-test-slow")
	var live, peak atomic.Int32
	c.OnStart = func() {
		n := live.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
	}
	c.OnExit = func() { live.Add(-1) }
	raw := goodLogo(t)
	const n = 20
	var wg sync.WaitGroup
	var ok, busy, other atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.Convert(t.Context(), raw)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrLogoBusy):
				busy.Add(1)
			default:
				other.Add(1)
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if p := peak.Load(); p > 2 {
		t.Errorf("%d children alive at once, the cap is 2", p)
	}
	if ok.Load() != 10 || busy.Load() != 10 {
		t.Errorf("ok=%d busy=%d, want 10 admitted (2 running + 8 waiting) and 10 refused", ok.Load(), busy.Load())
	}
}

// The permit is held until the child has EXITED. The hooks bracket the process's life, so if the permit were
// released earlier (at the kill, or at the timeout) more than the cap could sit between OnStart and OnExit.
func TestPermitIsHeldUntilTheChildExits(t *testing.T) {
	c := testConverter(2, 8, "logo-test-hang")
	c.Deadline = 150 * time.Millisecond
	var live, peak atomic.Int32
	c.OnStart = func() {
		n := live.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
	}
	c.OnExit = func() { time.Sleep(30 * time.Millisecond); live.Add(-1) } // exit bookkeeping is slow
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Convert(t.Context(), goodLogo(t))
		}()
	}
	wg.Wait()
	if p := peak.Load(); p != 2 {
		t.Errorf("peak concurrent children = %d, want exactly the cap of 2", p)
	}
	if live.Load() != 0 {
		t.Errorf("live = %d", live.Load())
	}
}

func TestQueuedCallerGivesUpWhenItsContextEnds(t *testing.T) {
	c := testConverter(1, 8, "logo-test-hang")
	c.Deadline = 2 * time.Second
	go func() { _, _ = c.Convert(t.Context(), goodLogo(t)) }()
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	_, err := c.Convert(ctx, goodLogo(t))
	if err == nil || errors.Is(err, ErrLogoBusy) {
		t.Fatalf("got %v, want the context error from the queue", err)
	}
}

// B5: a limit that cannot be applied at runtime turns support off: ErrLogoUnsupported (501 on the route), the
// capability reports false, and no further child is spent.
func TestRuntimeLimitFailureLatchesUploadSupportOff(t *testing.T) {
	c := testConverter(2, 8, "logo-test-limits-fail")
	if !c.Supported() {
		t.Skip("no child limits on this platform")
	}
	if _, err := c.Convert(t.Context(), goodLogo(t)); !errors.Is(err, ErrLogoUnsupported) {
		t.Fatalf("E_LIMITS: %v, want ErrLogoUnsupported", err)
	}
	if c.Supported() {
		t.Fatal("support is still advertised after the limits failed")
	}
	started, _ := c.Stats()
	if _, err := c.Convert(t.Context(), goodLogo(t)); !errors.Is(err, ErrLogoUnsupported) {
		t.Fatalf("second upload: %v", err)
	}
	if s, _ := c.Stats(); s != started {
		t.Error("a child was spent after support was latched off")
	}
	// Over HTTP: 501, and the Owner state tells the console to hide the field.
	b := newBrandSrv(t, RoleOwner, "00000000-0000-0000-0000-0000000000dd")
	b.srv.LogoConverter = testConverter(2, 8, "logo-test-limits-fail")
	body := revBody("Limits Co", `,"logo_data_uri":"`+pngDataURI(goodLogo(t))+`"`)
	if code, _, _ := b.call("POST", "/tenant/branding/revisions", body); code != http.StatusNotImplemented {
		t.Errorf("first upload over HTTP: %d, want 501 (not a generic 5xx)", code)
	}
	if _, out, _ := b.call("GET", "/tenant/branding/revisions", ""); out["logo_upload_supported"] != false {
		t.Errorf("capability after the failure: %v", out["logo_upload_supported"])
	}
}

// B1: the WORST VALID input (the largest image the gates admit: 2000x2000, 4 megapixels, as PNG and as JPEG)
// converts inside the child under its real memory limit. On Linux this is the test that failed under RLIMIT_AS:
// a Go child could not even start a decode inside 256 MiB of address space.
func TestChildConvertsTheLargestAllowedImagesUnderItsLimits(t *testing.T) {
	c := testConverter(1, 0, "logo-convert")
	c.Deadline = 20 * time.Second
	for name, raw := range map[string][]byte{
		"png 2000x2000":  solidPNG(t, 2000, 2000, color.NRGBA{R: 53, G: 101, B: 74, A: 255}),
		"jpeg 2000x2000": solidJPEG(t, 2000, 2000),
	} {
		out, err := c.Convert(t.Context(), raw)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if w, h := outDims(t, out); w != 256 || h != 256 {
			t.Errorf("%s: %dx%d", name, w, h)
		}
	}
}

func solidJPEG(t testing.TB, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := range img.Pix {
		img.Pix[i] = 180
	}
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: 50}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// r2-2: only the child's own limit installation (before it reads stdin) can say E_LIMITS. Everything a hostile
// image can provoke (memory exhaustion under the limit, the CPU limit, the wall-time kill) is an ordinary failure
// and must NOT turn upload support off: a following valid upload still succeeds.
func TestHostileImagesNeverLatchUploadSupportOff(t *testing.T) {
	c := NewLogoConverter(1, 0)
	c.Deadline = 4 * time.Second
	for name, args := range map[string][]string{
		"memory bomb (dies under the limit)": {"logo-test-memhog"},
		"cpu bomb (killed by the CPU limit)": {"logo-test-spin"},
		"decoder hang (wall-time kill)":      {"logo-test-hang"},
		"stdout flood (killed)":              {"logo-test-flood"},
	} {
		if name == "cpu bomb (killed by the CPU limit)" && testing.Short() {
			continue
		}
		c.Command = selfCmd(args...)
		if name == "decoder hang (wall-time kill)" || name == "stdout flood (killed)" {
			c.Deadline = 600 * time.Millisecond
		} else {
			c.Deadline = 20 * time.Second
		}
		_, err := c.Convert(t.Context(), goodLogo(t))
		if err == nil || errors.Is(err, ErrLogoUnsupported) {
			t.Fatalf("%s: %v (must be an ordinary failure, never ErrLogoUnsupported)", name, err)
		}
		if !c.Supported() {
			t.Fatalf("%s latched upload support OFF", name)
		}
		c.Command = selfCmd("logo-convert")
		c.Deadline = 5 * time.Second
		if _, err := c.Convert(t.Context(), goodLogo(t)); err != nil {
			t.Fatalf("%s: a valid upload afterwards failed: %v", name, err)
		}
	}
}

// A stderr that merely says E_LIMITS without the child's own exit status 4 is not the limit-installation failure.
func TestLimitsLatchNeedsTheChildsOwnExitStatus(t *testing.T) {
	if exitStatus(nil) != -1 {
		t.Error("exitStatus(nil)")
	}
	c := testConverter(1, 0, "logo-test-limits-fail")
	if !c.Supported() {
		t.Skip("no child limits on this platform")
	}
	fake := testConverter(1, 0, "logo-test-fake-limits")
	if _, err := fake.Convert(t.Context(), goodLogo(t)); errors.Is(err, ErrLogoUnsupported) || !fake.Supported() {
		t.Fatalf("an E_LIMITS-looking stderr with exit status 5 latched support off: %v", err)
	}
	if _, err := c.Convert(t.Context(), goodLogo(t)); !errors.Is(err, ErrLogoUnsupported) || c.Supported() {
		t.Fatalf("the real E_LIMITS (exit 4) must latch: %v supported=%v", err, c.Supported())
	}
}
