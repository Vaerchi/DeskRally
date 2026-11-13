package main

// Guard: an environment variable this binary reads must reach it in the production compose stack.
//
// Production runs deploy/docker-compose.yml merged with deploy/docker-compose.prod.yml, and `environment:`
// maps merge per key. A container sees ONLY the keys the merged files name, so a variable the server reads
// but no file forwards is a .env line that silently does nothing. That happened twice (signaling's TURN
// credential caps, most recently); the symptom is the default quietly applying while the operator believes
// the knob is set. Optional overlays (docker-compose.installer.yml) are NOT production: what only an
// overlay forwards is listed in composeOverlayClaims, and the test checks the overlay still names it.
//
// The scanner and the rule live in envscan_test.go (identical across the three server binaries).

import (
	"go/ast"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const composeDir = "../../../deploy/"

// prodComposeFiles are the files production runs (and only them).
var prodComposeFiles = []string{composeDir + "docker-compose.yml", composeDir + "docker-compose.prod.yml"}

// composeServices are the services built from this binary: the server and the one-shot migrate job.
var composeServices = []string{"controlplane", "migrate"}

// scanDirs are the directories whose non-test files this binary compiles (package main + the library).
var scanDirs = []string{".", "../.."}

// subcommandServices says which compose service(s) a subcommand's environment reads must be satisfied in
// (ANY ONE of those listed). Everything not listed is the server: main() and the library. The migrate
// service runs `migrate` and holds the schema owner's DSN; `platform` needs that owner DSN (MIGRATE_
// DATABASE_URL, no other source). reset-password and reencrypt-totp prefer DATABASE_URL and fall back to
// MIGRATE_DATABASE_URL so they can also be run from the migrate service (the runbooks use
// `run --rm controlplane ...`); bootstrap prefers MIGRATE_DATABASE_URL (only the owner may create a
// tenant) and falls back to DATABASE_URL. Either service covers all three.
var subcommandServices = map[string][]string{
	"runMigrate":       {"migrate"},
	"runPlatform":      {"migrate"},
	"runBootstrap":     {"controlplane", "migrate"},
	"runResetPassword": {"controlplane", "migrate"},
	"runReencryptTOTP": {"controlplane", "migrate"},
}

func servicesForFunc(fn string) []string {
	if s, ok := subcommandServices[fn]; ok {
		return s
	}
	return []string{"controlplane"}
}

// attributeReadsToEntries re-attributes every read to the ENTRY POINTS that may execute it, one read per
// entry, so a variable must be forwarded to every service that may run that code. Without this,
// `func migrationOption() string { return os.Getenv("X") }` called from runMigrate would count as a server read
// and pass with X forwarded only to controlplane, while the migrate container silently lacks it.
//
// Deliberately coarse, so it can only ADD requirements (a loud failure, never a silent pass):
//   - The server is never inferred away. Every read needs controlplane, except a read made directly in a
//     subcommand runner's own body (runMigrate reading MIGRATE_DATABASE_URL), which needs only that runner's
//     services. A helper only migrate uses therefore needs both; forward it to both or read it in the runner.
//   - A subcommand runner reaches every function whose NAME any reachable body mentions: a call, a function
//     value, a callback, a generic instantiation, a method of any type with that name.
//   - Package-level initialisers and init functions run in every mode: every runner reaches them and
//     everything they mention.
//
// KNOWN LIMIT (accepted, Codex r8): a function VALUE bound outside everything a runner reaches and then called
// by the runner through a variable it does reach (`var option func() string; func configure() { option =
// migrationOption }` called from main before runMigrate calls option()) is not attributed to the runner, so its
// read needs only controlplane. Closing that soundly needs points-to analysis; the coarse fixes (every read
// needs every runner's services) fail the real tree. Keep runner-specific configuration in the runner's own
// reach: call the helper, or pass the value from the runner.
func attributeReadsToEntries(files []*ast.File, reads []envRead) []envRead {
	refs := map[string]map[string]bool{} // function name ("" = package-level initialisers) -> names it mentions
	mention := func(owner string, n ast.Node) {
		if refs[owner] == nil {
			refs[owner] = map[string]bool{}
		}
		ast.Inspect(n, func(x ast.Node) bool {
			if id, ok := x.(*ast.Ident); ok {
				refs[owner][id.Name] = true
			}
			return true
		})
	}
	for _, f := range files {
		for _, d := range f.Decls {
			switch v := d.(type) {
			case *ast.FuncDecl:
				if v.Body != nil {
					mention(v.Name.Name, v.Body)
				}
			case *ast.GenDecl:
				if v.Tok == token.VAR {
					mention("", v)
				}
			}
		}
	}
	everyMode := []string{"", "init"}
	reach := map[string]map[string]bool{}
	for sub := range subcommandServices {
		seen := map[string]bool{}
		stack := append([]string{sub}, everyMode...)
		for len(stack) > 0 {
			fn := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[fn] {
				continue
			}
			seen[fn] = true
			for g := range refs[fn] {
				if !seen[g] {
					stack = append(stack, g)
				}
			}
		}
		reach[sub] = seen
	}
	var out []envRead
	for _, rd := range reads {
		if _, isRunner := subcommandServices[rd.Func]; isRunner {
			out = append(out, rd) // the runner's own body: only its services (servicesForFunc)
			continue
		}
		out = append(out, envRead{rd.Name, rd.Where, "main"})
		for sub, r := range reach {
			if r[rd.Func] {
				out = append(out, envRead{rd.Name, rd.Where + " (via " + sub + ")", sub})
			}
		}
	}
	return out
}

// composeOverlayClaims: variables the binary reads that ONLY an optional overlay forwards. Operators who
// want the managed installer apply that overlay; production without it never sets them.
var composeOverlayClaims = map[string]overlayClaim{
	"CP_MANAGED_INSTALL_DIR":               {composeDir + "docker-compose.installer.yml", "controlplane"},
	"CP_MANAGED_INSTALL_CONTROL_PLANE_URL": {composeDir + "docker-compose.installer.yml", "controlplane"},
	"CP_DEPLOYMENT_PASS_FILE":              {composeDir + "docker-compose.installer.yml", "controlplane"},
	"CP_AGENT_RELEASE_ATTESTATION_FILE":    {composeDir + "docker-compose.installer.yml", "controlplane"},
}

// composeEnvAllowlist: variables the binary reads that are DELIBERATELY not forwarded, with the reason.
// An entry that is forwarded after all, or no longer read, fails the test so the list cannot rot.
var composeEnvAllowlist = map[string]string{
	"USER":     "migrate/CLI audit actor fallback (os user name); never meaningful inside the service",
	"USERNAME": "Windows spelling of USER, same CLI-only fallback",

	"CP_INSECURE_DEV_GRANT_SEED": "dev-mode (CP_INSECURE_DEV) grant seed; production clears CP_INSECURE_DEV and must never be given one",

	"CP_DEPLOYMENT_PASS_TEST_ROOT_KEY": "lab-only test root for deployment passes; a stray .env line must never trust a non-production root",

	"CP_HOST_THEMING":                "docs/66 hostname theming ships dark: opt-in by uncommenting the commented lines (needs the Caddy edge marker too)",
	"CP_EDGE_SECRET":                 "docs/66 theming opt-in; forwarded to controlplane AND caddy together, by uncommenting both",
	"CP_DEFAULT_HOSTS":               "docs/66 theming opt-in (a non-empty value enables the host policy by itself)",
	"CP_LEGACY_UNSCOPED_HOSTS":       "docs/66 theming opt-in",
	"CP_PUBLIC_AUTHORITIES":          "docs/66 theming opt-in (the edge gate's authority list)",
	"CP_HOST_THEMING_ALLOW_UNSCOPED": "docs/66 break-glass for theming-off-with-assignments; an explicit act, never a stray .env line",
}

// sanityFloor: reads the scan must always find, or it has gone blind.
var sanityFloor = []string{"DATABASE_URL", "GRANT_ISSUER_SEED", "CP_SECURE_COOKIE", "RECORDING_MASTER_KEY", "CP_INSECURE_DEV", "MIGRATE_DATABASE_URL", "MIGRATIONS_DIR"}

// scannerCopies are the other binaries' copies of envscan_test.go; they must stay byte-identical to this one.
var scannerCopies = []string{"../../../server/signaling/envscan_test.go", "../../../server/relay/envscan_test.go"}

func TestComposeForwardsEveryEnvVarTheServerReads(t *testing.T) {
	fset, files := parseNonTestFiles(t, scanDirs)
	res := scanEnvFiles(fset, files, scanConfig{Imports: moduleImportDirs(t), Exemptions: readerExemptions})
	for _, u := range res.Unresolved {
		t.Errorf("unresolved env read: %s", u)
	}
	readNames := readNamesOf(res.Reads)
	for _, must := range sanityFloor {
		if !readNames[must] {
			t.Fatalf("scan did not find %s: the scanner no longer sees this binary's env reads", must)
		}
	}
	prod := composeEnvKeys(t, prodComposeFiles)
	for _, s := range composeServices {
		if prod[s] == nil {
			t.Fatalf("service %q not found in the production compose files: the compose scan is blind", s)
		}
	}
	overlayKeys := map[string]map[string]map[string]bool{}
	overlay := map[string]map[string]bool{}
	for name, c := range composeOverlayClaims {
		if overlayKeys[c.File] == nil {
			overlayKeys[c.File] = composeEnvKeys(t, []string{c.File})
		}
		if overlay[c.Service] == nil {
			overlay[c.Service] = map[string]bool{}
		}
		overlay[c.Service][name] = true
	}
	for _, p := range checkOverlayClaims(composeOverlayClaims, overlayKeys, prod, readNames) {
		t.Error(p)
	}
	for _, p := range checkComposeEnv(attributeReadsToEntries(files, res.Reads), servicesForFunc, composeEnvRules{Prod: prod, Overlay: overlay, Allow: composeEnvAllowlist}) {
		t.Error(p)
	}
}

func TestEnvScannerCopiesAreIdentical(t *testing.T) {
	mine, err := os.ReadFile("envscan_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range scannerCopies {
		other, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if string(other) != string(mine) {
			t.Errorf("%s differs from envscan_test.go: the shared env scanner must be changed in all three binaries together", p)
		}
	}
}

// Every subcommand runner is classified in subcommandServices, and every entry names a function that exists:
// a new `runFoo` must say which service's environment it reads from.
func TestSubcommandServicesCoverEveryRunner(t *testing.T) {
	_, files := parseNonTestFiles(t, []string{"."})
	runner := regexp.MustCompile(`^run[A-Z]`)
	seen := map[string]bool{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && runner.MatchString(fd.Name.Name) {
				seen[fd.Name.Name] = true
				if _, ok := subcommandServices[fd.Name.Name]; !ok {
					t.Errorf("%s is a subcommand runner with no entry in subcommandServices: say which compose service it reads its environment from", fd.Name.Name)
				}
			}
		}
	}
	var stale []string
	for fn, svcs := range subcommandServices {
		if !seen[fn] {
			stale = append(stale, fn)
		}
		for _, s := range svcs {
			if !strings.Contains(","+strings.Join(composeServices, ",")+",", ","+s+",") {
				t.Errorf("%s maps to unknown service %q", fn, s)
			}
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("subcommandServices names functions that no longer exist: %v", stale)
	}
}

// Codex r6/r7: a read is required in every service that may execute it.
func TestReadsAreAttributedToEveryEntryThatReachesThem(t *testing.T) {
	fset, files := parseEnvSources(t, `package main
import "os"
const startup = "CP_STARTUP"
var option = os.Getenv(startup)
var viaInit = initHelper()
func initHelper() string { return os.Getenv("CP_INIT_HELPER") }
func init() { _ = os.Getenv("CP_INIT_FUNC") }
func migrationOption() string { return os.Getenv("CP_MIGRATION_OPTION") }
func byValue() string { return os.Getenv("CP_BY_VALUE") }
func shared() string { return os.Getenv("CP_SHARED") }
func callback() string { return os.Getenv("CP_CALLBACK") }
func register(f func() string) {}
func runMigrate() { _ = os.Getenv("CP_RUNNER_OWN"); _ = migrationOption(); f := byValue; _ = f(); _ = shared() }
func main() { _ = shared(); register(callback); runMigrate() }`)
	res := scanEnvFiles(fset, files, scanConfig{})
	if len(res.Unresolved) != 0 {
		t.Fatalf("fixture: %v", res.Unresolved)
	}
	reads := attributeReadsToEntries(files, res.Reads)
	missing := func(cp, mig []string) string {
		set := func(xs []string) map[string]bool {
			m := map[string]bool{}
			for _, x := range xs {
				m[x] = true
			}
			return m
		}
		p := checkComposeEnv(reads, servicesForFunc, composeEnvRules{
			Prod: map[string]map[string]bool{"controlplane": set(cp), "migrate": set(mig)}, Allow: map[string]string{}})
		var names []string
		for _, line := range p {
			names = append(names, strings.Fields(line)[0])
		}
		sort.Strings(names)
		return strings.Join(names, ",")
	}
	all := []string{"CP_STARTUP", "CP_INIT_HELPER", "CP_INIT_FUNC", "CP_MIGRATION_OPTION", "CP_BY_VALUE", "CP_SHARED", "CP_CALLBACK", "CP_RUNNER_OWN"}
	if got := missing(all, all); got != "" {
		t.Fatalf("everything forwarded to both: reported %s", got)
	}
	// Migrate gets nothing: every read migrate may execute is reported (its own body, helpers, a function value,
	// shared code, package initialisers, init), and only the server-only callback is not.
	if got, want := missing(all, nil), "CP_BY_VALUE,CP_INIT_FUNC,CP_INIT_HELPER,CP_MIGRATION_OPTION,CP_RUNNER_OWN,CP_SHARED,CP_STARTUP"; got != want {
		t.Fatalf("migrate forwards nothing: reported %s, want %s", got, want)
	}
	// The server gets nothing: everything except the runner's own read is reported, including helpers only
	// migrate calls (the server is never inferred away).
	if got, want := missing(nil, all), "CP_BY_VALUE,CP_CALLBACK,CP_INIT_FUNC,CP_INIT_HELPER,CP_MIGRATION_OPTION,CP_SHARED,CP_STARTUP"; got != want {
		t.Fatalf("controlplane forwards nothing: reported %s, want %s", got, want)
	}
}
