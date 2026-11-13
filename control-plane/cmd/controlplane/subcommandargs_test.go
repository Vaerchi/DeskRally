package main

import (
	"flag"
	"os"
	"strings"
	"testing"
)

// `reencrypt-totp dry-run` (the dash forgotten) used to parse as no flags at all and perform the real
// run. A stray word must now stop the command, wherever it appears.
func TestAStrayArgumentStopsAMaintenanceCommand(t *testing.T) {
	for _, args := range [][]string{
		{"dry-run"},
		{"-dry-run", "extra"},
		{"dry-run", "-dry-run"}, // the flag after the stray word was silently dropped too
	} {
		fs := flag.NewFlagSet("reencrypt-totp", flag.ContinueOnError)
		fs.Bool("dry-run", false, "")
		err := checkSubcommandArgs(fs, args)
		if err == nil {
			t.Fatalf("%q: accepted, want an unexpected-argument error", args)
		}
		if !strings.Contains(err.Error(), "reencrypt-totp") || !strings.Contains(err.Error(), "nothing was done") {
			t.Fatalf("%q: error %q does not name the command and say nothing was done", args, err)
		}
	}

	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	fs.String("tenant", "", "")
	fs.String("email", "", "")
	if err := checkSubcommandArgs(fs, []string{"-tenant", "acme", "stray", "-email", "a@b"}); err == nil ||
		!strings.Contains(err.Error(), `"stray"`) {
		t.Fatalf("a word between flags: %v, want an error naming it", err)
	}
}

func TestWellFormedFlagsStillParse(t *testing.T) {
	fs := flag.NewFlagSet("reencrypt-totp", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "")
	if err := checkSubcommandArgs(fs, []string{"-dry-run"}); err != nil || !*dryRun {
		t.Fatalf("-dry-run: err=%v dryRun=%v, want nil and true", err, *dryRun)
	}
	fs = flag.NewFlagSet("migrate", flag.ContinueOnError)
	if err := checkSubcommandArgs(fs, nil); err != nil {
		t.Fatalf("no arguments: %v", err)
	}
}

// Every subcommand's flags go through the checked parse: a new subcommand that calls fs.Parse directly
// would bring the silent-drop back.
func TestEverySubcommandUsesTheCheckedParse(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	sets := strings.Count(s, "flag."+"NewFlagSet(")
	checked := strings.Count(s, "\tparseSubcommandFlags"+"(fs, ")
	direct := strings.Count(s, "fs."+"Parse(")
	if sets == 0 || checked != sets || direct != 1 {
		t.Fatalf("main.go: %d flag sets, %d checked parses, %d direct fs.Parse calls; want every set checked and "+
			"the only direct parse inside checkSubcommandArgs", sets, checked, direct)
	}
}
