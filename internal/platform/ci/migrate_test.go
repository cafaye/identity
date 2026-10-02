package ci

// `bin/migrate` APPLIED EVERY MIGRATION AND THEN REVERTED IT.
//
// This is the test for that, and the reason it is written the way it is.
//
// # WHAT WAS WRONG
//
// `bin/migrate` handed each migration to `psql --file`, on the strength of a
// comment in its own header: "`-- +goose Up` and `-- +goose Down` are comments,
// so a plain `psql -f` runs exactly the Up section and ignores the Down one."
// The annotations are comments. That is the entire problem: psql does not know
// they are annotations, so it runs the Down section too. Measured on a fresh
// Postgres with nothing else applied:
//
//	CREATE TABLE
//	CREATE INDEX
//	DROP TABLE
//	exit=0
//
// Each table created, then dropped, in one call, exit status zero, and the
// script printed "migrations applied" because nothing had failed — it applied a
// migration and its exact inverse, in order, correctly. A developer running
// `bin/dev` got an empty database and no error.
//
// CI never saw it, because CI runs `goose`, which honours the annotations. The
// broken path was the fallback nobody runs in CI: the most likely place for a
// bug to live, and the one place a developer is actually relying on.
//
// # WHY THE FIX IS A SEPARATE SCRIPT
//
// The Up section is now cut out by `bin/migration-up-section` before psql sees
// anything. That script exists as its own file so THIS test can run it without a
// database. The obvious alternative — an inline `awk … | psql` inside the loop —
// is only testable against a real Postgres with a real psql, and a test that
// skips when those are missing verifies nothing in the one environment a
// developer runs in. This repository does not accept a test that can silently
// stop running, and neither does this one.
//
// # HOW THE LOOP IS EXERCISED WITHOUT A DATABASE
//
// A stub `psql` is put first on PATH. It reads stdin — which is where the fixed
// script sends the Up section, and where the broken one sent nothing because it
// used `--file` — appends it to a capture file, and exits 0. `bin/migrate` then
// runs its real loop over the real migrations directory, unmodified, and this
// test asserts on what the stub was actually handed.
//
// That matters for the failure direction. Asserting on `migration-up-section`
// alone would pass even if `bin/migrate` stopped calling it, which is precisely
// the regression that broke this once: a correct extractor, never invoked. Going
// through the loop is what makes the test a statement about the script a
// developer runs rather than about a function beside it.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestMigrateFeedsPsqlTheUpSectionAndNotTheDownOne is the regression test.
func TestMigrateFeedsPsqlTheUpSectionAndNotTheDownOne(t *testing.T) {
	captured, run := stubPsql(t)

	if _, err := run("postgres://stub/identity"); err != nil {
		t.Fatalf("bin/migrate: %v\n\nwhat the stub psql received:\n%s", err, readAll(t, captured))
	}

	fed := readAll(t, captured)
	if fed == "" {
		t.Fatal("the stub psql received nothing at all on stdin, so bin/migrate " +
			"is still passing files with `--file` and psql is running their Down sections")
	}

	// The control in the opposite direction. Every migration in this repository
	// has a Down section, and 00002_users.sql drops the table it created — so a
	// run that forwards the Down section is easy to prove and hard to mistake for
	// a clean one. One assertion would do; all of them are listed because the
	// cost of naming which migration leaked is zero and the cost of not naming it
	// is a bisect.
	for _, name := range []string{
		"DROP TABLE users",
		"DROP TABLE account_invitations",
		"DROP INDEX users_email_key",
	} {
		if strings.Contains(fed, name) {
			t.Errorf("the Down section reached psql — the stub received %q, so applying this migration would undo it\n\nwhat the stub psql received:\n%s",
				name, fed)
		}
	}

	// And the control the other way: the Up sections are actually there. A fix
	// that sent psql nothing at all would pass every assertion above.
	for _, name := range []string{
		"CREATE TABLE users",
		"CREATE UNIQUE INDEX users_email_key",
		"CREATE TABLE account_invitations",
	} {
		if !strings.Contains(fed, name) {
			t.Errorf("the Up section is missing from what psql was sent: no %q\n\nwhat the stub psql received:\n%s", name, fed)
		}
	}

	// The marker itself must never appear: it is a comment, and a comment that
	// reaches the statement stream is a marker a splitter has to cope with.
	if strings.Contains(fed, "+goose Down") {
		t.Error("the `-- +goose Down` marker was fed to psql rather than used as the cut point")
	}
}

// Every migration in the tree, individually, through the extractor the loop uses.
//
// The loop test above proves the wiring; this proves the rule on all fifteen
// files as they are today, including the one that legitimately drops something
// inside its own Up section. That file is the interesting case: 00013 recreates
// `account_invitations_pending_idx` because an index predicate cannot be
// altered, so a naive "no DROP anywhere" rule would be wrong — which is why this
// checks for the table-level statements a Down section produces rather than for
// the word DROP.
func TestEveryMigrationForwardsItsUpSectionIntact(t *testing.T) {
	root := repoRoot(t)
	extractor := filepath.Join(root, "bin", "migration-up-section")

	migrations, err := filepath.Glob(filepath.Join(root, "migrations", "*.sql"))
	if err != nil {
		t.Fatalf("globbing migrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatalf("no migrations found in %s — a glob that matches nothing is the shape of a test that proves nothing", filepath.Join(root, "migrations"))
	}

	// A statement a Down section always contains and an Up section essentially
	// never does: dropping the table this migration is about.
	dropsTheSubject := regexp.MustCompile(`(?im)^\s*DROP\s+TABLE\s`)

	for _, migration := range migrations {
		t.Run(filepath.Base(migration), func(t *testing.T) {
			out, err := exec.Command(extractor, migration).Output()
			if err != nil {
				t.Fatalf("bin/migration-up-section %s: %v", filepath.Base(migration), err)
			}
			if len(out) == 0 {
				t.Fatal("the extracted Up section is empty, so this migration would apply nothing and say nothing")
			}
			if dropsTheSubject.Match(out) {
				t.Errorf("the extracted Up section drops a table, which means the Down section leaked into it:\n%s", out)
			}
		})
	}
}

// The extractor is asked for things it cannot do, and says so rather than
// printing nothing and letting psql succeed on an empty stream. An empty stdin
// is a successful psql run that migrated nothing, which is the exact failure
// identity-31 was.
func TestTheExtractorRefusesWhatItCannotRead(t *testing.T) {
	root := repoRoot(t)
	extractor := filepath.Join(root, "bin", "migration-up-section")

	for _, args := range [][]string{
		{}, // no argument at all
		{filepath.Join(root, "migrations", "00001_nonexistent.sql")}, // unreadable
		{"a.sql", "b.sql"}, // two files, one verb
	} {
		cmd := exec.Command(extractor, args...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		err := cmd.Run()

		if err == nil {
			t.Errorf("bin/migration-up-section %v exited 0 and printed to stdout; "+
				"an empty stream into psql is a run that migrated nothing and reported success", args)
			continue
		}
		if stderr.Len() == 0 {
			t.Errorf("bin/migration-up-section %v failed with no message on stderr, so the caller is told nothing about which file was wrong", args)
		}
	}
}

// stubPsql puts a fake psql first on PATH that appends whatever arrives on stdin
// to a capture file, and returns that file's path plus a function that runs
// `bin/migrate` with a stubbed PATH.
//
// It asserts the stub was actually used. A stub that is shadowed by a real psql
// elsewhere on PATH would let bin/migrate succeed against nothing and the test
// would pass with an empty capture — so the capture is checked by the caller,
// and this records in the output the stub was reached.
func stubPsql(t *testing.T) (string, func(dsn string) (string, error)) {
	t.Helper()
	root := repoRoot(t)

	dir := t.TempDir()
	capture := filepath.Join(dir, "fed-to-psql.sql")
	stub := filepath.Join(dir, "psql")

	// `--file` is deliberately NOT handled. The fixed script streams the Up
	// section on stdin, so a stub that only understood `--file` would fail the
	// broken implementation for the wrong reason — it would report "not reached"
	// rather than "the Down section was forwarded". Recording the argument and
	// the fact that stdin was empty lets the caller tell those apart.
	script := "#!/usr/bin/env bash\n" +
		"{\n" +
		"  echo \"### psql called with: $*\"\n" +
		"  echo '### stdin follows'\n" +
		"  cat\n" +
		"} >> " + capture + "\n" +
		"exit 0\n"

	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatalf("writing the stub psql: %v", err)
	}

	run := func(dsn string) (string, error) {
		cmd := exec.Command("bash", filepath.Join(root, "bin", "migrate"))
		cmd.Dir = root
		cmd.Env = append(os.Environ(),
			"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
			"DATABASE_URL="+dsn,
		)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	return capture, run
}

func readAll(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}
