// Checks on the rollback tier: that .github/workflows/ci.yml can reach a green
// boot at all, and that bin/rollback's contract is the one the workflow assumes.
//
// THE FINDING THIS FILE EXISTS FOR. `migrations/00016_account_isolation.sql`
// ends its Up with `select cafaye.protect_table('account_users')`. `protect_table`
// defaults its login role to `current_user || '_app'` and refuses to create a
// policy for a role that cannot log in, so the migration needs a LOGIN role
// named `<caller>_app`. `docker compose up` provides it — kit's cluster init
// reads `KIT_POSTGRES_DATABASES: identity` and provisions `<service>_app`
// beside each `<service>` — and .github/workflows/ci.yml did NOT, because it
// runs a bare `postgres:17-alpine` service container with no init script.
// `goose up` on that job died at 00016 with
//
//	ERROR: cafaye.protect_table(account_users, identity_app):
//	       identity_app is not a LOGIN role on this cluster.
//
// measured against a cluster built the way this job builds one. The gap is
// invisible locally and fatal in CI, which is the worst shape a gap can have,
// so it is checked here: the role is DERIVED from the workflow's own
// `POSTGRES_USER` rather than repeated, so renaming the service's database in
// docker-compose.yml cannot quietly un-provision it.
//
// Neither of these checks opens a database. They read files, which is what makes
// them run in bin/prime; the property that actually needs a server is bin/rollback's,
// and that is a CI step.
package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// migrationsInTree is every migration file, parsed from the directory rather
// than from a list, so a new migration is covered the day it is written and a
// deleted one is visible.
func migrationsInTree(t *testing.T) []string {
	t.Helper()

	dir := filepath.Join(repoRoot(t), "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations/: %v", err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		if !migrationOrderRE.MatchString(entry.Name()) {
			t.Errorf("migrations/%s is not named NNNNN_name.sql, so goose will not order it.\n"+
				"Every migration in this directory has followed that shape since 00001 and "+
				"a file that does not is applied last regardless of what its name says.", entry.Name())
			continue
		}
		names = append(names, entry.Name())
	}
	if len(names) == 0 {
		t.Fatal("migrations/ holds no .sql files, so nothing below is reading anything")
	}
	return names
}

var migrationOrderRE = regexp.MustCompile(`^[0-9]{5}_[a-z0-9_]+\.sql$`)

// serviceUser is the role the postgres service container creates as its
// superuser, read out of the workflow rather than assumed. Everything else here
// is derived from this one string, which is what keeps a rename from silently
// disarming the check.
var postgresUserRE = regexp.MustCompile(`(?m)^\s*POSTGRES_USER:\s*(\S+)\s*$`)

func serviceUser(t *testing.T) string {
	t.Helper()

	lines := workflowLines(t)
	for i, line := range lines {
		m := postgresUserRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// A service container's environment is not the job's environment, so
		// `$POSTGRES_USER` in a `run:` block is the empty string. That is
		// asserted separately; here we want the literal.
		if strings.HasPrefix(m[1], "$") {
			t.Fatalf(".github/workflows/ci.yml line %d sets POSTGRES_USER to %s, an expression "+
				"this check cannot resolve — write the role name out.", i+1, m[1])
		}
		return m[1]
	}
	t.Fatal(".github/workflows/ci.yml sets no POSTGRES_USER, so the service container's role is\n" +
		"unknown and the login role the migrations need cannot be derived. If the container moved\n" +
		"to an env: block this check has to learn where.")
	return ""
}

// firstLineMatching returns the 1-based line number of the first line containing
// `needle`, or 0. Line NUMBERS and not booleans, because the property here is
// an ORDER: the role has to exist before `goose up` runs, and a check that only
// asks "does this string appear anywhere" passes when the two statements are in
// the wrong order.
func firstLineMatching(t *testing.T, label string, lines []string, needle string) int {
	t.Helper()

	for i, line := range lines {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	return 0
}

// TestTheLoginRoleTheMigrationsProtectTablesForIsProvisionedBeforeTheyAreApplied
// is the check for the finding above: the login role `protect_table` defaults
// to must exist, and must exist BEFORE the migrations run, on the job whose
// cluster has no init script.
//
// The name is derived from POSTGRES_USER, not written out, so this fails if the
// service's database is renamed and the provisioning is not renamed with it. The
// reverse is also true and is why the assertion is a `<` and not two separate
// existence checks.
func TestTheLoginRoleTheMigrationsProtectTablesForIsProvisionedBeforeTheyAreApplied(t *testing.T) {
	lines := workflowLines(t)
	role := serviceUser(t) + "_app"

	provisionedAt := firstLineMatching(t, "provisioning "+role, lines, "create role "+role+" ")
	gooseUpAt := firstLineMatching(t, "goose up", lines, "goose -dir migrations postgres \"$DATABASE_URL\" up")

	if gooseUpAt == 0 {
		t.Fatalf(".github/workflows/ci.yml never runs `goose ... up`, so there is no point in this " +
			"check — but there is also no schema, and the suite would die on a missing table instead.")
	}
	if provisionedAt == 0 {
		t.Fatalf(".github/workflows/ci.yml never creates the `%s` login role.\n"+
			"migrations/00016_account_isolation.sql ends its Up with `select cafaye.protect_table('account_users')`,\n"+
			"and protect_table defaults its login role to `current_user || '_app'` and REFUSES to write a\n"+
			"policy for a role that cannot log in. This job's cluster is a bare postgres:17-alpine service\n"+
			"container with no init script, so nothing else provides the role: `goose up` fails at 00016\n"+
			"with \"cafaye.protect_table(account_users, %s): %s is not a LOGIN role on this cluster\".\n"+
			"docker compose is unaffected — kit's cluster init provisions it from KIT_POSTGRES_DATABASES —\n"+
			"which is exactly why this stayed invisible until bin/rollback ran the migrations on a CI-shaped\n"+
			"cluster.", role, role, role)
	}
	if provisionedAt > gooseUpAt {
		t.Fatalf(".github/workflows/ci.yml creates `%s` on line %d but applies the migrations on line %d.\n"+
			"The ordering is the whole property: a role created after `goose up` cannot be one 00016 used.",
			role, provisionedAt, gooseUpAt)
	}
}

// TestTheProvisionedRoleIsCreatedFromTheJobDatabaseNotTheServiceEnvironment
// guards a mistake this file's own header names: a service container's
// environment is not the job's environment. `$POSTGRES_USER` inside a `run:`
// block expands to nothing, so a step written with it creates a role literally
// called `_app` and reports success.
func TestTheProvisionedRoleIsCreatedFromTheJobDatabaseNotTheServiceEnvironment(t *testing.T) {
	lines := workflowLines(t)
	role := serviceUser(t) + "_app"

	at := firstLineMatching(t, "provisioning "+role, lines, "create role "+role+" ")
	if at == 0 {
		t.Fatal("the role is not provisioned at all — the check this file exists for is red; " +
			"see TestTheLoginRoleTheMigrationsProtectTablesForIsProvisionedBeforeTheyAreApplied")
	}
	for _, line := range lines {
		if !strings.Contains(line, "create role "+role+" ") {
			continue
		}
		if strings.Contains(line, "${") {
			t.Errorf(".github/workflows/ci.yml builds the role name with a shell expansion:\n%s\n"+
				"The job's environment does not carry the service container's POSTGRES_USER, POSTGRES_PASSWORD\n"+
				"or POSTGRES_DB — GitHub sets those on the container, not on the steps — so `%s` here expands to\n"+
				"an empty string and the role created is named `%s`.",
				strings.TrimSpace(line), "${POSTGRES_USER}_app", "_app")
		}
	}
}

// TestNoMigrationCreatesAClusterRole records the decision the fix rests on: the
// `<service>_app` role belongs to the ENVIRONMENT.
//
// It is worth a check because the alternative is available and looks harmless —
// a migration could `create role ... exception when duplicate_object then null`,
// and then every cluster would agree with the migration. What that buys is a
// schema that silently reconstitutes a role an operator dropped on purpose, on
// a cluster where the migration has no CREATEROLE and fails; and a `goose down`
// that cannot take the role away, because the role was never part of the
// migration's own Up. The role is provisioned by docker-compose.yml, by kit's
// cluster init, by .github/workflows/ci.yml and by bin/rollback. Those are four
// homes, and this check is the one that says why a fifth is not allowed.
func TestNoMigrationCreatesAClusterRole(t *testing.T) {
	// `create role`, in any casing, with or without `if not exists`.
	createRole := regexp.MustCompile(`(?i)create\s+role`)
	for _, name := range migrationsInTree(t) {
		for i, line := range strings.Split(readMigration(t, name), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "--") {
				continue
			}
			if createRole.MatchString(trimmed) {
				t.Errorf("migrations/%s line %d creates a cluster role:\n%s\n"+
					"Roles are the environment's: kit's cluster init provisions <service> and <service>_app\n"+
					"from KIT_POSTGRES_DATABASES, and a migration that creates one would (a) need CREATEROLE,\n"+
					"(b) recreate a role an operator dropped on purpose, and (c) leave a role no `goose down`\n"+
					"can remove.", name, i+1, trimmed)
			}
		}
	}
}

// TestEveryMigrationCarriesADownMarker is the property bin/rollback assumes
// before it reads anything: a Down section that is not there cannot be checked,
// and the extractor's response to a missing marker is an EMPTY stream, which
// psql accepts silently. So without this check a migration could lose its Down
// and the rollback check would report it as clean.
//
// The counterpart lives in bin/rollback itself, which names the file at run
// time; this one names it at commit time, where a reviewer will read it.
func TestEveryMigrationCarriesADownMarker(t *testing.T) {
	downMarker := regexp.MustCompile(`(?m)^--[[:space:]]*\+goose[[:space:]]+Down`)
	upMarker := regexp.MustCompile(`(?m)^--[[:space:]]*\+goose[[:space:]]+Up`)

	for _, name := range migrationsInTree(t) {
		body := readMigration(t, name)
		if !upMarker.MatchString(body) {
			t.Errorf("migrations/%s has no `-- +goose Up` marker, so goose applies nothing and the "+
				"file is a comment.", name)
		}
		if !downMarker.MatchString(body) {
			t.Errorf("migrations/%s has NO `-- +goose Down` marker — a deploy nobody can undo.\n"+
				"bin/migration-down-section prints an empty stream for a file with no marker, and psql\n"+
				"accepts an empty stream without complaint, so the rollback check would read this\n"+
				"migration as a clean rollback rather than as no rollback at all.\n"+
				"A marker migration whose Up creates nothing still needs the marker: an empty Down is a\n"+
				"verifiable no-op, and a missing one is indistinguishable from a forgotten file.", name)
		}
	}
}

// TestTheRollbackRunsInCIAndCannotExitZeroByStandingDown checks the wiring, and
// the half of it that is easy to get wrong.
//
// `IDENTITY_ROLLBACK_REQUIRED=1` on a step that has just been handed a URL is
// redundant under any reading — the URL is set, so the skip path is not
// reachable. It is there anyway, because the alternative is a step whose exit
// code depends on a variable four lines above it staying set, and the failure
// mode of that is a green tick on a check that never ran.
func TestTheRollbackRunsInCIAndCannotExitZeroByStandingDown(t *testing.T) {
	lines := workflowLines(t)

	at := firstLineMatching(t, "the rollback step", lines, "./bin/rollback")
	if at == 0 {
		t.Fatal(".github/workflows/ci.yml never runs bin/rollback, so seventeen Down sections go\n" +
			"unchecked forever. A Down is code that sits beside an Up every run exercises and reads as\n" +
			"though it were exercised too.")
	}

	var block strings.Builder
	for _, line := range lines[at-1:] {
		if strings.TrimSpace(line) == "" {
			break
		}
		block.WriteString(line)
		block.WriteString("\n")
	}
	got := block.String()

	if !strings.Contains(got, "IDENTITY_ROLLBACK_URL=") {
		t.Errorf(".github/workflows/ci.yml runs bin/rollback without naming a server:\n%s\n"+
			"With no URL the script prints a counted skip and exits 0, which is a green tick on a check\n"+
			"that never ran.", got)
	}
	if !strings.Contains(got, "IDENTITY_ROLLBACK_REQUIRED=1") {
		t.Errorf(".github/workflows/ci.yml runs bin/rollback without IDENTITY_ROLLBACK_REQUIRED=1:\n%s\n"+
			"The skip is the only path where that variable changes anything, and a step that can reach it\n"+
			"can report success without having applied a single migration.", got)
	}
}

// TestTheRollbackScriptNamesTheRoleItProvisionsFromTheCaller keeps bin/rollback
// honest about the finding that shaped it. The script cannot create the SERVICE
// role: on a fleet cluster that role exists, owns the service database, and
// cannot be dropped by a schema check — the first draft tried, and refused to
// run against the very cluster it was written for. What it can do is derive the
// `_app` role from whoever is connected, which is what `protect_table` derives
// it from, and that is the whole fix.
func TestTheRollbackScriptNamesTheRoleItProvisionsFromTheCaller(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "bin", "rollback"))
	if err != nil {
		t.Fatalf("read bin/rollback: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, `APP_ROLE="${CALLER}_app"`) {
		t.Errorf("bin/rollback does not name the login role it provisions from the caller.\n"+
			"protect_table defaults to `current_user || '_app'`, so a harness that provisions a\n"+
			"hardcoded role name is provisioning a role the migration will not ask for. Measured: the\n"+
			"hardcoded first draft failed at 00016 on a bare cluster with \"postgres_app is not a LOGIN\n"+
			"role\", and then failed to start at all on a cluster where `identity` already existed.")
	}
	if !strings.Contains(body, "rolcanlogin") {
		t.Errorf("bin/rollback creates its role without checking whether it can LOGIN.\n"+
			"protect_table's own check is `rolname = ... and rolcanlogin`, and a role that exists but\n"+
			"cannot log in is exactly the state that check rejects.")
	}
}