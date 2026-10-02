package ci

// The credential audit must read the catalog's DEPENDENCIES, never the text it
// pretty-prints.
//
// WHY THIS FILE EXISTS. `migrations/00016_account_isolation.sql` embeds a copy of
// kit's `templates/database/tenancy/substrate.sql`, taken before
// kit-rls-advisor-02 rewrote `credential_tables()`. Nothing compared the copy
// against the template again, so it drifted, and it drifted into an audit query
// that returns NOTHING for the role an operator audits credentials as — kit's
// cluster admin role, `cafaye` — while returning the right answer for every
// other role. Measured on a scratch postgres:17, both rows same database, same
// policy, same instant:
//
//	role      rows                           digest_column
//	identity  BEFORE 00017 (deparsing)       api_keys/token_digest
//	identity  AFTER  00017 (dependencies)    api_keys/token_digest
//	cafaye    BEFORE 00017 (deparsing)       (none)
//	cafaye    AFTER  00017 (dependencies)    api_keys/token_digest
//
// `bin/credential-audit-drift` reproduces that table; this file is the half that
// runs in `bin/prime`, on a machine with no Postgres.
//
// WHY NOT `caf lock --verify`, WHICH IS THE OBVIOUS TOOL. Measured, and the
// answer is no, in three independent ways:
//
//  1. It does not run here at all. `caf lock .` on this tree exits 1 with
//     "telemetry/otel-endpoint.json is pinned as generated but is not in the
//     tree" — this repository's `internal/telemetry/` is hand-written, not
//     `caf gen telemetry`'s output, so the discover walk refuses before writing
//     a byte.
//  2. Its kinds are a CLOSED SET: `internal/lock`'s `kinds` is exactly
//     `spec`, `vendored-schema`, `generated-client`, `rule-bundle`. A migration
//     embedding another repository's SQL template is none of those four, and
//     `discover` derives every entry from those four conventions with no
//     manifest field, flag or allowlist that adds a fifth.
//  3. Even with a fifth kind, a lock records what a tree HAS. The defect here
//     is that two trees DISAGREE, and `caf lock`'s doc.go is explicit that it is
//     "not a drift gate: it records what is there". Pinning this repository's
//     copy against a hash recorded in this repository would pin the drift in
//     place and call it green — the failure this whole file exists to prevent.
//
// So this is deliberately NOT a pin. It is a claim this repository makes about
// its own bytes, and it needs nothing from kit to make it: the property that
// matters is structural (resolve by OID, do not read a spelling) and it is
// checkable here with no network, no checkout and no recorded digest.
// What WOULD close the remaining gap — comparing this copy to kit's bytes at a
// ref — needs a kind of its own in `caf`, plus a declaration in `cafaye.yml`,
// plus kit's substrate being fetchable at a ref, which it deliberately is not:
// kit splits its templates into FETCHED (`templates/compose`, pinned by
// `kit.ref`) and COPIED (`templates/database`), and that split is the reason a
// copy can drift at all. That is a change in `caf` and `kit`, not one identity
// should fake with a sha256sum somebody keeps by hand.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two migrations this file reads. Named rather than globbed, because a glob
// would pick up a future migration that does not install the audit at all and
// quietly stop comparing the one that does.
const (
	substrateMigration = "migrations/00016_account_isolation.sql"
	fixMigration       = "migrations/00017_credential_audit_dependencies.sql"
)

// readMigration fails the test with the path when the file is unreadable, rather
// than returning "" for a reader that would then report a clean tree.
//
// A bare filename is read from migrations/ and anything with a separator is read
// from the repository root, so one reader serves both the named migrations above
// and the directory walk in the test below without either spelling out a prefix
// that could disagree with the other.
//
// `repoRoot` comes from ci_test.go and is deliberately not spelled again here: it
// resolves the root from this file's PATH rather than from the working directory,
// which `go test` sets to the package. A second copy of a helper that already
// exists is how two answers to one question end up in a tree.
func readMigration(t *testing.T, name string) string {
	t.Helper()
	if !strings.ContainsRune(name, filepath.Separator) {
		name = "migrations/" + name
	}
	b, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("%s: %v — a check that reads nothing reports agreement with nothing", name, err)
	}
	return string(b)
}

// sqlSection returns the text of one goose section of a migration: the Up body
// when `up` is true, the Down body when it is not.
//
// Cut at the DOWN MARKER and not at the Up marker, for the reason
// bin/migration-up-section's header gives: a forward-only migration with no Down
// section must still have its Up section read rather than produce an empty
// string, which every assertion below would then pass against.
func sqlSection(t *testing.T, migration string, up bool) string {
	t.Helper()
	full := readMigration(t, migration)
	downAt := strings.Index(full, "\n-- +goose Down")
	if downAt < 0 {
		downAt = len(full)
	}
	head := full[:downAt]
	if !up {
		return full[downAt:]
	}
	upAt := strings.Index(head, "\n-- +goose Up")
	if upAt < 0 {
		return head
	}
	return head[upAt:]
}

// functionBodies returns every `create or replace function cafaye.<fn>`
// definition inside `src`, from each declaration to the `$caf$;` that closes it.
//
// PLURAL, and that is the load-bearing part. A single-body reader checks the LAST
// definition and calls the file verified: reintroduce the deparsing audit into
// 00016 and the reader — which is about 00017's body — stays green, because 00017
// still installs the right one afterwards. Measured, and it is why this walks all
// of them: in a migration sequence the last definition wins, so a check has to
// read every definition, not the effective one.
//
// The terminator is matched as a line of its own rather than as a substring,
// because a `$caf$;` inside a comment or a string would otherwise truncate the
// body early and every assertion below would pass against a prefix.
func functionBodies(t *testing.T, migration, src, fn string) []string {
	t.Helper()
	needle := "create or replace function cafaye." + fn + "("
	var out []string
	for rest := src; ; {
		at := strings.Index(rest, needle)
		if at < 0 {
			return out
		}
		rest = rest[at:]
		end := strings.Index(rest, "\n$caf$;")
		if end < 0 {
			t.Fatalf("%s: cafaye.%s is opened and never closed with `$caf$;`", migration, fn)
		}
		out = append(out, rest[:end])
		rest = rest[end:]
	}
}

// functionBody returns the single `create or replace function` definition for
// `fn`, and fails when there is not exactly one — because a reader that takes the
// first of several has not been told which one the migration means.
func functionBody(t *testing.T, migration, src, fn string) string {
	t.Helper()
	bodies := functionBodies(t, migration, src, fn)
	if len(bodies) != 1 {
		t.Fatalf("%s: expected exactly one `create or replace function cafaye.%s(`, found %d.\n"+
			"A check that picks one of several is reading a file nobody can reason about, and\n"+
			"the file is either malformed or carrying a definition this reader does not know "+
			"about.", migration, fn, len(bodies))
	}
	return bodies[0]
}

// THE CHECK, AND IT IS ABOUT EVERY DEFINITION IN EVERY MIGRATION, NOT ABOUT THE
// EFFECTIVE ONE.
//
// The audit resolves the digest function by OID out of pg_proc and finds the
// column by a pg_depend row onto the policy's OWN table, and it reads no
// deparsed expression. The deparsed spelling is reader-dependent — `pg_get_expr`
// omits the schema of any name the session could resolve, and `"$user"` is a
// search_path entry — so a function that reads it has an answer that depends on
// who is asking, which is the defect 00017 fixed.
//
// WHY THE RULE IS SCOPED FORWARD AND 00016 IS A NAMED EXCEPTION, because the
// append-only rule forbids the other answer. 00016 has been applied in deployed
// environments; rewriting it changes the file the next environment applies and
// not the one the deployed ones ran, which is how two environments holding the
// same migration count diverge silently. So the defect has to be allowed to sit
// in 00016 and forbidden everywhere after it, and that exception is one entry in
// one table rather than a carve-out spread through the assertions.
//
// AND A DEAD ENTRY IS A FAILURE, the same rule kit's skip-allowlist and
// ESLint's reportUnusedDisableDirectives state. An exception no longer matching
// anything has stopped constraining anything, and an allowlist entry that rots in
// one direction is a ratchet.
var migrationsThatPredateTheFix = map[string]string{
	"00016_account_isolation.sql": "the substrate copy, applied in deployed environments before " +
		"this was found; 00017 replaces its credential_tables() and rewriting 00016 is the " +
		"divergence the append-only rule exists to prevent",
}

func TestNoMigrationAfterTheFixInstallsAnAuditThatReadsASpelling(t *testing.T) {
	migrations, err := filepath.Glob(filepath.Join(repoRoot(t), "migrations", "*.sql"))
	if err != nil {
		t.Fatalf("glob migrations/*.sql: %v", err)
	}
	if len(migrations) < 2 {
		t.Fatalf("found %d migrations, which cannot include both the copy and its fix — "+
			"a glob that matched nothing would leave this test asserting agreement with no file at all",
			len(migrations))
	}

	matched := map[string]bool{}
	for _, path := range migrations {
		name := filepath.Base(path)
		// The Up section only. A Down section is ALLOWED to carry the old body —
		// 00017's does, by contract, so that `goose down` returns the tree to the
		// state the previous migration left it in. Asserting on Down would make
		// the rollback the thing the check forbids.
		for i, body := range functionBodies(t, name, sqlSection(t, name, true), "credential_tables") {
			reads := ""
			for _, forbidden := range []string{"pg_get_expr", "regexp_match"} {
				if strings.Contains(body, forbidden) {
					reads = forbidden
					break
				}
			}
			if reads == "" {
				continue
			}
			matched[name] = true
			if _, excused := migrationsThatPredateTheFix[name]; excused {
				continue
			}
			t.Errorf("migrations/%s: the %d `credential_tables()` in its Up section contains %q.\n"+
				"Reading a pretty-printed expression makes the answer depend on the session's\n"+
				"search_path, so the audit returns NOTHING as kit's cluster admin role\n"+
				"`cafaye` and the right answer as every other role — measured by\n"+
				"bin/credential-audit-drift. It reads as 'no table here can be resolved without\n"+
				"an account', which is the one answer an operator believes.\n"+
				"A migration is APPEND-ONLY: fix this with a new numbered file, and if the body\n"+
				"genuinely has to differ from kit's, record why in that migration.",
				name, i+1, reads)
		}
	}

	for name, reason := range migrationsThatPredateTheFix {
		if !matched[name] {
			t.Errorf("migrationsThatPredateTheFix lists %s (%s), but that migration no longer "+
				"installs an audit that reads a spelling.\n"+
				"The exception has stopped excepting anything and can now be deleted. A stale\n"+
				"allowlist entry is worse than a missing one: it teaches the next reader that "+
				"this shape is excusable here.", name, reason)
		}
	}
}

// The one migration that installs the audit after 00017 carries kit's structural
// markers, so "no spelling" cannot be satisfied by a function that reads nothing
// at all and answers nothing.
func TestTheCredentialAuditReadsDependenciesAndNotASpelling(t *testing.T) {
	body := functionBody(t, fixMigration, sqlSection(t, fixMigration, true), "credential_tables")

	for _, want := range []string{
		"pg_depend",                  // the column, and the function, by reference rather than by text
		"pg_proc",                    // the digest function resolved by OID
		"pronargs = 0",               // an overload of the same name is not that function
		"cd.refobjid = pol.polrelid", // the policy's OWN table, so another table's column stays out
		"'(unresolved)'",             // a row we cannot narrow is reported, not dropped
	} {
		if !strings.Contains(body, want) {
			t.Errorf("cafaye.credential_tables() does not contain %q.\n"+
				"Without it the audit is reading something the session can change. The argument is\n"+
				"kit's, at templates/database/tenancy/substrate.sql above that function.", want)
		}
	}

	for _, forbidden := range []string{
		"pg_get_expr",
		"regexp_match",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("cafaye.credential_tables() contains %q.\n"+
				"That is the reading the whole fix removed: it makes the answer depend on the\n"+
				"session's search_path, so the audit returns NOTHING as kit's cluster admin\n"+
				"role `cafaye` and the right answer as every other role. Measured by\n"+
				"bin/credential-audit-drift.", forbidden)
		}
	}
}

// The pre-00017 body is not hypothetical: it is IN THIS TREE, in 00017's own Down
// section, so this file can prove the check above is able to fail rather than
// asserting that it would. A check that has never been watched red is a check
// that might not work, and the claim being made here is about a SHAPE — so the
// negative control has to be the real old body, not a paraphrase of it.
func TestTheDriftCheckIsProvenAbleToFailOnTheBodyItRejects(t *testing.T) {
	old := functionBody(t, fixMigration, sqlSection(t, fixMigration, false), "credential_tables")

	if !strings.Contains(old, "pg_get_expr") || !strings.Contains(old, "regexp_match") {
		t.Fatalf("00017's Down section no longer carries the body it is meant to roll back.\n" +
			"Either the rollback was rewritten, which is a change nobody reviewed, or it was\n" +
			"dropped, and then this file's negative control is comparing against nothing.\n" +
			"bin/credential-audit-drift reads that section to install the 'before' column of\n" +
			"its table, so a silently rewritten Down makes a measurement lie.")
	}

	// The same two predicates, applied to the old body, must fail. If they pass,
	// the check above is not checking anything and the whole file is decoration.
	if !strings.Contains(old, "pg_get_expr") {
		t.Errorf("control: the pre-00017 body no longer reads pg_get_expr, so " +
			"TestTheCredentialAuditReadsDependenciesAndNotASpelling's forbidden-list is not " +
			"the thing that would have caught this drift")
	}
	if strings.Contains(old, "pg_depend") {
		t.Errorf("control: the pre-00017 body already reads pg_depend, so it would have " +
			"passed the required-substring list and the check above never bit")
	}
}

// The other six substrate functions are byte-identical to kit's, measured by
// hashing each one out of both files. That is why 00017 replaces ONE body rather
// than re-applying a whole template, and it is why a future drift in any of them
// shows up here rather than as an unexplained difference.
//
// The comparison is against a LOCAL kit checkout when one is beside this
// repository's sibling, and is SKIPPED — loudly, naming itself — when there is
// not. A check that quietly passes because it could not find the other file is
// the failure this file exists to prevent, so the skip says what was not checked.
func TestTheOtherSixSubstrateFunctionsAreKitsBytes(t *testing.T) {
	kitPath := findKitSubstrate(t)
	kitBytes, err := os.ReadFile(kitPath)
	if err != nil {
		t.Skipf("SKIP: no kit substrate within three levels above this repository (%s), so the copy "+
			"could not be compared against the template. Not checked: that the six functions 00017 "+
			"did NOT replace are still byte-identical to kit's. Re-run this beside a kit checkout "+
			"to close it; the audit check above needs no kit and is not gated on this.",
			filepath.Join(repoRoot(t), ".."))
	}
	kitSrc := string(kitBytes)
	here := sqlSection(t, substrateMigration, true)

	for _, fn := range []string{
		"current_account_id",
		"begin_account",
		"current_credential_digest",
		"begin_credential",
		"protect_table",
		"protect_credential_table",
	} {
		if a, b := kitFunctionBody(t, kitSrc, fn), functionBody(t, substrateMigration, here, fn); a != b {
			t.Errorf("cafaye.%s differs from kit's.\n"+
				"00016 claims to embed kit's substrate verbatim, and one function differing\n"+
				"means the copy has drifted again. Either re-copy it in a NEW migration or\n"+
				"record why this one is deliberately different.", fn)
		}
	}

	// And the one that WAS replaced has to actually differ, or the migration that
	// claims to fix it fixed nothing.
	if kitFunctionBody(t, kitSrc, "credential_tables") != functionBody(t, fixMigration, sqlSection(t, fixMigration, true), "credential_tables") {
		t.Errorf("cafaye.credential_tables() in %s is NOT kit's current body.\n"+
			"The fix and the template have drifted apart, which is this file's own defect\n"+
			"one layer up.", fixMigration)
	}
}

func kitFunctionBody(t *testing.T, src, fn string) string {
	t.Helper()
	return functionBody(t, "kit/templates/database/tenancy/substrate.sql", src, fn)
}

// findKitSubstrate returns the path to kit's substrate template, or "" when there
// is not one within three levels above this repository.
//
// BOUNDED AT THREE, and named here because an unbounded upward walk is how a check
// reads a fleet it does not own: kit's own AGENTS.md records a sweep that found a
// whole fleet in a leftover checkout in a shared temp directory and went red on a
// tree with nothing wrong with it. Three levels covers a sibling (`../kit`) and a
// worktree nested one directory deeper (`identity/cafaye/wt-*/`), which is how
// this measurement is actually taken, and stops there.
//
// "" is the honest answer rather than a guess: the caller turns it into a named
// SKIP, and a check that quietly passed because it could not find the other file
// is the exact failure this file exists to prevent.
func findKitSubstrate(t *testing.T) string {
	t.Helper()
	dir := repoRoot(t)
	rel := []string{"kit", "templates", "database", "tenancy", "substrate.sql"}
	for range 3 {
		dir = filepath.Dir(dir)
		candidate := filepath.Join(append([]string{dir}, rel...)...)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}
