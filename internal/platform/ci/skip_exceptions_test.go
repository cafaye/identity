package ci

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// # THE ONE PERMITTED SKIP, AND WHAT HOLDS IT TO THREE NAMES
//
// Two steps in `.github/workflows/ci.yml` fail the job on any `--- SKIP:` line.
// That rule is older than `internal/courier` and it is right: `dbtest.Pool` skips
// when TEST_DATABASE_URL is unset, so the suite's most expensive third can verify
// nothing and still report green.
//
// `internal/courier`'s end-to-end file needs a LIVE courier, and CI has none and
// cannot have one without standing up a second service with its own database, its
// own migrations and its own principal resolver. So `E2E_SKIP_EXCEPTIONS` in the
// gate job's `env:` names the three tests that skip for that reason, and the two
// skip checks subtract exactly those and nothing else.
//
// # WHY THIS FILE EXISTS AT ALL, GIVEN THE WORKFLOW SAYS IT ALL
//
// Because a list of permitted exceptions is the exact shape of thing that rots, and
// it rots in BOTH directions:
//
//   - it grows. Somebody adds a test that skips, names it here to make CI green,
//     and the no-skip rule quietly stops covering a whole class of failure. This is
//     how a check gets made green by not checking.
//   - it empties. Somebody deletes an entry to hide a REAL skip — a database test
//     that started skipping is the failure this rule was written for, and quietly
//     allowing one is how a green badge comes to mean nothing.
//
// So the list is pinned at its exact contents, in both directions, and the only
// legal change to it is a change to the reasoning in the workflow's own comment.
//
// (It used to end "the way `knownDrift` in `internal/httpapi` is pinned: it cannot
// grow and it cannot be emptied". Packet identity-28 emptied that list, correctly
// and by documenting twelve routes, and had to drop the "cannot be emptied" half
// of the comparison — see DECISIONS.md D1. Citing it here as a model for a rule
// this repository no longer follows is the same class of mistake as citing a stale
// fact, so the citation goes.)

// e2eSkipExceptions are the tests permitted to skip because they need a live
// courier.
//
// THIS IS THE LIST, written out rather than read from the workflow, and the
// duplication is the assertion: `TestTheExemptionListIsExactlyTheseThreeNames`
// fails when the two disagree. A test that read the workflow for its expectations
// would agree with it by construction and prove nothing — which is the same reason
// `.golangci.yml`'s exclusion is stated in the test that holds it.
var e2eSkipExceptions = []string{
	"TestAPasswordResetGoesOutThroughARealCourier",
	"TestAVerificationLinkReachesCouriersWelcomeTemplate",
	"TestTheTwoEmailChangeMessagesCourierCannotSendAreRefused",
}

// TestTheExemptionListIsExactlyTheseThreeNames is the pin, and it fails in both
// directions on purpose.
//
// A fourth name is somebody widening the rule. A second name is somebody removing
// the proof — or renaming a test and forgetting the list, which is the same failure
// seen from the other side and is the one a renamed test produces on its own.
func TestTheExemptionListIsExactlyTheseThreeNames(t *testing.T) {
	declared := skipExceptionsInWorkflow(t)

	if len(declared) == 0 {
		t.Fatal("ci.yml declares no E2E_SKIP_EXCEPTIONS, so the two steps that fail on a " +
			"`--- SKIP:` line have nothing to subtract and every skip in this repository — " +
			"including a database test that stopped running — would be reported as undeclared. " +
			"See that variable's comment for why the exemption exists")
	}

	want := map[string]bool{}
	for _, name := range e2eSkipExceptions {
		want[name] = true
	}

	got := map[string]bool{}
	for _, name := range declared {
		got[name] = true
	}

	for _, name := range declared {
		if !want[name] {
			t.Errorf("ci.yml exempts %q from the no-skip rule, and this file does not know it.\n"+
				"Either the exemption is unjustified — a test that does not need a live "+
				"courier has no reason to skip, and naming it here exempts it from the rule "+
				"that catches a database test quietly going away — or this list was not "+
				"updated with it. Adding a name must be a deliberate edit to BOTH.", name)
		}
	}
	for _, name := range e2eSkipExceptions {
		if !got[name] {
			t.Errorf("ci.yml no longer exempts %q. If that test was renamed, the no-skip rule "+
				"is now firing on a declared exception and CI is red for a reason that has "+
				"nothing to do with the code. If it was deleted, deleting a test and "+
				"emptying the exemption together is the one edit that leaves no trace.", name)
		}
	}
}

// TestEveryExemptedTestReallyNeedsALiveCourier is the other half of the pin: it
// reads the tree and checks that each exempt test is in `internal/courier` and that
// each is the one that reaches for a live courier.
//
// WITHOUT IT, the list is a comment with a shape. Somebody could exempt a test in
// `internal/mfa` — a real database test — and this file would say the list was
// consistent, because it only compares the list to itself. The location check is
// cheap and it is the part that ties an exemption to a CAUSE: every name here is in
// the one package that has an end-to-end file needing a second service.
func TestEveryExemptedTestReallyNeedsALiveCourier(t *testing.T) {
	for _, name := range e2eSkipExceptions {
		if !testNamesIn(t, "internal/courier")[name] {
			t.Errorf("%s is exempt from the no-skip rule but is not a test in "+
				"internal/courier. The exemption exists because that package's e2e file "+
				"needs a live courier, and an exemption for a test anywhere else is "+
				"covering up something else.", name)
		}
	}
}

// TestTheSkipRuleIsStillInTheWorkflow is the assertion that the exemption did not
// become the rule's removal.
//
// It is here because "subtract the exemptions" is one edit away from "delete the
// check", and the diff of that edit looks like tidying. It requires, in the same
// job, that BOTH skip checks are still present and each is self-contained — it
// greps for `--- SKIP:`, exempts by whole name rather than by prefix, subtracts the
// exemptions, and exits 1 on what is left. A `grep -v` that filters a list out of
// the output without failing on the remainder is not a rule at all, it is a report.
func TestTheSkipRuleIsStillInTheWorkflow(t *testing.T) {
	// TWO INDEPENDENT SITES ARE REQUIRED, and that is the part this test got wrong
	// the first time it was written. Four booleans OR-ed across every step in the
	// job are satisfied by ONE surviving site: deleting the whole-suite check from
	// the security step left the per-package check in the tier step to answer all
	// four, and the test passed against a workflow that no longer failed on a skip
	// outside the database tier. That is the exact failure this file exists to
	// catch, introduced by the file meant to catch it.
	//
	// So each site is asserted as a unit, and both must be present. They are the two
	// halves of the rule and neither covers the other:
	//
	//	the tier step      per PACKAGE, over the packages derived from the tree. It
	//	                   catches a database test that stopped running, and says
	//	                   nothing about a skip outside those packages.
	//	the security step  over the WHOLE log. It catches a skip in a package the
	//	                   derivation never found — a new test file that skips, in a
	//	                   package that opens no pool.
	const wantSites = 2

	var sites int
	for _, script := range stepScripts(t, "gate") {
		if !strings.Contains(script, "--- SKIP: ") {
			continue
		}
		// The two sites match skip lines two different ways, and BOTH are accepted: the
		// tier step counts them in awk (`/^[[:space:]]*--- SKIP: /`) because it needs a
		// per-package count, and the security step greps the whole log
		// (`grep -E '^[[:space:]]*--- SKIP: '`) because it needs a name list. So the
		// marker is the part BOTH share — the character class and the `--- SKIP: `
		// that follows it — rather than either one's trailing delimiter.
		//
		// A site is only a site if all four halves are in the SAME step: it greps for
		// the line, it exempts by whole name, it subtracts the exemptions, and it
		// fails on what is left. Splitting them across steps is not a rule.
		greps := strings.Contains(script, "[[:space:]]*--- SKIP: ")
		exits := strings.Contains(script, "exit 1")
		// `grep -vxF` — the `-x` is the whole safety of the subtraction. Without it,
		// a fixed-substring match on a bare name exempts `TestFooBar` by way of
		// `TestFoo`, so an exemption list becomes a hole one character wide. The awk
		// site gets the same property from comparing field 3 for equality.
		exact := strings.Contains(script, "grep -vxF -f") ||
			strings.Contains(script, "exempted($3)")
		subtracts := exact

		if greps && exits && exact && subtracts {
			sites++
			continue
		}
		// Name the missing halves rather than counting the step as a site, because
		// "no step enforces the rule" and "a step enforces it by prefix" are different
		// bugs with different fixes.
		var missing []string
		for _, half := range []struct {
			ok   bool
			name string
		}{
			{greps, "greps the log for a `--- SKIP:` line"},
			{exits, "exits 1 on a `--- SKIP:` line"},
			{exact, "exempts by whole name (`grep -vxF` or an equality test on field 3), so `TestFoo` does not exempt `TestFooBar`"},
			{subtracts, "subtracts E2E_SKIP_EXCEPTIONS from the skips it found"},
		} {
			if !half.ok {
				missing = append(missing, half.name)
			}
		}
		t.Errorf("a step handles `--- SKIP:` lines but does not %s.\n"+
			"  Each of the two skip checks must be self-contained: one over the derived "+
			"database packages, one over the whole log. A check that reports and does "+
			"not fail is a decoration (PLAN.md §1), and one that exempts by prefix is "+
			"a hole.", strings.Join(missing, ", and "))
	}

	if sites < wantSites {
		t.Errorf("%d step(s) enforce the no-skip rule, want %d.\n"+
			"  Both are required and neither covers the other: the per-package check only "+
			"sees packages derived from the tree, and the whole-log check is what catches "+
			"a skip in a package the derivation never found.", sites, wantSites)
	}
}

// skipExceptionsInWorkflow reads E2E_SKIP_EXCEPTIONS out of the gate job's env
// block, as the list of test names it holds.
//
// IT IS READ FROM THE FILE rather than parsed as YAML, for the reason this package's
// header gives: line scanning is enough for a shape this repository controls. The
// value is a YAML folded block (`>-`), so the names arrive on following lines at the
// env block's indentation, and each is one `Test…` identifier.
func skipExceptionsInWorkflow(t *testing.T) []string {
	t.Helper()

	var names []string
	inValue := false
	for _, line := range workflowLines(t) {
		trimmed := strings.TrimSpace(line)

		// The key itself, at the env block's indentation.
		if strings.HasPrefix(trimmed, "E2E_SKIP_EXCEPTIONS:") {
			inValue = true
			continue
		}
		if !inValue {
			continue
		}
		// A continuation line of a folded block: an identifier on its own.
		if strings.HasPrefix(trimmed, "Test") {
			names = append(names, trimmed)
			continue
		}
		// Anything else ends the value, and a blank line is the shape YAML gives a
		// folded block once its last content line is read.
		if trimmed == "" {
			if len(names) > 0 {
				return names
			}
			continue
		}
		if len(names) > 0 {
			return names
		}
	}
	return names
}

// testNamesIn is the Test functions declared in ONE package directory.
//
// IT WALKS rather than filtering `testNamesInTree`, because that helper returns a
// flat set of names with the paths already discarded — and a name is not enough to
// answer "is this exempt test in internal/courier", which is the whole question
// here. The two helpers share the parse for that reason and not for tidiness.
func testNamesIn(t *testing.T, dir string) map[string]bool {
	t.Helper()

	names := map[string]bool{}
	root := filepath.Join(repoRoot(t), dir)

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				names[fn.Name.Name] = true
			}
		}
		return nil
	})
	if err != nil {
		// A missing directory is a hard error rather than an empty set, because an
		// empty set would make every exempted name fail the caller's check for the
		// wrong reason and read like a typo in the list.
		t.Fatalf("walking %s for test names: %v", root, err)
	}
	return names
}
