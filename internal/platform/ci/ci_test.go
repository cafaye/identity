// Package ci is the test that keeps this repository's CI honest.
//
// It holds no code: `.github/workflows/ci.yml` is the artifact under test, and a
// workflow file nobody has executed is a file nobody has tested — the same defect
// as a test suite nobody runs, one level further out.
//
// # Why this is a Go test and not a comment in the workflow
//
// Four things in that file rot silently, and every one of them turns CI green
// while verifying less:
//
//   - the `uses:` path. kit shipped the workflow at `workflows/ci.reusable.yml`,
//     where GitHub could not resolve it, and every service README documented a
//     string that did not exist. A layout bug and a documentation bug agree with
//     each other perfectly, which is why nothing caught it.
//   - the toolchain pin. `versions` is a literal, because a job that calls a
//     reusable workflow takes no steps and so cannot read go.mod. It drifts the
//     moment somebody raises the go directive.
//   - the ordering. `goose up` is a deploy step that has to run before the suite,
//     and a workflow that puts it after — or in the same step — produces a red
//     that reads like a code failure rather than a broken pipeline.
//   - the skip. `dbtest.Pool` returns a pool and skips the test when
//     TEST_DATABASE_URL is unset, so the suite's most expensive third verifies
//     nothing unless the environment is set AND the run is checked for having
//     not skipped.
//
// Each of those has a test below, and each test names the step it is about, so a
// failure says which part of the workflow moved.
//
// # What this deliberately does not do
//
// It does not parse the workflow as YAML. Doing that would mean a dependency
// with no stated cause, and AGENTS.md's rule is that go.mod moves only for one.
// Line scanning is enough for a file whose shape this repository controls, and a
// file that changes shape loudly is a file a human re-reads.
package ci

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// kitWorkflow is the one call this repository makes. It is written out in full
// rather than assembled from parts because the value of comparing it is that a
// reader can check it against kit's tree with one `ls`.
//
// Verified present at that path in ../kit at commit 13228ed.
const kitWorkflow = "cafaye/kit/.github/workflows/ci.reusable.yml@master"

// kitInputs are kit's `on.workflow_call` inputs, read from the reusable workflow
// itself and from kit/README.md's "How a service repo adopts kit". A caller that
// invents an input name gets a red build at run time, which is the same shape of
// defect as the path above: two files that disagree and nothing to say so.
var kitInputs = []string{
	"language",
	"working-dir",
	"versions",
	"coverage-fail-under",
	"telemetry",
}

// gateCommand is the gate, named once. `bin/prime` is what a developer runs and
// what CI must run; a CI-only variant of it is a second thing to be wrong.
const gateCommand = "./bin/prime"

var (
	usesLine    = regexp.MustCompile(`^\s+uses:\s+(\S+)\s*$`)
	withKey     = regexp.MustCompile(`^\s+([a-z][a-z-]*):\s*(.*?)\s*$`)
	goDirective = regexp.MustCompile(`(?m)^go\s+([0-9][^\s/]*)\s*$`)
	versionsGo  = regexp.MustCompile(`"go"\s*:\s*"([0-9][^"]*)"`)
)

// ---------------------------------------------------------------------------
// the shared call
// ---------------------------------------------------------------------------

// TestTheSharedJobCallsKitAtAPathThatResolves is the one that would have caught
// six months of callers pointing at a file nobody could reach.
//
// It requires exactly one call and requires its path to be the documented one,
// because both halves matter: a second job calling kit with the OLD path is a
// repository where somebody copied the wrong line, and "some job calls kit
// correctly" would not notice that one.
func TestTheSharedJobCallsKitAtAPathThatResolves(t *testing.T) {
	var calls []string
	for _, line := range workflowLines(t) {
		if m := usesLine.FindStringSubmatch(line); m != nil && strings.HasPrefix(m[1], "cafaye/kit/") {
			calls = append(calls, m[1])
		}
	}

	switch len(calls) {
	case 0:
		t.Fatalf("no job calls kit's reusable workflow; this repository is supposed to call %s", kitWorkflow)
	case 1:
	default:
		t.Fatalf("exactly one job should call kit's reusable workflow, and %d do: %v", len(calls), calls)
	}
	if calls[0] != kitWorkflow {
		t.Fatalf("the call is %q, want %q.\n"+
			"GitHub resolves a cross-repository reusable workflow at\n"+
			"  {owner}/{repo}/.github/workflows/{file}@{ref}\n"+
			"and documents that subdirectories of the workflows directory are NOT\n"+
			"supported, so any other path resolves to nothing and the build is red\n"+
			"before it starts.", calls[0], kitWorkflow)
	}
}

// TestTheSharedJobPassesOnlyInputsKitDeclares. GitHub rejects an undeclared
// `with:` key at run time, and the error names the input rather than the file,
// so the first person to see it is whoever merged.
func TestTheSharedJobPassesOnlyInputsKitDeclares(t *testing.T) {
	known := map[string]bool{}
	for _, name := range kitInputs {
		known[name] = true
	}

	passed := withBlock(t)
	if len(passed) == 0 {
		t.Fatal("the job calling kit passes no inputs at all, so `language` — which kit requires — is missing")
	}
	for name := range passed {
		if !known[name] {
			t.Errorf("the caller passes %q, which is not one of kit's inputs (%s)",
				name, strings.Join(kitInputs, ", "))
		}
	}
}

// TestTheGoPinIsGoModsGoDirective. The one value a caller cannot compute: a job
// that calls a reusable workflow takes no steps, so `versions` is a literal and
// nothing but a test keeps it true.
//
// The comparison is exact, not "compatible". kit's default is `stable`, and a
// suite that passes today must not depend on which patch of the toolchain the
// runner had cached — so `1.26` would be as wrong as `stable`, and `1.26.1` is
// what go.mod says.
func TestTheGoPinIsGoModsGoDirective(t *testing.T) {
	pinned := versionsGo.FindStringSubmatch(with(t, "versions"))
	if pinned == nil {
		t.Fatalf("the `versions` input carries no go pin: %q", with(t, "versions"))
	}

	want := goDirectiveOf(t)
	if pinned[1] != want {
		t.Errorf("the kit call pins go %s and go.mod says %q.\n"+
			"Raise both in the same commit: go.mod's `go` directive is the pin, and\n"+
			"the literal in .github/workflows/ci.yml is the copy kit reads.",
			pinned[1], want)
	}
}

// TestTheGateIsBuiltWithGoModsToolchainToo. The companion job sets up its own
// toolchain, and the two have to agree — so this job reads go.mod with
// `go-version-file` rather than repeating the literal a second time.
func TestTheGateIsBuiltWithGoModsToolchainToo(t *testing.T) {
	found := false
	for _, line := range workflowLines(t) {
		if strings.Contains(line, "go-version-file:") {
			found = true
			if !strings.Contains(line, "go.mod") {
				t.Errorf("setup-go reads %q; the pin that cannot drift is go.mod", strings.TrimSpace(line))
			}
		}
	}
	if !found {
		t.Error("no step reads the toolchain from go.mod, so the gate job's Go is a second literal somewhere")
	}
}

// TestTheCoverageFloorIsAboveZero. kit's default is 0 "so adoption never blocks
// a repository on day one", and 0 is also the value that fails nothing: a gate
// that cannot fail is not a gate.
func TestTheCoverageFloorIsAboveZero(t *testing.T) {
	floor := with(t, "coverage-fail-under")
	if floor == "" || floor == "0" {
		t.Fatalf("coverage-fail-under = %q, which fails nothing. Measure the suite and write the number down.", floor)
	}
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(floor) {
		t.Fatalf("coverage-fail-under = %q, which is not a number", floor)
	}
}

// TestTelemetryIsAQuotedString. kit compares `inputs.telemetry == 'true'` on
// purpose: GitHub coerces the bare word `false` to a boolean in some positions,
// so `if: inputs.telemetry` is a trap and an unquoted `false` here is a
// different type than the one kit compares against.
func TestTelemetryIsAQuotedString(t *testing.T) {
	value, found := withBlock(t)["telemetry"]
	if !found {
		t.Fatal("telemetry is not passed; kit defaults it to 'false' either way, but stating it is the contract")
	}
	if value != "'true'" && value != "'false'" {
		t.Errorf("telemetry = %s, want 'true' or 'false' in quotes. An unquoted false\n"+
			"reaches Actions as a boolean, which is not what kit compares against.", value)
	}
}

// ---------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------

// TestTheGateRunsBinPrimeItself. kit's Go job runs `go mod download`,
// `go build ./...` and `go test ./...` as three steps of its own. That is not the
// command a developer runs, so this repository runs the command a developer runs.
func TestTheGateRunsBinPrimeItself(t *testing.T) {
	scripts := stepScripts(t, "gate")
	invocations := 0
	for _, script := range scripts {
		if strings.Contains(script, gateCommand) {
			invocations++
		}
	}
	if invocations == 0 {
		t.Fatalf("no step in the gate job runs %s, so CI is not running the gate a developer runs", gateCommand)
	}
}

// TestTheMigrationsRunBeforeTheSuite is the ordering assertion, and it is the
// reason this file is worth existing.
//
// There are exactly two ways to get a green CI run that verified nothing, and the
// first is what `dbtest.Pool`'s skip gives you for free. The second is
// TEST_DATABASE_URL set with no migrations applied: every database test then
// fails on `relation "public.users" does not exist`, which is loud but reads like
// a bug in the code under test rather than a bug in the pipeline.
//
// Only the ordering fixes the second, so it is asserted rather than documented.
func TestTheMigrationsRunBeforeTheSuite(t *testing.T) {
	migrate, suite := -1, -1
	for i, script := range stepScripts(t, "gate") {
		if migrate < 0 && strings.Contains(script, "goose -dir migrations") && strings.Contains(script, " up") {
			migrate = i
		}
		if suite < 0 && strings.Contains(script, gateCommand) {
			suite = i
		}
	}

	if migrate < 0 {
		t.Fatalf("no step applies migrations, so the database tier runs against an empty schema.\n" +
			"Run `goose -dir migrations postgres \"$DATABASE_URL\" up` as its own step, above the gate.")
	}
	if suite < 0 {
		t.Fatalf("no step runs %s, so there is no gate to order against", gateCommand)
	}
	if migrate > suite {
		t.Errorf("migrations are applied in gate step %d and the gate runs in step %d.\n"+
			"A migration after the suite is a red that reads like a code failure.", migrate+1, suite+1)
	}
	if migrate == suite {
		t.Error("migrations and the suite share one step; a failure in either is then indistinguishable " +
			"from a failure in the other, and a `go test` that skipped is invisible")
	}
}

// TestTheMigrationsAreAppliedAndNotJustChecked. `goose status` prints what is
// applied and is not a gate on its own, so the `up` and the `status` have to be
// in the same step for the log to be evidence.
func TestTheMigrationsAreAppliedAndNotJustChecked(t *testing.T) {
	for _, script := range stepScripts(t, "gate") {
		if strings.Contains(script, "goose -dir migrations") && strings.Contains(script, " up") {
			if !strings.Contains(script, "status") {
				t.Error("the migration step applies and never reports; without `goose status` the log " +
					"carries no evidence that anything ran before the tests")
			}
			return
		}
	}
	t.Fatal("no step applies migrations")
}

// TestTheDatabaseTierCannotSkipQuietly is the assertion the packet exists for.
//
// dbtest.Pool returns a pool and calls t.Skipf when TEST_DATABASE_URL is unset,
// so every environment-gated test in this repository skips and the suite reports
// green. internal/mfa's TestTheDatabaseTierAlreadyRan catches the absence of the
// variable; this catches the workflow losing the check that the variable was
// honoured — a later edit to ci.yml that drops the grep, or a `-short` flag, or a
// test binary that prints nothing.
func TestTheDatabaseTierCannotSkipQuietly(t *testing.T) {
	var derives, refusesSkip, checksCount bool

	for _, script := range stepScripts(t, "gate") {
		if strings.Contains(script, "dbtest\\.") {
			derives = true
		}
		if strings.Contains(script, "--- SKIP:") && strings.Contains(script, "exit 1") {
			refusesSkip = true
		}
		if regexp.MustCompile(`DATABASE_TIER_FLOOR|SUITE_FLOOR`).MatchString(script) {
			checksCount = true
		}
	}

	if !derives {
		t.Error("no step derives the database tier from the tree. Deriving it means a new test file " +
			"that opens a pool joins the tier without anyone remembering to add it; a hand-written " +
			"list is a list that goes stale.")
	}
	if !refusesSkip {
		t.Error("no step fails the job on a `--- SKIP:` line. A skipped test proves nothing (PLAN.md §1), " +
			"and a suite that exits 0 with tests skipped has run less than it appears to.")
	}
	if !checksCount {
		t.Error("no step compares a test count against a floor, so a deleted database test is invisible")
	}
}

// TestThePostgresServiceIsPinned. `postgres:latest` means the suite's result
// depends on which tag the runner pulled, and a suite that passes today must not
// depend on that. A bare major (`postgres:17`) is better and still floats across
// minors, so this holds the shape kit's own compose template uses.
func TestThePostgresServiceIsPinned(t *testing.T) {
	images := serviceImages(t)
	if len(images) == 0 {
		t.Fatal("the gate job declares no services, so the database tier cannot run in CI at all")
	}
	for name, image := range images {
		switch {
		case image == "":
			t.Errorf("service %s has no image", name)
		case strings.HasSuffix(image, ":latest"):
			t.Errorf("service %s is :latest", name)
		case !strings.Contains(image[strings.LastIndex(image, "/")+1:], ":"):
			t.Errorf("service %s is %s, which floats to whatever the registry serves", name, image)
		}
	}
}

// TestTheLockfileGuardExists. go.sum is the lockfile and the gate's first step
// (`go mod download`) can move it. Cheap, and it catches a class of drift nothing
// else would.
//
// The two have to be on the SAME LINE, and that is the point: this repository's
// comments name go.sum in nearly every step that touches it, so a check that
// merely looked for the word in the script would pass on a comment.
func TestTheLockfileGuardExists(t *testing.T) {
	for _, script := range stepScripts(t, "gate") {
		for _, line := range strings.Split(script, "\n") {
			if strings.Contains(line, "git diff --exit-code") && strings.Contains(line, "go.sum") {
				return
			}
		}
	}
	t.Error("no step runs `git diff --exit-code … go.sum`; the gate can move the lockfile and " +
		"nothing here would say so")
}

// TestEveryRunBlockIsValidShell is the regression test for a defect that shipped
// into this file once, and it is here because nothing else in this package could
// have caught it.
//
// The awk program that counts PASS lines per package sat inside a shell
// single-quoted string, and the comment above it inside that string contained an
// apostrophe. That closed the quote early, the shell re-parsed the rest of the
// program as commands, and the step died on a syntax error — in the one step of
// the job that exists to prove the database tier ran. Every other test in this
// file read the workflow as text and passed: the text is well formed, and it
// means something other than what it appears to mean. The workflow had never been
// executed, which is the same defect as an untested suite, one level further out.
//
// So the blocks are parsed. GitHub runs a `run:` step on a Linux runner under
// `bash -e`, and this file uses a herestring, so bash is the shell these blocks
// are written for and the shell they are checked with. A machine with no bash can
// run neither this workflow nor `bin/prime`, so that is a failure here rather
// than a skip — a skip is precisely how a check that never ran comes to be
// counted as one that did.
func TestEveryRunBlockIsValidShell(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is not on PATH, so no `run:` block in .github/workflows/ci.yml can be parsed.\n"+
			"GitHub runs these under bash and bin/prime is a shell script, so a machine\n"+
			"without bash can run neither this workflow nor this repository's gate: %v", err)
	}

	dir := t.TempDir()
	checked := 0
	for _, job := range jobNames(t) {
		for i, script := range stepScripts(t, job) {
			// `bash -n` parses without executing, so nothing in these blocks runs
			// here: no database, no network, no /dev/urandom, no process bound.
			path := filepath.Join(dir, "step.sh")
			if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
				t.Fatalf("writing the run block of job %q, block %d: %v", job, i+1, err)
			}
			if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
				t.Errorf("job %q, run block %d, is not valid bash: %v\n%s\n"+
					"An apostrophe inside a single-quoted region — an awk program, a sed\n"+
					"script, a grep pattern — ends the quoting, and the shell re-parses the\n"+
					"rest as commands. Keep prose out of quoted programs and in shell\n"+
					"comments above them, where an apostrophe costs nothing.",
					job, i+1, err, out)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Error("no `run:` block was found in either job, so this parsed nothing and passed for the wrong reason")
	}
}

// TestNoSecretIsWrittenDown. MFA_ENCRYPTION_KEY and OIDC_SIGNING_KEY are read
// from the environment and never generated (AGENTS.md: a key generated at boot
// publishes a document no caching verifier has seen, and every restart would
// invalidate every enrolled user's secret). CI must not turn either into a
// literal, because a CI log is retained, searchable, and often public.
//
// An assignment is a literal when its own word contains no `$`. The word and not
// the rest of the line, because a step sets a dozen variables on one line and a
// check that looked at the whole line would be satisfied by any one of them —
// which is exactly the shape of bug it exists to catch.
func TestNoSecretIsWrittenDown(t *testing.T) {
	names := regexp.MustCompile(`(MFA_ENCRYPTION_KEY|OIDC_SIGNING_KEY)=`)
	for i, line := range workflowLines(t) {
		for _, name := range names.FindAllString(line, -1) {
			word := strings.SplitN(line, name, 2)[1]
			if blank := strings.IndexAny(word, " \t"); blank >= 0 {
				word = word[:blank]
			}
			if word == "" || strings.Contains(word, "$") {
				continue
			}
			t.Errorf("ci.yml:%d assigns %s a literal value: %s\n"+
				"Generate it for the run from /dev/urandom and mask it, or do not set it at all.",
				i+1, name, word)
		}
	}
}

// TestNoKeyOrPEMIsPastedIntoTheWorkflow. A heuristic, and stated as one: it
// cannot know what a secret looks like, so it looks for the two shapes a pasted
// key actually has — a PEM armour block, and a long opaque run that contains a
// digit. A test name or a package path contains neither.
//
// It is here because the failure is invisible in review: a key in a workflow
// reads as configuration, and it is only a leak once it is in somebody's log.
func TestNoKeyOrPEMIsPastedIntoTheWorkflow(t *testing.T) {
	pem := regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	opaque := regexp.MustCompile(`[A-Za-z0-9+/_=-]{40,}`)

	for i, line := range workflowLines(t) {
		if pem.MatchString(line) {
			t.Errorf("ci.yml:%d carries a PEM block. A private key in a workflow is a key in a log.", i+1)
		}
		for _, literal := range opaque.FindAllString(line, -1) {
			if !strings.ContainsAny(literal, "0123456789") {
				continue
			}
			t.Errorf("ci.yml:%d carries a 40+ character opaque literal with a digit in it (%s…).\n"+
				"That is what a pasted key looks like in a diff. Generate it per run, or say why it is not one.",
				i+1, literal[:12])
		}
	}
}

// ---------------------------------------------------------------------------
// the security tests
// ---------------------------------------------------------------------------

// TestTheNamedSecurityTestsExist is the check that keeps the workflow's named
// list from rotting into a list of tests that were renamed.
//
// Every name in the workflow's "the security tests ran, by name" step has to be a
// real function in this tree. A renamed test, or a deleted one, is the step
// silently covering one fewer thing — which is the failure a named list exists to
// prevent, and which nothing else in this file can see.
func TestTheNamedSecurityTestsExist(t *testing.T) {
	named := namedInWorkflow(t)
	if len(named) == 0 {
		t.Fatal("the workflow names no security tests, so the step that claims they ran asserts nothing")
	}

	defined := testNamesInTree(t)
	for _, name := range named {
		if !defined[name] {
			t.Errorf("ci.yml names %s as a test that must run, and no such function exists in this tree.\n"+
				"Rename it back, or fix the name in .github/workflows/ci.yml in the same commit —\n"+
				"a named list that no longer names anything is worse than no list.", name)
		}
	}
}

// TestTheNamedSecurityTestsAreEnough is deliberately a floor, not a list. It
// cannot know which of this repository's tests are the ones that matter, so it
// asserts six properties that would be catastrophic to lose quietly: a TOTP
// step cannot be spent twice, a recovery code is single-use, a session token is
// never stored raw, a secret sealed under one key does not open under another, a
// deployment with no key fails closed, and the tier that proves all of this
// actually ran.
func TestTheNamedSecurityTestsAreEnough(t *testing.T) {
	named := strings.Join(namedInWorkflow(t), " ")
	for _, property := range []struct{ subject, example string }{
		{"a TOTP replay guard", "TestClaimStepIsTheReplayGuard"},
		{"a single-use recovery code", "TestARecoveryCodeIsSingleUseUnderConcurrency"},
		{"a session token never stored raw", "TestStoreNeverWritesTheRawToken"},
		{"a deployment with no MFA key failing closed", "TestUnavailableVaultFailsClosed"},
		{"a secret sealed under another key not opening", "TestASecretSealedUnderAnotherKeyDoesNotOpen"},
		{"the database tier having run", "TestTheDatabaseTierActuallyRan"},
	} {
		if !strings.Contains(named, property.example) {
			t.Errorf("no named test covers %s. %s is in this tree; add it to the step named\n"+
				"\"the security tests ran, by name\" so the log has to carry it.", property.subject, property.example)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// withBlock is the `with:` mapping of the one job that calls kit, with values as
// they are written — quotes included, because one of the tests below is about the
// quotes.
//
// Indentation is the contract: a `uses:` at four spaces is a job, six spaces under
// a `with:` is an input, eight is a step key. Anything less indented than six ends
// the block, which is what stops the next job's name being read as an input.
func withBlock(t *testing.T) map[string]string {
	t.Helper()

	inputs := map[string]string{}
	lines := workflowLines(t)
	inJob, inWith := false, false
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "  ci:"):
			inJob = true
		case inJob && strings.HasPrefix(line, "    with:"):
			inWith = true
		case inWith && (strings.TrimSpace(line) == "" || !strings.HasPrefix(line, "      ")):
			return inputs
		case inWith:
			if m := withKey.FindStringSubmatch(line); m != nil {
				inputs[m[1]] = m[2]
			}
		}
	}
	if !inJob {
		t.Fatal("ci.yml declares no job named ci")
	}
	return inputs
}

// with is one input with its YAML quoting removed, because an input is a string
// and `'70'` is not a number until something takes the quotes off.
func with(t *testing.T, name string) string {
	t.Helper()
	value, found := withBlock(t)[name]
	if !found {
		t.Fatalf("the job calling kit does not pass %q", name)
	}
	return strings.Trim(value, `"'`)
}

// namedInWorkflow is the list the "security tests ran, by name" step iterates.
// It is read back out of the workflow rather than duplicated here, because a copy
// of the list is a second list.
func namedInWorkflow(t *testing.T) []string {
	t.Helper()

	// The list is the continuation lines of the step's `for name in \` … `; do`,
	// one test per line and nothing else. The last line carries the `; do`, so it
	// is optional in the shape. Matching on the line's own shape rather than on
	// the whole script is what keeps the two `Test…` names in the grep and the
	// error message below out of the result.
	name := regexp.MustCompile(`^\s+(Test[A-Za-z0-9_]+)\s*(\\)?\s*(; do)?\s*$`)

	var names []string
	found := false
	for _, script := range stepScripts(t, "gate") {
		if !strings.Contains(script, "did not PASS in this run") {
			continue
		}
		found = true
		for _, line := range strings.Split(script, "\n") {
			if m := name.FindStringSubmatch(line); m != nil {
				names = append(names, m[1])
			}
		}
		break
	}
	if !found {
		t.Fatal("no step fails the job when a named test does not PASS")
	}
	if len(names) == 0 {
		t.Fatal("the step that fails on a named test names none; it asserts nothing")
	}

	sort.Strings(names)
	return names
}

// stepScripts is the ordered list of `run:` bodies in one job, which is what the
// ordering and count assertions above are written against.
func stepScripts(t *testing.T, job string) []string {
	t.Helper()

	lines := workflowLines(t)
	var scripts []string
	var body []string
	inJob, inRun := false, false

	flush := func() {
		if len(body) > 0 {
			scripts = append(scripts, strings.Join(body, "\n"))
			body = nil
		}
		inRun = false
	}

	for _, line := range lines {
		if regexp.MustCompile(`^  [a-z][a-z-]*:`).MatchString(line) {
			if inJob {
				break // the next job started
			}
			inJob = strings.TrimSpace(line) == job+":"
			continue
		}
		if !inJob {
			continue
		}
		if strings.HasPrefix(line, "      - ") {
			flush()
			continue
		}
		if strings.HasPrefix(line, "        run: |") || strings.HasPrefix(line, "        run: |-") {
			inRun = true
			continue
		}
		if inRun {
			// A run body is everything indented past the `run:` key.
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "          ") {
				flush()
				continue
			}
			body = append(body, strings.TrimPrefix(line, "          "))
		}
	}
	flush()
	return scripts
}

// jobNames is every job in the workflow, read at two-space indent. stepScripts
// needs a job name, and a check that only ever looked at the `gate` job would
// miss a quoting bug in any other one.
func jobNames(t *testing.T) []string {
	t.Helper()

	declared := regexp.MustCompile(`^  ([a-z][a-z0-9-]*):\s*$`)
	var names []string
	for _, line := range workflowLines(t) {
		if m := declared.FindStringSubmatch(line); m != nil {
			names = append(names, m[1])
		}
	}
	return names
}

func serviceImages(t *testing.T) map[string]string {
	t.Helper()

	images := map[string]string{}
	inServices, pending := false, ""
	serviceName := regexp.MustCompile(`^ {6}([a-z][a-z0-9-]*):$`)
	serviceImage := regexp.MustCompile(`^\s+image:\s+(\S+)\s*$`)

	for _, line := range workflowLines(t) {
		if !inServices {
			inServices = strings.HasPrefix(line, "    services:")
			continue
		}
		if strings.HasPrefix(line, "    steps:") {
			break
		}
		// The name and the image sit on different lines in a normal workflow —
		// `postgres:`, then four comment lines, then `image:` — so the name is
		// carried across lines instead of being matched and dropped on its own.
		if m := serviceName.FindStringSubmatch(line); m != nil {
			pending = m[1]
		}
		if m := serviceImage.FindStringSubmatch(line); m != nil && pending != "" {
			images[pending] = m[1]
		}
	}
	return images
}

func goDirectiveOf(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	m := goDirective.FindSubmatch(raw)
	if m == nil {
		t.Fatal("go.mod carries no `go` directive")
	}
	return string(m[1])
}

func workflowLines(t *testing.T) []string {
	t.Helper()

	path := filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

// testNamesInTree is every Test function in this repository, parsed rather than
// grepped: a mention of a name in a comment is not a test, and this repository
// comments about its tests by name constantly.
func testNamesInTree(t *testing.T) map[string]bool {
	t.Helper()

	defined := map[string]bool{}
	err := filepath.WalkDir(repoRoot(t), func(path string, entry os.DirEntry, err error) error {
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
				defined[fn.Name.Name] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree for test functions: %v", err)
	}
	return defined
}

// repoRoot comes from this file's own path and not from the working directory:
// `go test` sets the working directory to the package, and a test that depends on
// where it was invoked from passes for the wrong reason somewhere.
func repoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed, so the repository root cannot be found")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}
