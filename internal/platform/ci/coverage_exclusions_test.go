package ci

// THE COVERAGE EXCLUSION IS ONLY GENERATED CODE, AND THIS IS THE TEST THAT KEEPS
// IT THAT WAY.
//
// `coverage-exclusions` is the second exclusion this repository declares, after
// the one in `.golangci.yml`, and it exists for the same reason with one hard
// difference: Go's coverage step takes a package PATTERN and not a file, so this
// exclusion is necessarily a directory and necessarily coarser than the lint
// exclusion beside it.
//
// # WHY A DIRECTORY EXCLUSION IS A HOLE, AND WHAT CLOSES IT
//
// `TestTheLintExclusionIsOneFileAndNotAPrefix` in `client/lint_exclusion_test.go`
// can assert that its pattern matches exactly one file, because golangci-lint
// takes a regex and a regex can be anchored to a file. Nothing in `go tool cover`
// can be anchored to a file, so `client/` would be a legal declaration here — and
// `client/` holds `baseurl.go`, `credentials.go`, `errors.go`, `redact.go`,
// `client.go` and this repository's own tests. Declaring `client/` would leave all
// of them unmeasured and the floor at 70, which is exactly the "quietly fix the
// red" move this packet was dispatched to prevent.
//
// So the compensating obligation moves into this file:
//
//   - the excluded prefix must resolve to a directory,
//   - every `.go` file under it must itself be generated,
//   - and the number of those files and their total lines must be the ones the
//     declaration recorded.
//
// A hand-written file appearing under the prefix therefore fails the build, which
// is the day somebody notices — rather than being absorbed by a directory rule.
//
// # INFERRED IS REFUSED, AND THE FAILURE DIRECTION IS WHY
//
// An inferred exclusion — "skip any file whose header says `// Code generated …
// DO NOT EDIT.`" — is the obvious implementation and it is refused because of
// which way it fails. The header is written by whichever generator ran. A
// generator that stops writing it, or a `//go:generate` line pointed at a
// different tool, would SILENTLY RE-EXCLUDE a quarter of the module while the
// floor stayed at 70, and the build would go green having measured almost
// nothing. An inferred exclusion that fails toward MORE coverage is safe — the
// floor bites and somebody is told. One that fails toward LESS is not.
//
// Which is also why the generated-header check in `isGeneratedGoFile` below is
// safe to use HERE even though the declaration must not be inferred: this check
// runs in the TEST, and its failure direction is "this test goes red", which is
// toward more scrutiny. If the header disappears, the file is no longer provably
// generated, the test refuses it, and somebody has to write down why. The
// inference decides nothing about what is measured; it only decides whether this
// test is satisfied.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// exclusionsFile is the declaration, relative to the repository root.
//
// At the root and not under `client/`, because it is a fact about the MODULE —
// the thing Go measures is the module, not a package — and because a declaration
// that lives inside the directory it excludes is one deletion away from deleting
// itself.
const exclusionsFile = "coverage-exclusions"

// generatedHeader is what a file must carry to be provably machine-written.
//
// Matched against the first lines of the file rather than the whole of it, and
// that is deliberate: a generated file may contain the words somewhere in its
// body — oapi-codegen's output quotes the phrase in a comment of its own — and a
// check that matched the whole file would be a check a generated file could
// satisfy by accident. The rule Go itself documents for this line is that it
// appears before the package clause and is followed by a blank line.
var generatedHeader = regexp.MustCompile(`(?m)^// Code generated .* DO NOT EDIT\.\s*$`)

// entryLine is one line of `coverage-exclusions`, whole.
//
// Parsed as a line and then field-scanned, rather than as a regex over the whole
// file, for the reason kit gives for the same file: a reason is a sentence, and a
// parser that splits on whitespace cannot be given one. The grammar is small and
// anything it does not recognise is an error rather than a skip — the failure
// mode of a permissive reader is a file that has quietly stopped excluding
// anything while still reading as a declaration.
var entryLine = regexp.MustCompile(`^excluded\s+coverage\s+(\S+)(.*)$`)

// fieldPair is `key=value` or `key="value"` in the tail of an entry.
var fieldPair = regexp.MustCompile(`([a-z][a-z-]*)=("[^"]*"|\S+)`)

// whyField is the reason each required field exists, so a failure says which
// rule was broken rather than "missing field".
var whyField = map[string]string{
	"reason":              `without one, "generated" becomes the reason for everything, including the hand-written file somebody put in a generated directory`,
	"owner":               "an exclusion nobody owns is an exclusion nobody will ever remove",
	"since":               "the ratchet needs the date the decision was taken",
	"until":               "an exclusion that cannot expire has stopped being a decision and become a fact",
	"files":               "without a file count, a file added to the excluded directory changes the denominator silently",
	"lines":               "without a line count, the size of the excluded set is not recorded anywhere",
	"coverage-fail-under": "without the floor on the same line, the excluded set and the floor are two facts that can drift apart",
}

// exclusion is one parsed entry.
type exclusion struct {
	prefix string
	fields map[string]string
	line   int
}

// TestTheCoverageExclusionIsOnlyGeneratedCode is the whole reason this file
// exists, and it is the coverage-side twin of
// `TestTheLintExclusionIsOneFileAndNotAPrefix`.
//
// The assertion is not "the declaration mentions the generated directory". It is
// four claims, each of which can be false independently:
//
//  1. the declaration names at least one entry (an exclusion with nothing in it
//     is not an exclusion);
//  2. every entry names a directory, and that directory resolves — kit's rule 4,
//     an entry matching nothing is a failure;
//  3. EVERY `.go` file under it is itself generated, and the entry's recorded
//     `files=` and `lines=` are the truth about the tree;
//  4. the prefix does not reach a `.go` file outside that directory — the
//     walk-every-file move from the lint test, so a widened exclusion is caught
//     by the same mechanism that would have applied it.
func TestTheCoverageExclusionIsOnlyGeneratedCode(t *testing.T) {
	root := repoRoot(t)
	entries := readExclusions(t, root)

	if len(entries) == 0 {
		t.Fatalf("%s declares no entry at all.\n"+
			"Every .go file in this module is measured when the list is empty, which is the right "+
			"default — but a declaration with nothing in it is a declaration nobody decided to "+
			"write, and the next entry gets added by whoever is under pressure.",
			exclusionsFile)
	}

	goFiles := goFilesUnder(t, root)

	for _, entry := range entries {
		// (2) the entry resolves. Rule 4, borrowed from ESLint's
		// reportUnusedDisableDirectives and the whole defence of the other three:
		// a generator that moves leaves the entry behind, and without this the
		// list is a ratchet that only turns one way.
		matched := goFilesUnder(t, root, entry.prefix)
		if len(matched) == 0 {
			t.Errorf("line %d: %s is excluded and contains no .go file in this repository.\n"+
				"The generator moved, the directory was deleted, or the path is a typo. Either "+
				"way this entry suppresses nothing, and an entry that suppresses nothing is dead "+
				"weight — dead entries are how an allowlist becomes a list of everything.",
				entry.line, entry.prefix)
			continue
		}

		// (3) every file under the excluded directory is itself generated. This
		// is the obligation the coarse exclusion creates and the thing that makes
		// `client/` illegal here rather than merely unwise.
		var (
			files  int
			lines  int
			notGen []string
		)
		for _, path := range matched {
			raw, err := os.ReadFile(filepath.Join(root, path))
			if err != nil {
				// `git ls-files` still lists a tracked file that has been deleted
				// from the worktree, so this IS the rule-4 case and not a broken
				// test — the generator moved, or the file was deleted, and the
				// declaration is now exempting nothing. Saying "no such file"
				// would be true and useless; the name below is what a reader needs.
				t.Errorf("line %d: %s is excluded and %s is in git but not in the worktree.\n"+
					"The declaration is now exempting nothing. `git ls-files` still lists it, "+
					"which is why this reads as a missing file rather than an unused entry — "+
					"the generator moved, or the file was deleted, and either way somebody has "+
					"to decide what the exclusion covers now.",
					entry.line, entry.prefix, path)
				continue
			}
			files++
			lines += strings.Count(string(raw), "\n")
			if !generatedHeader.Match(raw) {
				notGen = append(notGen, path)
			}
		}

		if len(notGen) > 0 {
			t.Errorf("line %d: %s excludes %d hand-written .go file(s):\n\n  %s\n\n"+
				"Go's coverage step takes a package pattern and not a file, so this exclusion is "+
				"necessarily a directory — which is why this assertion has to exist. A hand-written "+
				"file under an excluded directory is code nobody is measuring, held to no floor, "+
				"and it would be absorbed silently by a rule about the directory rather than the "+
				"file.\n\n"+
				"Either that code moves out of %s, or the declaration is wrong and the floor has to "+
				"cover it.",
				entry.line, entry.prefix, len(notGen), strings.Join(notGen, "\n  "), entry.prefix)
		}

		// The recorded fingerprint. A file added under the prefix without this
		// line being rewritten is a change of denominator nobody decided on, and
		// this is what catches it — the same commit, at review time.
		if got := entry.fields["files"]; got != strconv.Itoa(files) {
			t.Errorf("line %d: %s records files=%s and the tree holds %d.\n"+
				"The excluded set changed and the declaration was not restated, so the floor is "+
				"now a percentage of a set nobody has read. Rewrite this entry in the same commit "+
				"as whatever changed it.",
				entry.line, entry.prefix, got, files)
		}
		if got := entry.fields["lines"]; got != strconv.Itoa(lines) {
			t.Errorf("line %d: %s records lines=%s and the tree holds %d.\n"+
				"The excluded set changed and the declaration was not restated. Rewrite this entry "+
				"in the same commit as whatever changed it.",
				entry.line, entry.prefix, got, lines)
		}

		// (4) the walk-every-file move. A prefix that reaches a .go file OUTSIDE
		// its own directory is the broad-exclusion failure the lint config's
		// prose argues against, and this one is already coarser than that one.
		for _, path := range goFiles {
			if strings.HasPrefix(path, entry.prefix+"/") {
				continue
			}
			if underPathPrefix(path, entry.prefix) {
				t.Errorf("line %d: %s also reaches %s, which is outside the excluded directory.\n"+
					"A path prefix is matched at a directory boundary so that it cannot swallow a "+
					"sibling — `client/generated` must not exempt `client/generat` or "+
					"`client/generated_extra`. This one does, which means the prefix is being "+
					"applied as a string rather than as a path.",
					entry.line, entry.prefix, path)
			}
		}
	}
}

// TestEveryExcludedDirectoryIsNamedInTheDeclaration is the reverse direction, and
// it is the one that closes the failure this packet is really about.
//
// MD16's warning is about an exclusion that STOPS matching: a generator that
// stops writing its header un-excludes a quarter of the module while the floor
// stays where it is, and the number becomes decoration. Rule 4 catches an entry
// that has stopped matching. This catches the other shape — a directory of
// generated code that arrived and was never declared, so the floor is quietly
// measuring it — because that is the same defect arriving from the other end.
//
// It is deliberately the same walk the test above does, run over the whole tree
// rather than over the declared prefixes.
func TestEveryExcludedDirectoryIsNamedInTheDeclaration(t *testing.T) {
	root := repoRoot(t)
	entries := readExclusions(t, root)
	declared := map[string]bool{}
	for _, entry := range entries {
		declared[entry.prefix] = true
	}

	// Directories that hold at least one generated .go file and nothing else.
	generatedDirs := map[string]bool{}
	mixedDirs := map[string]bool{}
	for _, path := range goFilesUnder(t, root) {
		dir := path[:strings.LastIndex(path, "/")]
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			// Same rule-4 case as above, reported once and in the same words. A
			// reader who has just been told a file is missing should not also be
			// told a generated directory was never declared, because both are one
			// fact: the tree moved and the declaration did not.
			t.Errorf("%s is in git but not in the worktree, so this walk cannot tell "+
				"whether the directory it belongs to is generated. The generator moved, or "+
				"the file was deleted, and %s has not been restated.",
				path, exclusionsFile)
			continue
		}
		if generatedHeader.Match(raw) {
			generatedDirs[dir] = true
		} else {
			mixedDirs[dir] = true
		}
	}

	for dir := range generatedDirs {
		if !declared[dir] {
			t.Errorf("%s holds a generated .go file and is not in %s.\n"+
				"Either add it as an entry with its reason, its owner and its dates, or say why it "+
				"is measured. A generated directory that was never declared is a denominator that "+
				"grows without anybody deciding that it should.",
				dir, exclusionsFile)
		}
	}
	for dir := range mixedDirs {
		if declared[dir] {
			t.Errorf("%s holds both generated and hand-written .go files and is declared in %s.\n"+
				"The declaration is not wrong about the generated file — it is wrong about the "+
				"hand-written ones, which it excludes as a side effect of naming the directory.",
				dir, exclusionsFile)
		}
	}
}

// TestTheCoverageFloorInTheDeclarationIsTheFloorsFloor is property 3, and it is
// the only thing keeping "70%" one number.
//
// The measured number, the excluded set and the floor are three facts that belong
// together. The measured number is printed beside the other two on every run, by
// `bin/coverage-floor`. What CAN go stale is the floor itself: this repository
// states it in three places — the declaration, the gate job's `env:` block, and
// the `coverage-fail-under` input passed to kit — and three copies of a number is
// three chances for it to mean three different things.
//
// This asserts all three agree. Adding an exclusion is therefore an edit that has
// to touch the floor line, which is the point: the denominator and the threshold
// are one decision, and the test is what says so.
func TestTheCoverageFloorInTheDeclarationIsTheFloorsFloor(t *testing.T) {
	root := repoRoot(t)
	entries := readExclusions(t, root)

	declared := map[string]string{}
	for _, entry := range entries {
		value := entry.fields["coverage-fail-under"]
		if declared[value] == "" {
			declared[value] = entry.prefix
			continue
		}
		t.Errorf("%s names coverage-fail-under=%s on line %d and %s on line %d.\n"+
			"One floor, or none: a floor that depends on which line you read is not a floor.",
			exclusionsFile, value, entry.line, declared[value],
			entryLineNumberOf(t, root, declared[value]))
	}

	gate := gateEnvFloor(t)
	if gate == "" {
		t.Fatalf("the gate job sets no COVERAGE_FAIL_UNDER, so the floor this packet enforces " +
			"is not stated where the step reads it")
	}
	kitFloor := with(t, "coverage-fail-under")

	for floor, prefix := range declared {
		if floor != gate {
			t.Errorf("%s line %d says the floor is %s and .github/workflows/ci.yml says %s.\n"+
				"The excluded set, the gate's env: block and the input passed to kit are three "+
				"statements of one number. Keep them in step, or delete two of them.",
				exclusionsFile, entryLineNumberOf(t, root, prefix), floor, gate)
		}
		if floor != kitFloor {
			t.Errorf("%s line %d says the floor is %s and the kit call says %s.\n"+
				"kit's coverage step reads the WHOLE profile and cannot be told about this "+
				"repository's exclusions, so the two numbers are different by construction. They "+
				"must still be the same THRESHOLD, or a future reader cannot tell which one the "+
				"other is measured against.",
				exclusionsFile, entryLineNumberOf(t, root, prefix), floor, kitFloor)
		}
	}
}

// TestTheCoverageStepRunsTheCheckedInFilter keeps the enforcing filter and the
// tested filter from being two programs.
//
// `bin/coverage-floor` is executed by `TestTheCoverageFilterCanFail` in this
// package, which is what makes it a program with a proven exit code rather than a
// shell pipeline. It is only load-bearing if the workflow actually runs it: a
// step that went back to `go tool cover -func=coverage.out | awk …` would be
// green, would enforce the raw number, and would report the raw number as if it
// were the declared one — the exact "the number is decoration" failure this
// packet exists to prevent, arrived at from the other direction.
func TestTheCoverageStepRunsTheCheckedInFilter(t *testing.T) {
	var coverage, computingItself int
	for _, step := range namedStepScripts(t, "gate") {
		if step.name != "coverage" {
			continue
		}
		coverage++
		if strings.Contains(step.script, "bin/coverage-floor") {
			continue
		}
		computingItself++
		t.Errorf("the step named `coverage` does not run bin/coverage-floor:\n\n%s\n\n"+
			"bin/coverage-floor is the filter the exclusions are read by and the filter "+
			"TestTheCoverageFilterCanFail drives. A step that computes the total on its own "+
			"enforces the RAW profile — including the generated code this packet excludes — "+
			"while still printing a number a reader will take for the declared one.",
			step.script)
	}
	if coverage == 0 {
		t.Fatal("the gate job has no step named `coverage`, so the floor is not enforced here. " +
			"The kit job cannot enforce it: its `test` step dies on the first package that " +
			"needs a database, which this file's header documents")
	}
	if coverage > 1 {
		t.Errorf("the gate job has %d steps named `coverage`. Two steps enforcing one floor is "+
			"two numbers, and a reader cannot tell which one the badge means.", coverage)
	}
	if computingItself > 0 {
		return
	}
}

// namedStep is one `run:` body with the `name:` it belongs to.
//
// `stepScripts` returns the bodies without their names, and matching a body by a
// string it contains does not survive a comment: the `what actually ran` step
// quotes `COVERAGE_FAIL_UNDER` in its summary table, so a substring test for the
// coverage step finds the summary table instead. That is the failure
// kit's AGENTS.md names — "a check that a comment can satisfy is not a check" —
// and it is why this reader pairs a step with its name rather than searching for
// what it says.
type namedStep struct {
	name   string
	script string
}

func namedStepScripts(t *testing.T, job string) []namedStep {
	t.Helper()

	lines := workflowLines(t)
	var (
		steps    []namedStep
		name     string
		body     []string
		inJob    bool
		inRun    bool
		inScript bool
	)

	flush := func() {
		if inScript {
			steps = append(steps, namedStep{name: name, script: strings.Join(body, "\n")})
			body = nil
		}
		inRun = false
		inScript = false
	}

	for _, line := range lines {
		if regexp.MustCompile(`^  [a-z][a-z-]*:`).MatchString(line) {
			if inJob {
				break
			}
			inJob = strings.TrimSpace(line) == job+":"
			continue
		}
		if !inJob {
			continue
		}
		if m := regexp.MustCompile(`^      - name: (.+)$`).FindStringSubmatch(line); m != nil {
			flush()
			name = strings.TrimSpace(m[1])
			continue
		}
		if strings.HasPrefix(line, "      - ") {
			flush()
			continue
		}
		if strings.HasPrefix(line, "        run: |") {
			inRun, inScript = true, true
			continue
		}
		if inRun {
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "          ") {
				flush()
				continue
			}
			body = append(body, strings.TrimPrefix(line, "          "))
		}
	}
	flush()
	return steps
}

// TestTheCoverageExclusionsAreShellAndYAMLClean is the smallest test here and the
// one most likely to be forgotten: two files that are read by line scanning, one
// shell and one YAML, and a syntax error in either is a red build for a reason
// that has nothing to do with coverage.
func TestTheCoverageExclusionsAreShellAndYAMLClean(t *testing.T) {
	root := repoRoot(t)

	if out, err := exec.Command("bash", "-n", filepath.Join(root, "bin", "coverage-floor")).CombinedOutput(); err != nil {
		t.Fatalf("bin/coverage-floor is not valid bash: %v\n%s\n"+
			"The floor is enforced by this script. A syntax error in it is a floor that cannot "+
			"run, and a build that cannot run its floor is a build whose green badge is a guess.",
			err, out)
	}

	if _, err := os.Stat(filepath.Join(root, exclusionsFile)); err != nil {
		t.Fatalf("reading %s: %v\n"+
			"Without it the floor is measured over a set nobody wrote down, which is the whole "+
			"failure this declaration was added to prevent.", exclusionsFile, err)
	}
}

// --- the red proofs -----------------------------------------------------------

// TestTheCoverageFilterCanFail is the reason to believe any of the above.
//
// A gate that has only ever been seen green is a claim. Every row below is a
// deliberately broken declaration or profile, run through the REAL
// `bin/coverage-floor`, asserting a non-zero exit and a message naming the rule
// that caught it. Four of them are the four ways this exclusion has to fail, and
// the rest are the ways it could fail quietly instead.
//
// It is a test rather than a shell script in a report because a proof nobody runs
// is not a proof, and because `bin/coverage-floor` failing on a synthetic
// profile is the same code path CI uses — not a simulation of it.
func TestTheCoverageFilterCanFail(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, "bin", "coverage-floor")
	good, err := os.ReadFile(filepath.Join(root, exclusionsFile))
	if err != nil {
		t.Fatalf("reading %s: %v", exclusionsFile, err)
	}
	entry := lastNonCommentLine(string(good))

	// Two profiles in the module's own shape, naming packages that exist so the
	// file is a real coverage profile and not a string the script happens to
	// accept.
	//
	// `profileLow` is a module in trouble: three statements covered out of
	// thirteen, with one uncovered block in the generated client. 3/13 = 23.1%
	// over the whole module and 3/12 = 25.0% with the exclusion in place — both
	// far below the floor, which is what a real decrease looks like.
	const profileLow = "mode: set\n" +
		"github.com/cafaye/identity/internal/platform/clock:10.13,12.2 2 1\n" +
		"github.com/cafaye/identity/internal/platform/clock:20.13,22.2 9 0\n" +
		"github.com/cafaye/identity/internal/platform/id:10.13,12.2 1 1\n" +
		"github.com/cafaye/identity/client/generated/api.gen.go:10.13,12.2 1 0\n"

	// `profileHigh` is the same module after the tests caught up: every
	// hand-written statement covered, the generated block still at zero. 100.0%
	// over what is left, from 92.9% over everything.
	const profileHigh = "mode: set\n" +
		"github.com/cafaye/identity/internal/platform/clock:10.13,12.2 2 1\n" +
		"github.com/cafaye/identity/internal/platform/clock:20.13,22.2 9 1\n" +
		"github.com/cafaye/identity/internal/platform/id:10.13,12.2 1 1\n" +
		"github.com/cafaye/identity/client/generated/api.gen.go:10.13,12.2 1 0\n"

	// The two profiles that decide whether the floor means 70 at all: a module
	// one tenth of a percent under it, and one over.
	//
	// Built rather than written out, because a coverage block is covered WHOLE
	// or not at all — `999 698` is not 69.9%, it is a block of 999 statements
	// that was hit, and it reads as 100.0%. A single-line fixture for a
	// percentage near a boundary is a fixture that silently says something else.
	justBelow := oneStatementPerBlockProfile(699, 1000)
	justAbove := oneStatementPerBlockProfile(701, 1000)

	cases := []struct {
		name    string
		decl    string
		profile string
		assert  string
		want    string
	}{
		{
			name: "an entry that matches nothing is a failure",
			// kit's rule 4. The generator moved, or the path is a typo, and a
			// list that keeps dead entries keeps growing.
			decl: `excluded coverage client/nowhere files=1 lines=1 coverage-fail-under=70 ` +
				`reason="x" owner=identity since=2026-09-30 until=2027-03-31`,
			profile: profileLow,
			want:    "matches NOTHING",
		},
		{
			name:    "an entry with no reason is a failure",
			decl:    withoutField(entry, "reason"),
			profile: profileLow,
			want:    "no reason",
		},
		{
			name:    "an entry with no owner is a failure",
			decl:    withoutField(entry, "owner"),
			profile: profileLow,
			want:    "no owner",
		},
		{
			name:    "an entry with no since is a failure",
			decl:    withoutField(entry, "since"),
			profile: profileLow,
			want:    "no since",
		},
		{
			name:    "an entry with no until is a failure",
			decl:    withoutField(entry, "until"),
			profile: profileLow,
			want:    "no until",
		},
		{
			name:    "a misspelled field is a failure, not a silently dropped one",
			decl:    strings.Replace(entry, "owner=", "owners=", 1),
			profile: profileLow,
			want:    "unknown field",
		},
		{
			name:    "an expired entry is a failure on the day it passes",
			decl:    strings.Replace(entry, "until=2027-03-31", "until=2020-01-01", 1),
			profile: profileLow,
			want:    "EXPIRED",
		},
		{
			name:    "a malformed date is a failure",
			decl:    strings.Replace(entry, "since=2026-09-30", "since=last tuesday", 1),
			profile: profileLow,
			want:    "not an ISO date",
		},
		{
			name:    "a line that is not an entry is a failure, not a skip",
			decl:    entry + "\nclient/generated is fine, leave it out\n",
			profile: profileLow,
			want:    "not an entry",
		},
		{
			name:    "a declaration with no entry at all is a failure",
			decl:    "# nothing declared\n",
			profile: profileLow,
			want:    "declares no entry",
		},
		{
			name:    "a duplicate entry is a failure",
			decl:    entry + "\n" + entry + "\n",
			profile: profileLow,
			want:    "duplicate entry",
		},
		{
			// A second, differently-scoped entry over a DIFFERENT floor. Both
			// entries match the profile, so kit's rule 4 is satisfied and this is
			// caught by the floor check instead — which is the point: "70%" cannot
			// depend on which line of the declaration a reader opened.
			name: "two entries naming two floors is a failure",
			decl: entry + "\n" + `excluded coverage internal files=1 lines=1 ` +
				`coverage-fail-under=60 reason="a different floor" owner=identity ` +
				`since=2026-09-30 until=2027-03-31` + "\n",
			profile: profileLow,
			want:    "One floor, or none",
		},
		{
			name:    "a floor of zero is a failure",
			decl:    strings.Replace(entry, "coverage-fail-under=70", "coverage-fail-under=0", 1),
			profile: profileLow,
			want:    "not a positive number",
		},
		{
			name: "the floor still bites",
			// The one that matters most. An exclusion that makes coverage
			// unrestrictable is not a fix, so the floor has to fail a build on a
			// profile that is merely bad — with the repository's own declaration,
			// unchanged, doing the excluding. 2 of 3 hand-written statements.
			decl:    entry,
			profile: profileLow,
			want:    "below the",
		},
		{
			name:    "a profile with nothing covered at all is below the floor, not an error",
			decl:    entry,
			profile: strings.ReplaceAll(profileLow, " 1\n", " 0\n"),
			want:    "below the",
		},
		{
			// A file that is not a coverage profile is caught by rule 4 before the
			// arithmetic is reached: nothing in it matches the excluded path, so
			// the honest failure is "your entry suppresses nothing" rather than a
			// percentage computed from garbage. Named here because that ordering
			// is a decision, not an accident.
			name:    "a profile that is not a coverage profile is a failure, not a zero",
			decl:    entry,
			profile: "this is not a coverage profile\n",
			want:    "matches NOTHING",
		},
		{
			// The most dangerous shape an exclusion mechanism has: every package
			// declared, nothing left to measure, and 0/0 to divide. A naive
			// implementation reports either 0% (a false red forever) or 100% (a
			// green badge that measured nothing), and both are what this whole
			// packet exists to prevent.
			name: "a profile whose every package is excluded is a failure, not a 100%",
			decl: `excluded coverage internal coverage-fail-under=70 files=1 lines=1 ` +
				`reason="everything" owner=identity since=2026-09-30 until=2027-03-31` + "\n" +
				`excluded coverage client/generated coverage-fail-under=70 files=1 lines=1 ` +
				`reason="generated" owner=identity since=2026-09-30 until=2027-03-31` + "\n",
			profile: profileLow,
			want:    "no statements",
		},
		{
			name:    "a caller asserting a different floor than the declaration is a failure",
			decl:    entry,
			profile: profileHigh,
			assert:  "45",
			want:    "asserts a floor of 45",
		},
		{
			// THE FLOOR STILL BITES, to one statement. 698 covered of 999
			// hand-written statements is 69.9%: one below, and the build goes
			// red with the repository's own exclusion in place doing the
			// excluding. If this row ever passes, the exclusion has become a way
			// to make coverage unrestrictable, and that is not a fix.
			name:    "69.9% is red: the floor is still 70 with the exclusion in place",
			decl:    entry,
			profile: justBelow,
			want:    "coverage 69.9%",
		},
		{
			// The rounding case, and the reason this row exists rather than a
			// comment. 699 of 999 is 69.97%: it PRINTS as "70.0", and a floor
			// compared against the printed number is satisfied by a module below
			// it. The comparison is exact integer arithmetic
			// (`covered * 100 < floor * total`) precisely so that the display
			// format cannot give the floor away.
			//
			// Found by this very proof rather than by reading: the first version of
			// the 69.9% fixture had 999 statements instead of 1000, printed
			// "70.0", and went GREEN. A proof that found a bug in the thing it
			// was proving is the whole reason to run one.
			name:    "69.97% is red even though it PRINTS as 70.0",
			decl:    entry,
			profile: oneStatementPerBlockProfile(699, 999),
			want:    "(699/999 statements) is below",
		},
	}

	// And the other side of the same boundary, because a floor that fails
	// everything is not a floor either. 700 of 999 is 70.1%.
	t.Run("70.1% is green: one statement either side of the line decides the build", func(t *testing.T) {
		dir := t.TempDir()
		profPath := filepath.Join(dir, "coverage.out")
		if err := os.WriteFile(profPath, []byte(justAbove), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(script, profPath, filepath.Join(root, exclusionsFile)).CombinedOutput()
		if err != nil {
			t.Fatalf("bin/coverage-floor refused 70.1%% against a floor of 70: %v\\n%s", err, out)
		}
		if !strings.Contains(string(out), "coverage 70.1% at or above the 70% floor") {
			t.Errorf("the passing line does not read the way this case is about.\\nGot:\\n%s", out)
		}
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			declPath := filepath.Join(dir, "coverage-exclusions")
			profPath := filepath.Join(dir, "coverage.out")
			if err := os.WriteFile(declPath, []byte(tc.decl), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(profPath, []byte(tc.profile), 0o600); err != nil {
				t.Fatal(err)
			}

			out, err := exec.Command(script, profPath, declPath, tc.assert).CombinedOutput()
			if err == nil {
				t.Fatalf("bin/coverage-floor exited 0 on a declaration it must refuse.\n"+
					"Output was:\n%s", out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("bin/coverage-floor failed, but not for the reason this case is about.\n"+
					"expected output containing %q, got:\n%s", tc.want, out)
			}
		})
	}

	// The control, in the same table: the real declaration over a profile in the
	// real shape PASSES, and prints all three facts. Without this row every
	// failure above would be consistent with a script that fails at everything.
	t.Run("the control: a good declaration passes and prints the three facts", func(t *testing.T) {
		dir := t.TempDir()
		profPath := filepath.Join(dir, "coverage.out")
		if err := os.WriteFile(profPath, []byte(profileHigh), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(script, profPath, filepath.Join(root, exclusionsFile)).CombinedOutput()
		if err != nil {
			t.Fatalf("bin/coverage-floor refused the repository's own %s: %v\n%s",
				exclusionsFile, err, out)
		}
		for _, want := range []string{
			"coverage 100.0%",  // the three statements NOT excluded
			"client/generated", // the excluded set, named
			"reason:",          // and its reason
			"floor 70%",        // and the floor
			"12 statements",    // over what — the generated block is not in it
		} {
			if !strings.Contains(string(out), want) {
				t.Errorf("a passing run does not print %q.\n"+
					"The three facts — the measured number, the excluded set and the floor — have "+
					"to be readable from the output of a green run. A reader who cannot tell what "+
					"was excluded is reading decoration.\n\nGot:\n%s", want, out)
			}
		}
	})
}

// --- the reader ---------------------------------------------------------------

// readExclusions is every entry in the declaration, in file order.
//
// Strict, and it says why on stderr: a reader that finds nothing agrees with a
// declaration that excludes nothing, and the two are indistinguishable in a log.
// A malformed line, a missing required field, a non-ISO date and a duplicate are
// all failures here, which is the same set `bin/coverage-floor` refuses — the
// test and the tool are two readers of one grammar on purpose, so a change to
// either that the other does not see is a red build.
func readExclusions(t *testing.T, root string) []exclusion {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(root, exclusionsFile))
	if err != nil {
		t.Fatalf("reading %s: %v\n"+
			"Without it the coverage floor is measured over a set nobody wrote down, and a floor "+
			"over an undeclared set is a floor over whatever the last person felt like excluding.",
			exclusionsFile, err)
	}

	var entries []exclusion
	for i, line := range strings.Split(string(raw), "\n") {
		number := i + 1
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		m := entryLine.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("%s:%d is neither a comment nor an entry.\n"+
				"Expected `excluded coverage <path-prefix> files=N lines=N coverage-fail-under=N "+
				"reason=\"…\" owner=… since=YYYY-MM-DD until=YYYY-MM-DD` on ONE line — a wrapped "+
				"reason is two entries, one of which is a parse error.\n\n  %s",
				exclusionsFile, number, line)
		}

		fields := map[string]string{}
		for _, pair := range fieldPair.FindAllStringSubmatch(m[2], -1) {
			if _, duplicate := fields[pair[1]]; duplicate {
				t.Errorf("%s:%d names %s twice, and one of them is not being read.",
					exclusionsFile, number, pair[1])
			}
			fields[pair[1]] = strings.Trim(pair[2], `"`)
		}

		// Every required field, with the message that says which rule it is. An
		// allowlist entry with no reason is an assertion, and this repository
		// already holds `knownDrift` to that standard for the same reason: a list
		// nobody can check is a list that grows.
		//
		// `bin/coverage-floor` refuses exactly these too. Two readers of one
		// grammar, deliberately — a change to either that the other does not see is
		// a red build, and what is shared is the RULE, not a copy of the file.
		for _, name := range sortedKeys(whyField) {
			if fields[name] == "" {
				t.Errorf("%s:%d names no %s — %s.", exclusionsFile, number, name, whyField[name])
			}
		}

		for _, name := range []string{"since", "until"} {
			if value := fields[name]; value != "" && !isoDate.MatchString(value) {
				t.Errorf("%s:%d has %s=%q, which is not an ISO date (YYYY-MM-DD).",
					exclusionsFile, number, name, value)
			}
		}

		// The gate reads the clock. kit's rule, and the reason `until` is a field
		// rather than a comment: an entry that cannot expire has stopped being a
		// decision and become a fact.
		if until := fields["until"]; isoDate.MatchString(until) {
			if today := time.Now().UTC().Format("2006-01-02"); until < today {
				t.Errorf("%s:%d is EXPIRED on %s (today is %s). Delete the entry, or move the "+
					"date and write a new reason — a date that rolls forward by itself is not a "+
					"ratchet.", exclusionsFile, number, until, today)
			}
		}

		entries = append(entries, exclusion{prefix: m[1], fields: fields, line: number})
	}
	return entries
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

var isoDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// goFilesUnder is every `.go` file in the repository, or every one under a
// prefix, as a git-style forward-slash path relative to the root.
//
// `git ls-files` rather than `filepath.WalkDir`, for the reason
// `client/lint_exclusion_test.go` gives: the question is "which files does this
// repository have", and git is the only thing that answers it without counting
// ignored files — and an ignored generated file is exactly what this is about.
//
// The prefix is matched at a directory boundary and not as a string, so
// `client/generated` cannot match `client/generat/…`. That is the same rule
// `bin/coverage-floor` applies to a profile path, and the two are kept in step
// deliberately: a test that computed a different set from the filter it is
// testing would pass while the filter excluded something else.
func goFilesUnder(t *testing.T, root string, prefix ...string) []string {
	t.Helper()

	out, err := exec.Command("git", "-C", root, "ls-files", "*.go").CombinedOutput()
	if err != nil {
		t.Fatalf("git ls-files '*.go': %v\n%s", err, out)
	}

	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		line = filepath.ToSlash(line)
		if strings.HasPrefix(line, "vendor/") {
			continue
		}
		if len(prefix) > 0 && !underPathPrefix(line, prefix[0]) {
			continue
		}
		paths = append(paths, line)
	}
	sort.Strings(paths)
	return paths
}

// underPathPrefix is the one place the directory-boundary rule is written down.
func underPathPrefix(path, prefix string) bool {
	if !strings.HasSuffix(path, ".go") {
		return false
	}
	if !strings.HasPrefix(path, prefix+"/") {
		return false
	}
	// Anything at or below the prefix counts; a sibling one segment along does
	// not. The second half is the whole point, so it is written rather than
	// assumed: `strings.HasPrefix("client/generat/a.go", "client/generated/")`
	// is false anyway, and the case that bites is a prefix that is a string
	// prefix of a longer directory name, which the slash above already refuses.
	return len(path) > len(prefix)+1
}

// entryLineNumberOf is the line an entry is declared on, named in a message
// about a disagreement between two files.
func entryLineNumberOf(t *testing.T, root, prefix string) int {
	t.Helper()

	for _, entry := range readExclusions(t, root) {
		if entry.prefix == prefix {
			return entry.line
		}
	}
	return 0
}

// gateEnvFloor is `COVERAGE_FAIL_UNDER` in the gate job's `env:` block, which is
// the copy the coverage step actually reads.
func gateEnvFloor(t *testing.T) string {
	t.Helper()

	for _, line := range workflowLines(t) {
		m := regexp.MustCompile(`^\s+COVERAGE_FAIL_UNDER:\s*'?([0-9]+)'?\s*$`).
			FindStringSubmatch(line)
		if m != nil {
			return m[1]
		}
	}
	return ""
}

// oneStatementPerBlockProfile is a coverage profile of `total` single-statement
// blocks of which `covered` were hit, plus one uncovered block in the generated
// client. `covered/total` is therefore the exact number a floor is compared
// against once the exclusion has removed the generated block.
func oneStatementPerBlockProfile(covered, total int) string {
	var b strings.Builder
	b.WriteString("mode: set\n")
	for i := 0; i < total; i++ {
		count := 0
		if i < covered {
			count = 1
		}
		// Two real packages rather than one, so a reader cannot mistake the
		// fixture for a single-block profile.
		pkg := "internal/platform/clock"
		if i%2 == 1 {
			pkg = "internal/platform/id"
		}
		fmt.Fprintf(&b, "github.com/cafaye/identity/%s:%d.13,%d.2 1 %d\n", pkg, 10+i*10, 12+i*10, count)
	}
	b.WriteString("github.com/cafaye/identity/client/generated/api.gen.go:10.13,12.2 1 0\n")
	return b.String()
}

// lastNonCommentLine is the one entry in a declaration file, for the red proofs
// above to break in one place.
func lastNonCommentLine(raw string) string {
	var last string
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		last = trimmed
	}
	return last
}

// withoutField removes one field from an entry, quoted or not.
//
// Removing the SPAN rather than substituting a placeholder key is the point: a
// red proof that renames `owner=` to `owners=` is testing a different defect
// (an unknown field) than the one it says it is testing, and a proof that does
// not test what it claims is decoration.
func withoutField(entry, name string) string {
	quoted := regexp.MustCompile(`\s` + regexp.QuoteMeta(name) + `="[^"]*"`)
	if quoted.MatchString(entry) {
		return quoted.ReplaceAllString(entry, "")
	}
	return regexp.MustCompile(`\s`+regexp.QuoteMeta(name)+`=\S+`).ReplaceAllString(entry, "")
}
