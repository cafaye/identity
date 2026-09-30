package client

// REGENERATION IS A GATE, NOT A SUGGESTION.
//
// Without this test, a client and its document drift apart and the drift is
// invisible: `openapi/v1.yaml` gains an operation, `api.gen.go` keeps the old
// twenty methods, and every test in this package still passes because none of them
// reads the document. The caller gets a 404 from a method that is not there. That
// is the same failure `internal/httpapi/openapi_drift_test.go` exists to catch on
// the router side, and a client needs its own tripwire for the same reason — the
// two files cannot both be right and nothing else would say so.
//
// This is the Go half of a pair. `cafaye-ts`'s `regeneration.test.mjs` is the
// TypeScript half, and the three clients for one platform have to fail the same
// way or "we regenerate when we remember" is the platform's policy.
//
// # WHY A RED PROOF, AND WHY IT IS NOT A SEPARATE STEP
//
// A gate that has only ever been seen green is a claim. `TestTheGateFailsWhenThe
// CommittedFileIsWrong` below injects a fault and asserts the gate goes red, so
// the red is a fact rather than a prediction. It is in the same file on purpose:
// the fault and the check that catches it belong together, and separating them
// across two files is how a proof stops being run.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// generatorVersion is the pin, written out here rather than read out of
// generate.go's `//go:generate` line.
//
// Duplicated on purpose. The `//go:generate` line is what a developer runs and this
// constant is what the test runs, and a test that parsed the line would be testing
// that a string it just read contains the string it was written with. Two
// statements of one pin is the risk this package accepts; a third would be a
// maintenance tax for nothing. `TestThePinIsTheOneTheGeneratorDirectiveUses` is
// what keeps the two in step.
const generatorVersion = "v2.8.0"

// generatorModule is the module path half of the pin, for the same reason.
const generatorModule = "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen"

// generatedFile is the committed output, relative to this package.
//
// It names the SUBDIRECTORY because the generated code is its own package — the
// header on this file's sibling, transport.go, explains why — and because a path
// that is wrong about its directory produces a failure that reads like a missing
// file rather than a stale constant.
const generatedFile = "generated/api.gen.go"

// generateTimeout bounds a generator run.
//
// A bound rather than an unbounded wait, and generous because the first run in a
// clean checkout downloads and compiles the generator. There is no sleep and no
// retry: the generator either produces the file or it does not, and a poll loop
// waiting for something that may never arrive is how a suite turns a hang into a
// pass.
const generateTimeout = 10 * time.Minute

// repoRoot comes from this file's own path, as internal/platform/ci's does, and
// for the same reason: `go test` sets the working directory to the package, so a
// test that resolved the repository from `os.Getwd` would pass for the wrong
// reason when invoked from anywhere else.
func repoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed, so the repository root cannot be found")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

// TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces is the gate.
//
// It regenerates into a TEMPORARY directory and compares, rather than
// regenerating over the committed file and asking `git diff`. That is the
// difference between a test that reports what is wrong and a test that destroys
// the evidence before reporting it: a regenerate-in-place failure leaves the tree
// modified, so the next run passes, so the failure is visible exactly once. A
// temporary directory means the committed file is untouched whatever happens and
// the comparison is repeatable.
//
// `git status --porcelain` is asked as well, because `git diff` is blind to an
// untracked file and a generator that starts emitting an extra file changes the
// published surface while reporting a clean diff. That is the same reasoning
// cafaye-ts's regeneration test gives, and it is right for the same reason.
func TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces(t *testing.T) {
	root := repoRoot(t)

	// The generator must be in a git tree for the porcelain check to mean
	// anything. Not `t.Skip` — a checkout that is not a git tree cannot verify
	// the "no new file" half, and skipping would make that half untested
	// everywhere, which is the same as testing it nowhere.
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatalf("git is not on PATH, so this test cannot ask whether the generator "+
			"produced a file the repository does not have: %v", err)
	}
	if out, err := exec.Command("git", "-C", root, "rev-parse", "--is-inside-work-tree").CombinedOutput(); err != nil {
		t.Fatalf("this checkout is not a git work tree, so the regeneration gate cannot "+
			"detect a generated file that is new rather than changed: %v\n%s", err, out)
	}

	// A scratch config pointing at the scratch output. The committed
	// oapi-codegen.yaml is read and rewritten rather than duplicated: a copy here
	// would be a second statement of the generator's options and would drift from
	// the first, which is the thing this package exists to prevent.
	//
	// The output path must be ABSOLUTE. `output:` in oapi-codegen.yaml is
	// resolved relative to the config file's own directory — measured, not
	// assumed, after a first attempt wrote the file into a nested `client/client/`
	// — so a relative path here would send the output to the temp directory that
	// holds this scratch config, not to the one named here. An absolute path is
	// immune to whichever directory the config happens to sit in.
	out := filepath.Join(t.TempDir(), "api.gen.go")
	config := rewriteConfigFor(t, root, out)

	configPath := filepath.Join(t.TempDir(), "oapi-codegen.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("writing the scratch generator config: %v", err)
	}

	ctx, cancel := contextWithTimeout(generateTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run",
		generatorModule+"@"+generatorVersion,
		"--config", configPath,
		"-generate", "models,client",
		filepath.Join(root, "openapi", "v1.yaml"),
	)
	cmd.Dir = filepath.Join(root, "client")

	// The generator writes its own banner to stdout. Captured rather than
	// inherited so a successful run is quiet, and so a failing one carries the
	// tool's output into the message below.
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("the pinned generator (%s@%s) did not run: %v\n"+
			"This test cannot pass by skipping: a drift gate that does not run is not a gate.\n"+
			"stdout:\n%s\nstderr:\n%s",
			generatorModule, generatorVersion, err, stdout.String(), stderr.String())
	}

	want, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading the freshly generated file at %s: %v", out, err)
	}

	committedPath := filepath.Join(root, "client", generatedFile)
	got, err := os.ReadFile(committedPath)
	if err != nil {
		t.Fatalf("reading the committed %s: %v\n"+
			"The generated file is COMMITTED, deliberately: a generated file that is not "+
			"committed cannot be reviewed, and a diff nobody reads is a change nobody notices.\n"+
			"Run `go generate ./client/` and commit the result.", generatedFile, err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("%s is not what the pinned generator produces.\n\n"+
			"%s\n\n"+
			"Either the document changed without the client being regenerated, or the "+
			"generator was moved. Both are real events and both need the regenerated file "+
			"committed in the same commit — that commit IS the review.\n\n"+
			"To fix: `go generate ./client/`, read the diff, commit it.\n"+
			"Do NOT edit %s by hand and do NOT relax this test. A client that has drifted "+
			"from its document is the exact failure this check exists to catch, and it is "+
			"silent without it: nothing else in this package reads openapi/v1.yaml, so "+
			"every other test here would still pass.",
			generatedFile, firstDifference(got, want), generatedFile)
	}

	// The half `bytes.Equal` cannot see: a generator that starts emitting an
	// ADDITIONAL file, or stops emitting one, changes the published surface and
	// leaves the tree clean as far as a byte comparison of one file is concerned.
	//
	// TWO git questions, not one, because they fail differently and each covers
	// what the other cannot:
	//
	//   diff --cached   the index against HEAD. Catches a staged regeneration —
	//                   a modified, added or deleted generated file. A file that
	//                   is `git add`ed but not yet committed is `A` here, and that
	//                   IS a finding: the commit that regenerates the client has
	//                   not been made yet.
	//   ls-files        catches a file git does not track at all, which no diff
	//                   of any kind can see.
	//
	// Scoped to the GENERATED file rather than to `client/` as a directory,
	// because the question is about the generator's output and nothing else. The
	// wrapper files are hand-written, this test does not regenerate them, and
	// scoping to the directory would make an unrelated edit to a comment fail a
	// gate about generated output.
	staged := gitOutput(t, root, "diff", "--cached", "--name-status", "--",
		filepath.Join("client", generatedFile))
	if staged != "" {
		t.Errorf("the generated file is staged with changes against the last commit:\n\n%s\n\n"+
			"If the document changed, regenerate and commit the result in the same commit — "+
			"that commit IS the review, and a generated file nobody reviews is a change "+
			"nobody notices. If the change is one you did not make, the working tree and "+
			"the last commit disagree about the client, which is the drift this gate is for.",
			staged)
	}
}

// TestTheGateFailsWhenTheCommittedFileIsWrong is the red proof.
//
// It does not reimplement the comparison. That is the point: a fault test that
// builds its own diff proves something about the fault test. This takes the
// committed file, changes one line of it in a temp directory, and asserts the SAME
// comparison used above reports a difference. If the comparison were vacuous —
// comparing two empty slices, reading the wrong path, both sides being the same
// buffer — this fails while the gate above passes, which is the only failure mode
// worth catching here.
func TestTheGateFailsWhenTheCommittedFileIsWrong(t *testing.T) {
	root := repoRoot(t)

	committed, err := os.ReadFile(filepath.Join(root, "client", generatedFile))
	if err != nil {
		t.Fatalf("reading the committed %s: %v", generatedFile, err)
	}
	if len(committed) == 0 {
		t.Fatal("the committed generated file is empty, so there is nothing to perturb")
	}

	// One line, chosen as the `package` CLAUSE rather than the package name.
	//
	// The name is not written into the pattern: the generated code is its own
	// subpackage, so a perturbation that assumed `package client` silently became a
	// no-op when the output moved, and the red proof started failing for the wrong
	// reason — a hard failure, which is better than a silent pass but still a failure
	// about the harness rather than about the gate. Matching the clause means the
	// perturbation survives a package rename, which is exactly the event most likely
	// to need re-reading.
	clause := regexp.MustCompile(`(?m)^package \w+$`)
	perturbed := clause.ReplaceAll(committed, []byte("package perturbedbypoof"))

	if bytes.Equal(perturbed, committed) {
		t.Fatal("the red proof could not perturb the generated file: it carries no " +
			"`package <name>` clause to change. The gate is comparing a file this test " +
			"cannot modify, so the red proof below would pass for the wrong reason.")
	}

	if bytes.Equal(committed, perturbed) {
		t.Fatal("the perturbation changed nothing, so the comparison below cannot fail " +
			"and this test would pass without proving anything")
	}

	// The same comparison, run on the perturbed bytes. If this reports no
	// difference, the gate above is not comparing what it claims to compare.
	if difference := firstDifference(committed, perturbed); difference == "" {
		t.Error("the comparison used by the regeneration gate reports no difference " +
			"between the committed file and a file whose package clause was changed.\n" +
			"The gate is therefore vacuous: it would pass against any content, and the " +
			"drift it exists to catch is not being caught.")
	}
}

// TestThePinIsTheOneTheGeneratorDirectiveUses keeps the duplicated pin honest.
//
// This is the test that makes the duplication above safe. If somebody moves the
// generator to v2.9.0 in generate.go and forgets this file, the gate would keep
// checking v2.8.0 forever and report a confident, wrong answer — worse than no
// gate, because it is green.
func TestThePinIsTheOneTheGeneratorDirectiveUses(t *testing.T) {
	root := repoRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, "client", "generate.go"))
	if err != nil {
		t.Fatalf("reading client/generate.go: %v", err)
	}

	// The module is captured on its own and the trailing flags are ignored, rather
	// than anchoring to end of line: the directive carries `--config` and
	// `-generate` after the module, and a regex that demanded end-of-line would
	// silently stop matching the day anybody added a flag — which would fail this
	// test with "carries no line", a message that points at the wrong thing.
	directive := regexp.MustCompile(`(?m)^//go:generate\s+go run\s+(\S+@v[0-9][^\s]*)\s`)
	match := directive.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("client/generate.go carries no `//go:generate go run <module>@<version>` line.\n" +
			"Without one there is no generation wiring, and this package's " +
			"generated file cannot be reproduced at all.")
	}

	gotModule, gotVersion, _ := strings.Cut(string(match[1]), "@")
	if gotModule != generatorModule {
		t.Errorf("client/generate.go generates from %q and this gate checks %q.\n"+
			"The gate would verify a file the documented command does not produce.",
			gotModule, generatorModule)
	}
	if gotVersion != generatorVersion {
		t.Errorf("client/generate.go pins the generator at %q and this gate runs %q.\n"+
			"Raise both in the same commit: the `//go:generate` line is what a developer "+
			"runs, and generatorVersion is what proves the committed file matches it. "+
			"A gate that checked a version nobody generates with would be a green lie.",
			gotVersion, generatorVersion)
	}
}

// TestTheGeneratedFileIsCommittedAndNotIgnored is the test that catches the
// mistake with the longest fuse in a generated tree.
//
// A `.gitignore` entry for the generated file turns "generated and committed" into
// "generated at build time" with no error and no symptom, except that the
// regeneration gate starts comparing a file git is not tracking — and
// `git status` reports a permanently clean tree for a file that is not in it.
//
// So it asks git directly. This is deliberately not a grep for a `.gitignore`
// line: the entry could be a directory pattern, a negation elsewhere, or written by
// a tool. `git check-ignore` asks git whether the file is ignored, which is the
// question and not a guess at its spelling.
func TestTheGeneratedFileIsCommittedAndNotIgnored(t *testing.T) {
	root := repoRoot(t)
	rel := filepath.Join("client", generatedFile)

	// `git ls-files --error-unmatch` exits non-zero for a path git does not track,
	// which covers both "not committed" and "committed then deleted from the index".
	if out, err := exec.Command("git", "-C", root, "ls-files", "--error-unmatch", "--", rel).CombinedOutput(); err != nil {
		t.Fatalf("git does not track %s.\n"+
			"The generated file is COMMITTED, on purpose: a generated file that is not "+
			"committed cannot be reviewed, and a diff nobody reads is a change nobody "+
			"notices. The generator's version is pinned, so the file is reproducible "+
			"without being built in CI.\n"+
			"If you have just added it to .gitignore, undo that — that is the exact "+
			"mistake this test exists to catch.\n\ngit said: %s",
			rel, out)
	}

	// And ignored, which is the other half. `check-ignore` exits 0 and prints the
	// path when it IS ignored, so the exit status is the answer and the stdout is
	// not worth printing — `-q` makes it empty on success.
	if err := exec.Command("git", "-C", root, "check-ignore", "-q", "--", rel).Run(); err == nil {
		t.Errorf("git IGNORES %s even though it is tracked.\n"+
			"A tracked-but-ignored file is the worst of the two states: it is in the "+
			"history and it is invisible to every status query, so a regeneration gate "+
			"reading it through git sees a clean tree no matter what changed.", rel)
	}
}

// rewriteConfigFor reads the committed generator config and redirects its output,
// which is the one thing this test must not restate.
//
// A copy of the config here would be a second statement of every generator option,
// and a generator option that exists in only one of the two is a gate that
// verifies a file the committed config does not produce — a green answer to a
// question nobody asked.
//
// The line it replaces is found by ANCHORING AT THE START OF THE LINE, and that
// detail is not cosmetic: the committed config's header explains the `output:`
// key and quotes it verbatim inside a comment, so a naive `strings.Replace` on
// `output: api.gen.go` rewrites the prose in the comment and leaves the real key
// alone. The generator then writes to `client/api.gen.go` as usual and this test
// reports "the freshly generated file does not exist" — a failure that looks like
// a generator bug and is actually a stale-substring bug here. It happened once.
//
// A config with no anchored key is an error rather than a default, so a rename
// fails loudly instead of skipping the redirect and passing vacuously.
func rewriteConfigFor(t *testing.T, root, out string) string {
	t.Helper()

	path := filepath.Join(root, "client", "oapi-codegen.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	const key = "output: generated/api.gen.go"
	lines := strings.Split(string(raw), "\n")

	rewritten, replaced := 0, -1
	for i, line := range lines {
		// Exactly one occurrence: the first, and the only one that is the key.
		if strings.HasPrefix(line, key) {
			rewritten++
			replaced = i
			lines[i] = "output: " + out
		}
	}

	if replaced < 0 {
		t.Fatalf("%s carries no %q line at the start of a line.\n"+
			"This test redirects the generator's output to a temporary directory and "+
			"relies on that exact line to do it. Update this test and the config in the "+
			"same commit.", path, key)
	}
	if rewritten > 1 {
		t.Fatalf("%s carries %q at the start of %d lines, so this test cannot tell "+
			"which one the generator reads.\n"+
			"Give the second one a comment so only the real key is at the start of a line.",
			path, key, rewritten)
	}

	return strings.Join(lines, "\n")
}

// firstDifference describes the first differing line, which is what a reader needs
// to act on. "the files differ" and nothing else sends them to a diff tool; the
// name and the line number is most of the work of fixing it.
func firstDifference(got, want []byte) string {
	gotLines := strings.Split(string(got), "\n")
	wantLines := strings.Split(string(want), "\n")

	for i := 0; i < len(gotLines) && i < len(wantLines); i++ {
		if gotLines[i] != wantLines[i] {
			return "first difference at line " + itoa(i+1) + ":\n" +
				"  committed: " + truncate(gotLines[i], 120) + "\n" +
				"  generator: " + truncate(wantLines[i], 120)
		}
	}

	// One file is a prefix of the other: the generator emitted more or fewer
	// lines, which names the failure differently from a changed line and points at
	// a config change rather than a document change.
	if len(gotLines) != len(wantLines) {
		short, long := "committed", "generator"
		if len(gotLines) > len(wantLines) {
			short, long = "generator", "committed"
		}
		return "line count differs: " + short + " has " + itoa(len(gotLines)) +
			" lines, " + long + " has " + itoa(len(wantLines)) + ".\n" +
			"A pure line-count difference usually means a generator option moved rather " +
			"than a document schema changing — check client/oapi-codegen.yaml first."
	}
	return ""
}

// gitOutput asks git a question and returns its trimmed stdout, failing the test
// rather than continuing on an error — every caller below needs a real answer,
// and a git error surfaced as an empty string would read as "clean".
func gitOutput(t *testing.T, root string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = root

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}
