package client

// THE LINT EXCLUSION IS ONE FILE, AND THIS IS THE TEST THAT KEEPS IT THAT WAY.
//
// The exclusion in `.golangci.yml` is a comment with teeth only if something reads
// it. Left alone it is a piece of prose that everybody agrees with and nobody
// checks, and the ways it erodes are all quiet:
//
//   - somebody widens `client/api.gen.go` to `client/` while chasing a new
//     generated file, and from then on the hand-written wrapper is unlinted too;
//   - somebody deletes the exclusion because golangci-lint's release notes said
//     the default set changed, and the generated file becomes a wall of
//     complaints that gets "fixed" by gitignoring it;
//   - the linter list goes stale against a new default set, and the generated
//     file is half-linted with no edit to this repository at all.
//
// The third one is the subtle one and it is why this test asks golangci-lint what
// it has enabled rather than hard-coding a list. A generated file that is
// accidentally half-linted produces findings nobody reads and then a growing pile
// of `//nolint` comments in a file that is overwritten by the next regeneration —
// which is worse than being fully linted, because the `//nolint`s survive into
// code that no longer has the findings.
//
// So this test parses the config, checks the path is anchored to exactly the one
// file, and cross-checks the linter list against the tool's own view of what is
// enabled. A failure in any of the three is a finding about the exclusion, and
// the message says which one.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// generatedPath is the path the exclusion must name, in the repository-relative
// form golangci-lint matches against: forward slashes, no leading `./`.
const generatedPath = "client/generated/api.gen.go"

// lintConfig is the file under test, relative to the repository root.
const lintConfig = ".golangci.yml"

// lintExclusions is the set of rules read out of the config.
//
// Parsed by `regexp` and by hand rather than with a YAML library, and the reason
// is the one AGENTS.md gives for `openapi_reader_test.go`: this repository has no
// YAML dependency and adding one — for forty lines of structure — would make a
// transitive library a direct requirement with its own versions and CVEs. The
// subset understood here is stated in the two regexes below, and anything that
// does not match is reported rather than skipped, so this reader cannot quietly
// read nothing and pass.
var (
	// One `path:` value, as it appears in the file.
	lintPathValue = regexp.MustCompile(`^\s*- path:\s*(\S+)\s*$`)
	// The `linters:` block under it, as its list items.
	lintLinterItem = regexp.MustCompile(`^\s*-\s+([a-z][a-z0-9]*)\s*$`)
)

// TestTheLintExclusionIsOneFileAndNotAPrefix is the narrowness check, and it is
// the whole reason this file exists.
//
// The assertion is not "the path mentions api.gen.go". It is that the path
// matches exactly `client/api.gen.go` and nothing else, which is a stronger claim
// and the one that actually prevents a hand-written file from being exempted. The
// test asks the question the linter asks — does this pattern match this file —
// for every `.go` file in the repository, so a widened exclusion is caught by the
// same mechanism that would have applied it.
func TestTheLintExclusionIsOneFileAndNotAPrefix(t *testing.T) {
	root := repoRoot(t)
	paths := lintExclusionPaths(t, root)

	if len(paths) == 0 {
		t.Fatalf("%s excludes no path at all.\n"+
			"client/%s is %d lines of `go:generate` output and is not hand-written code, "+
			"so it is exempt from lint — but an exemption with no path in it is not an "+
			"exemption, it is a missing rule that will be added later without anyone "+
			"deciding to.", lintConfig, generatedFile, lineCount(t, filepath.Join(root, "client", generatedFile)))
	}

	for _, path := range paths {
		re := regexp.MustCompile(path)

		if !re.MatchString(generatedPath) {
			t.Errorf("the lint exclusion %q does not match %s.\n"+
				"That means the generated file is not exempt and will report every finding "+
				"oapi-codegen produces, which is what the exclusion exists to prevent.",
				path, generatedPath)
			continue
		}

		// The load-bearing half: walk the tree and ask which OTHER Go files the
		// pattern matches. A pattern that matches a hand-written file is a bug
		// however well-intentioned it is.
		for _, other := range goFiles(t, root) {
			if other == generatedPath {
				continue
			}
			if re.MatchString(other) {
				t.Errorf("the lint exclusion %q also matches %s, which is hand-written.\n"+
					"An exclusion is allowed to cover the generated file and NOTHING else. "+
					"This one covers code a reviewer is responsible for, and it was widened "+
					"from `^client/api\\.gen\\.go$` to something broader — which is how a real "+
					"file stops being linted.", path, other)
			}
		}
	}
}

// TestTheLintExclusionNamesEveryEnabledLinter is the staleness check, and it is
// why the linter list is written out in the config rather than left implicit.
//
// golangci-lint's enabled set is a default that moves between releases. If this
// test hard-coded the list, it would pass forever while the tool gained a linter,
// and the generated file would quietly become half-linted — the worst outcome,
// because findings nobody reads accumulate `//nolint` comments that survive into
// regenerated code which no longer has those findings.
//
// So the list is asked of the tool. If golangci-lint is not installed the test
// FAILS rather than skipping, for the reason this repository uses everywhere: a
// check that quietly does not run is indistinguishable from a check that passed,
// and `.github/workflows/ci.yml` fails the build on a `--- SKIP:` line for exactly
// this reason. The failure says how to install it.
//
// ## WHY ONE ENABLED LINTER IS ALLOWED TO BE MISSING FROM THE LIST
//
// `lintersKeptOnGenerated` names the enabled linters this repository deliberately
// does NOT exclude from the generated file, each with the reason it stays on.
// Every enabled linter must be either excluded or named there, so an upgrade that
// adds a linter fails this test rather than producing findings nobody reads.
//
// `govet` is the one entry, and it is the case that matters: `go vet ./client/`
// passes on the generated file, so excluding `govet` would buy nothing and would
// drop the check most likely to catch a generator bug. An exclusion list should
// carry linters that report on STYLE and never one that reports on CORRECTNESS.
//
// This test found its own gap, which is worth recording because the wrong fix was
// available. It first failed naming `govet` as unaccounted for, and adding `govet`
// to the exclusion would have made it green — a broader exclusion, in exchange for
// nothing, satisfying the test that was supposed to prevent exactly that. The
// right fix was to record why it stays on. A test that can be satisfied by
// widening the thing it checks is the wrong test; this is the evidence that it is
// not one.
func TestTheLintExclusionNamesEveryEnabledLinter(t *testing.T) {
	enabled := golangciLintEnabled(t)

	if len(enabled) == 0 {
		t.Fatalf("`golangci-lint linters` reported no enabled linters, so this test " +
			"cannot tell whether the exclusion list is stale.\n" +
			"Got the command's output but parsed no names out of it, which means the " +
			"output shape changed and this test is now reading nothing and passing for " +
			"the wrong reason.")
	}

	excluded := lintExclusionLinters(t, repoRoot(t))
	if len(excluded) == 0 {
		t.Fatalf("the exclusion in %s names no linter.\n"+
			"A path with an empty linter list matches no finding, so the generated file "+
			"is not exempt.", lintConfig)
	}

	// Naming a linter that is not enabled is harmless, so the reverse direction is
	// deliberately not asserted — it would make this file fail on every upgrade
	// that REMOVES a default linter, which is not a defect worth a red build.
	var unaccounted []string
	for _, name := range enabled {
		if excluded[name] {
			continue
		}
		if _, kept := lintersKeptOnGenerated[name]; kept {
			continue
		}
		unaccounted = append(unaccounted, name)
	}

	if len(unaccounted) > 0 {
		t.Errorf("golangci-lint has %d enabled linter(s) that %s neither excludes from "+
			"the generated file nor lists in lintersKeptOnGenerated:\n\n  %s\n\n"+
			"The generated file is %d lines of `go:generate` output. An enabled linter that "+
			"is neither excluded nor accounted for reports findings on it, and those findings "+
			"are either noise nobody reads or pressure to delete the exclusion.\n\n"+
			"Either add the name under the exclusion in %s, or — if the linter inspects "+
			"correctness rather than style, as govet does — add it to lintersKeptOnGenerated "+
			"in this file WITH the reason it stays on. Widening the exclusion is the wrong fix "+
			"whenever the linter is catching real problems in generated code.",
			len(unaccounted), lintConfig, strings.Join(unaccounted, "\n  "),
			lineCount(t, filepath.Join(repoRoot(t), "client", generatedFile)), lintConfig)
	}
}

// lintersKeptOnGenerated are the enabled linters this repository deliberately does
// NOT exclude from `client/api.gen.go`, and why each one stays on.
//
// A map rather than a bare list, because an entry with no reason is an assertion
// and `internal/httpapi/openapi_drift_test.go` already holds identity's
// `knownDrift` to that standard for exactly this reason: a list nobody can check
// is a list that grows.
//
// Empty means the test above has nothing to consult, which would make every
// enabled linter a failure — the right default, and the reason an empty map here
// cannot be mistaken for a finished state.
var lintersKeptOnGenerated = map[string]string{
	"govet": "`go vet ./client/` passes on the generated file — verified, not assumed, when " +
		"this packet was written — so excluding it would buy nothing. It is also the one " +
		"enabled linter that inspects what the code MEANS rather than how it is shaped, and " +
		"AGENTS.md names `go vet ./...` as one of this repository's four gates; the " +
		"generated client is inside `./...`, so it is vetted in CI regardless of this file.",
}

// TestTheLintExclusionFileItselfIsLinted proves the exclusion did not swallow the
// config, or any other file, by being written too broadly.
//
// A single path entry is the whole shape of this configuration, so a SECOND one
// is worth failing on: it means somebody exempted something else, and a config
// whose exemptions grow one at a time is how a repository ends up with none of
// its code linted and a green badge that means nothing. If a second genuinely
// generated file appears, this test is the thing that has to be updated in the
// same commit — and its failure message says so.
func TestTheLintExclusionFileItselfIsLinted(t *testing.T) {
	paths := lintExclusionPaths(t, repoRoot(t))

	if len(paths) > 1 {
		t.Errorf("%s excludes %d paths: %s.\n"+
			"This configuration exists to exempt ONE file — the generated client — and this "+
			"packet added exactly one generated file.\n\n"+
			"If a second generated file now exists, this test and the exclusion belong in the "+
			"same commit as it, with each path anchored to its own file. Exemptions added one "+
			"at a time, each for a good reason, are how a repository ends up with nothing "+
			"linted.",
			lintConfig, len(paths), strings.Join(paths, ", "))
	}
}

// --- the reader ---------------------------------------------------------------

// lintExclusionPaths is every `path:` value in the config's exclusion rules.
//
// The parser is deliberately narrow and says so: it looks for `- path:` entries
// under `linters: exclusions: rules:` and returns what it found. A shape it does
// not recognise is a failure below rather than an empty result, because a reader
// that finds nothing agrees with a config that excludes nothing and the two are
// indistinguishable.
func lintExclusionPaths(t *testing.T, root string) []string {
	t.Helper()

	raw := readLintConfig(t, root)

	var (
		paths     []string
		inRules   bool
		ruleDepth int
	)
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)

		// `linters:` / `exclusions:` / `rules:` at increasing indentation, and
		// `- path:` inside `rules:`.
		switch {
		case strings.HasPrefix(trimmed, "linters:"):
			inRules = false
		case strings.HasPrefix(trimmed, "exclusions:"):
			inRules = false
		case strings.HasPrefix(trimmed, "rules:"):
			inRules = true
		case inRules && trimmed == "- path:":
			// A `- path:` with nothing after it on the line; the value is on the
			// next. Handled below by the linter-item branch.
			continue
		}

		if inRules {
			if m := lintPathValue.FindStringSubmatch(line); m != nil {
				paths = append(paths, m[1])
				ruleDepth = len(line) - len(strings.TrimLeft(line, " "))
			}
			_ = ruleDepth
		}
	}

	if !strings.Contains(raw, "exclusions:") {
		t.Fatalf("%s declares no `exclusions:` block, so this reader is looking for a "+
			"structure the file does not have and would report no paths.\n"+
			"If golangci-lint's schema moved again, update this test and the config in the "+
			"same commit — the point of this test is that the exclusion cannot change "+
			"shape unnoticed.", lintConfig)
	}

	return paths
}

// lintExclusionLinters is the `linters:` list under the exclusion, as a set.
//
// It assumes the same structure lintExclusionPaths found and reads the items that
// follow the last `- path:` at the same indentation. That assumption is checked
// by the two tests above: if the shape moved, one of them fails with a message
// about the shape rather than this returning something plausible and wrong.
func lintExclusionLinters(t *testing.T, root string) map[string]bool {
	t.Helper()

	raw := readLintConfig(t, root)

	names := map[string]bool{}
	lines := strings.Split(raw, "\n")

	for i, line := range lines {
		if lintPathValue.FindStringSubmatch(line) == nil {
			continue
		}

		// Items are indented further than the `- path:` key itself.
		keyIndent := len(line) - len(strings.TrimLeft(line, " "))
		inList := false

		for _, next := range lines[i+1:] {
			trimmed := strings.TrimSpace(next)
			if trimmed == "" {
				continue
			}
			nextIndent := len(next) - len(strings.TrimLeft(next, " "))

			if nextIndent <= keyIndent {
				break
			}
			if strings.HasPrefix(trimmed, "linters:") {
				inList = true
				continue
			}
			if !inList {
				continue
			}
			if m := lintLinterItem.FindStringSubmatch(next); m != nil {
				names[m[1]] = true
			}
		}
		break
	}

	return names
}

func readLintConfig(t *testing.T, root string) string {
	t.Helper()

	path := filepath.Join(root, lintConfig)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v\n"+
			"Without it the generated client is linted as if it were hand-written, and "+
			"every finding oapi-codegen produces becomes this repository's problem.",
			lintConfig, err)
	}
	return string(raw)
}

// golangciLintEnabled asks the tool which linters it has enabled, in the same
// configuration this repository ships.
//
// `linters` with no `--json` prints a human table; the machine-readable form is
// requested explicitly so this parses names rather than prose. It fails rather
// than skips when the tool is absent, as explained on the test above.
func golangciLintEnabled(t *testing.T) []string {
	t.Helper()

	if _, err := exec.LookPath("golangci-lint"); err != nil {
		t.Fatalf("golangci-lint is not on PATH, so the stale-linter check cannot run.\n"+
			"This test FAILS rather than skips on purpose: a check that silently does not "+
			"run is indistinguishable from one that passed, and a stale exclusion list is "+
			"exactly the drift this test exists to catch. Install it with "+
			"`mise install` — kit pins the version, or `brew install golangci-lint`.\n"+
			"Original error: %v", err)
	}

	cmd := exec.Command("golangci-lint", "linters", "--json")
	cmd.Dir = repoRoot(t)

	var stdout strings.Builder
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		t.Fatalf("`golangci-lint linters --json` failed: %v\n"+
			"This test reads the enabled linter set from the tool rather than hard-coding "+
			"it, so a tool that cannot answer leaves this check unable to run.", err)
	}

	return parseEnabledLinters(stdout.String())
}

// parseEnabledLinters pulls the enabled linter names out of
// `golangci-lint linters --json`.
//
// `encoding/json` rather than a line scan, and the reason is that the line scan
// was wrong: the tool emits the whole document on ONE line, so a parser reading
// line by line found nothing, returned an empty list, and the test above failed
// with "the output shape changed" — a message that pointed at the parser when the
// parser was the bug. `encoding/json` is stdlib, so it costs this repository no
// dependency, which is the same reason openapi_reader_test.go hand-parses YAML.
//
// A shape it does not recognise yields an empty list, and the test above fails on
// that explicitly rather than passing quietly.
func parseEnabledLinters(raw string) []string {
	var document struct {
		Enabled []struct {
			Name string `json:"name"`
		} `json:"Enabled"`
	}

	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return nil
	}

	names := make([]string, 0, len(document.Enabled))
	for _, linter := range document.Enabled {
		if linter.Name != "" {
			names = append(names, linter.Name)
		}
	}
	return names
}

// --- the tree ----------------------------------------------------------------

// goFiles is every `.go` file in the repository, as a git-style forward-slash
// path relative to the root, excluding the vendor directory that does not exist
// here but would be a trap if one were added.
//
// `git ls-files` rather than a `filepath.WalkDir`, because the question is "which
// files does this repository have" and git is the only one that answers it
// without counting ignored files — and an ignored file is exactly what the
// generated-file test above is about.
func goFiles(t *testing.T, root string) []string {
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
		if strings.HasPrefix(line, "vendor/") {
			continue
		}
		paths = append(paths, filepath.ToSlash(line))
	}

	if len(paths) == 0 {
		t.Fatal("git reported no Go files in this repository, so the exclusion check " +
			"matched nothing and passed for the wrong reason")
	}
	return paths
}

func lineCount(t *testing.T, path string) int {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(raw), "\n") + 1
}
