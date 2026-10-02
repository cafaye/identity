// Checks on .github/workflows/publish.yml — the workflow that builds and pushes
// the image config/deploy.yml deploys.
//
// WHY A SEPARATE FILE. The tests in ci_test.go all read `ci.yml`, which is the
// workflow that proves the tree. This one reads a different file that proves
// something else: that the artifact a deploy pulls is produced by a pipeline
// rather than by one person on one machine. Splitting them keeps each file's
// header honest about which file it is talking about, and it means a change to
// one workflow does not have to be reasoned about through the other's tests.
//
// # What these deliberately do not do
//
// They do not parse the workflow as YAML. ci_test.go's header says why and the
// reason holds here: a dependency with no stated cause, and a line scan is
// enough for a file whose shape this repository controls.
//
// # Why these checks exist at all
//
// Every one of them is a claim that fails SILENTLY when it stops being true.
// The file is not run on a pull request, so a mistake in it cannot be caught by
// the mistake being noticed — it can only be caught by a check, or by a deploy
// failing to find an image.
package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// kitImageWorkflow is the build, called rather than copied. Written out in full
// for the same reason `kitWorkflow` is: the value of comparing it is that a
// reader can check it against kit's tree with one `ls`.
const kitImageWorkflow = "cafaye/kit/.github/workflows/image.reusable.yml@master"

// publishWorkflow is the file, relative to the repository root.
const publishWorkflow = ".github/workflows/publish.yml"

var (
	// Any `uses:` pointing at kit, at any indentation. Used to prove the file
	// calls kit and does not also carry a build of its own.
	kitUseLine = regexp.MustCompile(`^\s+uses:\s+(cafaye/kit/\S+)\s*$`)
	// `packages: write`, at any indentation, and nothing after it on the line.
	// Anchored both ends so `packages: write-foo` cannot satisfy it.
	packagesWrite = regexp.MustCompile(`(?m)^\s*packages:\s*write\s*$`)
	// A `pull_request:` trigger. This is deliberately read from the raw file
	// rather than from comment-stripped lines, because it is a `on:` key and
	// nothing else in this file can produce one.
	pullRequestTrigger = regexp.MustCompile(`(?m)^\s*pull_request:`)
)

func publishLines(t *testing.T) []string {
	t.Helper()

	path := filepath.Join(repoRoot(t), publishWorkflow)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s could not be read, and nothing else in this repository builds the image config/deploy.yml deploys: %v",
			publishWorkflow, err)
	}
	return strings.Split(string(raw), "\n")
}

// TestTheImageIsBuiltBySomethingThatRuns. The gap this closes: `config/deploy.yml`
// names ghcr.io/<org>/<repo> and `kamal deploy` pulls it, so with no publisher
// the only way the image existed was one person running `docker build`. CI
// stayed green the entire time — a green CI and an unbuilt image are not in
// tension, they are just both true, which is what makes the gap easy to miss.
func TestTheImageIsBuiltBySomethingThatRuns(t *testing.T) {
	// The t.Fatalf inside publishLines carries the whole explanation; this
	// exists so the failure reads as a claim that lost, not as a helper.
	publishLines(t)
}

// TestThePublishWorkflowCallsKitsImageAtAPathThatResolves. The second half of
// `kitWorkflow`'s rule, applied to the second call. GitHub resolves a
// cross-repository reusable workflow at
// {owner}/{repo}/.github/workflows/{file}@{ref} and documents that
// subdirectories of the workflows directory are NOT supported, so any other path
// resolves to nothing and the job is red before it starts.
//
// Exactly one kit call is required. A second one is a repository where somebody
// copied the wrong line, and "the right call is somewhere in here" would not
// notice that one.
func TestThePublishWorkflowCallsKitsImageAtAPathThatResolves(t *testing.T) {
	var calls []string
	for _, line := range publishLines(t) {
		if m := kitUseLine.FindStringSubmatch(line); m != nil {
			calls = append(calls, m[1])
		}
	}

	switch len(calls) {
	case 0:
		t.Fatalf("%s calls nothing from kit; the image build is supposed to be the shared one at %s",
			publishWorkflow, kitImageWorkflow)
	case 1:
	default:
		t.Fatalf("exactly one call to kit's image workflow belongs in %s, and %d do: %v",
			publishWorkflow, len(calls), calls)
	}
	if calls[0] != kitImageWorkflow {
		t.Fatalf("the call is %q, want %q.\n"+
			"GitHub resolves a cross-repository reusable workflow at\n"+
			"  {owner}/{repo}/.github/workflows/{file}@{ref}\n"+
			"and documents that subdirectories of the workflows directory are NOT\n"+
			"supported, so any other path resolves to nothing and the job is red\n"+
			"before it starts.", calls[0], kitImageWorkflow)
	}
}

// TestThePublishWorkflowDoesNotCarryItsOwnBuild. The reason this file calls kit
// instead of copying the build is that a copy is a second pipeline: six
// repositories with six copies is six places for a security fix to land in five,
// and the first one to drift is the one nobody remembers.
func TestThePublishWorkflowDoesNotCarryItsOwnBuild(t *testing.T) {
	for i, line := range publishLines(t) {
		if !strings.Contains(line, "docker/build-push-action@") {
			continue
		}
		// A comment is allowed to say the words — this file's own header does.
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		t.Errorf("%s:%d carries its own build step:\n\t%s\n"+
			"The build belongs to kit, shared, so a fix to how an image is built reaches\n"+
			"this repository on kit's next push. Naming the action in a comment is fine;\n"+
			"depending on it here is the thing being prevented.",
			publishWorkflow, i+1, strings.TrimSpace(line))
	}
}

// TestThePublishWorkflowGrantsPackagesWrite. A reusable workflow can REQUEST a
// permission but cannot grant itself one, so this line is the caller's job and
// there is no way to get it from the other repository.
//
// The failure mode is why this is checked: without it the push fails with a 401,
// which reads like a wrong password rather than like the missing line it is.
func TestThePublishWorkflowGrantsPackagesWrite(t *testing.T) {
	if !packagesWrite.MatchString(strings.Join(publishLines(t), "\n")) {
		t.Errorf("%s does not grant `packages: write`.\n"+
			"A reusable workflow can request a permission but cannot grant itself one, so\n"+
			"this line is the caller's job. Without it the push fails with a 401 at run\n"+
			"time, which reads like a bad password rather than like the missing line.",
			publishWorkflow)
	}
}

// TestThePublishWorkflowIsNotTriggeredByPullRequest. Two reasons and both are
// real: only master holds deployable commits, so a branch build publishes images
// nobody deploys; and a pull request build runs untrusted code — the Dockerfile,
// whatever a contributor changed — against a registry write.
//
// The reusable workflow refuses to publish on a pull request regardless of what
// the caller asks, so this is belt and braces. It is here because a reader of
// this file should be able to see the guard without reading another repository.
func TestThePublishWorkflowIsNotTriggeredByPullRequest(t *testing.T) {
	if pullRequestTrigger.MatchString(strings.Join(publishLines(t), "\n")) {
		t.Errorf("%s is triggered by `pull_request`.\n"+
			"A pull request build would run a contributor's Dockerfile against a\n"+
			"registry write, and publish images for commits nobody can deploy.",
			publishWorkflow)
	}
}

// TestThePublishWorkflowAsksToPush. `push` defaults to FALSE in the reusable
// workflow, deliberately: calling a build and publishing one are two different
// acts, and a default of true would mean every caller that only wanted to check
// the image still wrote to the registry. So this repository's caller has to say
// so out loud, and a caller that stops saying it goes back to building without
// publishing — which fails silently, and looks exactly like a slow CI run.
func TestThePublishWorkflowAsksToPush(t *testing.T) {
	for _, line := range publishLines(t) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "push: true" {
			return
		}
	}
	t.Errorf("%s never asks to publish.\n"+
		"`push` defaults to false in kit's image workflow, so a caller that does not\n"+
		"say `push: true` builds the image and pushes nothing. That failure is silent:\n"+
		"the job is green, the tag is written locally, and the registry has nothing.",
		publishWorkflow)
}
