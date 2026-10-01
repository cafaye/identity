package httpapi

// THE SOCIAL-LOGIN TRIPWIRE.
//
// This repository shipped a README, a roadmap checkbox and a `cafaye.yml` that all
// said identity does OAuth social login, and no route anywhere that could serve
// one. `internal/oauth/` is a complete, database-tested package and
// `migrations/00008_connected_accounts.sql` is an applied migration nothing writes
// to. A customer reading the README would have integrated against a 404, and a
// reviewer opening the tree would have concluded the feature shipped. This file is
// the tripwire for that, and it is deliberately a test that FAILS WHEN THE FEATURE
// IS MOUNTED.
//
// ## Why a test that asserts an absence
//
// Every other check in this package holds a claim to the router in the direction
// that fails when the claim is false. This one holds it in the other direction, and
// that is the point rather than a limitation:
//
//   - **The failure message is the work order.** When somebody mounts
//     `/v1/auth/oauth/google`, this test goes red and its output is the list of
//     things that have to happen with it. AGENTS.md's rule is that a claim with no
//     route behind it is what a security review asks about first; this turns that
//     question from "somebody should check" into a red build with a checklist on it.
//   - **The alternative is a lie with a green tick.** Without it, the day the
//     surface mounts, every other check still passes — the routes get documented,
//     the scope table gets its row, the matrix gets its row — and nothing anywhere
//     says the four places claiming the feature is *absent* were the four places
//     that were wrong. That is how a corrected README becomes a new lie.
//
// So the rule is: **mounting social login without deleting this file is not
// finishing the work.** Deleting it is a review-visible act, which is the only
// honest way for an absence to become a presence.
//
// ## What it asserts, and why each half is here
//
//   - No route under the social prefix. A route at a different path is the same
//     defect with a spelling nobody would grep for, so the prefix is the constant
//     and the callback paths are named too.
//   - Nothing imports the client. A handler can exist without a route, and a use
//     case can exist without a handler, and both are the shape of a feature that is
//     "nearly done" and has been for several packets. The import check is what
//     notices a use case landing in internal/auth before anyone mounts it.
//   - The README records the absence, in the section that says what v0 does not
//     claim. Four places say it and this is the one that fails if the README stops.
//   - The manifest does not claim the capability. `cafaye.yml` is the file a
//     customer is handed rather than reads.
//
// It deliberately does NOT assert anything about the quality of the code in
// internal/oauth. That code is exercised by its own package's tests, and a test
// here that re-judged it would be a second opinion with no access to the reasoning.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// socialLoginPrefix is the path the unmounted surface would live under. It is the
// prefix Provider.RedirectURI builds, so it cannot drift from the constant in
// internal/oauth without one of the two failing.
const socialLoginPrefix = "/v1/auth/oauth"

// TestTheSocialLoginSurfaceIsNotMounted is the assertion, and the failure message
// is the reason the file exists.
func TestTheSocialLoginSurfaceIsNotMounted(t *testing.T) {
	// socialLoginRoutesMounted is the same predicate claims_test.go's
	// falsifiability test drives with an injected route, which is what makes it
	// known to be able to return non-empty. Inlining a second copy here would be a
	// second implementation to keep in step with the first.
	if reported := socialLoginRoutesMounted(t, servedRoutes(t)); reported != "" {
		// Mounting it is allowed. Doing it without the rest is not, and this message
		// is the list.
		t.Errorf("%s.\n\n"+
			"Each is under %s, so the social-login surface is being mounted, and "+
			"four places in this repository still say it does not exist:\n\n"+
			"  1. README.md, the opening paragraph, which lists what this service owns. Add social\n"+
			"     login back, and add a section describing the round trip.\n"+
			"  2. README.md, the roadmap, where `- [ ] OAuth (social login)` is now unchecked.\n"+
			"     Check it.\n"+
			"  3. cafaye.yml, whose `description` no longer names OAuth. Add it, and add the item to\n"+
			"     manifestCapabilityEvidence in claims_test.go with the routes that prove it.\n"+
			"  4. README.md, \"Social login is not built, and the code that looks like it is\". That\n"+
			"     section is now false and has to go.\n\n"+
			"And the two security properties that were decided NOT to be decided in this packet, "+
			"which whoever mounts this has to settle explicitly:\n\n"+
			"  a. WHICH USER A CALLBACK RESOLVES TO. A provider email that matches an existing\n"+
			"     users.email is a takeover if permitted and a support call if refused. Jumpstart\n"+
			"     Pro refuses; this repository has not decided. Do not copy the answer by accident.\n"+
			"  b. GOOGLE'S `email_verified` IS NOT READ. internal/oauth/client.go decodes `email`\n"+
			"     with no check on `email_verified`, while GitHub's path refuses an unverified\n"+
			"     address. Close that before a provider address can reach a users.email lookup.\n\n"+
			"Plus the mechanical work this repository's own rules require: the two routes in\n"+
			"openapi/v1.yaml with operationIds, a row each in the README's endpoint table, and — if\n"+
			"the callback touches a session — a row in the authorization matrix.\n\n"+
			"Then DELETE THIS FILE. An absence test that outlives the absence is a test asserting\n"+
			"the feature does not exist, and the day it does, that is the repository lying to\n"+
			"itself in a file nobody reads. The deletion is the review.",
			reported, socialLoginPrefix)
	}
}

// TestNothingInTheServiceImportsTheSocialLoginClient is the earlier warning.
//
// A route is the last thing to appear. The first thing is a use case: someone adds
// an Exchange-and-link method to internal/auth because the pieces are all there and
// it is obviously the right shape, tests it, and leaves it unwired. That is the
// "tested but unwired" lie AGENTS.md already deleted an instance of, and it is how
// this packet's problem started in the first place.
//
// The check is on the import rather than on a symbol, because the import is what
// turns a dormant package into a reachable one, and a symbol name would have to be
// guessed and would go stale on a rename. Two packages are excluded and both
// exclusions are load-bearing:
//
//   - internal/oauth itself, trivially.
//   - internal/platform/oauthtest, the fake provider, which imports the package to
//     construct providers. It is test-only and reaches no production path.
//   - internal/httpapi, which legitimately imports NewState and VerifyState for the
//     OIDC login — the half of this package that IS mounted.
func TestNothingInTheServiceImportsTheSocialLoginClient(t *testing.T) {
	if testing.Short() {
		t.Skip("walks the module tree")
	}

	// The files that may import internal/oauth, and why. A sixth is a feature
	// arriving, which is what this test exists to notice.
	//
	// internal/oauth's OWN tests are on the list, which looks odd until you notice
	// that a table of "production importers" is the wrong shape: client_test.go is
	// `package oauth_test` and has to import the package to reach it. Listing it is
	// more honest than special-casing "any file under internal/oauth/", because the
	// point of the table is that a reader can see every reason at once.
	allowed := map[string]string{
		"internal/oauth/cipher.go":                 "the package itself",
		"internal/oauth/client_test.go":            "the package's own external test",
		"internal/platform/oauthtest/oauthtest.go": "the test-only fake provider",
		"internal/httpapi/oidc.go":                 "NewState and VerifyState only, for the OIDC login",
		"internal/httpapi/oidc_helpers_test.go":    "a test asserting the OIDC state",
		// The one importer that is ABOUT the unwired surface rather than beside it.
		// claims_faults_test.go calls oauth.Google().RedirectURI to prove the absence
		// check below watches the path the provider would really build, which is the
		// only way that constant means anything.
		"internal/httpapi/claims_faults_test.go": "a test proving the absence check watches the real callback path",
	}

	var found []string
	for path := range importingFiles(t) {
		if _, ok := allowed[path]; !ok {
			found = append(found, path+" — "+reasonForImport(path))
			continue
		}
		// The allowance is checked rather than trusted, because a future edit could
		// add a Client call to oidc.go and the comment above would quietly stop
		// describing anything. The state half is the only legitimate use.
		if path == "internal/httpapi/oidc.go" && usesProviderMachinery(t, path) {
			found = append(found, path+" — it now reaches past NewState/VerifyState into the "+
				"provider client, so the reason it is allowed to import this package has changed")
		}
	}
	sort.Strings(found)

	if len(found) > 0 {
		t.Errorf("%d file(s) outside the three allowed ones import internal/oauth:\n\n  %s\n\n"+
			"A use case landing before its route is how this repository ended up advertising a "+
			"feature with no endpoint. If you are adding one, that is a legitimate reason for "+
			"this test to fire — finish the surface and delete this file in the same change. If "+
			"you are not, an import is a dependency on a package this service does not mount, "+
			"which is the same defect as the README claim one layer down.", len(found), strings.Join(found, "\n  "))
	}
}

func reasonForImport(path string) string {
	switch {
	case strings.HasSuffix(path, "_test.go"):
		return "a test outside the OIDC surface"
	case strings.HasPrefix(path, "cmd/"):
		return "the service binary would depend on it"
	default:
		return "a production path"
	}
}

// importingFiles is every file in this module that imports internal/oauth, as a
// path relative to the repository root so the allowance table above is readable.
//
// It PARSES rather than greps, for the reason internal/platform/ci's testNamesInTree
// does: this repository names its own machinery in comments constantly, and a
// substring match on an import path finds every one of those. A comment saying "see
// internal/oauth/state.go" is not a dependency and reporting it as one would make
// this test cry wolf on the first honest mention.
//
// The module root comes from this file's own location rather than the working
// directory: `go test` sets the working directory to the package, and a test that
// depends on where it was invoked from passes for the wrong reason somewhere.
func importingFiles(t *testing.T) map[string]bool {
	t.Helper()

	root := repoRootFromHere()
	found := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name == ".git" || name == "vendor" || name == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, spec := range parsed.Imports {
			value, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			if value == "github.com/cafaye/identity/internal/oauth" {
				relative, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				found[filepath.ToSlash(relative)] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for importers of internal/oauth: %v", root, err)
	}
	if len(found) == 0 {
		t.Fatal("no file in this module imports internal/oauth, which cannot be true: " +
			"internal/oauth/cipher.go is the package. A walk that finds nothing agrees with " +
			"a walk that is looking in the wrong place, and the check above it would pass.")
	}
	return found
}

// usesProviderMachinery reports whether a file reaches past the state primitives
// into the client, registry, store or settings — the parts of internal/oauth that
// only a mounted social-login surface has any business calling.
func usesProviderMachinery(t *testing.T, relative string) bool {
	t.Helper()

	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(repoRootFromHere(), relative), nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", relative, err)
	}

	for _, call := range selectorCalls(parsed) {
		switch call {
		case "NewRegistry", "NewClient", "NewStore", "NewCipher", "NewState", "VerifyState", "Google", "GitHub", "Settings":
			if call != "NewState" && call != "VerifyState" {
				return true
			}
		}
	}
	return false
}

// selectorCalls is every `pkg.Name` selector expression in a file, deduplicated.
//
// Only `oauth.X` matters here, and the package qualifier is checked at the call
// site rather than here — this returns the method name and the caller compares it
// against a list, which keeps the comparison out of the AST walk.
func selectorCalls(parsed *ast.File) []string {
	seen := map[string]bool{}
	var out []string

	ast.Inspect(parsed, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if !ok || identifier.Name != "oauth" {
			return true
		}
		if !seen[selector.Sel.Name] {
			seen[selector.Sel.Name] = true
			out = append(out, selector.Sel.Name)
		}
		return true
	})
	return out
}

// repoRootFromHere is this repository's root, from this file's own path.
func repoRootFromHere() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		// Unreachable in practice: runtime.Caller on a package-level test file
		// resolves. There is no way to fail a test from a helper that cannot
		// return an error, so the panic is the honest outcome and it cannot be
		// reached without the toolchain being broken.
		panic("runtime.Caller(0) failed, so the repository root cannot be found")
	}
	// Two levels, not three: this file is at internal/httpapi/, so `..` is
	// internal/ and `../..` is the repository root. internal/platform/ci/ci_test.go
	// needs three for the same reason from one level deeper, which is exactly the
	// kind of thing that silently walks a parent directory and finds four other
	// repositories' worth of Go files.
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// TestTheManifestDoesNotClaimSocialLogin is the manifest half, and it is separate
// from the one in claims_test.go on purpose.
//
// That file holds the description to a declared capability table, which is a
// mapping somebody maintains. This one names the specific capability, so the
// regression is reported as itself rather than as "an item this file has never
// heard of" — which is a worse message for the exact defect most likely to come
// back, because the fix is always the same two words in the same line.
func TestTheManifestDoesNotClaimSocialLogin(t *testing.T) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading %s: %v", manifestPath, err)
	}

	for number, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "description:") {
			continue
		}
		// "OIDC" and "the OIDC provider" are this service's OAuth surface and are
		// true. The claim being refused is a BARE "OAuth" beside them, which reads as
		// a second capability.
		for _, word := range strings.Split(strings.Trim(trimmed[len("description:"):], " \""), ",") {
			if strings.EqualFold(strings.TrimSpace(word), "OAuth") {
				t.Errorf("%s:%d — the description claims %q as a capability beside the OIDC "+
					"provider. It is a different thing: the OIDC provider is this service BEING an "+
					"authorization server, and social login is this service CALLING one as a client. "+
					"The second is not mounted. Remove the word, or mount the surface and delete "+
					"this file.", manifestPath, number+1, strings.TrimSpace(word))
			}
		}
		return
	}
	t.Fatalf("%s has no `description:`. The manifest asserts nothing this check can hold.", manifestPath)
}

// TestTheReadmeRecordsTheAbsence is the README half.
//
// The README is the source of truth for what v0 does not claim, per AGENTS.md, and
// that only works if the section stays. Four things are required rather than one,
// because a single sentence is what rots: the heading a reader searches for, the
// callback path, the table name, and the file that is missing. Each one disappearing
// is how "we decided not to ship this" quietly becomes "nobody wrote it down".
func TestTheReadmeRecordsTheAbsence(t *testing.T) {
	raw, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("reading %s: %v", readmePath, err)
	}
	readme := string(raw)

	required := []struct {
		needle string
		why    string
	}{
		{"Social login is not built", "the section heading, which is what a reader searching for this capability looks for"},
		{"Not built yet", "the section AGENTS.md names as the source of truth for what v0 does not claim"},
		{socialLoginPrefix, "the callback path, so a reader can confirm for themselves that nothing serves it"},
		{"connected_accounts", "the table, which exists and is empty — an unmentioned applied migration reads as live schema"},
		{"email_verified", "the security gap in the provider client, which is the reason mounting it is not mechanical"},
		{"internal/httpapi/oauth.go", "the file that does not exist, named so the absence is specific rather than vague"},
		{"does not exist", "the plain statement, which is the one thing a skimmer will actually read"},
	}

	var missing []string
	for _, want := range required {
		if !strings.Contains(readme, want.needle) {
			missing = append(missing, want.needle+" — "+want.why)
		}
	}
	if len(missing) > 0 {
		t.Errorf("README.md no longer records that the social-login surface is not built. "+
			"Missing %d thing(s):\n\n  %s\n\n"+
			"This is not a style rule. The section is the only thing standing between a reader of "+
			"this repository and the conclusion that a complete, database-tested package with an "+
			"applied migration behind it is a shipping feature — which is the exact mistake this "+
			"packet found. If the feature is now mounted instead, delete this file rather than "+
			"restoring the section.", len(missing), strings.Join(missing, "\n  "))
	}
}
