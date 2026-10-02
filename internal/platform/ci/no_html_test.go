package ci

// THIS SERVICE SERVES NO HTML.
//
// The owner's rule is that `identity` must not have its own views: the browser
// belongs to `parlor`, and the sign-in form is a page in another repository. This
// file is what makes that claim CHECKABLE rather than a sentence in a commit
// message, and it is here — in the package that guards the gate itself — because a
// rule nobody runs is a rule nobody has.
//
// ## WHAT IS ACTUALLY FORBIDDEN, AND WHAT IS NOT
//
// There are three things, and they fail in different ways, so they are three
// tests rather than one:
//
//	no view file         a `.html`, `.tmpl`, `.gohtml` or `.tpl` anywhere in the
//	                     tree. A template file is a page, and there are no pages.
//
//	no markup in Go      `text/html`, `<html`, `<form` or `<!DOCTYPE` in a STRING
//	                     LITERAL, and no import of `html/template`. The login page
//	                     used to be an inline `html/template` literal, so this is
//	                     the shape the defect actually took and the shape it would
//	                     take again.
//
//	no HTML on the wire  a handler that serves a redirect whose body is
//	                     net/http's fallback anchor, or whose Content-Type names
//	                     a document. `internal/httpapi` strips the first and sets
//	                     no header for the second, and the test drives a real
//	                     request rather than reading the source.
//
// ## WHY THE SECOND TEST PARSES AND DOES NOT GREP, AND IT IS NOT AN OVERENGINEERING
//
// A grep for `text/html` in `*.go` files hits this repository's own COMMENTS: the
// comment above `oidcRedirect` says why net/http's fallback content type is a
// problem, and the comment above `TestNoGoFileCarriesMarkup` — this file — spells
// the marker out. That was measured, not predicted: the first version of this test
// was a grep and it went red on five lines of prose this packet had written
// explaining the rule it was checking.
//
// A comment cannot serve a response. So the check walks the parsed syntax tree and
// looks at string LITERALS and IMPORTS, which is the smaller question and the one
// with a failure behind it: a literal is something the process can put on the wire,
// and an import is something that can render one. The first version of this check
// was red, which is why there is a second one.
//
// ## THE ALLOWANCE LIST, AND WHY IT IS NOT A LOOPHOLE
//
// Four files contain one of those literals, every one on purpose, and each is named
// with its reason rather than tolerated:
//
//	`internal/platform/ci/no_html_test.go`  this file. The marker list itself is a
//	                               string literal, and a check that cannot name
//	                               what it forbids cannot be written.
//	`internal/platform/oauthtest/`  a DOUBLE for an EXTERNAL OAuth server, which
//	                               answers an authorize request with a body of its
//	                               own choosing. It is not this service, it is
//	                               under `platform/`, and nothing in `cmd/identity`
//	                               reaches it.
//	`client/errors_test.go`        the GENERATED client parsing a NON-problem
//	                               response. An upstream proxy answering
//	                               `502 Bad Gateway` with an HTML error page is a
//	                               real thing a client must survive, and the test is
//	                               what proves it does.
//	`internal/httpapi/oidc_test.go` an assertion that a Content-Type is ABSENT.
//	                               Writing "must not be text/html" is the test.
//	`internal/oidc/loginui_test.go` a `data:text/html` login UI, which is one of
//	                               the values ValidateLoginUIURL refuses. Writing
//	                               the value is the test.
//
// The list is a map, so a reader can see the reason next to the name, and the test
// FAILS on an allowance whose file is gone — a stale entry is a hole in the check
// that reads as coverage, which is the exact shape of defect this package exists to
// catch. An allowance is a claim about the tree, and a claim that is not re-checked
// becomes a permission that outlives its reason.
//
// # IT READS GIT'S LIST, SO A NEW FILE IS INVISIBLE UNTIL IT IS STAGED
//
// That is the same property `goFilesUnder` above has, and it is worth stating
// rather than leaving to be discovered: `go test` on a working tree misses an
// uncommitted file, and CI runs on a committed one, so the check is complete
// exactly where it gates. It is not a reason to grep the filesystem instead — a
// walk counts a build directory and an editor's swap file, and a check that
// reports those teaches a reader to ignore it.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/httpapi"
	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/platform/clock"
)

// htmlExtensions is a file that is a page, whatever it is called.
var htmlExtensions = []string{".html", ".htm", ".tmpl", ".gohtml", ".tpl"}

// htmlMarkers is what markup in a Go file looks like.
//
// `<form` is in the set rather than only `<html` because a Go file that
// assembles a login form does not necessarily assemble a whole document — a
// fragment is enough to be a page. `<!DOCTYPE` is in it because the login page's
// first line was one and a body without a doctype is still a body.
var htmlMarkers = []string{"text/html", "<html", "<form", "<!doctype", "<!DOCTYPE"}

// A view file anywhere in the tree.
//
// IT WALKS GIT'S LIST RATHER THAN THE FILESYSTEM, and the reason is the one
// `coverage_exclusions_test.go` already gives for its own walk: an untracked file
// is not part of the repository, and a build directory is not either. A filesystem
// walk reports a `.html` in somebody's editor swap file or in a vendored
// dependency that is not in the commit — noise that teaches a reader to ignore
// this test.
func TestNoViewFileIsCommitted(t *testing.T) {
	files, err := trackedFiles(t)
	if err != nil {
		t.Fatalf("listing the repository's files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no files were listed, so this walked nothing and passed for the wrong reason")
	}

	for _, name := range files {
		ext := strings.ToLower(filepath.Ext(name))
		for _, candidate := range htmlExtensions {
			if ext == candidate {
				t.Errorf("%s is committed. `identity` renders no views: the sign-in form is a "+
					"page in `parlor`, and a template file in this tree is a page that is not "+
					"being removed.", name)
			}
		}
	}
}

// Markup in a Go file, with the allowance list.
//
// IT READS THE PARSED TREE, NOT THE TEXT, and the file header says why. The
// consequence worth stating here is the one that makes it strict: a comment
// mentioning `text/html` is invisible to this test, which is correct, and a string
// literal is not, which is the whole claim.
func TestNoGoFileCarriesMarkup(t *testing.T) {
	allowances := map[string]string{
		"internal/platform/ci/no_html_test.go": "this file: the marker list itself is a " +
			"string literal, and a check that cannot name what it forbids cannot be written",
		"internal/platform/oauthtest/oauthtest.go": "a double for an EXTERNAL OAuth server, " +
			"which answers an authorize request with a body of its own choosing. It is not " +
			"this service and nothing in cmd/identity reaches it",
		"client/errors_test.go": "the generated client parsing a non-problem response: an " +
			"upstream proxy answering 502 with an HTML error page is real, and the test is " +
			"what proves the client survives it",
		"internal/httpapi/oidc_test.go": "an assertion that a Content-Type is ABSENT; " +
			"writing \"must not be text/html\" is the test",
		"internal/oidc/loginui_test.go": "a data:text/html URL as a login UI, which is one of " +
			"the values ValidateLoginUIURL refuses; writing the value is the test",
	}

	files, err := trackedFiles(t)
	if err != nil {
		t.Fatalf("listing the repository's files: %v", err)
	}

	// used records which allowances were reached, so a stale one is reported. An
	// allowance is a claim about the tree, and a claim nobody re-checks becomes a
	// permission that outlives its reason — which reads as coverage and is not.
	used := map[string]bool{}
	for _, name := range files {
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if _, ok := allowances[name]; ok {
			used[name] = true
			continue
		}
		for _, hit := range markupIn(t, name) {
			t.Errorf("%s carries %s. `identity` renders no views, and the sign-in form is a "+
				"page in `parlor`. The defect this catches took the shape of an inline "+
				"html/template literal, and this is the other shape it could take: a "+
				"Content-Type set by hand.", name, hit)
		}
	}

	for name, reason := range allowances {
		if !used[name] {
			t.Errorf("the allowance for %s is stale: that file is not in the tree, so the "+
				"allowance is a permission with nothing behind it. Delete the entry — and "+
				"check that the reason it recorded is still true somewhere else.\nIt said: %s",
				name, reason)
		}
	}
}

// markupIn is every place in one Go file where markup could be SERVED: a string
// literal carrying one of the markers, or an import of a renderer.
//
// A comment is not a hit, and a doc comment is not a hit, and a test's
// `t.Errorf("…text/html…")` in a file that is not on the allowance list IS a hit —
// because an allowance is the place to say so with a reason.
func markupIn(t *testing.T, name string) []string {
	t.Helper()

	path := filepath.Join(repoRoot(t), name)
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
	if err != nil {
		t.Errorf("parsing %s: %v", name, err)
		return nil
	}

	var hits []string
	for _, spec := range parsed.Imports {
		if strings.Contains(strings.Trim(spec.Path.Value, `"`), "html/template") {
			hits = append(hits, "an import of html/template")
		}
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		for _, marker := range htmlMarkers {
			if strings.Contains(literal.Value, marker) {
				hits = append(hits, "a string literal carrying "+strconv.Quote(marker))
			}
		}
		return true
	})
	sort.Strings(hits)
	return hits
}

// NO RESPONSE ANYWHERE ON THE WIRE NAMES A DOCUMENT.
//
// The other two tests are about the source. This one is about the response, and
// the shape the packet is most likely to regress into is not an inline template —
// it is `http.Redirect`, which is correct Go and writes `Content-Type:
// text/html; charset=utf-8` with a one-line anchor body because RFC 9110 §15.4
// recommends it for user agents that cannot follow a redirect. Every user agent in
// this deployment can.
//
// SO IT WALKS THE ROUTER rather than naming two paths, which is both broader and
// more honest than the first version of this test. That version asked for
// `/oidc/login/{unknown id}` and `/oidc/nope`, and the red proof showed what that
// bought: both are 404 problem documents, so it could not have caught the
// `http.Redirect` regression it was written for, because a redirect needs a live
// authorization request and this package has no database. The redirect case IS
// covered, by two tests in `internal/httpapi` over a real flow — one on the
// login redirect and one on the library's own — and this one is the sweep that
// says no route anywhere answers with a document.
//
// A route that refuses a stranger is the only kind this can reach, which is also
// the only kind that matters for the claim: a document behind a credential is
// still a document.
func TestNoResponseNamesADocument(t *testing.T) {
	handler := serviceRouter(t)

	for _, target := range []string{
		// The OIDC surface, including the interaction and the two well-known paths.
		"/oidc/login/00000000-0000-4000-8000-000000000000",
		"/oidc/nope",
		"/oidc/authorize",
		"/.well-known/openid-configuration",
		"/.well-known/jwks.json",
		// The JSON surface, to say the sweep is not only about one prefix.
		"/v1/users",
		"/v1/session",
		"/v1/me",
		"/v1/password-resets",
		// The probes, which are the two routes a person curls.
		"/healthz",
		"/readyz",
		// A miss, which is this service's own problem document rather than
		// net/http's plain text — the other place an HTML body could appear.
		"/nothing-here",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req := httptest.NewRequest(method, target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if got := rec.Header().Get("Content-Type"); strings.Contains(got, "text/html") {
				t.Errorf("%s %s answered Content-Type %q; `identity` serves no documents",
					method, target, got)
			}
			if isRedirectStatus(rec.Code) {
				if body := rec.Body.String(); body != "" {
					t.Errorf("%s %s answered a %d with a %d-byte body:\n%s\n"+
						"net/http writes an HTML anchor for a redirect, which is why "+
						"internal/httpapi's oidcRedirect and delegateOIDC both write the "+
						"status themselves.", method, target, rec.Code, len(body), body)
				}
			}
		}
	}
}

// isRedirectStatus is the 3xx range.
func isRedirectStatus(status int) bool { return status >= 300 && status < 400 }

// trackedFiles is every file git has, as a forward-slash path relative to the
// root.
//
// It is `git ls-files` for the reason goFilesUnder above gives, and it is a
// separate function rather than a call with no prefix because that one filters to
// `*.go` and this one cannot: the question here is whether a TEMPLATE is
// committed, so the filter would exclude the answer.
func trackedFiles(t *testing.T) ([]string, error) {
	out, err := exec.Command("git", "-C", repoRoot(t), "ls-files").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w\n%s", err, out)
	}
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		paths = append(paths, filepath.ToSlash(line))
	}
	sort.Strings(paths)
	return paths, nil
}

// serviceRouter is the real router with the real OIDC provider on it, so the
// responses this test reads are the ones a browser and a curl would get.
//
// The storage is a real `*oidc.Storage` over no pool, which is enough: the
// provider and the router are real, and the only thing the missing pool costs is
// the ability to complete a flow — which is not what any of these tests asserts.
// A double would agree with whatever the handler did, which is the bug a
// source-level check cannot see.
func serviceRouter(t *testing.T) http.Handler {
	t.Helper()

	key := throwawaySigningKey(t)
	storage := oidc.NewStorage(nil, oidc.NewProfileReader(), key, clock.System{}, nil, oidc.PathLogin)
	provider, err := oidc.NewProvider(oidc.Config{
		Issuer:     "https://identity.test",
		SigningKey: key,
		LoginUIURL: "https://login.example.com/sign-in/oidc",
	}, storage)
	if err != nil {
		t.Fatalf("building the provider: %v", err)
	}
	return httpapi.New(nil, httpapi.WithOIDC(provider))
}

// throwawaySigningKey is a throwaway RSA key, generated rather than read from a
// file: a PEM checked into a repository is a PEM somebody eventually copies into a
// deployment, and `cmd/identity`'s wiring test says the same thing.
func throwawaySigningKey(t *testing.T) *oidc.SigningKey {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshalling the signing key: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	key, err := oidc.LoadSigningKey(string(encoded), "cafaye-no-html-test")
	if err != nil {
		t.Fatalf("loading the signing key: %v", err)
	}
	return key
}
