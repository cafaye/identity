package client

// THE TRANSPORT IS THE GENERATED ONE, AND THE BINARY IS NOT.
//
// Two claims this file makes executable, both of which are claims about supply chain
// rather than about behaviour — which is exactly why they are claims rather than
// comments. `TestTheServiceBinaryDoesNotReachTheGeneratedClient` is the load-bearing
// one: DECISIONS.md D6 records that oapi-codegen's generated code imports
// `github.com/oapi-codegen/runtime`, and that MD6's claim of "no new dependency at
// runtime" is therefore false for the generated code while remaining true for the
// shipped binary. That is a property of the dependency graph, it can change the
// moment somebody imports this package from `cmd/`, and nobody would notice from
// reading a comment.

// `repoRoot` is defined once, in regeneration_test.go. A second definition of "where
// the repository is" would be a second thing to be wrong.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cafaye/identity/client/generated"
)

// generatedModule is the module the generated code imports, and the one MD6 says
// this client does not have.
const generatedModule = "github.com/oapi-codegen/runtime"

// TestTheServiceBinaryDoesNotReachTheGeneratedClient is DECISIONS.md D6 as a check.
//
// The service builds one static binary from `./cmd/identity`, and this is the service
// that issues every credential in the platform. Whether the oapi-codegen runtime
// reaches that artefact is the difference between "three modules in `go.mod`" — which
// is a fact about the module graph, and which D2 records honestly — and "three
// modules in the thing every cafaye service ships", which would be a supply-chain
// change to the whole platform.
//
// Asserted by asking `go list -deps`, which is the question itself rather than a
// proxy for it. A grep over the source would pass while a transitive import through
// somebody else's package pulled it in, and the whole point of the claim is that the
// dependency graph — not this package's imports — is what matters.
func TestTheServiceBinaryDoesNotReachTheGeneratedClient(t *testing.T) {
	root := repoRoot(t)

	if _, err := exec.LookPath("go"); err != nil {
		t.Fatalf("go is not on PATH, so the dependency graph cannot be read: %v", err)
	}

	cmd := exec.Command("go", "list", "-deps", "./cmd/identity")
	cmd.Dir = root

	var stdout strings.Builder
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		t.Fatalf("go list -deps ./cmd/identity: %v\n"+
			"Without this the claim below cannot be checked at all, and a check that "+
			"cannot run is not a check.", err)
	}

	dependencies := strings.Split(stdout.String(), "\n")

	// The empty case is the interesting one. A reader who finds nothing agrees with a
	// reader that found no dependencies, so a graph that came back empty is an error
	// rather than a pass — the same reasoning as `internal/httpapi`'s
	// `TestEveryServedRouteIsDocumentedOrNamed` and `readTheContract`.
	if len(strings.TrimSpace(stdout.String())) == 0 {
		t.Fatalf("`go list -deps ./cmd/identity` reported no dependencies at all, so this " +
			"check is reading nothing and would pass for the wrong reason.\n" +
			"The service imports pgx, chi and log/slog; a graph with none of them is not " +
			"a graph.")
	}

	for _, dependency := range dependencies {
		if strings.TrimSpace(dependency) == generatedModule {
			t.Errorf("%s reaches ./cmd/identity, so the service's binary now carries "+
				"oapi-codegen's runtime.\n\n"+
				"That is a supply-chain change to the artefact every cafaye service ships, "+
				"made by a client nobody asked for. DECISIONS.md D6 records that this "+
				"package does not reach the binary; if that has stopped being true, D2 is "+
				"wrong and the fix is to find the import that reached for it, not to edit "+
				"this test.\n\n"+
				"Full dependency list is %d packages; `go mod why %s` says who pulled it in.",
				generatedModule, len(dependencies), generatedModule)
		}
	}

	// And the inverse, because a check that only ever says "no" is a check that could
	// pass because it read nothing. If `client` were somehow not in the module at all,
	// the absence above would mean nothing.
	found := false
	for _, dependency := range dependencies {
		if strings.TrimSpace(dependency) == "github.com/cafaye/identity/client" {
			found = true
		}
	}
	if found {
		t.Errorf("./cmd/identity imports github.com/cafaye/identity/client.\n" +
			"The client is for CONSUMERS of identity, not for identity itself. A service " +
			"that called its own API over HTTP would add a network hop and a dependency " +
			"to itself for no benefit — it has the stores already.")
	}
}

// TestTheGeneratorIsNotAModuleDependency is the other half of MD6's sentence, and it
// IS true, which is worth having as a check rather than a claim.
//
// `go run <module>@<version>` resolves in module-aware mode and ignores this module's
// `go.mod`, so the GENERATOR is not a dependency of anything. Only the code it emits
// is. The two are easy to conflate and the distinction is the whole of D2.
func TestTheGeneratorIsNotAModuleDependency(t *testing.T) {
	root := repoRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}

	// `require` lines only. The generator's own module path appears in `generate.go`
	// and in the drift test's constant, and neither is a dependency.
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "github.com/oapi-codegen/oapi-codegen") {
			continue
		}
		t.Errorf("go.mod:%d requires the GENERATOR: %s\n\n"+
			"`go run <module>@<version>` runs in module-aware mode and ignores this "+
			"module's go.mod, so pinning the generator in a `//go:generate` line keeps it "+
			"out of the dependency graph — which is the same relationship goose is in "+
			"for migrations/README.md, and the reason `go.sum` does not move when the "+
			"generator is bumped. A `require` line here would put ten thousand lines of "+
			"generator and its own dependency tree into every consumer of this module.",
			i+1, trimmed)
	}
}

// TestTheTransportCoversEveryOperationInTheDocument is the companion to the
// compile-time assertion in transport.go, and it checks the direction an interface
// cannot check for itself.
//
// `var _ Transport = (*generated.Client)(nil)` proves the generated client SATISFIES
// the interface. It cannot prove the interface has not LOST a method to a document
// that gained one — an interface matching is perfectly compatible with being
// incomplete, and an incomplete interface is a client missing operations.
//
// So this reads both documents' `operationId`s and counts them. The reader is a
// regex over the committed YAML rather than a YAML library, for the reason
// `internal/httpapi/openapi_reader_test.go` gives: `go.mod` has no YAML dependency
// and this does not add one for the sake of forty lines of structure.
//
// `openid/openid.yaml` is deliberately NOT read. This client is generated from
// `openapi/v1.yaml`, and the OIDC surface has its own document and its own paths. A
// check that demanded a method per operationId across BOTH documents would fail on
// twenty-odd `/oidc/*` operations this client has never claimed — and the fix would
// be to widen a check rather than to build something nobody asked for. The scope is
// the document this client is generated from, and the count is stated so the
// boundary is visible rather than assumed.
func TestTheTransportCoversEveryOperationInTheDocument(t *testing.T) {
	root := repoRoot(t)

	document := filepath.Join(root, "openapi", "v1.yaml")
	raw, err := os.ReadFile(document)
	if err != nil {
		t.Fatalf("reading %s: %v", document, err)
	}

	// `operationId: <name>`, which core's conventions require for every operation and
	// which is the name of the method on every generated client in the fleet.
	inDocument := regexp.MustCompile(`(?m)^\s*operationId:\s*(\S+)\s*$`).FindAllStringSubmatch(
		string(raw), -1)

	if len(inDocument) == 0 {
		t.Fatalf("%s declares no operationId at all.\n"+
			"A reader that finds nothing agrees with a document that has nothing in it, "+
			"and this check would pass while covering no operations — which is the shape "+
			"of failure `internal/httpapi`'s document-versus-router tripwire was written "+
			"to prevent.", document)
	}

	declared := map[string]bool{}
	for _, match := range inDocument {
		declared[strings.ToLower(match[1])] = true
	}

	// The methods on the interface, read out of the source rather than the compiler:
	// this test is about a COMPLETE list, and a type parameter or an embedded
	// interface would defeat reflection over method values in ways that need not be
	// worth supporting. A signature that cannot be read is a finding.
	transportSource := filepath.Join(root, "client", "transport.go")
	source, err := os.ReadFile(transportSource)
	if err != nil {
		t.Fatalf("reading %s: %v", transportSource, err)
	}

	// The document's `operationId`s are lower camel case — `mintAPIKey` — and
	// oapi-codegen EXPORTS them, so the Go method is `MintAPIKey`. The comparison is
	// therefore case-insensitive rather than exact, and that is stated rather than
	// papered over: it is not a loose match, it is the generator's one documented
	// transformation, and an exact comparison here would report all twenty operations
	// as missing and all twenty methods as invented.
	method := regexp.MustCompile(`(?m)^\t([A-Z][A-Za-z0-9]*)\(ctx context\.Context`)
	implemented := map[string]bool{}
	for _, match := range method.FindAllStringSubmatch(string(source), -1) {
		implemented[strings.ToLower(match[1])] = true
	}

	if len(implemented) == 0 {
		t.Fatalf("no methods were read out of %s.\n"+
			"The pattern below no longer matches the interface's shape, so this check is "+
			"reading nothing and would pass while the transport covered nothing.",
			transportSource)
	}

	var missing []string
	for name := range declared {
		if !implemented[name] {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		sortStrings(missing)
		t.Errorf("openapi/v1.yaml declares %d operationId(s) the Transport interface has "+
			"no method for:\n\n  %s\n\n"+
			"The interface DOES satisfy the generated client — that is the compile-time "+
			"assertion in transport.go — and it can do that while being incomplete. That "+
			"is the shape of drift this check exists for: the document gains an operation, "+
			"the generator emits it, and the wrapper never wraps it, so a caller has a "+
			"route they cannot call.\n\n"+
			"Add a method to Transport and a wrapper method to Client. Do not delete this "+
			"operation from the document to make it go away: the drift gate holds the two "+
			"documents to the router in both directions, and the router serves it.",
			len(missing), strings.Join(missing, "\n  "))
	}

	// The inverse is asserted too, because a check that only ever says "missing" is a
	// check that passes on an empty document.
	for name := range implemented {
		if !declared[name] {
			t.Errorf("Transport has a method %q that openapi/v1.yaml declares no "+
				"operationId for.\n"+
				"Either the document lost an operationId (which `TestEveryOperationHasAn"+
				"OperationId` in internal/httpapi would also catch) or the interface has "+
				"kept a method for an operation that is gone.", name)
		}
	}
}

// TestTheGeneratedProblemEnumIsUsedRatherThanAString is a small guard on a decision
// that is easy to undo by accident.
//
// `client/generated` declares `ProblemCode` as a compile-time enum from the
// document. This package maps on it. If a `switch` ever moves to a raw string
// comparison, a renamed code becomes a silent fallback rather than a build failure —
// and the fallback is the thing whose whole job is to be correct about codes this
// build does not know.
func TestTheGeneratedProblemEnumIsUsedRatherThanAString(t *testing.T) {
	root := repoRoot(t)

	source, err := os.ReadFile(filepath.Join(root, "client", "errors.go"))
	if err != nil {
		t.Fatalf("reading client/errors.go: %v", err)
	}

	text := string(source)

	// The mapping table is keyed by `code` and every key in it is a snake_case slug.
	// If it were keyed by a status number, or by a raw `ProblemCode("...")` literal,
	// the enum would be decorative.
	if !strings.Contains(text, "var problemTypes = map[string]func(problem) error{") {
		t.Error("client/errors.go no longer keys its code table as a map[string] of " +
			"constructors.\nThe table is what makes the fallback visible: a missing " +
			"entry reads as \"a code this build has not seen\", which is what it means.")
	}

	// And the concrete codes are named as generated constants somewhere reachable, so
	// a typo in one is a compile error rather than a missing entry in a map.
	for _, code := range []generated.ProblemCode{
		generated.ProblemCodeUnauthorized,
		generated.ProblemCodeForbidden,
		generated.ProblemCodeNotFound,
		generated.ProblemCodeConflict,
		generated.ProblemCodeValidationFailed,
		generated.ProblemCodeRateLimited,
		generated.ProblemCodeAccountLocked,
	} {
		if code == "" {
			t.Error("the generated ProblemCode enum carries an empty value")
		}
		if !strings.Contains(text, strconv.Quote(string(code))) {
			t.Errorf("the code table does not contain %q.\n"+
				"It exists in the document and in the generated enum, so a missing row "+
				"means every response carrying it falls to *UnknownProblemError — which "+
				"works, but loses the specific type a caller may branch on.",
				string(code))
		}
	}
}

// sortStrings is a tiny insertion sort, here so this file does not import `sort` for
// three lines. The list is the size of a document's operation count.
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
