package httpapi

// The reader for openapi/v1.yaml, and the normalisation it applies before the
// two sides of the drift check in openapi_drift_test.go are compared.
//
// ## Why this is not a YAML parser
//
// `go.mod` has no YAML dependency and this packet adds none: the house rule is
// "no dependency without a cause stated in review" and "go mod tidy must leave
// go.mod and go.sum unchanged". A YAML library is already in the module graph
// as a *transitive* dependency of `zitadel/schema`, and importing it would be
// worse than writing this — it would promote an indirect module to a direct
// requirement, and the tree would then carry a parser whose version and whose
// CVEs are this service's problem, for the sake of reading forty lines of
// structure out of a file this repository also edits by hand.
//
// courier hit the same wall and solved it the same way: read the part of the
// document that describes routes — the `paths:` block and the keys under it —
// by indentation, and understand exactly that. The subset is stated below, and
// the whole of the test suite's value rests on one property: **every way this
// reader could come back with less than it should is an error, not an empty
// set.** A reader that finds nothing agrees with a reader that finds nothing,
// and that is the only way a drift check silently becomes a check over zero
// operations. See the "refuses rather than under-reads" cases in this file's
// own tests.
//
// ## The subset
//
//   - `openapi: <version>` and `info: → version: <v>`, both at fixed depth.
//   - `paths:` at column 0; path items one level in; operations one level below
//     that; anything deeper is an operation's body and is not read. The two
//     indentation levels are **derived from the document**, not assumed to be
//     two and four, so four-space YAML is read correctly rather than read as
//     empty.
//   - A direct child of `paths:` is a path if it starts with `/`; otherwise it
//     has to be one of the fields OpenAPI 3.1 allows directly under a path —
//     `summary`, `description`, `servers`, `parameters`, `$ref`, `x-…` — and
//     anything else is an error rather than a guess.
//   - A key under a path is an operation if it is one of the eight HTTP method
//     names and nothing else. `getaway:` is not a `GET`, and a schema property
//     named `delete` three levels down inside a response body is not a
//     `DELETE`.
//
// Anything outside that subset is an error. A service that needs a real parser
// should add one and delete this; the check itself does not change.

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

// openAPIDocument is what the reader takes out of openapi/v1.yaml. Three
// things, because those are the three the drift check asserts on: what the
// document declares it is, what build of it this is, and the operations.
type openAPIDocument struct {
	// Path is where it was read from, so a failure can name the file.
	Path string
	// SpecVersion is the `openapi:` value, e.g. "3.1.0".
	SpecVersion string
	// InfoVersion is `info.version`.
	InfoVersion string
	// Operations is keyed by the normalised {method, path}, valued by the
	// operation the document declares there, carrying the spellings the source
	// used so a failure can name a path as written — the document's `{id}` and
	// chi's `{id}` beside each other is the thing a reader needs to see.
	Operations map[operationKey]documentedOperation
}

// documentedOperation is one operation as the document spells it.
type documentedOperation struct {
	// Method and Path are the document's own spellings, not the normalised key's.
	Method string
	Path   string
	// OperationID is what a generator turns into a method name. Empty where the
	// document declares none, which is a breach the drift check reports rather
	// than tolerates.
	OperationID string
}

// Label is how a failure names this operation: "POST /v1/session", a request
// line, rather than a struct dump.
func (o documentedOperation) Label() string { return o.Method + " " + o.Path }

// operationKey is the normalised {method, path} both sides are keyed by, and it
// is a struct rather than a string because the brief's one hard requirement is
// that a method is part of the key. billing's first drift check compared paths
// only and could not see that `resources :customers … only: %i[update]` emits
// both PATCH and PUT: one path on each side, and the comparison reported
// agreement while `PUT /v1/customers/{id}` was being served in a
// money-handling service. Keying on a struct makes that mistake unavailable
// rather than merely discouraged.
type operationKey struct {
	Method string
	Path   string
}

func (k operationKey) String() string { return k.Method + " " + k.Path }

// The eight HTTP method names OpenAPI 3.1's Path Item Object allows, plus
// nothing. A key is an operation if it is exactly one of these: `getaway:` is
// not a `GET`, and a prefix match would count a schema property as a route.
var openAPIOperationKeys = map[string]string{
	"get":     "GET",
	"put":     "PUT",
	"post":    "POST",
	"delete":  "DELETE",
	"options": "OPTIONS",
	"head":    "HEAD",
	"patch":   "PATCH",
	"trace":   "TRACE",
}

// The fields OpenAPI 3.1 allows directly under a path key, in the Path Item
// Object. They belong to the path, not to any of its operations, and
// `parameters` is the one that bites: identity's document carries one on every
// account path, and a reader that did not know the difference would report
// `parameters` as an operation with no operationId.
var openAPIPathItemFields = map[string]bool{
	"summary": true, "description": true, "servers": true,
	"parameters": true, "$ref": true,
}

// readOpenAPIDocument reads the operations and the two version strings out of a
// document, or returns an error naming what it found instead.
//
// Every error here is a way the reader could have under-read. They are errors
// rather than empty results because a green drift check over an empty set is
// worse than no check: it reports agreement between a document and a router it
// never read.
func readOpenAPIDocument(path string) (openAPIDocument, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return openAPIDocument{}, fmt.Errorf("could not read %s: %w", path, err)
	}

	doc := openAPIDocument{Path: path, Operations: map[operationKey]documentedOperation{}}
	lines := significantLines(string(raw))

	if doc.SpecVersion, err = topLevelScalar(path, lines, "openapi"); err != nil {
		return openAPIDocument{}, err
	}
	if doc.InfoVersion, err = infoScalar(path, lines, "version"); err != nil {
		return openAPIDocument{}, err
	}

	block, pathLevel, methodLevel, err := pathsBlock(path, lines)
	if err != nil {
		return openAPIDocument{}, err
	}

	for _, group := range groupByPathLevel(block, pathLevel) {
		key := strings.TrimSuffix(group[0].text, ":")
		number := group[0].number

		if !strings.HasPrefix(key, "/") {
			if openAPIPathItemFields[key] || strings.HasPrefix(key, "x-") {
				continue
			}
			return openAPIDocument{}, fmt.Errorf(
				"%s:%d — %q is not a valid OpenAPI path. Every key directly under `paths:` "+
					"is a path starting with `/`, or a field of the Path Item Object "+
					"(summary, description, servers, parameters, $ref, x-…). This reader "+
					"refuses the document rather than guessing which was meant.",
				path, number, key)
		}

		methods := make([]documentedOperation, 0, len(openAPIOperationKeys))
		for _, line := range group[1:] {
			if line.indent != methodLevel {
				continue // an operation's body, and a body may contain a key spelled like a method
			}
			method, ok := openAPIOperationKeys[strings.TrimSuffix(line.text, ":")]
			if !ok {
				continue
			}
			methods = append(methods, documentedOperation{
				Method: method,
				Path:   key,
			})
		}

		if len(methods) == 0 {
			return openAPIDocument{}, fmt.Errorf(
				"%s:%d — the path %q has no operation under it. An OpenAPI path item with "+
					"no operation is not something a client can be generated from, and "+
					"skipping it would leave this check agreeing with a document that says "+
					"nothing about this route.",
				path, number, key)
		}

		for _, op := range methods {
			if err := doc.record(path, number, op); err != nil {
				return openAPIDocument{}, err
			}
		}
	}

	// The operationId is read in a second pass over the same groups, because it
	// lives at one level below the method key and this reader does not model an
	// operation's body — it only has to find one named field inside it. The
	// structure is already known to be sound, so this pass cannot fail and does
	// not return an error.
	doc.readOperationIDs(groupByPathLevel(block, pathLevel), methodLevel)

	if len(doc.Operations) == 0 {
		return openAPIDocument{}, fmt.Errorf(
			"%s documents no operations at all. Two readers that both find nothing agree, "+
				"which is how a check over nothing goes green.", path)
	}
	return doc, nil
}

// record files one operation, and refuses when two of them normalise onto the
// same key. A rewrite is only safe while it cannot map two different operations
// onto one, so the collision is reported rather than resolved by keeping either.
func (d *openAPIDocument) record(path string, number int, op documentedOperation) error {
	key := operationKey{Method: op.Method, Path: normalisePath(op.Path)}
	if existing, clash := d.Operations[key]; clash {
		return fmt.Errorf(
			"%s:%d — %s and %s both read as %s. They normalise onto one route, so a check "+
				"that could not see the collision would be blind to it.",
			path, number, existing.Label(), op.Label(), key)
	}
	d.Operations[key] = op
	return nil
}

// readOperationIDs fills in the operationId of every operation recorded, by
// walking the same groups and taking the first `operationId:` one level below
// each method key.
//
// It is a second pass rather than a nested parse because that field is the only
// thing inside an operation body this check cares about, and a reader that
// modelled an operation body would be modelling everything a future document
// might put in one.
func (d *openAPIDocument) readOperationIDs(groups [][]yamlLine, methodLevel int) {
	for _, group := range groups {
		key := strings.TrimSuffix(group[0].text, ":")
		if !strings.HasPrefix(key, "/") {
			continue
		}
		for _, line := range group[1:] {
			method, ok := openAPIOperationKeys[strings.TrimSuffix(line.text, ":")]
			if !ok || line.indent != methodLevel {
				continue
			}
			id, found := operationIDBelow(group[1:], line, methodLevel)
			if !found {
				continue // absent is a breach the check reports, not a read failure
			}
			normalised := operationKey{Method: method, Path: normalisePath(key)}
			op := d.Operations[normalised]
			op.OperationID = id
			d.Operations[normalised] = op
		}
	}
}

// operationIDBelow finds the `operationId:` that belongs to the operation
// starting at `methodLine`.
//
// It reads the operation's OWN fields — the lines between the method key and the
// next key at the same level — and identifies that level from the first line
// below the method key rather than assuming methodLevel+1, because the size of
// the gap is an authoring choice (two spaces in this document, one in courier's
// examples) and not a rule. Nothing nested deeper is read, so a schema property
// named `operationId`, or an example payload carrying one, is not mistaken for
// the operation's own field.
func operationIDBelow(group []yamlLine, methodLine yamlLine, methodLevel int) (string, bool) {
	bodyLevel := -1
	for _, line := range group {
		if line.number <= methodLine.number {
			continue
		}
		if line.indent <= methodLevel {
			break // the next operation, or the end of this one
		}
		if bodyLevel < 0 {
			bodyLevel = line.indent
		}
		if line.indent != bodyLevel {
			continue
		}
		if value, ok := strings.CutPrefix(line.text, "operationId:"); ok {
			return strings.Trim(strings.TrimSpace(value), `"'`), true
		}
	}
	return "", false
}

// normalisePath is the path with every path parameter's whole segment replaced
// by `{}` and any trailing slash removed. Both rewrites are mechanical, and both
// are applied to the document and the router alike — there is no "document
// rules" and "router rules", because a normaliser that treats the two sides
// differently is one that can hide a difference.
//
// This service spells its parameters differently on the two sides and has since
// the accounts packet: chi registers `{accountID}`, `{userID}`, `{keyID}`,
// `{clientID}`, `{enrollmentID}`, `{requestID}`, and the document spells
// `{account_id}`, `{user_id}`, `{key_id}`, `{client_id}`, `{enrollmentId}`.
// Those are one route to a client, which substitutes a path parameter
// positionally, so a rename inside one route is not a second route. Failing on
// it would make the check cry wolf, and a check people turn off is worse than
// none.
//
// What is *not* erased is which segment the parameter was, so a path that gains
// or loses a parameter is still a difference. A trailing slash is not a
// difference because chi agrees: it routes `/healthz/` to the `/healthz`
// handler.
//
// A path missing its leading slash is not given one either. The document is
// invalid, and quietly repairing an invalid document hides the invalidity — the
// reader above rejects it as not-a-path before this ever sees it.
func normalisePath(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment != "" && (strings.HasPrefix(segment, "{") || strings.HasPrefix(segment, ":")) {
			segments[i] = "{}"
		}
	}
	trimmed := strings.TrimRight(strings.Join(segments, "/"), "/")
	if trimmed == "" {
		return "/"
	}
	return trimmed
}

// --- reading lines ------------------------------------------------------------

// yamlLine is one significant line: its indentation, its trimmed text, and the
// line number it came from, so a failure can point at the file rather than at an
// index into a filtered slice.
type yamlLine struct {
	indent int
	text   string
	number int
}

// significantLines drops blank lines and comments. Nothing else: a block
// scalar's content is indented deeper than the key that owns it, so it never
// reaches a level this reader treats as structure, and dropping it here would
// mean modelling block scalars to keep the line numbers honest.
func significantLines(contents string) []yamlLine {
	var out []yamlLine
	scanner := bufio.NewScanner(strings.NewReader(contents))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for number := 1; scanner.Scan(); number++ {
		raw := scanner.Text()
		stripped := strings.TrimLeft(raw, " ")
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		out = append(out, yamlLine{
			indent: len(raw) - len(stripped),
			text:   strings.TrimRight(stripped, " "),
			number: number,
		})
	}
	return out
}

// topLevelScalar reads `key: value` at column 0.
func topLevelScalar(path string, lines []yamlLine, key string) (string, error) {
	for _, line := range lines {
		if line.indent != 0 {
			continue
		}
		if value, ok := strings.CutPrefix(line.text, key+":"); ok {
			return strings.Trim(strings.TrimSpace(value), `"'`), nil
		}
	}
	return "", fmt.Errorf(
		"%s has no top-level `%s:`. A document that does not say what it is cannot be "+
			"checked against anything, and this reader returns an error rather than an "+
			"empty one so a check over nothing cannot pass.", path, key)
}

// infoScalar reads `info:`'s `version:`, which is one level in. `info` is at
// column 0 and `version` directly beneath it, and nothing deeper is consulted:
// a `version` key inside a component schema is not this document's version.
func infoScalar(path string, lines []yamlLine, key string) (string, error) {
	for i, line := range lines {
		if line.indent != 0 || line.text != "info:" {
			continue
		}
		level := 0
		for _, child := range lines[i+1:] {
			if child.indent == 0 {
				break // the next top-level key: `info` has ended
			}
			if level == 0 {
				level = child.indent // the first key under `info` sets the level
			}
			if child.indent != level {
				continue
			}
			if value, ok := strings.CutPrefix(child.text, key+":"); ok {
				return strings.Trim(strings.TrimSpace(value), `"'`), nil
			}
		}
		break
	}
	return "", fmt.Errorf(
		"%s has no `info.version`. core requires it, and it is the only signal a consumer "+
			"has for attributing a deprecated endpoint to a release. Missing is an error "+
			"here, not an empty string.", path)
}

// pathsBlock is every line under `paths:`, the path-item level, and the
// operation level.
//
// It is an error rather than an empty result when there is no `paths:` key, and
// the two levels are derived from the document rather than assumed to be two and
// four spaces — so four-space YAML is read correctly instead of read as empty.
func pathsBlock(path string, lines []yamlLine) (block []yamlLine, pathLevel, methodLevel int, err error) {
	for i, line := range lines {
		if line.indent != 0 || line.text != "paths:" {
			continue
		}
		for _, child := range lines[i+1:] {
			if child.indent == 0 {
				break // the next top-level key: `components:` ends the block
			}
			block = append(block, child)
		}
		levels := distinctIndents(block)
		switch {
		case len(levels) == 0:
			return nil, 0, 0, fmt.Errorf(
				"%s documents no operations: nothing is under its `paths:` key. Two readers "+
					"that both find nothing agree, which is how a check over nothing goes green.", path)
		case len(levels) == 1:
			return nil, 0, 0, fmt.Errorf(
				"%s documents no operations: what is under `paths:` is one indentation level "+
					"deep, so there is no operation level below the path items.", path)
		}
		return block, levels[0], levels[1], nil
	}
	return nil, 0, 0, fmt.Errorf(
		"%s has no top-level `paths:` key. A reader that cannot find the document's paths "+
			"finds none, and a check over none passes — so this is an error, not an empty "+
			"result.", path)
}

// distinctIndents is the block's indentation levels, ascending. Only the first
// two are structure: anything deeper is inside an operation's body, and an
// operation's body is not part of the route set.
func distinctIndents(block []yamlLine) []int {
	seen := map[int]bool{}
	var levels []int
	for _, line := range block {
		if !seen[line.indent] {
			seen[line.indent] = true
			levels = append(levels, line.indent)
		}
	}
	sort.Ints(levels)
	return levels
}

// groupByPathLevel splits the block into one slice per direct child of `paths:`,
// each holding that child and everything indented under it. The level a key
// sits at is what makes it a path item, so grouping is by level and not by
// blank lines.
func groupByPathLevel(block []yamlLine, pathLevel int) [][]yamlLine {
	var groups [][]yamlLine
	for _, line := range block {
		if line.indent == pathLevel || len(groups) == 0 {
			groups = append(groups, []yamlLine{line})
			continue
		}
		groups[len(groups)-1] = append(groups[len(groups)-1], line)
	}
	return groups
}
