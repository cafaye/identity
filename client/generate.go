package client

// THIS FILE IS THE GENERATION WIRING, and the two questions a reader has about a
// generated tree are answered here rather than in a README nobody is required to
// read.
//
// # The pin
//
// oapi-codegen v2.8.0, pinned to an exact version here rather than in
// oapi-codegen.yaml, and the `@v2.8.0` is what makes the pin real: `go run
// <module>@<version>` resolves in module-aware mode and ignores this module's
// go.mod, so the generator is not a dependency of this repository and cannot be
// moved by `go get`. It is a build tool invoked on purpose, in the same
// relationship goose is in for migrations/README.md — "installed separately so
// that nothing in go.sum moves when it changes".
//
// A generator on a version range is a public API change waiting for a patch
// release, and this one has 10,000 lines of output that a patch release could
// rewrite. The `regeneration_test.go` drift check is what would notice, but
// noticing after the fact is not a pin.
//
// # `go:generate` from the package directory
//
// `go generate ./client/` runs with `client/` as its working directory, and the
// `--config` path and the input path below are both relative to it. `output:` in
// oapi-codegen.yaml is relative to the CONFIG FILE's directory instead, which is
// a third directory and is the reason that file says `output: api.gen.go` rather
// than `output: client/api.gen.go` — the latter writes to `client/client/`. That
// was measured rather than guessed; see the comment there.
//
// # The document is this repository's own
//
// There is no vendored copy and no provenance file, and that is unlike
// cafaye-ts on purpose. This client is generated from the document this
// repository ships, in the same commit, so a vendored copy would be a second
// copy of a file that is already committed two directories away and already read
// by internal/httpapi's drift check. A vendored copy can lag its source; this
// one cannot, because there is nothing to lag behind.
//
// The consequence is stated rather than hidden: **regenerating is only correct
// immediately after the document changes, in the same commit.** A client that
// drifted from its document is the failure this package's `regeneration_test.go`
// exists to make impossible.

// The unexported marker makes this a real file rather than a comment-only one, so
// `go build ./...` covers it and a syntax error here is a build failure instead of
// a surprise at `go generate` time.
var _ = struct{}{}

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 --config oapi-codegen.yaml -generate models,client ../openapi/v1.yaml
