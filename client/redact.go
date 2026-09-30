package client

// THE SECURITY INVARIANT: NO CREDENTIAL EVER REACHES A STRING A HUMAN READS.
//
// # WHY THIS FILE IS THE CENTRE OF THE PACKET
//
// This package is the one place in a consumer's application that touches every
// credential it has. It holds a token, and a Go `error`'s `Error()` string is the
// single most likely thing in a process to end up in a log file, a crash report, a
// support ticket, or a terminal somebody is shoulder-surfing — with no
// configuration, because `slog`'s default handler prints `%v` of anything you hand
// it and `fmt.Println(err)` prints the message.
//
// The rule is therefore not "be careful when building messages". It is that **no
// string this package constructs out of anything a caller or a service supplied
// passes through the redactor first**, and that the redactor's behaviour is a test
// rather than a review comment.
//
// # THE CREDENTIAL IS HELD IN A CLOSURE, AND THAT IS NOT A STYLE CHOICE
//
// `Redactor` stores what it knows as a `func(string) bool` rather than as a
// `[]string`. It is the only way to satisfy the brief's requirement that the token
// appear in no `fmt.Sprintf` of the client, because:
//
//   - `fmt` calls `String()` for `%v`, `%+v`, `%s` and `%q` — so a `String()` method
//     covers the four verbs that account for essentially all real logging;
//   - `fmt` does NOT call `String()` for `%#v`. It prints Go syntax, and every
//     exported field of a struct is printed by value.
//
// So a `[]string` of secrets inside a struct is a `%#v` leak, and a redactor holding
// one is a `%#v` leak on every error type in this package. A func value, by contrast,
// is rendered by every verb as `(func(string) bool)(0xADDR)` — the address, never the
// captured value. There is no formatting verb in Go that prints a closure's
// environment.
//
// That is why `Client` holds no `token` field either. The token lives inside the
// redactor's closure and inside the request editor's closure, and nowhere else.
// `Client.String()` is still written, for the four verbs `fmt` would otherwise route
// to a default struct rendering — but the closure is what makes `%#v` safe, and the
// two are load-bearing together rather than one being redundant.
//
// # THE RULE IS ALL OR NOTHING
//
// A string comes back whole, or comes back as one marker. There is no partial
// redaction, and that is the load-bearing decision.
//
// The obvious implementation — replace the substrings you recognise, return the
// rest — is wrong in a way that gets worse the more carefully it is written,
// because it invites a reader to add one more pattern, and the day that pattern has
// a gap in it is the day a credential ships. A scrubber that returns "the rest" is a
// scrubber whose safety depends on the completeness of a list nobody can check.
// Here, a string that matched anything at all is not shown, so a pattern with a gap
// can only ever cause a false NEGATIVE for "this string is clean" — and the two
// patterns below are deliberately generous for that reason.
//
// # WHAT MATCHES
//
//  1. Exact values this package was given. The client knows the one or two
//     credentials it holds and can recognise them character for character. This
//     catches a service echoing a caller's own token back inside a problem
//     `detail`.
//
//  2. Structural shapes, whether or not this instance ever held them: the
//     `cafaye_` API-token prefix, a JWS compact serialization, and any
//     `Authorization` / `Proxy-Authorization` / `Cookie` / `Set-Cookie` header
//     line. This catches credentials the instance never held — a `Set-Cookie` on a
//     response it did not authenticate, or a header a caller built by hand.
//
// # WHAT DOES NOT MATCH, DELIBERATELY
//
// Ordinary prose containing the words. "the request was not authorized" is a
// message worth having. `dial tcp 10.0.0.5:5432: connect: connection refused` is
// the most useful line in a network error and nothing here touches it.
//
// A 32-hex `trace_id` survives, which matters more than it sounds: core's
// conventions say support starts from the `trace_id`, so a redactor that ate it
// would have made every unsupported failure harder to report. That is why the
// shapes are credential-shaped and not merely hex-shaped.

import (
	"regexp"
	"sort"
	"strings"
)

// Redacted is the replacement for any string that matched. It is exported because
// a consumer has to be able to recognise it — a log line containing this marker is
// a log line about redaction, and a caller who wants to assert on it needs the exact
// string.
//
// It is deliberately not an empty string. A message that is suddenly blank reads as
// "the error had no detail", which is a different and wrong conclusion, and the
// operator who then goes looking for a missing field is looking for the wrong thing.
const Redacted = "[redacted: a credential-shaped value was present]"

// credentialShapes matches anything that carries a credential, matched STRUCTURALLY
// rather than by comparison against a known list.
//
// Kept as one alternation so "did anything match" is one question, which is what
// makes the all-or-nothing rule cheap to implement honestly. The `cookie` and
// `authorization` alternatives run to the end of the line rather than to the first
// space, because a cookie value contains neither and a `Set-Cookie` line carries
// four attributes after the one that matters.
//
// The JWS alternative requires a real header AND payload segment. `one.two.three`
// is three segments and not a JWT, and treating it as one would redact ordinary
// prose about version numbers for no security benefit — a redactor that eats too
// much trains people to ignore the marker, which is how the marker stops working.
//
// A package-level compiled regexp is safe to share: `MatchString` does not mutate
// `lastIndex`, which only `Find` and `FindAll` do, and this one is only ever used
// with `MatchString`.
var credentialShapes = regexp.MustCompile(
	`\bcafaye_[A-Za-z0-9_-]+` +
		`|\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*` +
		`|(?:^|[\s,;])(?:proxy-)?authorization\s*:\s*\S+` +
		`|(?:^|[\s,;])(?:set-)?cookie\s*:\s*[^\r\n]*`)

// Redactor removes credentials from anything this package is about to hand a human.
//
// ONE field, and it is a function. See the file header: a func value is rendered as
// an address by every `fmt` verb including `%#v`, so the credential cannot be
// printed out of this type by any formatting path.
//
// The zero value is usable and redacts nothing but credential SHAPES, which is what
// the structural fallback exists for.
type Redactor struct {
	// holdsKnown reports whether `value` contains one of the exact credential
	// values this redactor was constructed with. nil on the zero value.
	holdsKnown func(string) bool
}

// NewRedactor binds a redactor to the credential values this instance holds.
//
// Blank and empty values are dropped rather than kept: an empty secret would match
// at position zero in every string and redact all of them, which is the kind of bug
// that looks like a security feature and is a denial of service.
//
// Longest first, so a secret that is a prefix of another cannot be replaced
// part-way and leave a tail behind. With the all-or-nothing rule that particular bug
// is harmless — either string still matches — but ordering by length costs nothing
// and keeps the intent obvious.
func NewRedactor(known ...string) Redactor {
	seen := map[string]bool{}
	var exact []string

	for _, secret := range known {
		if secret == "" || seen[secret] {
			continue
		}
		seen[secret] = true
		exact = append(exact, secret)
	}

	if len(exact) == 0 {
		return Redactor{}
	}

	sort.SliceStable(exact, func(i, j int) bool { return len(exact[i]) > len(exact[j]) })

	// The secret leaves Go's data structures here and exists only inside this
	// closure's environment, which no formatting verb prints.
	return Redactor{holdsKnown: func(value string) bool {
		for _, secret := range exact {
			if strings.Contains(value, secret) {
				return true
			}
		}
		return false
	}}
}

// String returns the text unchanged, or Redacted if anything credential-shaped is in
// it. It never returns a partially-redacted string.
//
// The empty case is `""` rather than the marker: "no value" is not a secret, and
// redacting the absence of a thing would make a redaction marker meaningless.
func (r Redactor) String(value string) string {
	if value == "" {
		return ""
	}

	// FIRST, before anything else. Truncating first and then looking would mean
	// only the first N characters were ever checked, which is a hole rather than an
	// optimisation.
	if r.holdsKnown != nil && r.holdsKnown(value) {
		return Redacted
	}

	if credentialShapes.MatchString(value) {
		return Redacted
	}

	return value
}

// Error renders an error's message, or Redacted if it carried a credential.
//
// This is the method that matters most and it exists because it is the one Go calls
// implicitly. `slog.Any("error", err)`, `fmt.Printf("%v", err)` and
// `log.Println(err)` all reach `Error()`, so redacting here covers every path that
// does not go through this package's own formatting — including the ones this
// package does not know about.
func (r Redactor) Error(err error) string {
	if err == nil {
		return ""
	}
	return r.String(err.Error())
}

// SafeCause keeps a wrapped error as a cause, unless there is something in it to
// keep out of one.
//
// A cause is how the errno survives: `net/http`'s `*url.Error` says almost nothing,
// and the difference between a refused connection and a DNS failure is one level
// down in `Err`. So the original is normally preserved untouched and a caller who
// wants `errors.Is(err, syscall.ECONNREFUSED)` still has it.
//
// Except when the redactor finds a credential in it. A cause is a real object this
// package does not own and it is reachable — `%+v` on it prints it, every crash
// reporter prints it, `slog` prints it. Passing a partially-scrubbed copy would be
// the worst of both: a cause that is no longer the platform's, carrying a message
// that is no longer true. So when there is anything to withhold the original is
// withheld ENTIRELY, and what is kept is a stand-in that says so.
//
// The stand-in does NOT unwrap. That is the point, and it is a cost worth naming:
// `errors.Is` and `errors.As` will not reach through it. Preserving the ability to
// unwrap would preserve the ability to print the original message, which is the
// thing being prevented.
func (r Redactor) SafeCause(err error) error {
	if err == nil {
		return nil
	}
	if r.String(err.Error()) == err.Error() {
		return err
	}
	return &redactedCause{}
}

// redactedCauseError stands in for a cause that carried a credential.
//
// It holds nothing — not even a reference to the original — because a field is a
// field, and `fmt` prints fields. The original is unreachable from here by
// construction, which is a stronger statement than "unreachable by convention".
type redactedCause struct{}

func (*redactedCause) Error() string {
	return Redacted + " — the original error carried a credential-shaped value, so it is not " +
		"attached, and it is deliberately not unwrappable: errors.Is would otherwise put " +
		"the original message back into any error chain somebody formats."
}

// truncate bounds a string that came from outside this package — a response body
// excerpt, a diff line — so an error message is readable.
//
// An ellipsis rather than a hard cut, so a reader can tell something was removed.
// Redaction runs BEFORE truncation in every caller, deliberately: truncating first
// would mean only the first `max` characters were ever checked for a credential,
// which is a hole rather than an optimisation.
func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "…"
}
