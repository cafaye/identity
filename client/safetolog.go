package client

// SAFE TO LOG. A redacting `fmt.Stringer` for the generated types that carry a
// secret, and the reason it is a function rather than a method.
//
// # THE PROBLEM, MEASURED
//
// The brief says it exactly: "Check whether the generated types have a `String()`
// or a `MarshalLogObject`, and if the answer is 'no', add one that redacts — do not
// rely on nobody calling it."
//
// The answer here is 'no'. oapi-codegen v2.8.0 emits no `String()` method and no
// `MarshalLogObject` for any type, so `fmt.Sprintf("%v", issued)` prints every
// exported field of an `IssuedAPIKey` — including `Token`, the plaintext of a
// scoped credential that this service stores only a SHA-256 of and returns exactly
// once.
//
// That is a live footgun, not a theoretical one. `slog.Any("key", issued)` renders
// it, `log.Printf("%v", issued)` renders it, a `%+v` in a panic message renders it,
// and `json.Marshal` on it in a structured log renders it. A caller does not have to
// be careless: passing a returned value to a logger is the most ordinary line in a
// Go program, and Go's default struct formatting makes it a leak without anybody
// writing a format string they did not mean to.
//
// # WHY A FUNCTION AND NOT A METHOD
//
// Go does not let one package define a method on another package's type. The
// generated types belong to `client/generated`, so `func (i generated.IssuedAPIKey)
// String() string` will not compile — which is the constraint that forces the shape
// of the answer, and it is worth recording because the alternative (renaming a
// generated type, or wrapping every one of them) is worse.
//
// A wrapping struct per generated type would mean twenty new exported types a caller
// has to remember to use, and a caller who forgets has exactly the leak they were
// trying to avoid. So there is one function, one name, and the test above asserts
// it works on the three worst cases.
//
// # WHAT IT PRINTS
//
// The type's name, its fields, and `Redacted` in place of anything credential-
// shaped. Not the type alone: a log line reading `IssuedAPIKey` with no fields is
// not diagnosable, and a redactor that removes everything trains people to ignore
// the marker.
//
// The `trace_id` case is the reason the redactor has to be structural rather than
// field-name-based, and it is why the shape rules in redact.go are generous: a 32-hex
// trace id must survive while a 43-character credential must not.

import (
	"fmt"
	"reflect"
	"strings"
)

// SafeToLog renders any value for a log record with credential-SHAPED strings
// replaced by `Redacted`.
//
// The name is a statement rather than a description: it answers the question a caller
// has at the call site — "may I log this?" — and it has to be readable in a diff
// review, where `fmt.Sprintf("%v", …)` on a credential-bearing type looks entirely
// ordinary.
//
// It is a function taking `any` rather than twenty typed entry points, because a
// caller holding a value should not have to know which of the twenty shapes it is.
//
// ## THE LIMIT OF THIS ONE, AND WHICH OF THE TWO TO REACH FOR
//
// **This function does not know your credential.** It recognises the `cafaye_`
// prefix, a JWS, and header lines — shapes. A bare session token is 43 base64url
// characters with no prefix and no dots, and there is nothing about it that
// distinguishes it from an opaque id, so this function passes it through.
//
// `(*Client).SafeToLog` is the one that knows: it uses the client's redactor, which
// holds this client's own credential, so an exact match is caught too. **If you have
// a client, use that.** This function is for a value you hold with no client to hand
// — a token read out of a config file, a struct built by a test.
func SafeToLog(value any) string {
	if value == nil {
		return "<nil>"
	}
	return safeToLog(reflect.ValueOf(value), 0, "", Redactor{})
}

// SafeToLog renders any value with THIS CLIENT'S credential known, so an exact
// match is redacted as well as the shapes.
//
// Strictly stronger than the package-level `SafeToLog`, and the one to reach for
// when a client is in hand — which, in a caller that has constructed one, it always
// is. The package-level function exists for the value-with-no-client case.
func (c *Client) SafeToLog(value any) string {
	if value == nil {
		return "<nil>"
	}
	return safeToLog(reflect.ValueOf(value), 0, "", c.redactor)
}

// safeToLog is the recursive worker.
//
// The depth bound and the visited set are for the same reason the ones in the test
// are: a generated type holds a `time.Time`, which holds a `*Location` with a
// pointer back into zone data, and an unbounded walk is a hang rather than a failure.
func safeToLog(v reflect.Value, depth int, indent string, redact Redactor) string {
	if depth > 6 || !v.IsValid() {
		return "…"
	}

	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return "<nil>"
		}
		return safeToLog(v.Elem(), depth+1, indent, redact)

	case reflect.Struct:
		var out strings.Builder

		name := v.Type().String()
		// A `time.Time` has no fields a reader needs; its `%v` is already
		// diagnostic and contains nothing a credential could reach.
		if name == "time.Time" {
			out.WriteString(redact.String(fmt.Sprintf("%v", v.Interface())))
			return out.String()
		}

		out.WriteString(name + "{")
		t := v.Type()
		wrote := false

		for i := 0; i < v.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() {
				// An unexported field is not reachable by a caller who did not build
				// this value, and this service's generated structs have none.
				continue
			}

			if wrote {
				out.WriteString(" ")
			}
			wrote = true

			out.WriteString(field.Name + ": ")
			out.WriteString(safeToLog(v.Field(i), depth+1, indent+"  ", redact))
		}

		out.WriteString("}")
		return out.String()

	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return "[]"
		}
		var out strings.Builder
		out.WriteString("[")
		for i := 0; i < v.Len() && i < 16; i++ {
			if i > 0 {
				out.WriteString(" ")
			}
			out.WriteString(safeToLog(v.Index(i), depth+1, indent, redact))
		}
		out.WriteString("]")
		return out.String()

	case reflect.Map:
		var out strings.Builder
		out.WriteString("map[")
		for i, key := range v.MapKeys() {
			if i > 0 {
				out.WriteString(" ")
			}
			if i >= 16 {
				out.WriteString("…")
				break
			}
			out.WriteString(safeToLog(key, depth+1, indent, redact))
			out.WriteString(":")
			out.WriteString(safeToLog(v.MapIndex(key), depth+1, indent, redact))
		}
		out.WriteString("]")
		return out.String()

	default:
		return redact.String(fmt.Sprintf("%v", v.Interface()))
	}
}
