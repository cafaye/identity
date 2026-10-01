package courier

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/recovery"
)

// These are the test-only helpers the leak sweep and the drift checks need, kept
// in one file so `mailer_test.go` is about behaviour rather than about plumbing.

// sprint formats a value under one verb.
//
// It is a function rather than inline `fmt.Sprintf` so a panic in formatting is
// reported with the verb that caused it, which is the difference between "the leak
// sweep panicked" and "the leak sweep panicked on `%#v`", and the second one names
// the leak.
func sprint(t *testing.T, thing any, verb string) (out string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("formatting under %s panicked: %v", verb, r)
		}
	}()
	return fmt.Sprintf(verb, thing)
}

// reflectMessageFields reads `recovery.Message`'s field names, in order.
//
// IT IS A REFLECTION TEST AND NOT A COMPILE-TIME ONE because the claim is about
// ABSENCE — that no field names a courier type — and absence is not expressible in
// the type system. A test that constructs the struct and checks a field does not
// exist cannot be written; one that lists the fields and shows the list is short
// can.
func reflectMessageFields() string {
	typ := reflect.TypeOf(recovery.Message{})
	names := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		names = append(names, typ.Field(i).Name)
	}
	return strings.Join(names, " ")
}

// subjectLine is how `internal/recovery/message.go` declares a subject.
var subjectLine = regexp.MustCompile(`Subject:\s*"([^"]+)"`)

// subjectsInRecoverySource reads the subjects `internal/recovery` renders, from its
// source rather than from a copy.
//
// IT READS THE FILE BECAUSE THE CONSTANTS ARE UNEXPORTED, and un-exporting them is
// a decision `internal/recovery` makes deliberately: a delivery adapter must not be
// able to switch on a message kind and become a second place that knows what a
// message is. The cost of that decision is that this check has to read prose, and
// it is worth it — the alternative is an exported enum that exists only so a test
// can see it.
func subjectsInRecoverySource(t *testing.T) map[string]struct{} {
	t.Helper()
	path := filepath.Join("..", "recovery", "message.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	found := map[string]struct{}{}
	for _, match := range subjectLine.FindAllStringSubmatch(string(raw), -1) {
		found[match[1]] = struct{}{}
	}
	if len(found) == 0 {
		t.Fatalf("no subjects found in %s; the pattern this test reads has drifted "+
			"from the file and the check is now agreeing with nothing", path)
	}
	return found
}
