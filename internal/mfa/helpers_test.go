package mfa

import (
	"testing"

	"github.com/cafaye/identity/internal/platform/id"
)

// mustUUID is a test-only parse that fails the test rather than returning a zero
// id, so a typo in a fixture cannot become a row that no query can find.
func mustUUID(t *testing.T, raw string) id.UUID {
	t.Helper()
	parsed, err := id.Parse(raw)
	if err != nil {
		t.Fatalf("parsing the fixture id %q: %v", raw, err)
	}
	return parsed
}
