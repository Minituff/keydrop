package mask

import (
	"strings"
	"testing"
)

// A value stored with a trailing newline usually reaches the output without
// it, and must still be masked either way.
func TestTrailingWhitespaceVariant(t *testing.T) {
	for _, stored := range []string{"sk-fake-value-1234\n", "  sk-fake-value-1234\r\n", "sk-fake-value-1234"} {
		var m Masker
		if !m.Add("K", []byte(stored)) {
			t.Fatalf("%q not added", stored)
		}
		if out := m.String(`curl -H "Authorization: sk-fake-value-1234"`); strings.Contains(out, "sk-fake") {
			t.Fatalf("%q leaked: %s", stored, out)
		}
	}
}

// Too short once trimmed means the caller has to warn: "abc" can't be
// masked, even though "abc" plus a newline is long enough to add.
func TestAddReportsShortTrimmedValue(t *testing.T) {
	for _, stored := range []string{"abc\n", "  ab  ", "    "} {
		var m Masker
		if m.Add("K", []byte(stored)) {
			t.Fatalf("%q reported as masked", stored)
		}
	}
}
