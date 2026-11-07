//go:build e2eclock

package main

import (
	"os"
	"strings"
	"time"

	"github.com/minituff/keydrop/internal/client"
)

// The e2e tests' build only: the clock runs ahead by the duration in the
// file KEYDROP_E2E_CLOCK_FILE names (e.g. "744h"), read on every call so a
// test can move time while the server runs. Release builds don't have it.
func init() {
	path := os.Getenv("KEYDROP_E2E_CLOCK_FILE")
	if path == "" {
		return
	}
	testClock = func() time.Time {
		b, _ := os.ReadFile(path)
		d, _ := time.ParseDuration(strings.TrimSpace(string(b)))
		return time.Now().Add(d)
	}
	client.SetClock(testClock)
}
