package main

import "time"

// testClock replaces the clock in the e2e tests' build (tag e2eclock), so
// tokens can expire during a test. Nil in every other build.
var testClock func() time.Time

func clockNow() time.Time {
	if testClock != nil {
		return testClock()
	}
	return time.Now()
}
