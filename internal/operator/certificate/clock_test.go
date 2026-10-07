package certificate

import "k8s.io/utils/clock"

// aliases so the fixedClock in renewal_test.go satisfies clock.Clock
// without importing its interfaces by their long names.
type (
	clockTimer  = clock.Timer
	clockTicker = clock.Ticker
)
