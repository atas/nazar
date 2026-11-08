//go:build race

package config

// raceSlowdown scales time budgets in tests: the race detector makes Go
// code 5–10× slower, more so while the other packages' tests run in
// parallel.
const raceSlowdown = 4
