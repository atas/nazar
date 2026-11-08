//go:build !race

package config

// raceSlowdown scales time budgets in tests (see race_on_test.go).
const raceSlowdown = 1
