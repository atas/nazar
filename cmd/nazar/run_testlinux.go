//go:build nazartest

package main

// The nazartest build only: core/daemon's end-to-end tests drive nazar run on
// Linux with the real CLI, through NAZAR_TEST_RUN_ON_LINUX. The late-env
// protocol keeps being proved there although the shipped Linux CLI refuses
// the command. A tagged binary gains nothing against a real nazar-agent: it
// is not the genuine CLI.
func init() {
	testRunOnLinux = func(getenv func(string) string) bool {
		return getenv("NAZAR_TEST_RUN_ON_LINUX") == "1"
	}
}
