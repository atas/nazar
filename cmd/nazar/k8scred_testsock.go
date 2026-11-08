//go:build nazartest

package main

// The nazartest build only (k8s design 1.1): the integration tests point
// k8s credential and aws credential at nazar-testd through
// NAZAR_TEST_CONTROL_SOCKET, with the
// same-user check (the test daemon is not the signed agent). HOME and
// NAZAR_CONTROL_SOCKET stay ignored in this build too. A tagged binary
// gains nothing against a real nazar-agent: it is not the genuine CLI, so
// check 0 refuses it.
func init() {
	testCredentialSocket = func(getenv func(string) string) (string, bool) {
		s := getenv("NAZAR_TEST_CONTROL_SOCKET")
		return s, s != ""
	}
}
