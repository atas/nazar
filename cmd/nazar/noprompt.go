package main

import "strings"

// The help is written once, for macOS, which has a hidden prompt. A build
// with none (app.noHiddenPrompt) takes these words instead, so that its help
// does not promise what `secret add` refuses at a terminal (errNoHiddenPrompt;
// spec, "Weaker than macOS" 10). The macOS text is never rewritten, so it stays
// byte for byte as it was.
var noPromptWords = strings.NewReplacer(
	"Store a secret, read from stdin or a hidden prompt (Touch ID once)",
	"Store a secret, read from stdin (Touch ID once)",

	"The value is read from stdin, or typed at a hidden prompt; it is never an argument (an argument\n"+
		"is visible in ps). The prompt takes one line of at most about 1000 bytes; pipe anything longer\n"+
		"or with several lines. ",
	"The value is read from stdin; it is never an argument (an argument is visible in ps). This\n"+
		"system has no hidden prompt: at a terminal the command refuses and reads nothing, because what\n"+
		"you type would show. ",

	"\n  nazar secret add NOTES                  # typed at a hidden prompt", "",

	"(the value on stdin, or typed at a hidden prompt; never an argument)",
	"(the value on stdin; never an argument)",
)

// noHiddenPromptOn says whether goos has no hidden prompt: only macOS has one
// (tty_darwin.go).
func noHiddenPromptOn(goos string) bool { return goos != "darwin" }

// promptWords is a help text as this build can keep its word: unchanged on
// macOS.
func (a *app) promptWords(s string) string {
	if !a.noHiddenPrompt {
		return s
	}
	return noPromptWords.Replace(s)
}
