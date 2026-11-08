package config

import (
	"fmt"
	"strings"
)

type Severity string

const (
	SevError   Severity = "error"
	SevWarning Severity = "warning"
)

// Problem is one validation finding. Path is a dotted location such as
// "ssh_agent.keys.github.rules[1].gate"; Line is 0 when unknown.
type Problem struct {
	Severity Severity
	Path     string
	Line     int
	Message  string
}

func (p Problem) String() string {
	loc := p.Path
	if p.Line > 0 {
		loc = fmt.Sprintf("line %d: %s", p.Line, p.Path)
	}
	if loc == "" {
		return fmt.Sprintf("%s: %s", p.Severity, p.Message)
	}
	return fmt.Sprintf("%s: %s: %s", p.Severity, loc, p.Message)
}

// Problems is what Parse reports: errors (the file is refused) and warnings
// (the file is accepted, but config check shows them).
type Problems []Problem

func (ps Problems) HasErrors() bool {
	for _, p := range ps {
		if p.Severity == SevError {
			return true
		}
	}
	return false
}

// Error renders every problem, one per line, errors and warnings alike.
func (ps Problems) Error() string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, "\n")
}
