package platform

// The Milestone 3 seam must be written down where the Swift implementer
// will read it. These tests check the documentation exists and
// says the load-bearing things; they don't pin wording beyond key terms.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

// docs collects, per type name, the type's doc comment plus every field's
// doc and line comment, and the interface methods' comments, from
// platform.go.
func typeDocs(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "platform.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts := spec.(*ast.TypeSpec)
			var b strings.Builder
			b.WriteString(gd.Doc.Text())
			b.WriteString(ts.Doc.Text())
			var fields *ast.FieldList
			switch tt := ts.Type.(type) {
			case *ast.StructType:
				fields = tt.Fields
			case *ast.InterfaceType:
				fields = tt.Methods
			}
			if fields != nil {
				for _, f := range fields.List {
					b.WriteString(f.Doc.Text())
					b.WriteString(f.Comment.Text())
				}
			}
			out[ts.Name.Name] = b.String()
		}
	}
	return out
}

func mustMatch(t *testing.T, where, text string, patterns ...string) {
	t.Helper()
	var missing []string
	for _, p := range patterns {
		if !regexp.MustCompile(p).MatchString(text) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%s: documentation does not match %q; it reads:\n%s", where, missing, text)
	}
}

// Spec 4.7: approval refs are never reused within a process, and an unknown
// or released ref means "no approval" (ErrAuthRequired) and never crashes.
// The Swift side keeps the LAContext table, so this must be on ApprovalRef
// and on the Platform interface where M3 will read it.
func TestApprovalRefContractIsDocumented(t *testing.T) {
	d := typeDocs(t)
	for _, name := range []string{"ApprovalRef", "Platform"} {
		mustMatch(t, name, d[name],
			`(?is)never\s+(be\s+)?reused`,
			`(?is)unknown`,
			`(?is)released`,
			`(?is)no\s+approval`,
			`(?is)ErrAuthRequired`,
			`(?is)(never\s+crash|must\s+not\s+crash|never\s+panic|must\s+not\s+panic)`,
		)
	}
}

// Spike S3: the peer's ref comes from the audit token, but parents walked
// with KERN_PROC_PID (and the responsible-process lookup) give a PID only.
// ProcessRef must say what Generation is on macOS (start time, which every
// route can provide) and that Generation 0 means a PID-only ref.
func TestProcessRefGenerationIsDocumented(t *testing.T) {
	d := typeDocs(t)
	mustMatch(t, "ProcessRef", d["ProcessRef"],
		`(?is)start\s+time`,
		`(?is)pid[- ]only`,
		`(?is)(generation\s+0|zero\s+generation|generation\s+(is\s+)?zero)`,
		`(?is)audit\s+token`,
		`(?is)KERN_PROC_PID`,
	)
	mustMatch(t, "ProcessInfo.Parent", d["ProcessInfo"], `(?is)pid[- ]only`)
	mustMatch(t, "Platform (Process/ResponsibleFor)", d["Platform"], `(?is)pid[- ]only`)
}

// M11 resolved the TODO about the log sender: `nazar log` keeps only
// entries whose process image and sender image are the trusted Nazar.app
// (compared by LC_UUID, fromSender; since Milestone 5 also any earlier
// build at the installed path, fromNazar), so entries another process
// forges under dev.nazar/audit are dropped. The TODO is gone and the check
// is in place (TestLogKeepsOnlyNazarsOwnEntries and
// TestLogKeepsEveryBuildAtTheInstalledPath run it against the real log).
func TestLogSenderIsChecked(t *testing.T) {
	src, err := os.ReadFile("../../cmd/nazar/logcmd.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "TODO(M3)") {
		t.Fatal("cmd/nazar/logcmd.go still carries the TODO(M3) about the log sender")
	}
	mustMatch(t, "logcmd.go", string(src),
		`fromNazar\(e, sender\)`,
		`fromSender\(e, s\.UUID\)`,
		`Nazar\.app`,
		`(?is)(forged|forge)`,
	)
}

// The spec records the decisions that superseded earlier designs (spec 14),
// each with the terms that make it findable.
func TestSpecListsSupersededDecisions(t *testing.T) {
	b, err := os.ReadFile("../../docs/design/nazar-design.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	loc := regexp.MustCompile(`(?im)^#{2,3}\s*(\d+\.\s*)?Superseded decisions\b.*$`).FindStringIndex(doc)
	if loc == nil {
		t.Fatal("spec has no 'Superseded decisions' section")
	}
	section := doc[loc[1]:]
	if next := regexp.MustCompile(`(?m)^#{1,2}\s`).FindStringIndex(section); next != nil {
		section = section[:next[0]]
	}
	items := map[string][]string{
		"responsible process is display only":   {`(?is)responsible`, `(?is)display`, `ResponsibleFor`},
		"redaction allowlist replaced patterns": {`(?is)allowlist`, `(?is)redact`},
		"gate: none matcher rule":               {`(?is)gate:\s*none`},
		"app team pinned at config load":        {`InstalledApp`, `(?is)team`, `(?is)pin`},
		"nazar trust --app":                     {`nazar trust --app`},
		"refused bind fails closed":             {`(?is)fail[- ]closed|fails\s+closed`, `(?is)bind`},
		"duplicate session IDs":                 {`(?is)duplicate\s+session`},
	}
	for what, pats := range items {
		for _, p := range pats {
			if !regexp.MustCompile(p).MatchString(section) {
				t.Errorf("Superseded decisions: %s: missing %q", what, p)
			}
		}
	}
}
