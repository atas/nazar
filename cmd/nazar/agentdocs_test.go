package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.yaml.in/yaml/v3"
)

// The agent docs (skills/nazar, the Setup section of docs/CLI.md,
// llms.txt) are what an AI agent runs from: a command or flag they name
// that the CLI doesn't have sends the agent into usage errors (exit 2) and
// guesses. Every nazar command line in their code spans and code blocks is
// checked here against the command tree help and completion use
// (a.commands), and the skill's packaging (frontmatter, the Claude Code
// marketplace and plugin manifests, llms.txt's links) against the files
// they point at.

const repoRoot = "../.."

var (
	skillDir      = filepath.Join(repoRoot, "skills", "nazar")
	skillPath     = filepath.Join(skillDir, "SKILL.md")
	llmsPath      = filepath.Join(repoRoot, "llms.txt")
	cliGuidePath  = filepath.Join(repoRoot, "docs", "CLI.md")
	repoBlobURL   = "https://github.com/atas/nazar/blob/main/"
	skillNameRule = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
)

// Agent Skills specification (https://agentskills.io/specification), which
// Codex follows; Claude Code's own cap is higher (1,536 characters for
// description and when_to_use together).
const (
	skillNameMax        = 64
	skillDescriptionMax = 1024
)

type docCommand struct {
	where string   // file:line
	args  []string // the tokens after nazar
}

// codeTexts returns the code of markdown text: each line of a fenced
// block, and each inline code span outside one, with its line number.
func codeTexts(text string) (lines []string, nums []int) {
	inFence := false
	span := regexp.MustCompile("`([^`]+)`")
	for i, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			lines, nums = append(lines, l), append(nums, i+1)
			continue
		}
		for _, m := range span.FindAllStringSubmatch(l, -1) {
			lines, nums = append(lines, m[1]), append(nums, i+1)
		}
	}
	return lines, nums
}

// isNazar reports whether a shell word runs the nazar CLI: nazar on PATH,
// $(nazar …) and <(nazar …), or the CLI inside the bundle or a bin folder.
func isNazar(word string) bool {
	for _, p := range []string{"$(", "<(", "\"$("} {
		word = strings.TrimPrefix(word, p)
	}
	return word == "nazar" || strings.HasSuffix(word, "/MacOS/nazar") || strings.HasSuffix(word, "/bin/nazar")
}

// nazarCommands finds every nazar command line in text's code. A line
// ends at a shell operator, a comment, or a closing parenthesis; a `|`
// inside [brackets] is the usage text's "or", not a pipe.
func nazarCommands(name, text string) []docCommand {
	var out []docCommand
	lines, nums := codeTexts(text)
	for k, l := range lines {
		words := shellWords(l)
		for i := 0; i < len(words); i++ {
			if !isNazar(words[i]) {
				continue
			}
			var args []string
			depth := 0
		line:
			for _, w := range words[i+1:] {
				switch {
				case strings.HasPrefix(w, "#"):
					break line
				// `\|` is a pipe written inside a Markdown table cell.
				case depth == 0 && slices.Contains([]string{"|", `\|`, "||", "&&", ";", ">", "<", "2>&1"}, w):
					break line
				}
				depth += strings.Count(w, "[") - strings.Count(w, "]")
				if strings.HasSuffix(w, ")") && !strings.Contains(w, "(") {
					args = append(args, strings.TrimRight(w, ")"))
					break line
				}
				w = strings.TrimSuffix(w, ";")
				args = append(args, w)
			}
			out = append(out, docCommand{where: fmt.Sprintf("%s:%d", name, nums[k]), args: args})
			i += len(args)
		}
	}
	return out
}

// shellWords splits a line on blanks, keeping a quoted word ("$(command
// -v kubectl)") whole.
func shellWords(line string) []string {
	var words []string
	f := strings.Fields(line)
	for i := 0; i < len(f); i++ {
		w := f[i]
		if q := w[:1]; (q == `"` || q == "'") && (len(w) == 1 || !strings.HasSuffix(w, q)) {
			for i+1 < len(f) && !strings.HasSuffix(w, q) {
				i++
				w += " " + f[i]
			}
		}
		words = append(words, w)
	}
	return words
}

// placeholder reports whether a word stands for a value the reader fills
// in: <name>, …, H, M[,M], NAME, $VAR or "$(…)".
func placeholder(w string) bool {
	if strings.ContainsAny(w, "<>…$") || strings.Contains(w, "...") {
		return true
	}
	return strings.Trim(w, "[],") != "" && strings.Trim(w, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_[],") == ""
}

// fixedValueFlags are the flags whose values the tree completes from a
// fixed list; a value the docs give them must be one of those.
var fixedValueFlags = []string{"gate", "scope", "decision"}

// checkCommand walks args down the tree as a.run takes them: global flags
// anywhere, subcommand names first, then the command's own flags (each
// with its value, if it takes one) and positionals.
func checkCommand(root *cobra.Command, args []string) error {
	c := root
	pathDone := false
	for i := 0; i < len(args); i++ {
		w := strings.Trim(args[i], "[]")
		switch {
		case w == "" || w == "|":
			continue
		case w == "--":
			if c.CommandPath() != "nazar run" {
				return fmt.Errorf("`--` after %q, which takes no command line", c.CommandPath())
			}
			return nil // the program's command line
		case strings.HasPrefix(w, "-") && len(w) > 1:
			name, value, hasValue := strings.Cut(strings.TrimLeft(w, "-"), "=")
			var f *pflag.Flag
			if strings.HasPrefix(w, "--") {
				f = c.Flags().Lookup(name)
				if f == nil {
					f = c.InheritedFlags().Lookup(name)
				}
			} else if len(name) == 1 {
				f = c.Flags().ShorthandLookup(name)
				if f == nil {
					f = c.InheritedFlags().ShorthandLookup(name)
				}
			}
			if f == nil || f.Hidden { // a hidden flag is there to be refused with a reason
				return fmt.Errorf("%q has no flag %s", c.CommandPath(), w)
			}
			if root.PersistentFlags().Lookup(f.Name) == nil {
				pathDone = true // a global flag may come before the command
			}
			if f.NoOptDefVal != "" {
				continue // a bool
			}
			if !hasValue {
				if i+1 >= len(args) {
					return fmt.Errorf("%q: %s takes a value", c.CommandPath(), w)
				}
				i++
				value = args[i]
			}
			if err := checkValue(c, f.Name, value); err != nil {
				return err
			}
		default:
			if !pathDone {
				if s := subcommand(c, w); s != nil {
					c = s
					continue
				}
			}
			if !c.Runnable() && !placeholder(w) {
				return fmt.Errorf("%q has no command %q", c.CommandPath(), w)
			}
			pathDone = true
		}
	}
	return nil
}

func subcommand(c *cobra.Command, name string) *cobra.Command {
	for _, s := range c.Commands() {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

// checkValue checks a fixed-value flag's value (each of a|b|c) against
// what completion offers for it.
func checkValue(c *cobra.Command, flag, value string) error {
	if !slices.Contains(fixedValueFlags, flag) || placeholder(value) {
		return nil
	}
	fn, ok := c.GetFlagCompletionFunc(flag)
	if !ok {
		return fmt.Errorf("%q --%s: no completion registered", c.CommandPath(), flag)
	}
	comps, _ := fn(c, nil, "")
	var allowed []string
	for _, v := range comps {
		allowed = append(allowed, strings.SplitN(v, "\t", 2)[0])
	}
	for _, v := range strings.Split(strings.Trim(value, "[]"), "|") {
		if !slices.Contains(allowed, v) {
			return fmt.Errorf("%q --%s %s: not one of %v", c.CommandPath(), flag, v, allowed)
		}
	}
	return nil
}

// section returns the text of a markdown file from heading to the next
// heading of the same level, after one empty line for each line before it
// (so line numbers are the file's).
func section(t *testing.T, path, heading string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	start := strings.Index(text, "\n"+heading+"\n")
	if start < 0 {
		t.Fatalf("%s has no %q section", path, heading)
	}
	before := strings.Count(text[:start+1], "\n")
	text = text[start+1:]
	level := heading[:strings.Index(heading, " ")+1]
	if end := strings.Index(text[len(heading):], "\n"+level); end >= 0 {
		text = text[:len(heading)+end]
	}
	return strings.Repeat("\n", before) + text
}

// agentDocs returns the files the agent docs consist of, name to text.
func agentDocs(t *testing.T) map[string]string {
	t.Helper()
	docs := map[string]string{"docs/CLI.md": section(t, cliGuidePath, "## Setup")}
	err := filepath.WalkDir(skillDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".md" {
			return err
		}
		b, err := os.ReadFile(p)
		rel, _ := filepath.Rel(repoRoot, p)
		docs[rel] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(llmsPath)
	if err != nil {
		t.Fatal(err)
	}
	docs["llms.txt"] = string(b)
	return docs
}

func TestAgentDocsCommandsExist(t *testing.T) {
	h := newHarness(t)
	root := h.a.commands(true)
	n := 0
	for name, text := range agentDocs(t) {
		for _, dc := range nazarCommands(name, text) {
			n++
			if err := checkCommand(root, dc.args); err != nil {
				t.Errorf("%s: `nazar %s`: %v", dc.where, strings.Join(dc.args, " "), err)
			}
		}
	}
	if n < 40 {
		t.Fatalf("found only %d nazar command lines in the agent docs; is the parser broken?", n)
	}
}

// The checker itself: it has to catch the mistakes it exists for.
func TestAgentDocsCheckerCatchesMistakes(t *testing.T) {
	h := newHarness(t)
	root := h.a.commands(true)
	text := "```bash\n" +
		"nazar ssh-key create github --always-ask   # ok\n" +
		"printf '%s' \"$X\" | nazar secret add NAME --only-when-unlocked\n" +
		"source <(nazar completion bash)\n" +
		"nazar --json ssh-key rule add github --apps any --gate dialog --scope session --at 1\n" +
		"```\n" +
		"`nazar ssh-key set <key> --gate login|dialog|block [--scope S] [--expire D | --no-expire]`, " +
		"`nazar run --secret NAME -- npx -y --whatever`, `nazar <command> --help`, `nazar log --decision denied|error`, " +
		"`nazar trust --app com.googlecode.iterm2`\n"
	good := nazarCommands("good", text)
	if len(good) != 9 {
		t.Fatalf("found %d commands, want 9: %+v", len(good), good)
	}
	for _, dc := range good {
		if err := checkCommand(root, dc.args); err != nil {
			t.Errorf("%s `nazar %s`: %v", dc.where, strings.Join(dc.args, " "), err)
		}
	}
	for _, bad := range []string{
		"`nazar ssh-key create github --always-asks`",
		"`nazar ssh-keys list`",
		"`nazar secret ad NAME`",
		"`nazar k8s rule add hydra --apps any --to ssh --gate login`",
		"`nazar ssh-key rule add github --apps any --gate always`",
		"`nazar ssh-key set github --gate none`",
		"`nazar ssh-key rule add github --apps any --gate login --no-expire`",
		"`nazar trust --app com.googlecode.iterm2 --force`",
		"`nazar log --since 1h --decision refused`",
		"`nazar status -- x`",
		"```\nnazar config apply --hash H --yes --force\n```",
	} {
		cmds := nazarCommands("bad", bad)
		if len(cmds) != 1 {
			t.Fatalf("%q: %d commands", bad, len(cmds))
		}
		if err := checkCommand(root, cmds[0].args); err == nil {
			t.Errorf("%q passed the check", bad)
		}
	}
}

// skillFrontmatter parses SKILL.md's YAML frontmatter.
func skillFrontmatter(t *testing.T) (name, description string) {
	t.Helper()
	b, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.HasPrefix(text, "---\n") {
		t.Fatal("SKILL.md does not start with a --- frontmatter line")
	}
	end := strings.Index(text[4:], "\n---\n")
	if end < 0 {
		t.Fatal("SKILL.md's frontmatter has no closing ---")
	}
	var fm struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
	if err := yaml.Unmarshal([]byte(text[4:4+end]), &fm); err != nil {
		t.Fatalf("SKILL.md frontmatter: %v", err)
	}
	return fm.Name, fm.Description
}

func TestSkillFrontmatter(t *testing.T) {
	name, desc := skillFrontmatter(t)
	if name != filepath.Base(skillDir) || len(name) > skillNameMax || !skillNameRule.MatchString(name) {
		t.Errorf("skill name %q: want the folder's name, lowercase letters, digits and single hyphens, at most %d", name, skillNameMax)
	}
	if n := utf8.RuneCountInString(desc); n == 0 || n > skillDescriptionMax {
		t.Errorf("skill description is %d characters; want 1 to %d", n, skillDescriptionMax)
	}
	// What a user says when the skill should load.
	for _, w := range []string{"nazar", "SSH keys", "commit signing", "API keys", "MCP servers", "kubectl"} {
		if !strings.Contains(desc, w) {
			t.Errorf("skill description doesn't mention %q", w)
		}
	}
}

// The Claude Code marketplace lists the plugin; the plugin's skills/ is
// the repository's own, so the skill exists once.
func TestClaudePluginMarketplace(t *testing.T) {
	var mk struct {
		Name  string `json:"name"`
		Owner struct {
			Name string `json:"name"`
		} `json:"owner"`
		Plugins []struct {
			Name   string `json:"name"`
			Source any    `json:"source"`
		} `json:"plugins"`
	}
	readJSON(t, filepath.Join(repoRoot, ".claude-plugin", "marketplace.json"), &mk)
	idRule := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	if !idRule.MatchString(mk.Name) || strings.Contains(mk.Name, "..") || mk.Owner.Name == "" || len(mk.Plugins) == 0 {
		t.Fatalf("marketplace.json: name %q, owner %q, %d plugins", mk.Name, mk.Owner.Name, len(mk.Plugins))
	}
	want, err := filepath.Abs(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range mk.Plugins {
		src, ok := p.Source.(string)
		if !idRule.MatchString(p.Name) || !ok || (src != "." && !strings.HasPrefix(src, "./")) || strings.Contains(src, "..") {
			t.Errorf("marketplace plugin %q: source %v: want a ./ path inside the repository", p.Name, p.Source)
			continue
		}
		dir := filepath.Join(repoRoot, src)
		var pj struct {
			Name   string `json:"name"`
			Skills any    `json:"skills"`
		}
		manifest := filepath.Join(dir, ".claude-plugin", "plugin.json")
		if _, err := os.Stat(manifest); err == nil {
			readJSON(t, manifest, &pj)
			if pj.Name != p.Name {
				t.Errorf("plugin.json name %q, marketplace entry %q: install by one name fails", pj.Name, p.Name)
			}
		}
		skills, _ := filepath.Glob(filepath.Join(dir, "skills", "*", "SKILL.md"))
		for _, s := range skills {
			if abs, _ := filepath.Abs(s); abs == want {
				found = true
			}
		}
		if p.Name == "nazar" && !found {
			t.Errorf("plugin %q (%s) has no skills/nazar/SKILL.md: %v", p.Name, dir, skills)
		}
	}
	if !found {
		t.Error("no marketplace plugin carries skills/nazar/SKILL.md")
	}
	// One copy: no other SKILL.md for the skill anywhere in the tree.
	var copies []string
	err = filepath.WalkDir(repoRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && p != repoRoot && (strings.HasPrefix(d.Name(), ".") && d.Name() != ".claude-plugin" || d.Name() == "build") {
			return filepath.SkipDir
		}
		if d.Name() == "SKILL.md" {
			copies = append(copies, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(copies) != 1 {
		t.Errorf("SKILL.md files in the repository: %v; want only %s", copies, skillPath)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// llms.txt (https://llmstxt.org): an H1, a blockquote summary, sections of
// links; every link, there and in the skill, is a file of this repository.
func TestLLMsTxt(t *testing.T) {
	b, err := os.ReadFile(llmsPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	lines := strings.Split(text, "\n")
	if lines[0] != "# nazar" {
		t.Errorf("llms.txt starts with %q, want the H1 `# nazar`", lines[0])
	}
	if !slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, "> ") }) || !strings.Contains(text, "\n## ") {
		t.Error("llms.txt has no blockquote summary or no ## section")
	}
	linked := checkLinks(t, "llms.txt", text, false)
	for _, want := range []string{"AGENTS.md", "docs/CLI.md", "skills/nazar/SKILL.md", "docs/THREAT-MODEL.md"} {
		if !slices.Contains(linked, want) {
			t.Errorf("llms.txt doesn't link %s", want)
		}
	}
	sb, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	checkLinks(t, "SKILL.md", string(sb), true)
}

// checkLinks checks that every markdown link names a file of this
// repository, as a blob/main URL or, unless absoluteOnly, a relative path
// (the skill is installed outside the repository, so its links must be
// absolute), and returns the paths. Neither file links anywhere else.
func checkLinks(t *testing.T, name, text string, absoluteOnly bool) []string {
	t.Helper()
	var paths []string
	link := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	for _, m := range link.FindAllStringSubmatch(text, -1) {
		target, _, _ := strings.Cut(m[1], "#")
		var rel string
		switch {
		case strings.HasPrefix(target, repoBlobURL):
			rel = strings.TrimPrefix(target, repoBlobURL)
		case strings.Contains(target, "://"):
			t.Errorf("%s links %s: want %s<path>", name, m[1], repoBlobURL)
			continue
		case absoluteOnly:
			t.Errorf("%s links %s relatively: the skill is installed outside the repository, use %s<path>", name, m[1], repoBlobURL)
			continue
		default:
			rel = target
		}
		if _, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(rel))); errors.Is(err, fs.ErrNotExist) || rel == "" || strings.Contains(rel, "..") {
			t.Errorf("%s links %s: no file %s in the repository", name, m[1], rel)
			continue
		}
		paths = append(paths, rel)
	}
	return paths
}
