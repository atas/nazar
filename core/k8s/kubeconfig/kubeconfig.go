// Package kubeconfig is what `nazar k8s ca create` and `nazar k8s forget`
// do to kubeconfigs (k8s design): find the set,
// read the public facts of a context and its cluster (never a user entry
// or its credential), and add or remove exactly nazar's three entries for
// a context (cluster nazar-<context>, user nazar-<context>, context
// <context>) as lines of text, so every other byte of the file stays as it
// was; the file is replaced atomically with one backup. It runs in the
// CLI, as the user; nazar-agent never reads a kubeconfig. Every kubeconfig
// is attacker-writable: nothing read here is trusted, and nothing printed
// from it is raw.
package kubeconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	yaml "go.yaml.in/yaml/v3"

	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/k8s/cluster"
)

// maxFile bounds a kubeconfig (and a file it names) nazar reads.
const maxFile = 4 << 20

// Paths is the kubeconfig set as kubectl finds it: $KUBECONFIG split on
// the list separator (empty elements skipped; no ~ expansion, as client-go
// does none; a relative one is made absolute against the working
// directory, as kubectl reads it), else ~/.kube/config.
func Paths(getenv func(string) string, home string) []string {
	v := getenv("KUBECONFIG")
	if v == "" {
		return []string{filepath.Join(home, ".kube", "config")}
	}
	var out []string
	for _, p := range filepath.SplitList(v) {
		if p == "" {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		out = append(out, p)
	}
	return out
}

// File is one kubeconfig of the set, parsed.
type File struct {
	Path string
	Raw  []byte
	doc  *yaml.Node // the document's top-level mapping
}

// Set is the kubeconfig set, in order: the first definition of a name wins
// (client-go's rule). Files are never merged on disk.
type Set struct {
	Files []*File
	paths []string // every path of the set, existing or not
}

// Load reads the files of paths; a file that does not exist is skipped, as
// kubectl skips it. A file nazar could not edit faithfully is refused: a
// second YAML document, anchors, aliases and merge keys (an entry could
// then be other than its text reads).
func Load(paths []string) (*Set, error) {
	s := &Set{paths: append([]string(nil), paths...)}
	for _, p := range paths {
		raw, err := readFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		doc, err := parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", cluster.Display(p), err)
		}
		s.Files = append(s.Files, &File{Path: p, Raw: raw, doc: doc})
	}
	return s, nil
}

// parse decodes exactly one YAML document whose top level is a mapping (nil
// for an empty file) and refuses anchors, aliases and merge keys.
func parse(raw []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("not a kubeconfig: %v", err)
	}
	var more yaml.Node
	if err := dec.Decode(&more); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one YAML document: nazar edits only single-document kubeconfigs")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("not a kubeconfig")
	}
	var plain func(n *yaml.Node) bool
	plain = func(n *yaml.Node) bool {
		if n.Kind == yaml.AliasNode || n.Anchor != "" || n.Tag == "!!merge" {
			return false
		}
		for _, c := range n.Content {
			if !plain(c) {
				return false
			}
		}
		return true
	}
	if !plain(&doc) {
		return nil, errors.New("anchors, aliases and merge keys (&, *, <<) are not supported: write the values out")
	}
	// A key given twice reads one way here and another in kubectl (the
	// last one wins there): refused, so what nazar reads is what kubectl
	// reads.
	var dup func(n *yaml.Node) bool
	dup = func(n *yaml.Node) bool {
		if n.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for i := 0; i+1 < len(n.Content); i += 2 {
				if k := n.Content[i].Value; seen[k] {
					return true
				} else {
					seen[k] = true
				}
			}
		}
		for _, c := range n.Content {
			if dup(c) {
				return true
			}
		}
		return false
	}
	if dup(&doc) {
		return nil, errors.New("a key is given twice in one mapping: kubectl would read the last one; remove the other")
	}
	return doc.Content[0], nil
}

// readFile reads a regular file of at most maxFile bytes: a FIFO or a
// device (/dev/tty) is refused before it is opened, so it can neither hang
// the CLI nor take what is typed at its questions.
func readFile(p string) ([]byte, error) {
	if fi, err := os.Stat(p); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", cluster.Display(p))
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var b bytes.Buffer
	n, err := b.ReadFrom(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if n > maxFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", cluster.Display(p), maxFile)
	}
	return b.Bytes(), nil
}

// named is one entry of a kubeconfig list (clusters, users, contexts).
type named struct {
	file *File
	item *yaml.Node // the list item: name: and the cluster:, user: or context: mapping
	body *yaml.Node // the cluster:, user: or context: mapping
}

// find returns the first entry called name in list of the set's files.
func (s *Set) find(list, field, name string) (named, bool) {
	for _, f := range s.Files {
		for _, it := range items(f, list) {
			if scalar(it, "name") == name {
				return named{file: f, item: it, body: mapping(it, field)}, true
			}
		}
	}
	return named{}, false
}

// findAll returns every entry called name in list, in every file.
func (s *Set) findAll(list, field, name string) []named {
	var out []named
	for _, f := range s.Files {
		for _, it := range items(f, list) {
			if scalar(it, "name") == name {
				out = append(out, named{file: f, item: it, body: mapping(it, field)})
			}
		}
	}
	return out
}

func items(f *File, list string) []*yaml.Node {
	if f.doc == nil {
		return nil
	}
	n := get(f.doc, list)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

// get is the value of key in mapping m, or nil.
func get(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalar(m *yaml.Node, key string) string {
	n := get(m, key)
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func mapping(m *yaml.Node, key string) *yaml.Node {
	n := get(m, key)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	return n
}

func has(m *yaml.Node, key string) bool { return get(m, key) != nil }

// keysAre reports whether mapping m has exactly the keys in want (each
// once), with optional ones allowed.
func keysAre(m *yaml.Node, want []string, optional ...string) bool {
	if m == nil || m.Kind != yaml.MappingNode {
		return false
	}
	seen := map[string]bool{}
	allowed := map[string]bool{}
	for _, k := range append(append([]string(nil), want...), optional...) {
		allowed[k] = true
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind != yaml.ScalarNode || !allowed[k.Value] || seen[k.Value] {
			return false
		}
		seen[k.Value] = true
	}
	for _, k := range want {
		if !seen[k] {
			return false
		}
	}
	return true
}

// runsNazar reports whether an exec mapping runs `… k8s credential
// <context>`, whatever its command.
func runsNazar(ex *yaml.Node, context string) bool {
	args := get(ex, "args")
	if args == nil || args.Kind != yaml.SequenceNode || len(args.Content) != 3 {
		return false
	}
	return args.Content[0].Value == "k8s" && args.Content[1].Value == "credential" && args.Content[2].Value == context
}

// exactEntry reports whether user mapping u is exactly the exec entry nazar
// writes for context (an absolute command, v1, the cluster info, never
// interactive, no env:, no credential beside it), and returns its command.
func exactEntry(u *yaml.Node, context string) (string, bool) {
	if !keysAre(u, []string{"exec"}) {
		return "", false
	}
	ex := mapping(u, "exec")
	if ex == nil || !runsNazar(ex, context) {
		return "", false
	}
	if !keysAre(ex, []string{"apiVersion", "command", "args", "provideClusterInfo", "interactiveMode"}, "installHint") {
		return "", false
	}
	cmd := scalar(ex, "command")
	if scalar(ex, "apiVersion") != k8s.ExecAPIVersion || scalar(ex, "provideClusterInfo") != "true" || scalar(ex, "interactiveMode") != "Never" ||
		!filepath.IsAbs(cmd) || filepath.Clean(cmd) != cmd {
		return "", false
	}
	return cmd, true
}
