package kubeconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/k8s/cluster"
)

// Entries are the three kubeconfig entries nazar adds for a context
// (k8s design): cluster nazar-<context> (the server and its
// CA), user nazar-<context> (nazar's exec plugin, nothing else) and
// context <context> naming the two. Existing entries are never changed.
type Entries struct {
	Context       string
	Server        string // normalised (cluster.NormalizeServer)
	CAPEM         []byte
	TLSServerName string
	ProxyURL      string
	Command       string // the nazar CLI, a clean absolute path
}

// EntryName is the name of nazar's cluster and user entries for context.
func EntryName(context string) string { return "nazar-" + context }

// ErrSetUp: the set already holds exactly these entries.
var ErrSetUp = errors.New("kubeconfig: nazar's entries are there already")

// Change is one kubeconfig file to write.
type Change struct {
	Path     string
	New      bool   // the file does not exist yet
	Original []byte // what Data was made from
	Data     []byte
	Removed  []string // Remove: the entries removed, as "context hydra"
}

func (e Entries) check() error {
	if !config.ValidK8sContextName(e.Context) {
		return fmt.Errorf("invalid context name %s", cluster.Display(e.Context))
	}
	if norm, err := cluster.NormalizeServer(e.Server); err != nil || norm != e.Server {
		return fmt.Errorf("invalid server %s", cluster.Display(e.Server))
	}
	if _, err := cluster.CAHash(e.CAPEM); err != nil {
		return err
	}
	if !filepath.IsAbs(e.Command) || filepath.Clean(e.Command) != e.Command {
		return fmt.Errorf("the nazar path %s is not a clean absolute path", cluster.Display(e.Command))
	}
	return nil
}

// quote renders s as a YAML double-quoted scalar (a JSON string is one):
// a name like "true" or "123" stays a string and nothing in s can start
// another key.
func quote(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

// itemText renders one list item, its dash at column indent.
func itemText(indent int, lines ...string) string {
	pad := strings.Repeat(" ", indent)
	var b strings.Builder
	for i, l := range lines {
		if i == 0 {
			b.WriteString(pad + "- " + l + "\n")
		} else {
			b.WriteString(pad + "  " + l + "\n")
		}
	}
	return b.String()
}

// items are the three entries' lines, by list.
func (e Entries) items() map[string][]string {
	n := EntryName(e.Context)
	cl := []string{"name: " + quote(n), "cluster:",
		"  server: " + quote(e.Server),
		"  certificate-authority-data: " + quote(base64.StdEncoding.EncodeToString(e.CAPEM))}
	if e.TLSServerName != "" {
		cl = append(cl, "  tls-server-name: "+quote(e.TLSServerName))
	}
	if e.ProxyURL != "" {
		cl = append(cl, "  proxy-url: "+quote(e.ProxyURL))
	}
	return map[string][]string{
		"clusters": cl,
		"users": {"name: " + quote(n), "user:", "  exec:",
			"    apiVersion: " + quote(k8s.ExecAPIVersion),
			"    command: " + quote(e.Command),
			"    args:", "    - \"k8s\"", "    - \"credential\"", "    - " + quote(e.Context),
			"    provideClusterInfo: true",
			"    interactiveMode: \"Never\"",
			"    installHint: " + quote("nazar is not installed at "+e.Command+"; reinstall nazar there, or point this entry's command at the nazar you have")},
		"contexts": {"name: " + quote(e.Context), "context:", "  cluster: " + quote(n), "  user: " + quote(n)},
	}
}

// lists are the three lists, in the order they are written.
var lists = []struct{ list, field string }{{"clusters", "cluster"}, {"users", "user"}, {"contexts", "context"}}

// names returns the entry name of list for context.
func names(list, context string) string {
	if list == "contexts" {
		return context
	}
	return EntryName(context)
}

// isNazars reports whether entry it of list is exactly nazar's for
// context; with e set, also with e's values (an empty e.Command accepts
// any nazar path).
func isNazars(list string, it *yaml.Node, context string, e *Entries) bool {
	switch list {
	case "clusters":
		if !keysAre(it, []string{"name", "cluster"}) {
			return false
		}
		b := mapping(it, "cluster")
		if !keysAre(b, []string{"server", "certificate-authority-data"}, "tls-server-name", "proxy-url") {
			return false
		}
		pem, err := base64.StdEncoding.DecodeString(scalar(b, "certificate-authority-data"))
		if err != nil {
			return false
		}
		if _, err := cluster.CAHash(pem); err != nil {
			return false
		}
		return e == nil || (scalar(b, "server") == e.Server && bytes.Equal(pem, e.CAPEM) &&
			scalar(b, "tls-server-name") == e.TLSServerName && scalar(b, "proxy-url") == e.ProxyURL)
	case "users":
		if !keysAre(it, []string{"name", "user"}) {
			return false
		}
		cmd, ok := exactEntry(mapping(it, "user"), context)
		return ok && (e == nil || e.Command == "" || cmd == e.Command)
	case "contexts":
		b := mapping(it, "context")
		return keysAre(it, []string{"name", "context"}) && keysAre(b, []string{"cluster", "user"}) &&
			scalar(b, "cluster") == EntryName(context) && scalar(b, "user") == EntryName(context)
	}
	return false
}

// Add returns the change that adds e's three entries to the set: to its
// first file, or a new file at the set's first path when none exists. A
// name already taken anywhere in the set is refused, unless all three are
// there, once each, exactly as nazar writes them for e: ErrSetUp, with a
// Change that names the file only. Of the users: list only the names and
// an entry of nazar's name are read, never another user's credential.
func (s *Set) Add(e Entries) (*Change, error) {
	if err := e.check(); err != nil {
		return nil, err
	}
	var taken []string
	exact, file := 0, ""
	for _, l := range lists {
		n := names(l.list, e.Context)
		found := s.findAll(l.list, l.field, n)
		if len(found) > 0 {
			taken = append(taken, l.field+" "+cluster.Display(n))
		}
		if len(found) == 1 && isNazars(l.list, found[0].item, e.Context, &e) {
			exact, file = exact+1, found[0].file.Path
		}
	}
	if exact == len(lists) {
		return &Change{Path: file}, ErrSetUp // the context entry's file
	}
	if len(taken) > 0 {
		return nil, fmt.Errorf("the kubeconfig already has %s; nazar never changes an entry it did not write: pick another context name, or remove them (kubectl config delete-context, delete-cluster, delete-user)",
			strings.Join(taken, ", "))
	}
	ch := &Change{}
	var top *yaml.Node
	switch {
	case len(s.Files) > 0:
		f := s.Files[0]
		ch.Path, ch.Original, top = f.Path, f.Raw, f.doc
	case len(s.paths) > 0:
		ch.Path, ch.New = s.paths[0], true
	default:
		return nil, errors.New("no kubeconfig path")
	}
	base := ch.Original
	if len(bytes.TrimSpace(base)) == 0 {
		// A new or empty file: what kubectl writes first.
		base, top = []byte("apiVersion: v1\nkind: Config\n"), nil
	}
	if top == nil {
		var err error
		if top, err = parse(base); err != nil || top == nil {
			return nil, errors.New("the kubeconfig can't be read again")
		}
	}
	add := e.items()
	data, err := edit(base, top, func(list string) ([]string, []*yaml.Node) { return add[list], nil })
	if err != nil {
		return nil, fmt.Errorf("%s: %v", cluster.Display(ch.Path), err)
	}
	ch.Data = data
	return ch, nil
}

// IsNazarContext reports whether the set's one context called name is
// exactly the context entry nazar writes for it.
func (s *Set) IsNazarContext(name string) bool {
	found := s.findAll("contexts", "context", name)
	return len(found) == 1 && isNazars("contexts", found[0].item, name, nil)
}

// Remove returns the change that removes nazar's three entries for
// context (nil when the set has none of them) and the kubectl commands
// that remove by hand what nazar leaves: an entry of those names that is
// not exactly nazar's, one defined twice, or entries spread over several
// files. Nothing else is read or changed.
func (s *Set) Remove(context string) (*Change, []string, error) {
	var file *File
	byList := map[string]*yaml.Node{}
	var left []string
	byHand := func(list, n string) {
		left = append(left, "kubectl config "+map[string]string{"clusters": "delete-cluster", "users": "delete-user", "contexts": "delete-context"}[list]+" "+n)
	}
	for _, l := range lists {
		n := names(l.list, context)
		found := s.findAll(l.list, l.field, n)
		switch {
		case len(found) == 0:
		case len(found) == 1 && isNazars(l.list, found[0].item, context, nil) && (file == nil || file == found[0].file):
			file, byList[l.list] = found[0].file, found[0].item
		default:
			byHand(l.list, n)
		}
	}
	if file == nil {
		return nil, left, nil
	}
	ch := &Change{Path: file.Path, Original: file.Raw}
	data, err := edit(file.Raw, file.doc, func(list string) ([]string, []*yaml.Node) {
		if it := byList[list]; it != nil {
			return nil, []*yaml.Node{it}
		}
		return nil, nil
	})
	if err != nil {
		for _, l := range lists {
			if byList[l.list] != nil {
				byHand(l.list, names(l.list, context))
			}
		}
		sort.Strings(left)
		return nil, left, fmt.Errorf("%s: %v", cluster.Display(file.Path), err)
	}
	for _, l := range lists {
		if byList[l.list] != nil {
			ch.Removed = append(ch.Removed, l.field+" "+names(l.list, context))
		}
	}
	ch.Data = data
	return ch, left, nil
}

// splice is one edit of the file's lines: lines [at, at+del) replaced by
// text.
type splice struct {
	at, del int
	text    string
}

// edit adds the item (lines, its dash put where the list's items have
// theirs) to, or removes the given items from, each of the three lists of
// the document raw (whose top mapping is top), as lines of text: every
// other line stays byte for byte. The result is parsed again and must be
// the document with exactly those items added or removed, or nothing is
// returned.
func edit(raw []byte, top *yaml.Node, what func(list string) ([]string, []*yaml.Node)) ([]byte, error) {
	if top.Style&yaml.FlowStyle != 0 {
		return nil, errors.New("the kubeconfig is written in flow style ({…}); nazar edits block style only")
	}
	lines := splitLines(raw)
	if n := len(lines); n > 0 && !bytes.HasSuffix(lines[n-1], []byte("\n")) {
		// An item may go after the last line (from a security review).
		lines[n-1] = append(append([]byte(nil), lines[n-1]...), '\n')
	}
	var splices []splice
	var tail strings.Builder // lists the file has no key for, added at its end
	for _, l := range lists {
		add, remove := what(l.list)
		if add == nil && remove == nil {
			continue
		}
		key, v := keyOf(top, l.list)
		switch {
		case remove != nil:
			if v == nil || v.Kind != yaml.SequenceNode || v.Style&yaml.FlowStyle != 0 {
				return nil, fmt.Errorf("its %s: list is not one nazar can edit", l.list)
			}
			dash := v.Column - 1
			for _, it := range remove {
				start := it.Line - 1
				if start < 0 || start >= len(lines) || !isDashLine(lines[start], dash) {
					return nil, fmt.Errorf("its %s: list is laid out in a way nazar can't edit", l.list)
				}
				splices = append(splices, splice{at: start, del: blockEnd(lines, maxLine(it)-1, dash) - start})
			}
		case v == nil:
			tail.WriteString(l.list + ":\n" + itemText(0, add...))
		case isNull(v) || (v.Kind == yaml.SequenceNode && v.Style&yaml.FlowStyle != 0 && len(v.Content) == 0):
			// `clusters: null`, `clusters:` or `clusters: []` on the key's own line.
			if key.Column != 1 || v.Line != key.Line {
				return nil, fmt.Errorf("its %s: list is laid out in a way nazar can't edit", l.list)
			}
			splices = append(splices, splice{at: key.Line - 1, del: 1, text: l.list + ":\n" + itemText(0, add...)})
		case v.Kind == yaml.SequenceNode && v.Style&yaml.FlowStyle == 0 && len(v.Content) > 0:
			dash := v.Column - 1
			last := v.Content[len(v.Content)-1]
			splices = append(splices, splice{at: blockEnd(lines, maxLine(last)-1, dash), text: itemText(dash, add...)})
		default:
			return nil, fmt.Errorf("its %s: is not a block list nazar can add to", l.list)
		}
	}
	// Bottom up, so each splice's line numbers still hold; at one line the
	// replacement first, then what goes before it.
	sort.SliceStable(splices, func(i, j int) bool {
		if splices[i].at != splices[j].at {
			return splices[i].at > splices[j].at
		}
		return splices[i].del > splices[j].del
	})
	for _, sp := range splices {
		repl := splitLines([]byte(sp.text))
		lines = slices.Concat(lines[:sp.at], repl, lines[sp.at+sp.del:])
	}
	if t := tail.String(); t != "" {
		lines = append(lines, splitLines([]byte(t))...)
	}
	out := bytes.Join(lines, nil)
	if err := verify(raw, out, what); err != nil {
		return nil, err
	}
	return out, nil
}

// verify checks that out, parsed, is raw with exactly the edit: each list
// gains its added item at its end, or loses exactly its removed items, and
// nothing else differs.
func verify(raw, out []byte, what func(list string) ([]string, []*yaml.Node)) error {
	failed := errors.New("the edited kubeconfig does not read back as expected; nothing was written")
	if _, err := parse(out); err != nil {
		return failed
	}
	var before, after map[string]any
	if err := yaml.Unmarshal(raw, &before); err != nil {
		return failed
	}
	if err := yaml.Unmarshal(out, &after); err != nil || after == nil {
		return failed
	}
	if before == nil {
		before = map[string]any{}
	}
	for _, l := range lists {
		add, remove := what(l.list)
		old, _ := before[l.list].([]any)
		switch {
		case add != nil:
			var item []any
			if err := yaml.Unmarshal([]byte(itemText(0, add...)), &item); err != nil || len(item) != 1 {
				return failed
			}
			before[l.list] = append(slices.Clone(old), item[0])
		case remove != nil:
			keep := []any{}
			for _, it := range old {
				m, _ := it.(map[string]any)
				gone := false
				for _, r := range remove {
					if m != nil && m["name"] == scalar(r, "name") {
						gone = true
					}
				}
				if !gone {
					keep = append(keep, it)
				}
			}
			if len(keep) != len(old)-len(remove) {
				return failed
			}
			if len(keep) == 0 {
				before[l.list] = nil
			} else {
				before[l.list] = keep
			}
			if v, ok := after[l.list]; ok && v != nil {
				if s, ok := v.([]any); ok && len(s) == 0 {
					after[l.list] = nil
				}
			}
		}
	}
	if !reflect.DeepEqual(before, after) {
		return failed
	}
	return nil
}

func keyOf(top *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == key {
			return top.Content[i], top.Content[i+1]
		}
	}
	return nil, nil
}

func isNull(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.Tag == "!!null" }

// splitLines splits b after each newline; the last line may have none.
func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			out = append(out, b)
			break
		}
		out = append(out, b[:i+1])
		b = b[i+1:]
	}
	return out
}

func indent(l []byte) (int, bool) {
	n := 0
	for n < len(l) && l[n] == ' ' {
		n++
	}
	rest := bytes.TrimRight(l[n:], " \t\r\n")
	return n, len(rest) == 0
}

// isDashLine reports whether l is a list item's first line, its dash at
// column dash.
func isDashLine(l []byte, dash int) bool {
	n, blank := indent(l)
	return !blank && n == dash && l[n] == '-'
}

// blockEnd is the index of the first line after the item whose last node
// starts on line last (0-based), its dash at column dash: the lines
// indented past the dash belong to it (a block scalar's text, comments),
// blank lines too when more of it follows.
func blockEnd(lines [][]byte, last, dash int) int {
	j := last + 1
	for j < len(lines) {
		n, blank := indent(lines[j])
		if !blank && n > dash {
			j++
			continue
		}
		if blank {
			k := j
			for k < len(lines) {
				if _, b := indent(lines[k]); !b {
					break
				}
				k++
			}
			if k < len(lines) {
				if n, _ := indent(lines[k]); n > dash {
					j = k
					continue
				}
			}
		}
		break
	}
	return j
}

// maxLine is the last line any node under n starts on.
func maxLine(n *yaml.Node) int {
	m := n.Line
	for _, c := range n.Content {
		if l := maxLine(c); l > m {
			m = l
		}
	}
	return m
}
