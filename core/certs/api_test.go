package certs

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"go/ast"
	"go/doc"
	"go/importer"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// No raw signing entry point (aws design 2.3, 11.1): the package's
// exported API is pinned, the signer is made only in Create and Issue, and
// no other package hands a CA's handle to Platform.Sign.

var updateAPI = flag.Bool("update-api", false, "rewrite testdata/api.golden")

const certsPath = "github.com/atas/nazar/core/certs"

// sources parses the package's non-test files.
func sources(t *testing.T) (*token.FileSet, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, n := range names {
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	return fset, files
}

// renderAPI is every exported declaration, without doc comments or
// bodies, in go/doc's order.
func renderAPI(t *testing.T) []byte {
	fset, files := sources(t)
	pkg, err := doc.NewFromFiles(fset, files, certsPath)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	gofmt := printer.Config{Mode: printer.UseSpaces | printer.TabIndent, Tabwidth: 8}
	out := func(n ast.Node) {
		if err := gofmt.Fprint(&b, fset, n); err != nil {
			t.Fatal(err)
		}
		b.WriteString("\n\n")
	}
	values := func(vs []*doc.Value) {
		for _, v := range vs {
			out(v.Decl)
		}
	}
	funcs := func(fs []*doc.Func) {
		for _, f := range fs {
			out(f.Decl)
		}
	}
	b.WriteString("package certs // " + certsPath + "\n\n")
	values(pkg.Consts)
	values(pkg.Vars)
	funcs(pkg.Funcs)
	for _, ty := range pkg.Types {
		out(ty.Decl)
		values(ty.Consts)
		values(ty.Vars)
		funcs(ty.Funcs)
		funcs(ty.Methods)
	}
	return bytes.TrimSpace(b.Bytes())
}

func TestExportedAPI(t *testing.T) {
	got := append(renderAPI(t), '\n')
	const golden = "testdata/api.golden"
	if *updateAPI {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the exported API changed (aws design 2.3: a new entry point is a reviewed diff).\n"+
			"Regenerate with: go test ./core/certs -run TestExportedAPI -update-api\n--- got\n%s\n--- want\n%s", got, want)
	}
}

// funcName is "F", "(T).M" or "(*T).M".
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	var b strings.Builder
	printer.Fprint(&b, token.NewFileSet(), fd.Recv.List[0].Type)
	return "(" + b.String() + ")." + fd.Name.Name
}

func mentions(n ast.Node, name string) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// The CA key's signer is made in Create (the CA's own certificate) and
// Issue (a leaf from a LeafSpec) and nowhere else in the package, and only
// its SignMessage calls Platform.Sign.
func TestSignerOnlyInCreateAndIssue(t *testing.T) {
	_, files := sources(t)
	var makers, signers []string
	for _, f := range files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				name := funcName(d)
				own := strings.HasPrefix(name, "(*signer).") || strings.HasPrefix(name, "(signer).")
				if !own && mentions(d, "signer") {
					makers = append(makers, name)
				}
				ast.Inspect(d, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok {
						if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Sign" {
							signers = append(signers, name)
						}
					}
					return true
				})
			case *ast.GenDecl:
				for _, s := range d.Specs {
					if ts, ok := s.(*ast.TypeSpec); ok && ts.Name.Name == "signer" {
						continue
					}
					if mentions(s, "signer") {
						t.Errorf("a package-level declaration refers to the signer: %v", s)
					}
				}
			}
		}
	}
	slices.Sort(makers)
	if want := []string{"(*CA).Issue", "(*Store).Create"}; !slices.Equal(makers, want) {
		t.Errorf("the signer is reached from %v, want only %v", makers, want)
	}
	if want := []string{"(*signer).SignMessage"}; !slices.Equal(signers, want) {
		t.Errorf("Platform.Sign is called from %v, want only %v", signers, want)
	}
}

// signsWithCAHandle is the one call outside core/certs known to pass a CA
// handle to Sign, and why it may: the conformance suite checks that a
// deleted CA's key no longer signs. It also proves the scan finds such a
// call through k8s.CA's embedded certs.CA.
var signsWithCAHandle = map[string]bool{
	"github.com/atas/nazar/core/platform/conformance": true,
}

// No package of the module but core/certs passes a certs.CA's Handle to a
// Sign call: the CA key signs only what the engine built.
func TestNoOtherPackageSignsWithACAHandle(t *testing.T) {
	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(strings.TrimSpace(string(gomod)))
	patterns := []string{"./core/...", "./cmd/...", "./internal/..."}
	if runtime.GOOS == "darwin" {
		patterns = append(patterns, "./bridge/...") // cgo glue, built on a Mac only
	}
	cmd := exec.Command("go", append([]string{"list", "-e", "-export", "-deps", "-json=ImportPath,Dir,GoFiles,CgoFiles,Export,Standard,Module,Error"}, patterns...)...)
	cmd.Dir = root
	cmd.Stderr = os.Stderr
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	type pkg struct {
		ImportPath, Dir, Export string
		GoFiles, CgoFiles       []string
		Standard                bool
		Module                  *struct{ Path string }
		Error                   *struct{ Err string }
	}
	exports := map[string]string{}
	var ours []pkg
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var p pkg
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if p.Error != nil {
			t.Fatalf("%s: %s", p.ImportPath, p.Error.Err)
		}
		exports[p.ImportPath] = p.Export
		if !p.Standard && p.Module != nil && p.Module.Path == "github.com/atas/nazar" && p.ImportPath != certsPath {
			ours = append(ours, p)
		}
	}
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		f, ok := exports[path]
		if !ok || f == "" {
			return nil, errors.New("no export data for " + path)
		}
		return os.Open(f)
	})
	found := map[string][]string{}
	checked := 0
	for _, p := range ours {
		var files []*ast.File
		for _, n := range append(slices.Clone(p.GoFiles), p.CgoFiles...) {
			f, err := parser.ParseFile(fset, filepath.Join(p.Dir, n), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}, Uses: map[*ast.Ident]types.Object{}}
		var typeErrs []error
		conf := types.Config{Importer: imp, FakeImportC: true, Error: func(err error) { typeErrs = append(typeErrs, err) }}
		_, _ = conf.Check(p.ImportPath, fset, files, info)
		if len(p.CgoFiles) == 0 && len(typeErrs) > 0 {
			t.Fatalf("%s does not type-check: %v", p.ImportPath, typeErrs[0])
		}
		checked++
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var name string
				switch fn := c.Fun.(type) {
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				case *ast.Ident:
					name = fn.Name
				}
				if name != "Sign" {
					return true
				}
				for _, a := range c.Args {
					ast.Inspect(a, func(n ast.Node) bool {
						sel, ok := n.(*ast.SelectorExpr)
						if !ok {
							return true
						}
						obj := info.Uses[sel.Sel]
						if s := info.Selections[sel]; s != nil {
							obj = s.Obj()
						}
						if v, ok := obj.(*types.Var); ok && v.IsField() && v.Name() == "Handle" && v.Pkg() != nil && v.Pkg().Path() == certsPath {
							found[p.ImportPath] = append(found[p.ImportPath], fset.Position(c.Pos()).String())
						}
						return true
					})
				}
				return true
			})
		}
	}
	if checked < 10 {
		t.Fatalf("only %d packages checked", checked)
	}
	for path, at := range found {
		if !signsWithCAHandle[path] {
			t.Errorf("%s hands a CA's handle to Sign at %v; only core/certs signs with a CA key", path, at)
		}
	}
	for path := range signsWithCAHandle {
		if len(found[path]) == 0 {
			t.Errorf("the scan no longer finds the known call in %s: the scan or the allowance is stale", path)
		}
	}
}
