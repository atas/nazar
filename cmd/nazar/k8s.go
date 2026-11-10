package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/k8s/kubeconfig"
)

// k8s is `nazar k8s …` (k8s design 7, Milestone 12).
func (a *app) k8s(args []string) int {
	if len(args) == 0 {
		return a.usageError("k8s: expected a subcommand (ca, list, rule, forget, credential)")
	}
	switch args[0] {
	case "credential":
		return a.k8sCredential(args[1:])
	case "ca":
		return a.k8sCA(args[1:])
	case "list":
		return a.k8sList(args[1:])
	case "rule":
		return a.ruleEdit(k8sTarget, args[1:])
	case "forget":
		return a.k8sForget(args[1:])
	}
	return a.usageError("k8s: unknown subcommand %q", args[0])
}

// contextArg is the one context-name argument of a k8s command.
func (a *app) contextArg(name string, args []string, flags func(fs *flag.FlagSet)) (string, error) {
	fs := a.flags(name)
	if flags != nil {
		flags(fs)
	}
	pos, err := a.parse(fs, args, 1)
	if err != nil {
		return "", err
	}
	if !config.ValidK8sContextName(pos[0]) {
		return "", control.NewProblem(control.CodeUsage, "%s: invalid context name %q (letters, digits, . _ @ -)", name, pos[0])
	}
	return pos[0], nil
}

func (a *app) k8sCA(args []string) int {
	if len(args) == 0 {
		return a.usageError("k8s ca: expected create or show")
	}
	switch args[0] {
	case "create":
		return a.k8sCACreate(args[1:])
	case "show":
		var microk8s bool
		name, err := a.contextArg("k8s ca show", args[1:], func(fs *flag.FlagSet) { fs.BoolVar(&microk8s, "microk8s", false, "") })
		if err != nil {
			return a.fail(err)
		}
		var ca control.K8sCA
		if err := a.call(control.CmdK8sCAShow, map[string]string{"name": name}, control.KindK8sCA, &ca); err != nil {
			return a.fail(err)
		}
		if !plainCertPEM(ca.CertPEM) {
			return a.fail(control.NewProblem(control.CodeError, "k8s ca show: a malformed certificate came back"))
		}
		return a.emit(ca, func() {
			if microk8s {
				fmt.Fprint(a.stdout, microk8sSteps(name, ca.CertPEM))
			} else {
				fmt.Fprint(a.stdout, ca.CertPEM)
			}
		})
	}
	return a.usageError("k8s ca: unknown subcommand %q", args[0])
}

// plainCertPEM reports whether s is a PEM certificate and nothing a
// terminal could take for a control sequence.
func plainCertPEM(s string) bool {
	return strings.HasPrefix(s, "-----BEGIN CERTIFICATE-----\n") && !strings.ContainsFunc(s, func(r rune) bool { return r != '\n' && (r < ' ' || r > '~') })
}

// microk8sCA is where microk8s keeps the cluster CA on the node.
const microk8sCA = "/var/snap/microk8s/current/certs/ca.crt"

// fingerprintCommand prints, on a microk8s node, the fingerprint nazar
// shows for the cluster CA, in the same format (fingerprints).
const fingerprintCommand = "sudo openssl x509 -in " + microk8sCA + " -noout -fingerprint -sha256"

// microk8sSteps is what makes a microk8s API server accept the context's
// certificates (k8s design 6.1): a separate client CA bundle, the cluster
// CA plus every nazar CA saved on the node (so a second context keeps the
// first), named by --client-ca-file. nazar never runs it.
func microk8sSteps(name, certPEM string) string {
	const certs = "/var/snap/microk8s/current/certs"
	return fmt.Sprintf(`On the microk8s node, as a user who can sudo (read each line before you run it):

1. Save the nazar CA:
sudo tee %[1]s/nazar-ca-%[2]s.crt >/dev/null <<'EOF'
%[3]sEOF

2. Make the client CA bundle, the cluster CA and every nazar CA saved here together:
sudo sh -c 'cat %[1]s/ca.crt %[1]s/nazar-ca-*.crt > %[1]s/client-ca.crt'

3. Point the API server at the bundle, and check the line:
sudo sed -i 's|^--client-ca-file=.*|--client-ca-file=${SNAP_DATA}/certs/client-ca.crt|' /var/snap/microk8s/current/args/kube-apiserver
grep client-ca-file /var/snap/microk8s/current/args/kube-apiserver

4. Restart the API server:
sudo snap restart microk8s.daemon-kubelite

microk8s refresh-certs rewrites ca.crt: run step 2 again after it. To stop trusting a
nazar CA, delete its nazar-ca-<context>.crt and run steps 2 and 4 again.
nazar never touches the cluster: these steps are yours to run.
`, certs, name, certPEM)
}

// fingerprints are the SHA-256 fingerprints of the certificates in
// pemData, as `openssl x509 -noout -fingerprint -sha256` (OpenSSL 3)
// prints them, so the two compare by eye.
func fingerprints(pemData []byte) []string {
	var out []string
	rest := pemData
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			continue
		}
		sum := sha256.Sum256(b.Bytes)
		hex := make([]string, len(sum))
		for i, c := range sum {
			hex[i] = fmt.Sprintf("%02X", c)
		}
		out = append(out, "sha256 Fingerprint="+strings.Join(hex, ":"))
	}
}

// maxCAFile bounds the CA file `ca create` reads at the prompt.
const maxCAFile = 1 << 20

// k8sCACreate is `nazar k8s ca create [<context> [<server>]]` (k8s
// design): one command sets a context up without the kubeconfig's
// credential. The CLI reads the context and the server and its CA, at a
// terminal with the kubeconfig's current context as defaults, without one
// from the arguments and the kubeconfig cluster entry with exactly that
// server; only contexts: and clusters: are read, never a user entry. It
// renders the kubeconfig with nazar's three entries added before
// nazar-agent's one login prompt (the CA and the config entry), and
// writes it only after the prompt said yes.
func (a *app) k8sCACreate(args []string) int {
	fs := a.flags("k8s ca create")
	onlyWhenUnlocked := onlyWhenUnlockedFlag(fs)
	pos, err := a.parseArgs(fs, args)
	if err != nil {
		return a.fail(err)
	}
	if len(pos) > 2 {
		return a.usageError("k8s ca create: expected at most a context and a server, got %d arguments", len(pos))
	}
	set, err := kubeconfig.Load(kubeconfig.Paths(a.getenv, a.home()))
	if err != nil {
		return a.fail(control.NewProblem(control.CodeError, "%v", err))
	}
	cur, _ := set.CurrentContext()
	if !config.ValidK8sContextName(cur) {
		cur = "" // never put a name that could be more than a name in a command to copy
	}
	var name, server string
	if len(pos) > 0 {
		name = pos[0]
	}
	if len(pos) > 1 {
		server = pos[1]
	}
	var src *kubeconfig.Cluster // the kubeconfig cluster the CA came from
	var caPEM []byte
	if a.stdinTerminal != nil && a.stdinTerminal() {
		if name, server, src, caPEM, err = a.askSetup(set, cur, name, server); err != nil {
			return a.fail(err)
		}
	} else {
		if len(pos) != 2 {
			return a.usageError("k8s ca create: without a terminal, give the context and the server (nazar k8s ca create <context> <server>); the server's CA is then the one of the kubeconfig cluster entry with exactly that server")
		}
		if src, err = set.ClusterByServer(server); err != nil {
			return a.fail(control.NewProblem(control.CodeError, "%v; run nazar k8s ca create at a terminal and give the server's CA", err))
		}
		if src == nil {
			return a.usageError("k8s ca create: no cluster in the kubeconfig has the server %s exactly; run it at a terminal to give the server's CA (on microk8s: %s on the node)", cluster.Display(server), microk8sCA)
		}
		if src.CAErr != nil {
			return a.fail(control.NewProblem(control.CodeError, "%v", src.CAErr))
		}
		caPEM = src.CAPEM
	}
	if !config.ValidK8sContextName(name) {
		return a.usageError("k8s ca create: invalid context name %s (letters, digits, . _ @ -)", cluster.Display(name))
	}
	if src != nil && src.Insecure {
		return a.fail(control.NewProblem(control.CodeError, "cluster %s has insecure-skip-tls-verify: nazar cannot protect a cluster whose server certificate is not checked", cluster.Display(src.Name)))
	}
	norm, err := cluster.NormalizeServer(server)
	if err != nil {
		return a.usageError("k8s ca create: %v", err)
	}
	caHash, err := cluster.CAHash(caPEM)
	if err != nil {
		return a.fail(control.NewProblem(control.CodeError, "the server's CA: %v", err))
	}
	caPEM = certsOnly(caPEM) // what was around the PEM blocks stays out of the kubeconfig
	e := kubeconfig.Entries{Context: name, Server: norm, CAPEM: caPEM}
	if src != nil {
		e.TLSServerName, e.ProxyURL = src.TLSServerName, src.ProxyURL
	}
	self, err := a.selfPath()
	if err != nil || !filepath.IsAbs(self) || filepath.Clean(self) != self {
		return a.fail(control.NewProblem(control.CodeError, "k8s ca create: can't tell this nazar's absolute path, which the kubeconfig must name"))
	}
	e.Command = self
	ch, err := set.Add(e)
	setUp := errors.Is(err, kubeconfig.ErrSetUp)
	if err != nil && !setUp {
		return a.fail(control.NewProblem(control.CodeError, "%v", err))
	}
	callArgs := map[string]string{"name": name, "server": norm, "caSHA256": caHash, "tlsServerName": e.TLSServerName,
		"proxyURL": e.ProxyURL}
	withOnlyWhenUnlocked(callArgs, *onlyWhenUnlocked)
	var pend *kubeconfig.Pending
	if !setUp {
		// Rendered and written to a temp file before the prompt: a
		// kubeconfig nazar can't write fails before anything is made.
		if pend, err = kubeconfig.PrepareChange(ch); err != nil {
			return a.fail(control.NewProblem(control.CodeError, "%v", err))
		}
		defer guardTemp(pend)()
		callArgs["kubeconfig"] = ch.Path
	}
	var ctx control.K8sContext
	if err := a.call(control.CmdK8sCACreate, callArgs, control.KindK8sContext, &ctx); err != nil {
		if pend != nil {
			pend.Abort()
		}
		return a.fail(err)
	}
	res := control.K8sSetup{TypeMeta: control.Meta(control.KindK8sSetup), Context: ctx, Kubeconfig: ch.Path}
	if pend != nil {
		backup, err := pend.Commit(ch.Original, time.Now())
		if err != nil {
			return a.fail(control.NewProblem(control.CodeError, "%s is set up in nazar, but the kubeconfig could not be written: %v; run nazar k8s ca create %s %s again to add its entries",
				name, err, name, norm))
		}
		res.Added, res.Backup = true, backup
	}
	if ctx.CA == nil || !plainCertPEM(ctx.CA.CertPEM) || ctx.Identity == nil || !config.ValidK8sSubject(ctx.Identity.User) {
		return a.fail(control.NewProblem(control.CodeError, "k8s ca create: nazar-agent's reply has no usable CA certificate or identity; nazar k8s list shows the context"))
	}
	if *onlyWhenUnlocked && ctx.CA.WhileLocked {
		return a.fail(a.wrongAccess("the CA of "+name, "nazar k8s forget "+name))
	}
	return a.emit(res, func() {
		user := ctx.Identity.User
		fmt.Fprintf(a.stdout, "%s is set up: its CA is in %s (SHA-256 %s), config.yaml has k8s.contexts.%s.\n",
			name, a.traits().Chip, term(ctx.CA.Fingerprint), name)
		fmt.Fprintln(a.stdout, a.caLockedLine(ctx.CA.WhileLocked))
		if res.Added {
			fmt.Fprintf(a.stdout, "Added the context %s and the cluster and user %s to %s.\n", name, kubeconfig.EntryName(name), term(ch.Path))
		} else {
			fmt.Fprintf(a.stdout, "%s already has nazar's entries for %s.\n", term(ch.Path), name)
		}
		if res.Backup != "" {
			fmt.Fprintf(a.stdout, "The file as it was is at %s; delete it once kubectl works.\n", term(res.Backup))
		}
		fmt.Fprintf(a.stdout, "\nNext, make the cluster trust the CA.\n%s", microk8sSteps(name, ctx.CA.CertPEM))
		admin := "kubectl"
		if cur != "" && cur != name {
			admin += " --context " + cur
		}
		fmt.Fprintf(a.stdout, "\nThen give %s a role, with your current admin access:\n  %s create clusterrolebinding %s --clusterrole=cluster-admin --user=%s\n", user, admin, user, user)
		fmt.Fprintf(a.stdout, "\nThen use it (%s once per tab):\n  kubectl --context %s get pods\n", a.traits().LoginGate, name)
	})
}

// askSetup asks for the context name, the server and the server's CA at
// the terminal, each with its default from the kubeconfig's current
// context cur (Enter takes it). Questions go to stderr, so --json output
// stays one object. The CA is shown as its fingerprints; another can be
// given as the path of a PEM file.
func (a *app) askSetup(set *kubeconfig.Set, cur, name, server string) (string, string, *kubeconfig.Cluster, []byte, error) {
	in := bufio.NewReaderSize(a.stdin, 4096)
	w := a.stderr
	_, curCl := set.CurrentContext()
	viewCtx := cur
	if viewCtx == "" {
		viewCtx = "<context>"
	}
	fmt.Fprintf(w, "The defaults in [brackets] come from your kubeconfig; Enter takes one. These show the same:\n  kubectl config get-contexts\n  kubectl config view --minify --context %s -o jsonpath='{.clusters[0].cluster.server}'\n", viewCtx)
	var err error
	if name == "" {
		def := ""
		if cur != "" {
			// The current context is the admin one the cluster steps need:
			// nazar's gets its own name, unless it is nazar's already.
			def = cur + "-nazar"
			if set.IsNazarContext(cur) {
				def = cur
			}
			if !config.ValidK8sContextName(def) {
				def = ""
			}
		}
		if name, err = ask(in, w, "Context name", def); err != nil {
			return "", "", nil, nil, err
		}
	} else {
		fmt.Fprintf(w, "Context name: %s\n", term(name))
	}
	if server == "" {
		def := ""
		if curCl != nil {
			if _, err := cluster.NormalizeServer(curCl.Server); err == nil {
				def = curCl.Server
			}
		}
		if server, err = ask(in, w, "Server", def); err != nil {
			return "", "", nil, nil, err
		}
	} else {
		fmt.Fprintf(w, "Server: %s\n", term(server))
	}
	// A bad answer stops here, before the CA is asked for.
	if !config.ValidK8sContextName(name) {
		return "", "", nil, nil, control.NewProblem(control.CodeUsage, "k8s ca create: invalid context name %s (letters, digits, . _ @ -)", cluster.Display(name))
	}
	if _, err := cluster.NormalizeServer(server); err != nil {
		return "", "", nil, nil, control.NewProblem(control.CodeUsage, "k8s ca create: %v", err)
	}
	var src *kubeconfig.Cluster
	if curCl != nil && curCl.Server == server {
		src = curCl
	} else if src, err = set.ClusterByServer(server); err != nil {
		src = nil
		fmt.Fprintf(w, "(%s: no default CA)\n", term(err.Error()))
	}
	var def []byte
	var shown []string
	if src != nil && src.CAErr == nil {
		if shown = fingerprints(src.CAPEM); len(shown) > 0 {
			def = src.CAPEM
		}
	}
	if def != nil {
		fmt.Fprintf(w, "Server CA [%s]\n  on a microk8s node this prints the same: %s\n  Enter takes it; or the path of the CA's PEM file: ", strings.Join(shown, ", "), fingerprintCommand)
	} else {
		fmt.Fprintf(w, "Server CA: the kubeconfig has none for this server.\n  on a microk8s node it is %s (its fingerprint: %s)\n  the path of a copy of it here: ", microk8sCA, fingerprintCommand)
	}
	ans, err := readAnswer(in)
	if err != nil {
		return "", "", nil, nil, err
	}
	if ans == "" {
		if def == nil {
			return "", "", nil, nil, control.NewProblem(control.CodeUsage, "k8s ca create: no server CA; copy %s from the node (for example: scp <node>:%s ./ca.crt) and give its path", microk8sCA, microk8sCA)
		}
		return name, server, src, def, nil
	}
	p := ans
	if strings.HasPrefix(p, "~/") {
		p = filepath.Join(a.home(), p[2:])
	}
	data, err := readBounded(p, maxCAFile)
	if err != nil {
		return "", "", nil, nil, control.NewProblem(control.CodeError, "the CA file %s: %v", cluster.Display(p), err)
	}
	fps := fingerprints(data)
	if _, err := cluster.CAHash(data); err != nil || len(fps) == 0 {
		return "", "", nil, nil, control.NewProblem(control.CodeError, "the CA file %s holds no plain PEM certificate", cluster.Display(p))
	}
	fmt.Fprintf(w, "  %s: %s\n", term(p), strings.Join(fps, ", "))
	return name, server, src, data, nil
}

// ask prints question with its default and reads the answer: the default
// for an empty one.
func ask(in *bufio.Reader, w io.Writer, question, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(w, "%s [%s]: ", question, term(def))
	} else {
		fmt.Fprintf(w, "%s: ", question)
	}
	ans, err := readAnswer(in)
	if err != nil {
		return "", err
	}
	if ans == "" {
		return def, nil
	}
	return ans, nil
}

// readAnswer reads one line typed at the terminal, spaces trimmed: at most
// 4 KiB, no control or escape character (a terminal's paste markers, a
// cursor key).
func readAnswer(in *bufio.Reader) (string, error) {
	line, err := in.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		return "", control.NewProblem(control.CodeUsage, "k8s ca create: the answer is too long")
	case errors.Is(err, io.EOF) && len(line) == 0:
		return "", control.NewProblem(control.CodeUsage, "k8s ca create: no answer (end of input); nothing was made")
	case err != nil && !errors.Is(err, io.EOF):
		return "", control.NewProblem(control.CodeError, "k8s ca create: reading the answer: %v", err)
	}
	s := strings.TrimSpace(string(line))
	if strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f || (r >= 0x80 && r <= 0x9f) }) {
		return "", control.NewProblem(control.CodeUsage, "k8s ca create: the answer has a control character; nothing was made")
	}
	return s, nil
}

// certsOnly re-encodes the certificates of pemData, nothing else: text
// around or between the blocks (notes, other data) is dropped.
func certsOnly(pemData []byte) []byte {
	var out []byte
	rest := pemData
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		if b.Type == "CERTIFICATE" {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.Bytes})...)
		}
	}
}

// guardTemp removes p's temp file, a whole copy of the kubeconfig, and
// exits 130 if the CLI is interrupted before the returned stop runs: the
// prompt can stay open a minute.
func guardTemp(p *kubeconfig.Pending) (stop func()) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	end := abortOnSignal(sigs, p, func(code int) {
		os.Stderr.WriteString("\nnazar: interrupted; the kubeconfig was not changed\n")
		os.Exit(code)
	})
	return func() { signal.Stop(sigs); end() }
}

// abortOnSignal is guardTemp's watch: the first signal on sigs before stop
// aborts p and calls exit(130).
func abortOnSignal(sigs <-chan os.Signal, p *kubeconfig.Pending, exit func(int)) (stop func()) {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-sigs:
			select {
			case <-done: // stopped first: the file is the commit's now
				return
			default:
			}
			p.Abort()
			exit(130)
		case <-done:
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// readBounded reads at most max bytes of the regular file at p (never a
// FIFO or a device, which could hang or take the terminal's input).
func readBounded(p string, max int64) ([]byte, error) {
	if fi, err := os.Stat(p); err != nil {
		return nil, errors.Unwrap(err)
	} else if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, errors.Unwrap(err)
	}
	defer f.Close()
	var b bytes.Buffer
	n, err := b.ReadFrom(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if n > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return b.Bytes(), nil
}

func (a *app) k8sList(args []string) int {
	if _, err := a.parse(a.flags("k8s list"), args, 0); err != nil {
		return a.fail(err)
	}
	var l control.K8sContextList
	if err := a.call(control.CmdK8sList, nil, control.KindK8sContextList, &l); err != nil {
		return a.fail(err)
	}
	return a.emit(l, func() {
		if len(l.Items) == 0 {
			fmt.Fprintln(a.stdout, "No k8s contexts. nazar k8s ca create sets one up.")
		}
		for _, c := range l.Items {
			fmt.Fprintln(a.stdout, term(c.Name))
			if c.Configured {
				id := "CN=" + c.Identity.User
				for _, g := range c.Identity.Groups {
					id += ",O=" + g
				}
				fmt.Fprintf(a.stdout, "  %s for %s (ttl_cert %s)\n  cluster: %s\n", term(c.Credential), term(id), term(c.TTLCert),
					term(c.Cluster.Server))
				for _, r := range c.Rules {
					fmt.Fprintf(a.stdout, "  rule %s\n", term(r))
				}
				for _, w := range c.Warnings {
					fmt.Fprintf(a.stdout, "  warning: %s\n", term(w))
				}
			} else if !c.CABroken {
				fmt.Fprintln(a.stdout, "  not in config.yaml: "+term(c.Remedy))
			}
			switch {
			case c.CA != nil:
				mark := ""
				if !c.CA.WhileLocked {
					mark = ", " + onlyWhenUnlockedMark
				}
				fmt.Fprintf(a.stdout, "  CA: SHA-256 %s, %s%s\n", term(c.CA.Fingerprint), term(c.CA.CertFile), mark)
			case c.CABroken:
				fmt.Fprintf(a.stdout, "  CA unusable: %s\n  fix: %s\n", term(c.UnusableReason), term(c.Remedy))
			case c.Remedy != "":
				fmt.Fprintf(a.stdout, "  no CA: %s\n", term(c.Remedy))
			}
		}
	})
}

// k8sForget is `nazar k8s forget <context>`: nazar-agent destroys the CA
// and the config entry on its prompt; then the CLI removes the kubeconfig
// entries ca create added, while they are still exactly nazar's, and names
// what it leaves (a kubeconfig it can't read changes nothing in the
// forget).
func (a *app) k8sForget(args []string) int {
	name, err := a.contextArg("k8s forget", args, nil)
	if err != nil {
		return a.fail(err)
	}
	var rm *kubeconfig.Change
	var left []string
	var kerr error
	set, err := kubeconfig.Load(kubeconfig.Paths(a.getenv, a.home()))
	if err == nil {
		rm, left, kerr = set.Remove(name)
	} else {
		kerr = err
	}
	var pend *kubeconfig.Pending
	if rm != nil {
		if pend, err = kubeconfig.PrepareChange(rm); err != nil {
			kerr, left, rm = err, append(left, byHand(rm.Removed)...), nil
		} else {
			defer guardTemp(pend)()
		}
	}
	callArgs := map[string]string{"name": name}
	if pend != nil {
		callArgs["kubeconfig"] = rm.Path
	}
	var c control.K8sContext
	if err := a.call(control.CmdK8sForget, callArgs, control.KindK8sContext, &c); err != nil {
		if pend != nil {
			pend.Abort()
		}
		return a.fail(err)
	}
	backup := ""
	if pend != nil {
		if backup, err = pend.Commit(rm.Original, time.Now()); err != nil {
			kerr, left, rm = err, append(left, byHand(rm.Removed)...), nil
		}
	}
	return a.emit(c, func() {
		fmt.Fprintf(a.stdout, "nazar forgot %s: it has no CA and no config.yaml entry now.\n", name)
		if rm != nil {
			fmt.Fprintf(a.stdout, "Removed nazar's entries for %s from %s (%s).\n", name, term(rm.Path), strings.Join(rm.Removed, ", "))
			if backup != "" {
				fmt.Fprintf(a.stdout, "The file as it was is at %s; delete it when you no longer need it.\n", term(backup))
			}
		}
		if kerr != nil {
			fmt.Fprintf(a.stdout, "The kubeconfig was not changed: %s\n", term(kerr.Error()))
		}
		if len(left) > 0 {
			fmt.Fprintf(a.stdout, "These kubeconfig entries are not exactly nazar's (or could not be removed); remove them yourself:\n")
			for _, l := range left {
				fmt.Fprintf(a.stdout, "  %s\n", term(l))
			}
		}
	})
}

// byHand turns removed entries ("cluster nazar-hydra") into the kubectl
// commands that remove them.
func byHand(removed []string) []string {
	verb := map[string]string{"cluster": "delete-cluster", "user": "delete-user", "context": "delete-context"}
	var out []string
	for _, r := range removed {
		if kind, n, ok := strings.Cut(r, " "); ok {
			out = append(out, "kubectl config "+verb[kind]+" "+n)
		}
	}
	return out
}
