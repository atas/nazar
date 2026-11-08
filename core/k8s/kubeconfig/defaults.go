package kubeconfig

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/atas/nazar/core/k8s/cluster"
)

// Cluster is a kubeconfig cluster entry: public facts only. A cluster's
// CA is public (every client of the cluster has it); nothing here comes
// from a user entry.
type Cluster struct {
	Name, File    string
	Server        string
	TLSServerName string
	ProxyURL      string
	Insecure      bool   // insecure-skip-tls-verify (YAML 1.1 booleans: anything but false)
	CAPEM         []byte // certificate-authority-data, or the file certificate-authority names
	CAErr         error  // why there is no CAPEM
}

// CurrentContext returns the set's current-context (the first file that
// names one, as client-go reads it) and the cluster its context entry
// names; either may be missing. Only the contexts: and clusters: lists
// are read: never a user entry.
func (s *Set) CurrentContext() (string, *Cluster) {
	name := ""
	for _, f := range s.Files {
		if v := scalar(f.doc, "current-context"); v != "" {
			name = v
			break
		}
	}
	if name == "" {
		return "", nil
	}
	ctx, ok := s.find("contexts", "context", name)
	if !ok || ctx.body == nil {
		return name, nil
	}
	cl, ok := s.find("clusters", "cluster", scalar(ctx.body, "cluster"))
	if !ok || cl.body == nil {
		return name, nil
	}
	return name, readCluster(cl)
}

// ErrAmbiguous: several cluster entries have the server, with different
// CAs or names on the wire.
var ErrAmbiguous = errors.New("kubeconfig: several clusters with that server differ")

// ClusterByServer returns the cluster entry (the first definition of each
// name) whose server is exactly server, or nil when there is none. Several
// with the same CA, TLS server name and proxy are one; several that differ
// are ErrAmbiguous: nazar never picks one.
func (s *Set) ClusterByServer(server string) (*Cluster, error) {
	var found *Cluster
	seen := map[string]bool{}
	for _, f := range s.Files {
		for _, it := range items(f, "clusters") {
			name := scalar(it, "name")
			if seen[name] {
				continue // a later definition of a name kubectl never reads
			}
			seen[name] = true
			body := mapping(it, "cluster")
			if body == nil || scalar(body, "server") != server {
				continue
			}
			c := readCluster(named{file: f, item: it, body: body})
			if found == nil {
				found = c
				continue
			}
			if !sameWire(found, c) {
				return nil, fmt.Errorf("%w: %s and %s", ErrAmbiguous, cluster.Display(found.Name), cluster.Display(c.Name))
			}
		}
	}
	return found, nil
}

func sameWire(a, b *Cluster) bool {
	ha, ea := cluster.CAHash(a.CAPEM)
	hb, eb := cluster.CAHash(b.CAPEM)
	return ea == nil && eb == nil && ha == hb && a.TLSServerName == b.TLSServerName && a.ProxyURL == b.ProxyURL && a.Insecure == b.Insecure
}

// readCluster reads a cluster entry's public facts: the inline CA or the
// file certificate-authority names (relative to the kubeconfig's
// directory, as client-go resolves it).
func readCluster(cl named) *Cluster {
	b := cl.body
	c := &Cluster{Name: scalar(cl.item, "name"), File: cl.file.Path, Server: scalar(b, "server"),
		TLSServerName: scalar(b, "tls-server-name"), ProxyURL: scalar(b, "proxy-url"),
		Insecure: has(b, "insecure-skip-tls-verify") && scalar(b, "insecure-skip-tls-verify") != "false"}
	switch {
	case scalar(b, "certificate-authority-data") != "":
		pem, err := base64.StdEncoding.DecodeString(scalar(b, "certificate-authority-data"))
		if err != nil {
			c.CAErr = fmt.Errorf("the certificate-authority-data of cluster %s is not base64", cluster.Display(c.Name))
		} else {
			c.CAPEM = pem
		}
	case scalar(b, "certificate-authority") != "":
		p := scalar(b, "certificate-authority")
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(cl.file.Path), p)
		}
		pem, err := readFile(p)
		if err != nil {
			c.CAErr = fmt.Errorf("the certificate-authority %s of cluster %s can't be read", cluster.Display(p), cluster.Display(c.Name))
		} else {
			c.CAPEM = pem
		}
	default:
		c.CAErr = fmt.Errorf("cluster %s has no certificate-authority(-data)", cluster.Display(c.Name))
	}
	return c
}
