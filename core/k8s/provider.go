package k8s

import (
	"errors"
	"time"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
)

// IssueInput is what a provider is given once a request is allowed.
type IssueInput struct {
	Context  *config.K8sContext
	Approval platform.ApprovalRef
	Now      time.Time
}

// Provider issues the credential of one context kind (k8s design 4).
type Provider interface {
	Kind() config.CredentialKind
	Issue(in IssueInput) (Credential, error)
}

type caCertProvider struct {
	s *CAStore
	p platform.Platform
}

// CACertProvider is the ca-cert provider: the context's CA from s, signed
// on p.
func CACertProvider(s *CAStore, p platform.Platform) Provider { return &caCertProvider{s: s, p: p} }

func (c *caCertProvider) Kind() config.CredentialKind { return config.CredentialCACert }

func (c *caCertProvider) Issue(in IssueInput) (Credential, error) {
	if in.Context == nil || in.Context.Credential != config.CredentialCACert {
		return Credential{}, errors.New("k8s: not a ca-cert context")
	}
	ca, err := c.s.Get(in.Context.Name)
	if err != nil {
		return Credential{}, err
	}
	return ca.Issue(c.p, in.Context.Identity, in.Context.TTLCert, in.Now, in.Approval)
}
