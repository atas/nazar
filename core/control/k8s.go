package control

import "time"

// The k8s commands (k8s design 7, Milestone 12).
const (
	// CmdK8sCredential is the exec plugin's request (args: name, execInfo):
	// gated, and a value command, answered only to the genuine nazar CLI.
	CmdK8sCredential = "k8s.credential"
)

// KindK8sCredential is wire only: the reply to k8s.credential, never
// printed by a --json command.
const KindK8sCredential = "K8sCredential"

// K8sCredential is a minted client certificate and its key, as PEM, and
// when kubectl must ask again: the certificate's own end.
type K8sCredential struct {
	TypeMeta
	Name                  string    `json:"name"`
	ClientCertificateData string    `json:"clientCertificateData"`
	ClientKeyData         string    `json:"clientKeyData"`
	ExpirationTimestamp   time.Time `json:"expirationTimestamp"`
}

// The management commands (k8s design 7).
const (
	// CmdK8sCACreate sets a context up on one login prompt: its CA, its
	// config entry (identity <user>-nazar, the cluster pin, the terminal's
	// login rule) and the kubectl pin (loosen). Args: name, server,
	// caSHA256, tlsServerName, proxyURL, kubectl (its path), kubeconfig
	// (the file the CLI adds its entries to, for the prompt) and
	// [onlyWhenUnlocked=true]. The reply is
	// a K8sContext whose CA carries its certificate.
	CmdK8sCACreate = "k8s.ca.create"
	CmdK8sCAShow   = "k8s.ca.show" // args: name                     (read)
	CmdK8sList     = "k8s.list"    //                                (read)
	CmdK8sForget   = "k8s.forget"  // args: name, kubeconfig         (login: the CA is destroyed)
)

// Kinds of the management commands.
const (
	KindK8sCA          = "K8sCA"
	KindK8sContext     = "K8sContext"
	KindK8sContextList = "K8sContextList"
	KindK8sSetup       = "K8sSetup"
)

// K8sCA is a context's certificate authority: public facts only. CertPEM
// is set by k8s.ca.show.
type K8sCA struct {
	TypeMeta
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"` // SHA-256 of the certificate, hex
	Created     time.Time `json:"created"`
	NotAfter    time.Time `json:"notAfter"`
	CertFile    string    `json:"certFile"`
	CertPEM     string    `json:"certPEM,omitempty"`
	// WhileLocked: the CA signs while the Mac is locked too (as
	// SSHKey.WhileLocked).
	WhileLocked bool `json:"whileLocked"`
}

// K8sIdentity is the subject the context's certificates carry.
type K8sIdentity struct {
	User   string   `json:"user"`
	Groups []string `json:"groups"`
}

// K8sCluster is the recorded cluster (check 2).
type K8sCluster struct {
	Server        string `json:"server"`
	CASHA256      string `json:"caSHA256"`
	TLSServerName string `json:"tlsServerName,omitempty"`
	ProxyURL      string `json:"proxyURL,omitempty"`
}

// K8sContext is a context as config.yaml configures it and its CA as the
// Vault holds it; either may be missing.
type K8sContext struct {
	TypeMeta
	Name       string       `json:"name"`
	Configured bool         `json:"configured"`
	Credential string       `json:"credential,omitempty"`
	Identity   *K8sIdentity `json:"identity,omitempty"`
	TTLCert    string       `json:"ttlCert,omitempty"`
	Cluster    *K8sCluster  `json:"cluster,omitempty"`
	Rules      []string     `json:"rules"`
	// Policy is the context's rules as config.yaml has them now (the staged
	// change when there is one), in the shape of a key's; FallbackSource is
	// "context-gate" for the context's own gate. Absent when config.yaml
	// has no entry for it. Configured and State are the config in
	// force: they differ from Policy only while a change is staged.
	Policy *SSHKeyRules `json:"policy,omitempty"`
	// Warnings are the config warnings about this context's own entry.
	Warnings []string `json:"warnings"`
	// State is one of the K8sState values; Remedy says what fixes it.
	State string `json:"state"`
	CA    *K8sCA `json:"ca"`
	// CABroken: a CA record exists but can't be used; UnusableReason says
	// why and Remedy what to run. Remedy is also set for the states
	// no-entry and no-ca (State).
	CABroken       bool   `json:"caBroken"`
	UnusableReason string `json:"unusableReason,omitempty"`
	Remedy         string `json:"remedy,omitempty"`
}

// States of a context (K8sContext.State).
const (
	K8sStateOK         = "ok"          // configured, its CA usable
	K8sStateNoEntry    = "no-entry"    // a CA, no config entry: nazar k8s forget NAME, then nazar k8s ca create NAME
	K8sStateNoCA       = "no-ca"       // configured, no CA: the same remedy
	K8sStateCAUnusable = "ca-unusable" // a CA record this agent can't use (CABroken)
	K8sStateAbsent     = "absent"      // neither: the reply of k8s forget
)

// K8sContextList is the reply to k8s.list.
type K8sContextList struct {
	TypeMeta
	Items []K8sContext `json:"items"`
}

// K8sSetup is what `nazar k8s ca create --json` prints; the CLI makes it.
type K8sSetup struct {
	TypeMeta
	Context    K8sContext `json:"context"`    // nazar-agent's reply
	Kubeconfig string     `json:"kubeconfig"` // the file that has nazar's entries
	Added      bool       `json:"added"`      // false: they were there already
	Backup     string     `json:"backup,omitempty"`
}
