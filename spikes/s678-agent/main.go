// Toy SSH agent for spikes S6/S7/S8. THROWAWAY: logs every request it sees.
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type logAgent struct {
	agent.ExtendedAgent
	knownHosts string
}

func (a *logAgent) List() ([]*agent.Key, error) {
	log.Println("REQUEST_IDENTITIES")
	return a.ExtendedAgent.List()
}

func (a *logAgent) Sign(k ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	describeSign(data)
	return a.ExtendedAgent.Sign(k, data)
}

func (a *logAgent) SignWithFlags(k ssh.PublicKey, data []byte, f agent.SignatureFlags) (*ssh.Signature, error) {
	describeSign(data)
	return a.ExtendedAgent.SignWithFlags(k, data, f)
}

func (a *logAgent) Extension(t string, contents []byte) ([]byte, error) {
	if t == "session-bind@openssh.com" {
		a.describeBind(contents)
		return nil, nil
	}
	log.Printf("EXTENSION %s (unsupported)", t)
	return nil, agent.ErrExtensionUnsupported
}

func describeSign(data []byte) {
	if bytes.HasPrefix(data, []byte("SSHSIG")) {
		var s struct {
			Namespace string
			Reserved  []byte
			HashAlg   string
			Hash      []byte
		}
		if err := ssh.Unmarshal(data[6:], &s); err != nil {
			log.Printf("SIGN SSHSIG (unparsed: %v)", err)
			return
		}
		log.Printf("SIGN SSHSIG namespace=%q hash=%s", s.Namespace, s.HashAlg)
		return
	}
	var u struct {
		SessionID []byte
		Type      byte
		User      string
		Service   string
		Method    string
		HasSig    bool
		Algo      string
		PubKey    []byte
		// publickey-hostbound-v00@openssh.com (OpenSSH >= 8.9) appends "string hostkey".
		Rest []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(data, &u); err != nil {
		log.Printf("SIGN %d bytes (unparsed: %v)", len(data), err)
		return
	}
	bound := ""
	if len(u.Rest) > 0 {
		var hb struct{ HostKey []byte }
		if err := ssh.Unmarshal(u.Rest, &hb); err == nil {
			if hk, err := ssh.ParsePublicKey(hb.HostKey); err == nil {
				bound = " boundHostKey=" + ssh.FingerprintSHA256(hk)
			}
		}
	}
	log.Printf("SIGN userauth user=%q service=%q method=%q algo=%q%s", u.User, u.Service, u.Method, u.Algo, bound)
}

func (a *logAgent) describeBind(c []byte) {
	var b struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}
	if err := ssh.Unmarshal(c, &b); err != nil {
		log.Printf("EXTENSION session-bind (unparsed: %v)", err)
		return
	}
	pk, err := ssh.ParsePublicKey(b.HostKey)
	if err != nil {
		log.Printf("EXTENSION session-bind bad host key: %v", err)
		return
	}
	plain, hashed := matchKnownHosts(a.knownHosts, pk)
	log.Printf("EXTENSION session-bind host=%s %s forwarding=%v known_hosts plain=%v hashedMatches=%d",
		pk.Type(), ssh.FingerprintSHA256(pk), b.Forwarding, plain, hashed)
}

func matchKnownHosts(path string, pk ssh.PublicKey) (plain []string, hashed int) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		_, hosts, key, _, _, err := ssh.ParseKnownHosts(sc.Bytes())
		if err != nil || !bytes.Equal(key.Marshal(), pk.Marshal()) {
			continue
		}
		for _, h := range hosts {
			if strings.HasPrefix(h, "|1|") {
				hashed++
			} else {
				plain = append(plain, h)
			}
		}
	}
	return plain, hashed
}

func main() {
	home, _ := os.UserHomeDir()
	sock := flag.String("sock", filepath.Join(home, ".nazar", "agent.sock"), "socket path")
	pubOut := flag.String("pub", filepath.Join(home, ".nazar", "s678.pub"), "where to write the public key")
	known := flag.String("known", filepath.Join(home, ".ssh", "known_hosts"), "known_hosts to match (read-only)")
	flag.Parse()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	kr := agent.NewKeyring().(agent.ExtendedAgent)
	if err := kr.Add(agent.AddedKey{PrivateKey: priv, Comment: "nazar-s678-toy"}); err != nil {
		log.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(&priv.PublicKey)
	if err := os.WriteFile(*pubOut, ssh.MarshalAuthorizedKey(sshPub), 0o600); err != nil {
		log.Fatal(err)
	}

	_ = os.MkdirAll(filepath.Dir(*sock), 0o700)
	_ = os.Remove(*sock)
	l, err := net.Listen("unix", *sock)
	if err != nil {
		log.Fatal(err)
	}
	_ = os.Chmod(*sock, 0o600)
	log.Printf("toy agent on %s, key %s written to %s, known_hosts=%s", *sock, ssh.FingerprintSHA256(sshPub), *pubOut, *known)
	a := &logAgent{ExtendedAgent: kr, knownHosts: *known}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func() { defer c.Close(); _ = agent.ServeAgent(a, c) }()
	}
}
