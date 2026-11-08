package agentproto

// Tests for the SSH agent wire protocol (spec 5, draft-miller-ssh-agent),
// session-bind@openssh.com verification, sign-payload classification
// (Phase 0 S7) and DER → ecdsa-sha2-nistp256 conversion. Everything parsed
// here arrives from an untrusted peer on the agent socket, so most cases are
// malformed or hostile inputs.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// wstr appends an SSH wire "string" (uint32 big-endian length + bytes).
// Deliberately test-local so the tests don't lean on implementation helpers.
func wstr(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b)))
	return append(dst, b...)
}

// ---------------------------------------------------------------------------
// Constants and one-byte replies

func TestConstants(t *testing.T) {
	ints := map[string][2]int{
		"MsgFailure":           {MsgFailure, 5},
		"MsgSuccess":           {MsgSuccess, 6},
		"MsgRequestIdentities": {MsgRequestIdentities, 11},
		"MsgIdentitiesAnswer":  {MsgIdentitiesAnswer, 12},
		"MsgSignRequest":       {MsgSignRequest, 13},
		"MsgSignResponse":      {MsgSignResponse, 14},
		"MsgExtension":         {MsgExtension, 27},
		"MaxMessageLen":        {MaxMessageLen, 256 * 1024}, // OpenSSH AGENT_MAX_LEN
		"MaxSessionIDLen":      {MaxSessionIDLen, 64},       // OpenSSH SSH_DIGEST_MAX_LENGTH
	}
	for name, v := range ints {
		if v[0] != v[1] {
			t.Errorf("%s = %d, want %d", name, v[0], v[1])
		}
	}
	strs := map[string][2]string{
		"SessionBindName":          {SessionBindName, "session-bind@openssh.com"},
		"MethodPublicKey":          {MethodPublicKey, "publickey"},
		"MethodPublicKeyHostbound": {MethodPublicKeyHostbound, "publickey-hostbound-v00@openssh.com"},
	}
	for name, v := range strs {
		if v[0] != v[1] {
			t.Errorf("%s = %q, want %q", name, v[0], v[1])
		}
	}
}

func TestFailureAndSuccessReplies(t *testing.T) {
	if f := Failure(); !bytes.Equal(f, []byte{5}) {
		t.Fatalf("Failure() = %v, want [5]", f)
	}
	if s := Success(); !bytes.Equal(s, []byte{6}) {
		t.Fatalf("Success() = %v, want [6]", s)
	}
	// Replies must not share a mutable backing array between calls.
	f := Failure()
	f[0] = 0xff
	if g := Failure(); !bytes.Equal(g, []byte{5}) {
		t.Fatalf("Failure() returned shared state: %v", g)
	}
	s := Success()
	s[0] = 0xff
	if g := Success(); !bytes.Equal(g, []byte{6}) {
		t.Fatalf("Success() returned shared state: %v", g)
	}
}

// ---------------------------------------------------------------------------
// Framing

func TestFraming(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMessage(&buf, []byte{MsgRequestIdentities}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{0, 0, 0, 1, 11}) {
		t.Fatalf("framed %x", buf.Bytes())
	}
	body, err := ReadMessage(&buf)
	if err != nil || !bytes.Equal(body, []byte{11}) {
		t.Fatalf("%x %v", body, err)
	}
	big := make([]byte, 4)
	binary.BigEndian.PutUint32(big, MaxMessageLen+1)
	if _, err := ReadMessage(bytes.NewReader(big)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	if _, err := ReadMessage(bytes.NewReader([]byte{0, 0, 0, 0})); err == nil {
		t.Fatal("empty message accepted")
	}
	if _, err := ReadMessage(bytes.NewReader([]byte{0, 0, 0, 5, 1})); err == nil {
		t.Fatal("truncated message accepted")
	}
}

func TestFramingLimits(t *testing.T) {
	// Exactly the cap is fine.
	full := bytes.Repeat([]byte{MsgSignRequest}, MaxMessageLen)
	var buf bytes.Buffer
	if err := WriteMessage(&buf, full); err != nil {
		t.Fatalf("WriteMessage at cap: %v", err)
	}
	got, err := ReadMessage(&buf)
	if err != nil || len(got) != MaxMessageLen {
		t.Fatalf("ReadMessage at cap: len %d, %v", len(got), err)
	}

	// A hostile 4 GiB length must be refused from the header alone (no body
	// follows, so an implementation that tried to read it would see EOF).
	if _, err := ReadMessage(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff})); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("0xffffffff length: want ErrTooLarge, got %v", err)
	}

	// Writing more than the cap is refused and writes nothing.
	buf.Reset()
	if err := WriteMessage(&buf, make([]byte, MaxMessageLen+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized write: want ErrTooLarge, got %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("oversized write still wrote %d bytes", buf.Len())
	}
}

func TestFramingStreamEnds(t *testing.T) {
	// A peer that closes between messages is a clean io.EOF.
	if _, err := ReadMessage(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("closed stream: want io.EOF, got %v", err)
	}
	// A peer that closes mid-header or mid-body is an error, never a message.
	for _, in := range [][]byte{{0}, {0, 0, 1}, {0, 0, 0, 3, 13, 0}} {
		if body, err := ReadMessage(bytes.NewReader(in)); err == nil {
			t.Errorf("ReadMessage(%x) = %x, want error", in, body)
		}
	}
}

func TestFramingBackToBack(t *testing.T) {
	var buf bytes.Buffer
	msgs := [][]byte{{MsgRequestIdentities}, {MsgExtension, 1, 2, 3}, {lockMsg}}
	for _, m := range msgs {
		if err := WriteMessage(&buf, m); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range msgs {
		got, err := ReadMessage(&buf)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("message %d: %x %v, want %x", i, got, err, want)
		}
	}
	if _, err := ReadMessage(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("after last message: want io.EOF, got %v", err)
	}
}

// lockMsg is SSH_AGENTC_LOCK (22), spelled out so the test doesn't
// depend on optional constants.
const lockMsg = 22

// ---------------------------------------------------------------------------
// SIGN_REQUEST

func signReq(blob, data []byte, flags uint32) []byte {
	b := []byte{MsgSignRequest}
	b = wstr(b, blob)
	b = wstr(b, data)
	return binary.BigEndian.AppendUint32(b, flags)
}

func TestParseSignRequest(t *testing.T) {
	req, err := ParseSignRequest(signReq([]byte("key"), []byte("data"), 4))
	if err != nil || string(req.KeyBlob) != "key" || string(req.Data) != "data" || req.Flags != 4 {
		t.Fatalf("%+v %v", req, err)
	}
	if _, err := ParseSignRequest(append(signReq([]byte("k"), []byte("d"), 0), 0)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
	bad := []byte{MsgSignRequest, 0xff, 0xff, 0xff, 0xff}
	if _, err := ParseSignRequest(bad); err == nil {
		t.Fatal("oversized string length accepted")
	}
}

func TestParseSignRequestRejectsMalformed(t *testing.T) {
	valid := signReq([]byte("key"), []byte("data"), 2)
	wrongType := append([]byte{MsgExtension}, valid[1:]...)
	cases := map[string][]byte{
		"empty body":              {},
		"type byte only":          {MsgSignRequest},
		"wrong message type":      wrongType,
		"identities request type": {MsgRequestIdentities},
		"missing flags":           valid[:len(valid)-4],
		"partial flags":           valid[:len(valid)-1],
		"data length past end":    append(wstr([]byte{MsgSignRequest}, []byte("key")), 0, 0, 0, 200, 'd'),
		"key length past end":     {MsgSignRequest, 0, 0, 0, 9, 'k'},
		"many trailing bytes":     append(append([]byte{}, valid...), bytes.Repeat([]byte{0}, 64)...),
	}
	for name, body := range cases {
		if req, err := ParseSignRequest(body); err == nil {
			t.Errorf("%s: accepted as %+v", name, req)
		}
	}
	// Every proper prefix of a valid request is truncated and must fail.
	for i := 0; i < len(valid); i++ {
		if _, err := ParseSignRequest(valid[:i]); err == nil {
			t.Errorf("prefix of %d bytes accepted", i)
		}
	}
}

// ---------------------------------------------------------------------------
// IDENTITIES_ANSWER and SIGN_RESPONSE encoding

func TestMarshalIdentities(t *testing.T) {
	b := MarshalIdentities([]Identity{{Blob: []byte("a"), Comment: "github"}})
	want := []byte{12, 0, 0, 0, 1, 0, 0, 0, 1, 'a', 0, 0, 0, 6, 'g', 'i', 't', 'h', 'u', 'b'}
	if !bytes.Equal(b, want) {
		t.Fatalf("%v", b)
	}
	if got := MarshalIdentities(nil); !bytes.Equal(got, []byte{12, 0, 0, 0, 0}) {
		t.Fatalf("no identities: %v", got)
	}
}

// Milestone 7: the CLI parses another agent's IDENTITIES_ANSWER.
// A round trip through MarshalIdentities; and the hostile shapes: the
// wrong type, a count the body cannot hold (never an allocation of that
// size), a truncated entry, trailing bytes.
func TestParseIdentities(t *testing.T) {
	want := []Identity{{Blob: []byte("blob-a"), Comment: "github"}, {Blob: []byte("b"), Comment: ""}}
	got, err := ParseIdentities(MarshalIdentities(want))
	if err != nil || len(got) != 2 || !bytes.Equal(got[0].Blob, want[0].Blob) || got[0].Comment != "github" || got[1].Comment != "" {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if got, err := ParseIdentities(MarshalIdentities(nil)); err != nil || len(got) != 0 {
		t.Fatalf("empty: %+v %v", got, err)
	}
	for name, body := range map[string][]byte{
		"empty":       {},
		"wrong type":  {MsgFailure},
		"no count":    {MsgIdentitiesAnswer, 0, 0},
		"huge count":  {MsgIdentitiesAnswer, 0xff, 0xff, 0xff, 0xff},
		"short entry": {MsgIdentitiesAnswer, 0, 0, 0, 1, 0, 0, 0, 5, 'a'},
		"no comment":  {MsgIdentitiesAnswer, 0, 0, 0, 1, 0, 0, 0, 1, 'a'},
		"trailing":    append(MarshalIdentities(want), 0),
	} {
		if ids, err := ParseIdentities(body); err == nil {
			t.Errorf("%s: parsed %+v, want an error", name, ids)
		}
	}
}

func TestMarshalIdentitiesManyDecodes(t *testing.T) {
	ids := []Identity{
		{Blob: []byte("first-blob"), Comment: "github"},
		{Blob: []byte{}, Comment: ""},
		{Blob: bytes.Repeat([]byte{0xab}, 300), Comment: "another key"},
	}
	b := MarshalIdentities(ids)
	if b[0] != MsgIdentitiesAnswer {
		t.Fatalf("type byte %d", b[0])
	}
	r := b[1:]
	n := binary.BigEndian.Uint32(r)
	r = r[4:]
	if int(n) != len(ids) {
		t.Fatalf("count %d, want %d", n, len(ids))
	}
	next := func() []byte {
		l := binary.BigEndian.Uint32(r)
		v := r[4 : 4+l]
		r = r[4+l:]
		return v
	}
	for i, id := range ids {
		if blob := next(); !bytes.Equal(blob, id.Blob) {
			t.Fatalf("identity %d blob %x", i, blob)
		}
		if c := next(); string(c) != id.Comment {
			t.Fatalf("identity %d comment %q", i, c)
		}
	}
	if len(r) != 0 {
		t.Fatalf("%d trailing bytes", len(r))
	}
}

func TestMarshalSignResponseDecodes(t *testing.T) {
	sig := &ssh.Signature{Format: ssh.KeyAlgoECDSA256, Blob: []byte("blob")}
	b := MarshalSignResponse(sig)
	if b[0] != MsgSignResponse {
		t.Fatalf("type byte %d", b[0])
	}
	l := binary.BigEndian.Uint32(b[1:])
	if int(l) != len(b)-5 {
		t.Fatalf("signature string length %d, body has %d", l, len(b)-5)
	}
	var got ssh.Signature
	if err := ssh.Unmarshal(b[5:], &got); err != nil {
		t.Fatal(err)
	}
	if got.Format != sig.Format || !bytes.Equal(got.Blob, sig.Blob) {
		t.Fatalf("decoded %+v", got)
	}
}

// ---------------------------------------------------------------------------
// Interop: the real x/crypto agent client against a minimal server built
// only from this package's primitives.

func TestAgentClientInterop(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cconn, sconn := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer sconn.Close()
		for {
			body, err := ReadMessage(sconn)
			if err != nil {
				return
			}
			var reply []byte
			switch body[0] {
			case MsgRequestIdentities:
				reply = MarshalIdentities([]Identity{{Blob: pub.Marshal(), Comment: "github"}})
			case MsgSignRequest:
				req, err := ParseSignRequest(body)
				if err != nil || !bytes.Equal(req.KeyBlob, pub.Marshal()) {
					reply = Failure()
					break
				}
				sum := sha256.Sum256(req.Data)
				der, err := ecdsa.SignASN1(rand.Reader, k, sum[:])
				if err != nil {
					reply = Failure()
					break
				}
				sig, err := ECDSASignatureFromDER(der)
				if err != nil {
					reply = Failure()
					break
				}
				reply = MarshalSignResponse(sig)
			default:
				reply = Failure()
			}
			if err := WriteMessage(sconn, reply); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { cconn.Close(); wg.Wait() })

	client := agent.NewClient(cconn)
	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Comment != "github" || !bytes.Equal(keys[0].Blob, pub.Marshal()) {
		t.Fatalf("List() = %v", keys)
	}
	data := []byte("data the client wants signed")
	sig, err := client.Sign(pub, data)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Format != ssh.KeyAlgoECDSA256 {
		t.Fatalf("signature format %q", sig.Format)
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Fatalf("signature from agent does not verify: %v", err)
	}
	// Signing with a key the agent doesn't hold fails cleanly.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherPub, _ := ssh.NewPublicKey(&other.PublicKey)
	if _, err := client.Sign(otherPub, data); err == nil {
		t.Fatal("sign with unknown key succeeded")
	}
	// Mutating requests get SSH_AGENT_FAILURE, which the client reports as errors.
	if err := client.Add(agent.AddedKey{PrivateKey: other}); err == nil {
		t.Fatal("ADD_IDENTITY succeeded")
	}
	if err := client.Lock([]byte("pw")); err == nil {
		t.Fatal("LOCK succeeded")
	}
	if _, err := client.Extension("unknown@example.com", nil); err == nil {
		t.Fatal("unknown extension succeeded")
	}
}

// ---------------------------------------------------------------------------
// EXTENSION and session-bind@openssh.com

func TestParseExtensionRejectsMalformed(t *testing.T) {
	e, err := ParseExtension(wstr([]byte{MsgExtension}, []byte(SessionBindName)))
	if err != nil || e.Name != SessionBindName || len(e.Contents) != 0 {
		t.Fatalf("no contents: %+v %v", e, err)
	}
	cases := map[string][]byte{
		"empty body":       {},
		"type byte only":   {MsgExtension},
		"wrong type":       wstr([]byte{MsgSignRequest}, []byte(SessionBindName)),
		"name past end":    {MsgExtension, 0, 0, 0, 30, 's', 'e'},
		"short length hdr": {MsgExtension, 0, 0},
	}
	for name, body := range cases {
		if e, err := ParseExtension(body); err == nil {
			t.Errorf("%s: accepted as %+v", name, e)
		}
	}
}

func hostKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.PublicKey()
}

// bind builds session-bind contents: string hostkey, string session id,
// string signature, bool is_forwarding (OpenSSH PROTOCOL.agent).
func bind(hostKey, sid, sig []byte, fwd bool) []byte {
	b := wstr(nil, hostKey)
	b = wstr(b, sid)
	b = wstr(b, sig)
	if fwd {
		return append(b, 1)
	}
	return append(b, 0)
}

func bindContents(t *testing.T, s ssh.Signer, sid []byte, fwd bool, tamper bool) []byte {
	sig, err := s.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	if tamper {
		sid = append([]byte{}, sid...)
		sid[0] ^= 1
	}
	return bind(s.PublicKey().Marshal(), sid, ssh.Marshal(sig), fwd)
}

func TestSessionBindVerifiesSignature(t *testing.T) {
	s, pub := hostKey(t)
	sid := bytes.Repeat([]byte{7}, 32)
	b, err := ParseSessionBind(bindContents(t, s, sid, true, false))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.HostKey.Marshal(), pub.Marshal()) || !bytes.Equal(b.SessionID, sid) || !b.Forwarding {
		t.Fatalf("%+v", b)
	}
	if _, err := ParseSessionBind(bindContents(t, s, sid, false, true)); err == nil {
		t.Fatal("forged session-bind accepted")
	}
	if _, err := ParseSessionBind(bindContents(t, s, bytes.Repeat([]byte{1}, 65), false, false)); err == nil {
		t.Fatal("oversized session id accepted")
	}
	ext := append(wstr([]byte{MsgExtension}, []byte(SessionBindName)), 1, 2)
	e, err := ParseExtension(ext)
	if err != nil || e.Name != SessionBindName || !bytes.Equal(e.Contents, []byte{1, 2}) {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestSessionBindNotForwarding(t *testing.T) {
	s, _ := hostKey(t)
	b, err := ParseSessionBind(bindContents(t, s, bytes.Repeat([]byte{9}, 48), false, false))
	if err != nil {
		t.Fatal(err)
	}
	if b.Forwarding {
		t.Fatal("is_forwarding=0 parsed as forwarding")
	}
}

func TestSessionBindSessionIDBounds(t *testing.T) {
	s, _ := hostKey(t)
	if _, err := ParseSessionBind(bindContents(t, s, bytes.Repeat([]byte{1}, MaxSessionIDLen), false, false)); err != nil {
		t.Fatalf("64-byte session id (sha512 kex) refused: %v", err)
	}
	if _, err := ParseSessionBind(bindContents(t, s, []byte{}, false, false)); err == nil {
		t.Fatal("empty session id accepted")
	}
}

// An attacker who controls the connection presents a well-known host key
// (say github.com's) but can only sign with its own key.
func TestSessionBindRejectsSubstitutedHostKey(t *testing.T) {
	attacker, _ := hostKey(t)
	_, victim := hostKey(t)
	sid := bytes.Repeat([]byte{5}, 32)
	sig, err := attacker.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := ParseSessionBind(bind(victim.Marshal(), sid, ssh.Marshal(sig), false)); err == nil {
		t.Fatalf("host key not matching the signature accepted: %+v", b)
	}
}

func TestSessionBindRejectsMalformed(t *testing.T) {
	s, pub := hostKey(t)
	sid := bytes.Repeat([]byte{4}, 32)
	sig, err := s.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	good := bind(pub.Marshal(), sid, ssh.Marshal(sig), false)
	if _, err := ParseSessionBind(good); err != nil {
		t.Fatalf("baseline refused: %v", err)
	}
	cases := map[string][]byte{
		"empty":                {},
		"trailing byte":        append(append([]byte{}, good...), 0),
		"missing forward flag": good[:len(good)-1],
		"garbage host key":     bind([]byte("not a key"), sid, ssh.Marshal(sig), false),
		"empty host key":       bind(nil, sid, ssh.Marshal(sig), false),
		"garbage signature":    bind(pub.Marshal(), sid, []byte("not a signature"), false),
		"empty signature":      bind(pub.Marshal(), sid, nil, false),
		"signature blob flipped": func() []byte {
			bad := *sig
			bad.Blob = append([]byte{}, sig.Blob...)
			bad.Blob[0] ^= 0x80
			return bind(pub.Marshal(), sid, ssh.Marshal(&bad), false)
		}(),
		"signature format mismatch": func() []byte {
			bad := *sig
			bad.Format = ssh.KeyAlgoECDSA256
			return bind(pub.Marshal(), sid, ssh.Marshal(&bad), false)
		}(),
	}
	for name, c := range cases {
		if b, err := ParseSessionBind(c); err == nil {
			t.Errorf("%s: accepted as %+v", name, b)
		}
	}
	for i := 0; i < len(good); i++ {
		if _, err := ParseSessionBind(good[:i]); err == nil {
			t.Errorf("prefix of %d bytes accepted", i)
		}
	}
}

func TestSessionBindOtherHostKeyTypes(t *testing.T) {
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	es, err := ssh.NewSignerFromKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rs0, err := ssh.NewSignerFromKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	// OpenSSH servers sign with rsa-sha2-512/256, never legacy ssh-rsa.
	rs, err := ssh.NewSignerWithAlgorithms(rs0.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSASHA512})
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]ssh.Signer{"ecdsa-p256": es, "rsa-sha2-512": rs} {
		sid := bytes.Repeat([]byte{2}, 32)
		b, err := ParseSessionBind(bindContents(t, s, sid, false, false))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !bytes.Equal(b.HostKey.Marshal(), s.PublicKey().Marshal()) {
			t.Errorf("%s: host key mismatch", name)
		}
		if _, err := ParseSessionBind(bindContents(t, s, sid, false, true)); err == nil {
			t.Errorf("%s: forged bind accepted", name)
		}
	}
}

func TestSessionBindDoesNotAliasInput(t *testing.T) {
	s, _ := hostKey(t)
	sid := bytes.Repeat([]byte{6}, 32)
	in := bindContents(t, s, sid, false, false)
	b, err := ParseSessionBind(in)
	if err != nil {
		t.Fatal(err)
	}
	for i := range in {
		in[i] = 0
	}
	if !bytes.Equal(b.SessionID, sid) {
		t.Fatal("SessionID aliases the request buffer")
	}
}

// ---------------------------------------------------------------------------
// Payload classification: SSH_MSG_USERAUTH_REQUEST

func userauth(sid []byte, method string, pub []byte, hostKey []byte) []byte {
	return userauthFull(sid, 50, "git", method, 1, pub, hostKey)
}

func userauthFull(sid []byte, msg byte, user, method string, hasSig byte, pub []byte, hostKey []byte) []byte {
	b := wstr(nil, sid)
	b = append(b, msg)
	b = wstr(b, []byte(user))
	b = wstr(b, []byte("ssh-connection"))
	b = wstr(b, []byte(method))
	b = append(b, hasSig)
	b = wstr(b, []byte("ecdsa-sha2-nistp256"))
	b = wstr(b, pub)
	if hostKey != nil {
		b = wstr(b, hostKey)
	}
	return b
}

func TestParsePayloadUserAuth(t *testing.T) {
	_, hk := hostKey(t)
	sid := bytes.Repeat([]byte{3}, 32)
	p := ParsePayload(userauth(sid, MethodPublicKey, []byte("pk"), nil))
	if p.Kind != PayloadUserAuth || p.UserAuth.User != "git" || p.UserAuth.HostKey != nil {
		t.Fatalf("%+v", p)
	}
	p = ParsePayload(userauth(sid, MethodPublicKeyHostbound, []byte("pk"), hk.Marshal()))
	if p.Kind != PayloadUserAuth || p.UserAuth.HostKey == nil {
		t.Fatalf("hostbound: %+v", p)
	}
	if got := Describe(p, "github.com"); got != "login to github.com as git" {
		t.Fatal(got)
	}
	// Hostbound without a host key, plain with trailing bytes, other methods: unknown.
	for _, data := range [][]byte{
		userauth(sid, MethodPublicKeyHostbound, []byte("pk"), nil),
		append(userauth(sid, MethodPublicKey, []byte("pk"), nil), 0),
		userauth(sid, "password", []byte("pk"), nil),
	} {
		if p := ParsePayload(data); p.Kind != PayloadUnknown {
			t.Errorf("want unknown, got %+v", p)
		}
	}
}

func TestParsePayloadUserAuthFields(t *testing.T) {
	_, hk := hostKey(t)
	sid := bytes.Repeat([]byte{8}, 32)
	data := userauthFull(sid, 50, "deploy", MethodPublicKeyHostbound, 1, []byte("pubkey-blob"), hk.Marshal())
	p := ParsePayload(data)
	if p.Kind != PayloadUserAuth || p.UserAuth == nil {
		t.Fatalf("%+v", p)
	}
	u := p.UserAuth
	if !bytes.Equal(u.SessionID, sid) || u.User != "deploy" || u.Service != "ssh-connection" ||
		u.Method != MethodPublicKeyHostbound || u.Algo != "ecdsa-sha2-nistp256" ||
		!bytes.Equal(u.PubKey, []byte("pubkey-blob")) {
		t.Fatalf("fields %+v", u)
	}
	if u.HostKey == nil || !bytes.Equal(u.HostKey.Marshal(), hk.Marshal()) {
		t.Fatal("hostbound host key not parsed")
	}
	if p.Len != len(data) || p.SSHSig != nil {
		t.Fatalf("Len %d (want %d), SSHSig %v", p.Len, len(data), p.SSHSig)
	}
}

func TestParsePayloadUserAuthRejectsMalformed(t *testing.T) {
	_, hk := hostKey(t)
	sid := bytes.Repeat([]byte{3}, 32)
	cases := map[string][]byte{
		"wrong message number (51)":        userauthFull(sid, 51, "git", MethodPublicKey, 1, []byte("pk"), nil),
		"has_signature false":              userauthFull(sid, 50, "git", MethodPublicKey, 0, []byte("pk"), nil),
		"empty session id":                 userauth(nil, MethodPublicKey, []byte("pk"), nil),
		"session id over 64 bytes":         userauth(bytes.Repeat([]byte{1}, MaxSessionIDLen+1), MethodPublicKey, []byte("pk"), nil),
		"hostbound with garbage host key":  userauth(sid, MethodPublicKeyHostbound, []byte("pk"), []byte("not a key")),
		"plain publickey with a host key":  userauth(sid, MethodPublicKey, []byte("pk"), hk.Marshal()),
		"hostbound with trailing byte":     append(userauth(sid, MethodPublicKeyHostbound, []byte("pk"), hk.Marshal()), 0),
		"keyboard-interactive method":      userauth(sid, "keyboard-interactive", []byte("pk"), nil),
		"method differs only in case":      userauth(sid, "PublicKey", []byte("pk"), nil),
		"hostbound method, unknown suffix": userauth(sid, "publickey-hostbound-v01@openssh.com", []byte("pk"), hk.Marshal()),
	}
	for name, data := range cases {
		p := ParsePayload(data)
		if p.Kind != PayloadUnknown || p.UserAuth != nil {
			t.Errorf("%s: want unknown, got %+v", name, p)
		}
		if p.Len != len(data) {
			t.Errorf("%s: Len %d, want %d", name, p.Len, len(data))
		}
	}
	// Every truncation of a valid hostbound payload is unknown, never a
	// half-parsed login.
	full := userauth(sid, MethodPublicKeyHostbound, []byte("pk"), hk.Marshal())
	for i := 0; i < len(full); i++ {
		if p := ParsePayload(full[:i]); p.Kind != PayloadUnknown {
			t.Errorf("prefix of %d bytes classified as %v", i, p.Kind)
		}
	}
}

// ---------------------------------------------------------------------------
// Payload classification: SSHSIG

func sshsig(ns string) []byte {
	return sshsigFull(ns, "sha512")
}

func sshsigFull(ns, hash string) []byte {
	b := []byte("SSHSIG")
	b = wstr(b, []byte(ns))
	b = wstr(b, nil)
	b = wstr(b, []byte(hash))
	return wstr(b, bytes.Repeat([]byte{1}, 64))
}

func TestParsePayloadSSHSig(t *testing.T) {
	p := ParsePayload(sshsig("git"))
	if p.Kind != PayloadSSHSig || p.SSHSig.Namespace != "git" || Describe(p, "") != "sign a git commit/tag" {
		t.Fatalf("%+v", p)
	}
	if got := Describe(ParsePayload(sshsig("file\x1b[31m")), ""); got != `sign data (namespace "file[31m")` {
		t.Fatalf("namespace not sanitised: %q", got)
	}
	if p := ParsePayload([]byte("SSHSIG\x00\x00")); p.Kind != PayloadUnknown {
		t.Fatal("truncated SSHSIG must be unknown")
	}
	if got := Describe(ParsePayload([]byte("hello")), ""); got != "sign unrecognized data (5 bytes)" {
		t.Fatal(got)
	}
}

func TestParsePayloadSSHSigFields(t *testing.T) {
	data := sshsigFull("file", "sha256")
	p := ParsePayload(data)
	if p.Kind != PayloadSSHSig || p.SSHSig == nil || p.UserAuth != nil {
		t.Fatalf("%+v", p)
	}
	if p.SSHSig.Namespace != "file" || p.SSHSig.HashAlg != "sha256" || p.Len != len(data) {
		t.Fatalf("%+v len %d", p.SSHSig, p.Len)
	}
	if got := Describe(p, "ignored.example"); got != `sign data (namespace "file")` {
		t.Fatalf("%q", got)
	}
}

func TestParsePayloadSSHSigRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"empty namespace": sshsig(""), // PROTOCOL.sshsig: namespace MUST NOT be empty
		"trailing byte":   append(sshsig("git"), 0),
		"magic only":      []byte("SSHSIG"),
		"lowercase magic": append([]byte("sshsig"), sshsig("git")[6:]...),
		"hash length past end": func() []byte {
			b := sshsig("git")
			return b[:len(b)-1]
		}(),
	}
	for name, data := range cases {
		if p := ParsePayload(data); p.Kind != PayloadUnknown || p.SSHSig != nil {
			t.Errorf("%s: want unknown, got %+v", name, p)
		}
	}
	full := sshsig("git")
	for i := 0; i < len(full); i++ {
		if p := ParsePayload(full[:i]); p.Kind != PayloadUnknown {
			t.Errorf("prefix of %d bytes classified as %v", i, p.Kind)
		}
	}
}

// Only the exact namespace "git" may be described as a git signature;
// look-alikes are shown verbatim (sanitised) so the user sees the difference.
func TestOnlyExactGitNamespaceIsGit(t *testing.T) {
	for _, ns := range []string{"Git", "git ", " git", "git\x00", "git\n", "gît", "git@example.com", "file"} {
		p := ParsePayload(sshsig(ns))
		if p.Kind != PayloadSSHSig {
			t.Errorf("namespace %q: not classified as SSHSIG: %+v", ns, p)
			continue
		}
		got := Describe(p, "")
		if got == "sign a git commit/tag" {
			t.Errorf("namespace %q described as a git signature", ns)
		}
		if !strings.HasPrefix(got, "sign data (namespace ") {
			t.Errorf("namespace %q: %q", ns, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Describe: the dialog's "what for" line

func TestDescribeDestinations(t *testing.T) {
	sid := bytes.Repeat([]byte{3}, 32)
	p := ParsePayload(userauth(sid, MethodPublicKey, []byte("pk"), nil))
	for dest, want := range map[string]string{
		"[127.0.0.1]:2222":         "login to [127.0.0.1]:2222 as git",
		"host key SHA256:abcdef12": "login to host key SHA256:abcdef12 as git",
	} {
		if got := Describe(p, dest); got != want {
			t.Errorf("Describe(%q) = %q, want %q", dest, got, want)
		}
	}
	// No destination known: still a login line naming the user, never an
	// empty name ("login to  as git").
	got := Describe(p, "")
	if !strings.HasPrefix(got, "login to ") || !strings.HasSuffix(got, " as git") || strings.Contains(got, "  ") {
		t.Fatalf("Describe with no destination = %q", got)
	}
}

func allPrintable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// The user name and namespace come from the client; a hostile client must
// not be able to inject terminal escapes, newlines or bidi overrides into the
// approval dialog, nor make the line arbitrarily long.
func TestDescribeSanitisesClientStrings(t *testing.T) {
	sid := bytes.Repeat([]byte{3}, 32)
	hostile := []string{
		"git\x1b[2J\x1b[H",
		"root\r\nlogin to github.com as git",
		"git‮⁦moc.buhtig",
		"git​\x00\x7f",
		string([]byte{'g', 0xff, 0xfe, 'i', 't'}),
		strings.Repeat("A", 10000),
	}
	for _, s := range hostile {
		for _, data := range [][]byte{
			userauthFull(sid, 50, s, MethodPublicKey, 1, []byte("pk"), nil),
			sshsig(s),
		} {
			p := ParsePayload(data)
			if p.Kind == PayloadUnknown {
				t.Fatalf("%q: not classified: %+v", s, p)
			}
			got := Describe(p, "github.com")
			if !allPrintable(got) {
				t.Errorf("Describe leaks non-printable runes for %q: %q", s, got)
			}
			if n := utf8.RuneCountInString(got); n > 200 {
				t.Errorf("Describe line has %d runes for a long client string", n)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Printable

func TestPrintable(t *testing.T) {
	if got := Printable("ab\ncd", 3); got != "abc…" {
		t.Fatalf("%q", got)
	}
	if !strings.Contains(Printable("ok", 10), "ok") {
		t.Fatal()
	}
}

func TestPrintableCases(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"abc", 3, "abc"},                // exactly max: no ellipsis
		{"abcd", 3, "abc…"},              // one over: truncated
		{"a b", 10, "a b"},               // plain spaces are kept
		{"ééééé", 2, "éé…"},              // counts runes, not bytes
		{"\x1b[31mred", 10, "[31mred"},   // ESC removed
		{"tab\there", 10, "tabhere"},     // tab removed
		{"nul\x00del\x7f", 10, "nuldel"}, // NUL and DEL removed
		{"a‮b⁦c​d", 10, "abcd"},          // bidi overrides, zero-width removed
		{"", 5, ""},
	}
	for _, c := range cases {
		if got := Printable(c.in, c.max); got != c.want {
			t.Errorf("Printable(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
	if got := Printable(string([]byte{'a', 0xff, 'b'}), 10); !utf8.ValidString(got) {
		t.Errorf("invalid UTF-8 in, invalid UTF-8 out: %q", got)
	}
}

// ---------------------------------------------------------------------------
// DER → ecdsa-sha2-nistp256

func derSig(r, s *big.Int) []byte {
	b, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		panic(err)
	}
	return b
}

func TestECDSASignatureFromDER(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := []byte("payload")
	sum := sha256.Sum256(data)
	der, _ := ecdsa.SignASN1(rand.Reader, k, sum[:])
	sig, err := ECDSASignatureFromDER(der)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Format != ssh.KeyAlgoECDSA256 {
		t.Fatalf("format %q", sig.Format)
	}
	pub, _ := ssh.NewPublicKey(&k.PublicKey)
	if err := pub.Verify(data, sig); err != nil {
		t.Fatalf("converted signature does not verify: %v", err)
	}
	if err := pub.Verify([]byte("other payload"), sig); err == nil {
		t.Fatal("converted signature verifies other data")
	}
	if _, err := ECDSASignatureFromDER(append(der, 0)); err == nil {
		t.Fatal("trailing DER bytes accepted")
	}
	if _, err := ECDSASignatureFromDER([]byte{0x30, 0}); err == nil {
		t.Fatal("empty DER accepted")
	}
	resp := MarshalSignResponse(sig)
	if resp[0] != MsgSignResponse {
		t.Fatal("type byte")
	}
}

func TestECDSASignatureFromDERRejectsMalformed(t *testing.T) {
	one := big.NewInt(1)
	cases := map[string][]byte{
		"nil":          nil,
		"garbage":      []byte("not der at all"),
		"zero r":       derSig(big.NewInt(0), one),
		"zero s":       derSig(one, big.NewInt(0)),
		"negative r":   derSig(big.NewInt(-5), one),
		"negative s":   derSig(one, big.NewInt(-5)),
		"only r":       func() []byte { b, _ := asn1.Marshal(struct{ R *big.Int }{one}); return b }(),
		"three values": func() []byte { b, _ := asn1.Marshal(struct{ R, S, T *big.Int }{one, one, one}); return b }(),
		"truncated":    derSig(big.NewInt(12345), big.NewInt(67890))[:5],
	}
	for name, der := range cases {
		if sig, err := ECDSASignatureFromDER(der); err == nil {
			t.Errorf("%s: accepted as %+v", name, sig)
		}
	}
}

// ---------------------------------------------------------------------------
// Fuzzing: hostile input never panics and never yields half-parsed results.

func FuzzParsePayload(f *testing.F) {
	f.Add(sshsig("git"))
	f.Add(userauth(bytes.Repeat([]byte{3}, 32), MethodPublicKey, []byte("pk"), nil))
	f.Add([]byte("SSHSIG"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		p := ParsePayload(data)
		d := Describe(p, "x")
		if p.Kind == PayloadUserAuth && p.UserAuth == nil || p.Kind == PayloadSSHSig && p.SSHSig == nil {
			t.Fatal("kind without details")
		}
		if p.Len != len(data) {
			t.Fatalf("Len %d, want %d", p.Len, len(data))
		}
		if !allPrintable(d) {
			t.Fatalf("Describe produced non-printable output %q", d)
		}
	})
}

func FuzzParseSignRequest(f *testing.F) {
	f.Add(signReq([]byte("k"), []byte("d"), 0))
	f.Add(wstr([]byte{MsgExtension}, []byte(SessionBindName)))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = ParseSignRequest(body)
		_, _ = ParseExtension(body)
		_, _ = ParseSessionBind(body)
	})
}

func FuzzReadMessage(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 11})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, in []byte) {
		body, err := ReadMessage(bytes.NewReader(in))
		if err == nil && (len(body) == 0 || len(body) > MaxMessageLen) {
			t.Fatalf("accepted body of %d bytes", len(body))
		}
	})
}

// ---------------------------------------------------------------------------
// Cost bounds. Everything above parses attacker bytes, so besides being
// correct it must stay cheap: no length field may drive an allocation or a
// loop, and the heaviest structure a client can put in the largest frame
// ReadMessage admits must parse in milliseconds. These inputs were built
// while investigating a CI fuzz stall (go.yml run 38135509088), which turned
// out to be the fuzzing engine, not the parsers; the measurements that
// showed that are pinned here so a future regression would be caught by
// `make test`, not by a flaky fuzz budget.
// ---------------------------------------------------------------------------

// hostileSessionID is a valid session id for the payload and bind builders.
var hostileSessionID = bytes.Repeat([]byte{3}, 32)

// mpint appends v as an SSH mpint (two's complement, minimal, big-endian).
func mpint(dst []byte, v *big.Int) []byte {
	b := v.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return wstr(dst, b)
}

// rsaBlob is an ssh-rsa public key blob with a random odd modulus of the
// given size (a key need not be well-formed to cost a verification).
func rsaBlob(bits int, e int64) []byte {
	n := make([]byte, bits/8)
	if _, err := rand.Read(n); err != nil {
		panic(err)
	}
	n[0] |= 0x80
	n[len(n)-1] |= 1
	b := wstr(nil, []byte("ssh-rsa"))
	b = mpint(b, big.NewInt(e))
	return mpint(b, new(big.Int).SetBytes(n))
}

// certBlob is an ssh-ed25519-cert-v01@openssh.com blob for the ed25519 key
// blob key with n empty principals, signed (invalidly) by sigKey.
func certBlob(key, sigKey []byte, n int) []byte {
	b := wstr(nil, []byte("ssh-ed25519-cert-v01@openssh.com"))
	b = wstr(b, bytes.Repeat([]byte{7}, 32))          // nonce
	b = wstr(b, key[len(key)-ed25519.PublicKeySize:]) // raw public key
	b = binary.BigEndian.AppendUint64(b, 1)           // serial
	b = binary.BigEndian.AppendUint32(b, 2)           // host cert
	b = wstr(b, []byte("id"))
	principals := make([]byte, 0, 4*n)
	for i := 0; i < n; i++ {
		principals = wstr(principals, nil)
	}
	b = wstr(b, principals)
	b = binary.BigEndian.AppendUint64(b, 0)
	b = binary.BigEndian.AppendUint64(b, 1<<62)
	b = wstr(b, nil) // critical options
	b = wstr(b, nil) // extensions
	b = wstr(b, nil) // reserved
	b = wstr(b, sigKey)
	return wstr(b, wstr(wstr(nil, []byte("ssh-ed25519")), bytes.Repeat([]byte{9}, 64)))
}

func TestHostileInputsStayCheap(t *testing.T) {
	_, edPub := hostKey(t)
	ed := edPub.Marshal()
	const frame = MaxMessageLen
	ff := []byte{0xff, 0xff, 0xff, 0xff}
	fill := bytes.Repeat([]byte{'a'}, frame)
	// The largest key x/crypto/ssh parses, with the largest exponent it
	// accepts: the most expensive single Verify a client can request.
	rsaMax := rsaBlob(16384, 1<<24-1)
	// A certificate whose principal list is as long as the frame allows.
	wideCert := certBlob(ed, ed, (frame-1024)/4)
	// Certificates nested as signature keys until the frame is full. x/crypto
	// refuses a certificate signed by a certificate, so this must stop at
	// depth one rather than recurse.
	nested := ed
	for len(nested) < frame-400 {
		nested = certBlob(ed, nested, 0)
	}
	rsaSig := wstr(wstr(nil, []byte("rsa-sha2-512")), bytes.Repeat([]byte{5}, 2048))
	edSig := wstr(wstr(nil, []byte("ssh-ed25519")), bytes.Repeat([]byte{5}, 64))

	cases := map[string][]byte{
		"zero frame":                 make([]byte, frame),
		"0xff frame":                 bytes.Repeat([]byte{0xff}, frame),
		"length 0xffffffff":          ff,
		"sshsig length 0xffffffff":   append([]byte("SSHSIG"), ff...),
		"sshsig frame namespace":     sshsigFull(string(fill[:frame-100]), "sha512"),
		"userauth frame user":        userauthFull(hostileSessionID, 50, string(fill[:frame-200]), MethodPublicKey, 1, []byte("pk"), nil),
		"userauth frame pubkey":      userauth(hostileSessionID, MethodPublicKey, fill[:frame-200], nil),
		"userauth length 0xffffffff": append(wstr(nil, hostileSessionID), append([]byte{50}, ff...)...),
		"hostbound rsa-16384":        userauth(hostileSessionID, MethodPublicKeyHostbound, []byte("pk"), rsaMax),
		"hostbound wide cert":        userauth(hostileSessionID, MethodPublicKeyHostbound, []byte("pk"), wideCert),
		"hostbound nested certs":     userauth(hostileSessionID, MethodPublicKeyHostbound, []byte("pk"), nested),
		"sign request frame data":    signReq([]byte("k"), fill[:frame-100], 0),
		"sign request length 0xff..": append([]byte{MsgSignRequest}, ff...),
		"bind rsa-16384 e=2^24-1":    bind(rsaMax, hostileSessionID, rsaSig, false),
		"bind rsa-16384 e=65537":     bind(rsaBlob(16384, 65537), hostileSessionID, rsaSig, false),
		"bind wide cert":             bind(wideCert, hostileSessionID, edSig, false),
		"bind nested certs":          bind(nested, hostileSessionID, edSig, false),
		"bind frame signature":       bind(ed, hostileSessionID, fill[:frame-200], false),
		"extension frame name":       wstr([]byte{MsgExtension}, fill[:frame-100]),
	}
	// Measured worst case on a laptop: 5 ms (the RSA verify) and 6 MiB (the
	// wide certificate, x/crypto's per-principal strings). The bounds leave
	// two orders of magnitude for a loaded -race CI machine and still fail on
	// anything quadratic in a 256 KiB frame.
	const maxTime, maxAlloc = 500 * time.Millisecond, 64 << 20
	for name, in := range cases {
		if len(in) > frame {
			t.Fatalf("%s: %d bytes does not fit a frame", name, len(in))
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		p := ParsePayload(in)
		_ = Describe(p, "x")
		_, _ = ParseSignRequest(in)
		_, _ = ParseExtension(in)
		_, _ = ParseSessionBind(in)
		took := time.Since(start)
		runtime.ReadMemStats(&after)
		alloc := after.TotalAlloc - before.TotalAlloc
		t.Logf("%-28s %7d bytes  %10v  %9d bytes allocated", name, len(in), took, alloc)
		if took > maxTime {
			t.Errorf("%s: took %v, want < %v", name, took, maxTime)
		}
		if alloc > maxAlloc {
			t.Errorf("%s: allocated %d bytes, want < %d", name, alloc, maxAlloc)
		}
	}
}
