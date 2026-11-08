package config

import "reflect"

// The old forms: what builds before accepted and this one refuses, so
// that each key has one shape and one meaning (spec 4.8, "Migration to
// today's form"). The legacy reading (parser.legacy) reads them as those
// builds did and records, for each one a rewrite can drop or reshape
// without changing what it means, the edit (parser.fixes):
//
//   - apps: or to: as one matcher on its own: wrapped in a list of one;
//   - scope or expire next to gate: none or block, and expire next to
//     scope: use, which those builds ignored: removed;
//   - any in to:, which matches every receiver, as no to: does: the
//     to: removed on a secret's rule (a secret's approvals always name
//     their receiver) and on a key's rule that remembers nothing (gate
//     none or block, or scope: use), and read as no to: there.
//
// Two old forms have no rewrite of the same meaning, and are only read:
//
//   - a team: spelled apple in another case ("Apple"): matched exactly, it
//     matches nothing, where apple matches Apple's programs;
//   - any in to: on a key's rule that remembers approvals: each approval
//     then names the program that receives the signature, which it does
//     not without to:.
//
// A file with them stays invalid (Parse says how to fix it) and is left for
// the user, while ParseApproved keeps the approved config that holds them
// in force: no rewrite approves something the user did not.

// Migrate rewrites a config written in old forms into today's, where that
// keeps its meaning. ok is true only when data does not parse as it is,
// parses read the old way, holds something to rewrite, and the rewrite
// reads (the old way) to exactly the same config: every key, secret,
// context and entry, every rule and matcher. The rewrite may still hold the
// forms that have no rewrite (ParseApproved reads it; Parse refuses it).
// Otherwise out is nil and data is left as it is. The rewrite is written as
// every nazar edit is (encode), so the same data always gives the same out.
func Migrate(data []byte, env Env) (out []byte, ok bool) {
	if _, probs := Parse(data, env); !probs.HasErrors() {
		return nil, false
	}
	p := &parser{env: env, legacy: true}
	old := p.parse(data)
	if p.probs.HasErrors() || old == nil || len(p.fixes) == 0 || p.doc == nil {
		return nil, false
	}
	for _, f := range p.fixes {
		f()
	}
	b, err := encode(p.doc)
	if err != nil {
		return nil, false
	}
	q := &parser{env: env, legacy: true}
	nw := q.parse(b)
	if q.probs.HasErrors() || nw == nil || len(q.fixes) != 0 || !sameMeaning(old, nw) {
		return nil, false
	}
	return b, true
}

// ParseApproved reads the approved config nazar-agent keeps in the vault
// (configstage.Open): as Parse, except that the old forms are read as the
// builds that approved them read them, each with a warning. Only that item
// is read this way; config.yaml is read by Parse, which refuses them, so a
// file another process writes gains nothing from it.
func ParseApproved(data []byte, env Env) (*Config, Problems) {
	return read(&parser{env: env, legacy: true}, data)
}

// sameMeaning reports whether a and b are the same config, apart from the
// bytes they were read from.
func sameMeaning(a, b *Config) bool {
	x, y := *a, *b
	x.Raw, x.Hash, y.Raw, y.Hash = nil, "", nil, ""
	return reflect.DeepEqual(x, y)
}
