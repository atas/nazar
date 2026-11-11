package configstage

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
)

// App team pins (spec 4.2 "pinned on first load", 4.8). An `app:` matcher
// without team: matches only the team pinned for its bundle ID, and
// core/match never writes a pin. Pins are created here, from the INSTALLED
// app, and only behind the login gate:
//
//   - A loosening config change shows, in its diff, the pin for every
//     unpinned app: matcher whose bundle resolves to a validly signed
//     installed app; approving records exactly those pins. A bundle ID new
//     to the config makes the change a loosening by itself, because a new
//     pin is new trust.
//   - A tightening applies at once and never pins; an app: matcher it
//     carries without a pin stays inactive (matches nothing) until a
//     loosening is approved or `nazar trust --app` pins it. AppProblems
//     reports every inactive or mismatched matcher with that fix.
//   - A config change never changes an existing pin. Only TrustApp (`nazar
//     trust --app`, behind the gate) replaces one, after showing the old
//     and the new team.

// AppResolver resolves a bundle ID to the installed app (platform.Platform).
type AppResolver interface {
	InstalledApp(bundleID string) (platform.AppBundle, error)
}

// PinStore is the pin side of the trust store (*trust.Store).
type PinStore interface {
	PinnedTeam(bundleID string) (string, bool)
	Pin(bundleID, team string) (string, error) // first writer wins
	SetPin(bundleID, team string) error        // replace
}

// PinChange is one pin an approval records: Team of the bundle at Path
// becomes the pin for BundleID. Old is the pin replaced ("" for a new pin;
// only TrustApp ever replaces one).
type PinChange struct {
	BundleID, Team, Old, Path string
}

// AppProblem is an app: matcher that matches nothing or whose installed app
// no longer matches its pin, with the command that fixes it. Fix is empty
// when no command can: the platform says no process can ever match the id
// (on Linux an entry that runs a launcher or a script), and the reason
// says what the entry is instead.
type AppProblem struct {
	BundleID, Reason, Fix string
}

// ErrNotApproved: the login gate was not passed for the change.
var ErrNotApproved = errors.New("configstage: the change was not approved")

// FixTrustApp is the fix for an unpinned or mismatched app: matcher, as a
// shell command: a bundle id that is not a plain word is single-quoted.
func FixTrustApp(bundleID string) string { return "nazar trust --app " + ShellWord(bundleID) }

// q quotes a value that comes from outside the config approval (a bundle
// path or team read from disk, a bundle id from the config file, a pin or
// error text) for the strings the user sees. ASCII-only, with every control
// character and non-ASCII rune escaped, so a crafted path cannot forge a
// second pin line, a terminal escape or a bidi override in the approval
// diff, and so an id containing a quote cannot end its own quoting.
func q(s string) string { return strconv.QuoteToASCII(s) }

// appTarget is the Finding.Target of an app: pin, "app:" + the quoted
// bundle id, as Matcher.Canonical spells it.
func appTarget(bundleID string) string { return "app:" + q(bundleID) }

// ShellWord returns s for a shell: bare when it is a plain word (letters,
// digits, dot, underscore, dash), else single-quoted with every single
// quote in it closed, backslash-escaped and reopened. (Also the CLI's, for
// the command line it suggests for a refused loosening.)
func ShellWord(s string) string {
	plain := s != ""
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			plain = false
			break
		}
	}
	if plain {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// appIDs lists, sorted and without duplicates, the bundle IDs of the app:
// matchers without an explicit team: in the rules of c's keys and secrets
// (apps: and to:).
// Those are the matchers in force, so those are the ones that need a pin.
func appIDs(c *config.Config) []string {
	seen := map[string]bool{}
	add := func(ms []config.Matcher) {
		for _, m := range ms {
			if m.Kind == config.MatchApp && m.Team == "" && m.ID != "" {
				seen[m.ID] = true
			}
		}
	}
	for _, k := range c.SSHAgent.Keys {
		for _, r := range k.Rules {
			add(r.Apps)
			add(r.To)
		}
	}
	for _, s := range c.Secrets {
		for _, r := range s.Rules {
			add(r.Apps)
			add(r.To)
		}
	}
	for _, k := range c.K8s {
		for _, r := range k.Rules {
			add(r.Apps)
		}
	}
	for _, e := range c.AWS {
		for _, r := range e.Rules {
			add(r.Apps)
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// pinWords words the pin texts for what a pin records: the signing team
// on macOS (hash false), the executable's hash on a platform without code
// signatures (Linux, spec "app: on Linux"), where an update of the app
// changes the hash and `nazar trust --app` pins the new one.
type pinWords struct{ hash bool }

// wordsOf is the pinWords of the platform apps is: a platform.Describer
// whose PinWord is not macOS's pins hashes; anything else is macOS.
func wordsOf(apps AppResolver) pinWords {
	if d, ok := apps.(platform.Describer); ok {
		return pinWords{hash: d.Traits().PinWord != platform.MacTraits.PinWord}
	}
	return pinWords{}
}

// resolve returns the installed bundle for id when it is validly signed, or
// a reason it can't be pinned. unpinnable is set when the platform itself
// says no process can ever match the id (a platform.NotFoundError; on
// Linux an entry that runs a launcher or a script, a Terminal=true entry,
// or an id another entry owns): then no pin, old or new, would help, and
// `nazar trust --app` would refuse with the same reason. The macOS
// platform never returns one.
func resolve(apps AppResolver, id string) (b platform.AppBundle, why string, unpinnable bool) {
	w := wordsOf(apps)
	b, err := apps.InstalledApp(id)
	var nf *platform.NotFoundError
	switch {
	case errors.As(err, &nf):
		// The platform knows why nothing can match this id; "not
		// installed" would be false.
		return b, nf.Reason, true
	case errors.Is(err, platform.ErrNotFound) && w.hash:
		return b, "no app with this app id is installed", false
	case errors.Is(err, platform.ErrNotFound):
		return b, "no app with this bundle id is installed", false
	case errors.Is(err, platform.ErrAmbiguous) && w.hash:
		return b, "several installed apps have this app id, with different executables", false
	case errors.Is(err, platform.ErrAmbiguous):
		return b, "several installed apps have this bundle id and they are signed by different teams", false
	case err != nil:
		return b, "the installed app could not be checked: " + q(err.Error()), false
	case b.Code.Team() == "" && w.hash:
		return b, fmt.Sprintf("the installed app at %s has no executable hash to pin", q(b.Path)), false
	case b.Code.Team() == "":
		return b, fmt.Sprintf("the installed app at %s is not validly signed, so it has no team to pin", q(b.Path)), false
	}
	return b, "", false
}

// stagePins adds to d the pins an approval of nw would record (d.Pins), each
// as a Loosening finding and a change, so the login prompt shows which team
// is trusted for which bundle id. A bundle id that is new to the config
// forces the gate; one the active config already carried is pinned only
// when the change goes to the gate anyway, so a tightening never pins.
func stagePins(pins PinStore, apps AppResolver, old, nw *config.Config, d *Diff) {
	if pins == nil || apps == nil {
		return
	}
	was := map[string]bool{}
	for _, id := range appIDs(old) {
		was[id] = true
	}
	var cands []PinChange
	forced := false
	for _, id := range appIDs(nw) {
		if _, ok := pins.PinnedTeam(id); ok {
			continue // never changed by a config change
		}
		b, why, _ := resolve(apps, id)
		if why != "" {
			continue // stays inactive; AppProblems reports it
		}
		cands = append(cands, PinChange{BundleID: id, Team: b.Code.Team(), Path: b.Path})
		if !was[id] {
			forced = true
		}
	}
	if !forced && !d.Loosens() {
		return
	}
	w := wordsOf(apps)
	for _, c := range cands {
		d.Pins = append(d.Pins, c)
		if w.hash {
			d.Changes = append(d.Changes, fmt.Sprintf("%s: executable hash %s pinned from %s", appTarget(c.BundleID), q(c.Team), q(c.Path)))
			d.Loosening = append(d.Loosening, Finding{Target: appTarget(c.BundleID), Why: fmt.Sprintf(
				"trusts the executable at %s (hash %s) as this app from now on; an update of the app changes the hash, and then `%s` pins the new one",
				q(c.Path), q(c.Team), FixTrustApp(c.BundleID))})
			continue
		}
		d.Changes = append(d.Changes, fmt.Sprintf("%s: team %s pinned from %s", appTarget(c.BundleID), q(c.Team), q(c.Path)))
		d.Loosening = append(d.Loosening, Finding{Target: appTarget(c.BundleID), Why: fmt.Sprintf(
			"trusts team %s, the signer of the installed app at %s, as this app from now on", q(c.Team), q(c.Path))})
	}
}

// recordPins writes the pins an approval showed. First writer wins: a pin
// that appeared meanwhile is kept, and reported when it is not the team the
// user approved.
func recordPins(pins PinStore, w pinWords, changes []PinChange) error {
	what := "team"
	if w.hash {
		what = "executable hash"
	}
	for _, c := range changes {
		got, err := pins.Pin(c.BundleID, c.Team)
		if err != nil {
			return err
		}
		if got != c.Team {
			return fmt.Errorf("%w: app %s is now pinned to %s %s, not the %s that was approved", ErrStale, q(c.BundleID), what, q(got), q(c.Team))
		}
	}
	return nil
}

// AppProblems lists, for `nazar config check` and `nazar status`, every
// app: matcher of c that matches nothing (no pin, because the app is not
// installed, ambiguous or not validly signed, or because it was never
// approved behind the gate) or whose installed app is signed by another
// team than the pin, each with the fix. An id the platform says no process
// can ever match is reported with its reason whether or not it has a pin
// (an upgrade can turn a pinned app's program into a wrapper script), and
// with no fix: `nazar trust --app` would refuse it with the same reason.
// Sorted by bundle id.
func AppProblems(c *config.Config, pins PinStore, apps AppResolver) []AppProblem {
	var out []AppProblem
	w := wordsOf(apps)
	for _, id := range appIDs(c) {
		b, why, unpinnable := resolve(apps, id)
		pinned, ok := pins.PinnedTeam(id)
		switch {
		case unpinnable:
			out = append(out, AppProblem{BundleID: id, Reason: why + "; the matcher matches nothing"})
			continue
		case ok && why == "" && b.Code.Team() != pinned && w.hash:
			why = fmt.Sprintf("the installed app's executable at %s has hash %s but %s is pinned, so it does not match (an update of the app replaces its executable; find out why it changed before you run the fix)",
				q(b.Path), q(b.Code.Team()), q(pinned))
		case ok && why == "" && b.Code.Team() != pinned:
			why = fmt.Sprintf("the installed app at %s is signed by team %s but %s is pinned, so it does not match", q(b.Path), q(b.Code.Team()), q(pinned))
		case ok:
			continue
		case why == "" && w.hash:
			why = fmt.Sprintf("executable hash %s of the installed app at %s is not pinned yet, so the matcher matches nothing", q(b.Code.Team()), q(b.Path))
		case why == "":
			why = fmt.Sprintf("team %s of the installed app at %s is not pinned yet, so the matcher matches nothing", q(b.Code.Team()), q(b.Path))
		default:
			why += "; the matcher matches nothing"
		}
		out = append(out, AppProblem{BundleID: id, Reason: why, Fix: FixTrustApp(id)})
	}
	return out
}

// TrustApp is `nazar trust --app <bundle id>`: it resolves the installed
// app, refuses one that can't be pinned before any prompt, shows the pin
// (with the pin it replaces, if any) to approve, which must run the login
// gate, and records it only on approval. The pin written is the one shown,
// whatever is installed by then. An app already pinned to the installed
// team needs nothing and is returned without a prompt.
func TrustApp(bundleID string, pins PinStore, apps AppResolver, approve func(PinChange) (bool, error)) (PinChange, error) {
	if bundleID == "" {
		return PinChange{}, errors.New("configstage: a bundle id is required")
	}
	b, err := apps.InstalledApp(bundleID)
	var nf *platform.NotFoundError
	if errors.As(err, &nf) {
		// The platform's reason, bare: the error it came wrapped in names
		// the platform and the id again (Linux: "desktop: <id>: ...").
		return PinChange{}, fmt.Errorf("configstage: app %s can't be pinned: %w", q(bundleID), nf)
	}
	if err != nil {
		return PinChange{}, fmt.Errorf("configstage: app %s can't be pinned: %w", q(bundleID), err)
	}
	team := b.Code.Team()
	if team == "" && wordsOf(apps).hash {
		return PinChange{}, fmt.Errorf("configstage: app %s can't be pinned: the executable at %s has no hash to pin", q(bundleID), q(b.Path))
	}
	if team == "" {
		return PinChange{}, fmt.Errorf("configstage: app %s can't be pinned: the bundle at %s is not validly signed", q(bundleID), q(b.Path))
	}
	c := PinChange{BundleID: bundleID, Team: team, Path: b.Path}
	c.Old, _ = pins.PinnedTeam(bundleID)
	if c.Old == team {
		return c, nil
	}
	ok, err := approve(c)
	if err != nil {
		return c, err
	}
	if !ok {
		return c, ErrNotApproved
	}
	if err := pins.SetPin(c.BundleID, c.Team); err != nil {
		return c, err
	}
	return c, nil
}
