package config

import (
	"strings"
	"testing"
	"time"
)

// aws design 7: the aws section, an entry per Roles Anywhere role with its
// identity, the three ARNs and duration; rules, scope, gate and expire as
// for a k8s context, judged on whoever ran the program that runs
// credential_process. There is no clients: list (aws design 6.1).

const (
	awsAnchor  = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539"
	awsProfile = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/6f4943fb-13d4-4242-89c4-be367595c380"
	awsRole    = "arn:aws:iam::123456789012:role/dev"
)

const awsApps = hdr + `apps:
  iterm: {app: com.googlecode.iterm2}
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  aws: {signed: {team: AWSTEAM001}}
  awscli: {signed: {team: 94KV3E626L, id: aws}}
  terraform: {signed: {team: TFTEAM0001}}
`

// awsDev is a connected dev entry; extra is added to its mapping (4 spaces
// deep).
func awsDev(extra string) string {
	return awsApps + `aws:
  dev:
    identity: {user: you-nazar}
    trustAnchorArn: ` + awsAnchor + `
    profileArn: ` + awsProfile + `
    roleArn: ` + awsRole + "\n" + extra
}

func TestAWSEntryParses(t *testing.T) {
	c, probs := mustParse(t, awsDev(`    duration: 30m
    gate: block
    rules:
      - apps: [iterm]
        scope: session
        gate: login
        expire: 8h
      - apps: [claude]
        gate: dialog
`))
	if strings.Contains(probs.Error(), "not connected") {
		t.Fatalf("a connected entry: %v", probs)
	}
	e := c.AWS["dev"]
	if e == nil {
		t.Fatal("no dev")
	}
	if e.Name != "dev" || e.Identity.User != "you-nazar" || e.TrustAnchorArn != awsAnchor || e.ProfileArn != awsProfile ||
		e.RoleArn != awsRole || e.Duration != 30*time.Minute || !e.Connected() {
		t.Fatalf("%+v", e)
	}
	if e.Region != "us-east-1" || e.Account != "123456789012" {
		t.Fatalf("region %q account %q", e.Region, e.Account)
	}
	if len(e.Rules) != 2 || e.Rules[0].Policy != (Policy{Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}) ||
		e.Rules[1].Policy.Gate != GateDialog {
		t.Fatalf("rules %+v", e.Rules)
	}
	if e.Own == nil || e.Own.Gate != GateBlock || c.AWSFallback("dev") != *e.Own {
		t.Fatalf("own %+v", e.Own)
	}
	if c.AWSFallback("nope") != c.Defaults.Fallback {
		t.Fatal("an unknown entry falls back to defaults.fallback")
	}
	if got := strings.Join(c.AWSNames(), ","); got != "dev" {
		t.Fatal(got)
	}
}

func TestAWSEntryDefaults(t *testing.T) {
	c, _ := mustParse(t, awsDev(""))
	e := c.AWS["dev"]
	if e.Duration != DefaultAWSDuration || DefaultAWSDuration != time.Hour {
		t.Fatalf("duration defaults to 1h: %v", e.Duration)
	}
	if e.Own != nil || len(e.Rules) != 0 || c.AWSFallback("dev") != c.Defaults.Fallback {
		t.Fatalf("no own policy: %+v", e.Own)
	}
	// The range's ends are accepted.
	for _, d := range []string{"15m", "1h", "900s"} {
		mustParse(t, awsDev("    duration: "+d+"\n"))
	}
}

// An entry with none of the ARNs is valid and not connected yet: what ca
// create writes, with the steps that connect it.
func TestAWSEntryNotConnected(t *testing.T) {
	c, probs := mustParse(t, awsApps+"aws:\n  dev:\n    identity: {user: you-nazar}\n    gate: block\n")
	e := c.AWS["dev"]
	if e == nil || e.Connected() || e.Region != "" || e.Account != "" {
		t.Fatalf("%+v", e)
	}
	want := "aws.dev is not connected yet: add trustAnchorArn, profileArn and roleArn (nazar aws ca create printed the steps)"
	if !strings.Contains(probs.Error(), want) {
		t.Fatalf("want the not-connected warning, got %v", probs)
	}
	if NotConnected("dev") != want {
		t.Fatal(NotConnected("dev"))
	}
}

func TestAWSEntryValidation(t *testing.T) {
	id := "    identity: {user: you-nazar}\n"
	arns := func(anchor, profile, role string) string {
		s := ""
		if anchor != "" {
			s += "    trustAnchorArn: \"" + anchor + "\"\n"
		}
		if profile != "" {
			s += "    profileArn: \"" + profile + "\"\n"
		}
		if role != "" {
			s += "    roleArn: \"" + role + "\"\n"
		}
		return s
	}
	base := func(body string) string { return awsApps + "aws:\n  dev:\n" + body }
	ok := arns(awsAnchor, awsProfile, awsRole)
	euAnchor := strings.Replace(awsAnchor, "us-east-1", "eu-west-2", 1)
	for name, tc := range map[string]struct{ src, want string }{
		"no identity":          {base(ok), "identity is required"},
		"bare entry":           {awsApps + "aws:\n  dev:\n", "identity is required"},
		"no user":              {base("    identity: {}\n" + ok), "identity.user"},
		"empty user":           {base("    identity: {user: \"\"}\n" + ok), "identity.user must be 1 to 61"},
		"user with space":      {base("    identity: {user: \"a b\"}\n" + ok), "identity.user must be 1 to 61"},
		"user too long":        {base("    identity: {user: " + strings.Repeat("a", 62) + "}\n" + ok), "identity.user must be 1 to 61"},
		"non-ascii user":       {base("    identity: {user: \"yoú\"}\n" + ok), "identity.user must be 1 to 61"},
		"groups":               {base("    identity: {user: a, groups: [x]}\n" + ok), "the identity.groups: field is not in this version"},
		"identity unknown key": {base("    identity: {user: a, uid: \"1\"}\n" + ok), "unknown field"},
		"anchor only":          {base(id + arns(awsAnchor, "", "")), "trustAnchorArn, profileArn and roleArn go together"},
		"no role":              {base(id + arns(awsAnchor, awsProfile, "")), "trustAnchorArn, profileArn and roleArn go together"},
		"role only":            {base(id + arns("", "", awsRole)), "trustAnchorArn, profileArn and roleArn go together"},
		"anchor shape":         {base(id + arns("arn:aws:rolesanywhere:us-east-1:123456789012:profile/4579702c-9abb-47c2-88b2-c734e0b29539", awsProfile, awsRole)), "trustAnchorArn must be arn:aws:rolesanywhere:<region>:<account>:trust-anchor/<id>"},
		"anchor short account": {base(id + arns(strings.Replace(awsAnchor, "123456789012", "12345", 1), awsProfile, awsRole)), "trustAnchorArn must be"},
		"anchor bad id":        {base(id + arns(strings.Replace(awsAnchor, "4579702c", "XYZ", 1), awsProfile, awsRole)), "trustAnchorArn must be"},
		"anchor trailing":      {base(id + arns(awsAnchor+"/x", awsProfile, awsRole)), "trustAnchorArn must be"},
		"anchor newline":       {base(id + arns(awsAnchor+"\\n", awsProfile, awsRole)), "trustAnchorArn must be"},
		"anchor region shape":  {base(id + arns(strings.Replace(awsAnchor, "us-east-1", "useast1", 1), strings.Replace(awsProfile, "us-east-1", "useast1", 1), awsRole)), "region"},
		"profile shape":        {base(id + arns(awsAnchor, strings.Replace(awsProfile, "profile/", "role/", 1), awsRole)), "profileArn must be arn:aws:rolesanywhere:<region>:<account>:profile/<id>"},
		"profile other region": {base(id + arns(euAnchor, awsProfile, awsRole)), "profileArn is in us-east-1, the trust anchor in eu-west-2: they must be in one region"},
		"role shape":           {base(id + arns(awsAnchor, awsProfile, "arn:aws:iam::123456789012:user/dev")), "roleArn must be arn:aws:iam::<account>:role/<name>"},
		"role region":          {base(id + arns(awsAnchor, awsProfile, "arn:aws:iam:us-east-1:123456789012:role/dev")), "roleArn must be"},
		"role empty name":      {base(id + arns(awsAnchor, awsProfile, "arn:aws:iam::123456789012:role/")), "roleArn must be"},
		"role bad char":        {base(id + arns(awsAnchor, awsProfile, "arn:aws:iam::123456789012:role/d e")), "roleArn must be"},
		"china":                {base(id + arns(strings.Replace(awsAnchor, "arn:aws:", "arn:aws-cn:", 1), strings.Replace(awsProfile, "arn:aws:", "arn:aws-cn:", 1), "arn:aws-cn:iam::123456789012:role/dev")), "only the aws partition is in this version"},
		"gov role":             {base(id + arns(awsAnchor, awsProfile, "arn:aws-us-gov:iam::123456789012:role/dev")), "only the aws partition is in this version"},
		"arn not a string":     {base(id + "    trustAnchorArn: [a]\n    profileArn: x\n    roleArn: y\n"), "must be a string"},
		"duration short":       {base(id + ok + "    duration: 14m\n"), "duration must be between 15m and 1h, not 14m0s"},
		"duration long":        {base(id + ok + "    duration: 61m\n"), "duration must be between 15m and 1h"},
		"duration bad":         {base(id + ok + "    duration: soon\n"), "duration"},
		"unknown field":        {base(id + ok + "    region: us-east-1\n"), "unknown field"},
		// There is no client list (aws design 6.1): the line is an error
		// that says so, whatever it lists.
		"clients":       {base(id + ok + "    clients: [aws]\n"), "aws.dev.clients: " + AWSNoClients},
		"clients empty": {base(id + ok + "    clients: []\n"), AWSNoClients},
		"clients one":   {base(id + ok + "    clients: terraform\n"), AWSNoClients},
		"own gate none": {base(id + ok + "    gate: none\n"), "an aws entry's own gate applies to every caller, so it can't be none"},
		"rule to":       {base(id + ok + "    rules:\n      - apps: [iterm]\n        to: [aws]\n        gate: login\n"), "aws rules take no to:; the program that runs credential_process receives the credential"},
		// A rule naming aws would match aws running another program
		// (aws ▸ x ▸ nazar), never aws asking: refused, as kubectl is for k8s.
		"rule names aws":     {base(id + ok + "    rules:\n      - apps: [aws]\n        gate: login\n"), "rule 1 names aws; rules are judged on who called it"},
		"rule aws of a team": {base(id + ok + "    rules:\n      - apps: [awscli]\n        gate: login\n"), "names aws"},
		"rule inline aws":    {base(id + ok + "    rules:\n      - apps: [{path: /opt/homebrew/bin/aws}]\n        gate: login\n"), "it would pass any program aws runs"},
		"rule any none":      {base(id + ok + "    rules:\n      - apps: [any]\n        gate: none\n"), "rule 1 would give this entry's credential to every program on this Mac without asking"},
		"rule unknown none":  {base(id + ok + "    rules:\n      - apps: [unknown]\n        gate: none\n"), "every program"},
		"rule command":       {base(id + ok + "    rules:\n      - apps: [{command: [x]}]\n        gate: login\n"), "command: matchers are only allowed in to:"},
		"entry not a map":    {awsApps + "aws:\n  dev: [1]\n", "must be a mapping"},
		"aws not a map":      {awsApps + "aws: [1]\n", "must be a mapping"},
	} {
		t.Run(name, func(t *testing.T) { wantError(t, tc.src, tc.want) })
	}
	// No apps.aws is needed, and a role with a path passes.
	noAWS := strings.Replace(base(id+arns(awsAnchor, awsProfile, "arn:aws:iam::123456789012:role/team/ci/deploy-1.x@y")), "  aws: {signed: {team: AWSTEAM001}}\n", "", 1)
	c, _ := mustParse(t, noAWS)
	if e := c.AWS["dev"]; e == nil || e.RoleArn != "arn:aws:iam::123456789012:role/team/ci/deploy-1.x@y" {
		t.Fatalf("%+v", e)
	}
	// A rule naming the terminal or another tool is fine.
	mustParse(t, base(id+ok+"    rules:\n      - apps: [terraform]\n        gate: dialog\n      - apps: [iterm]\n        gate: login\n"))
	// A user of exactly 61 bytes passes.
	mustParse(t, base("    identity: {user: "+strings.Repeat("a", 61)+"}\n"+ok))
}

func TestAWSEntryNames(t *testing.T) {
	for _, ok := range []string{"dev", "prod-admin", "a.b_c", "A1", strings.Repeat("a", 64)} {
		if !ValidAWSName(ok) {
			t.Errorf("%q must be valid", ok)
		}
	}
	for _, bad := range []string{"", "-a", ".a", "a/b", "a:b", "a b", "a..b", "a@b", "ä", "a\n", strings.Repeat("a", 65)} {
		if ValidAWSName(bad) {
			t.Errorf("%q must be invalid", bad)
		}
	}
	src := awsApps + "aws:\n"
	for _, n := range []string{"dev", "DEV"} {
		src += "  " + n + ":\n    identity: {user: a}\n"
	}
	wantError(t, src, "names must differ in more than letter case")
	wantError(t, awsApps+"aws:\n  \"a:b\":\n    identity: {user: a}\n", "aws entry names are letters, digits, . _ and -, at most 64 bytes")
}

// Rules of an entry are checked for order like a key's.
func TestAWSRuleOrderWarnings(t *testing.T) {
	_, probs := mustParse(t, awsDev("    rules:\n      - apps: [any]\n        gate: dialog\n      - apps: [iterm]\n        gate: login\n"))
	if !strings.Contains(probs.Error(), "aws.dev.rules[2]") || !strings.Contains(probs.Error(), "can never match: rule 1") {
		t.Fatalf("want the shadowing warning: %v", probs)
	}
}

func TestAWSARNParts(t *testing.T) {
	region, account, ok := ParseTrustAnchorArn(awsAnchor)
	if !ok || region != "us-east-1" || account != "123456789012" {
		t.Fatal(region, account, ok)
	}
	if _, _, ok := ParseTrustAnchorArn(awsProfile); ok {
		t.Fatal("a profile is no trust anchor")
	}
}
