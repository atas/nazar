package main

import (
	"flag"
	"fmt"
	"regexp"
	"strings"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
)

// aws is `nazar aws …` (aws design 8).
func (a *app) aws(args []string) int {
	if len(args) == 0 {
		return a.usageError("aws: expected a subcommand (ca, list, rule, forget, credential)")
	}
	switch args[0] {
	case "credential":
		return a.awsCredential(args[1:])
	case "ca":
		return a.awsCA(args[1:])
	case "list":
		return a.awsList(args[1:])
	case "rule":
		return a.ruleEdit(awsTarget, args[1:])
	case "forget":
		return a.awsForget(args[1:])
	}
	return a.usageError("aws: unknown subcommand %q", args[0])
}

// awsArg is the one entry-name argument of an aws command.
func (a *app) awsArg(name string, args []string, flags func(fs *flag.FlagSet)) (string, error) {
	fs := a.flags(name)
	if flags != nil {
		flags(fs)
	}
	pos, err := a.parse(fs, args, 1)
	if err != nil {
		return "", err
	}
	if !config.ValidAWSName(pos[0]) {
		return "", control.NewProblem(control.CodeUsage, "%s: invalid entry name %q (letters, digits, . _ -)", name, pos[0])
	}
	return pos[0], nil
}

func (a *app) awsCA(args []string) int {
	if len(args) == 0 {
		return a.usageError("aws ca: expected create or show")
	}
	switch args[0] {
	case "create":
		return a.awsCACreate(args[1:])
	case "show":
		name, err := a.awsArg("aws ca show", args[1:], nil)
		if err != nil {
			return a.fail(err)
		}
		var ca control.AWSCA
		if err := a.call(control.CmdAWSCAShow, map[string]string{"name": name}, control.KindAWSCA, &ca); err != nil {
			return a.fail(err)
		}
		if !plainCertPEM(ca.CertPEM) {
			return a.fail(control.NewProblem(control.CodeError, "aws ca show: a malformed certificate came back"))
		}
		return a.emit(ca, func() { fmt.Fprint(a.stdout, ca.CertPEM) })
	}
	return a.usageError("aws ca: unknown subcommand %q", args[0])
}

// processPathRE is what AWS takes in a credential_process path: letters,
// digits, - _ . / and spaces (aws design 3.1).
var processPathRE = regexp.MustCompile(`^/[A-Za-z0-9_./ -]*$`)

// credentialProcess is the ~/.aws/config line for entry name: this CLI's
// absolute path (links not resolved, as k8s ca create writes kubeconfig's
// command), quoted when it has a space.
func credentialProcess(self, name string) string {
	if strings.Contains(self, " ") {
		self = `"` + self + `"`
	}
	return "credential_process = " + self + " aws credential " + name
}

// awsCACreate is `nazar aws ca create <name> [--only-when-unlocked]`: the
// CLI finds its own path; nazar-agent makes the CA and the entry on one
// login prompt (no program is pinned: aws design 6.1). Then it prints the
// AWS-side steps and the ~/.aws/config lines; nazar runs none of them.
func (a *app) awsCACreate(args []string) int {
	var onlyWhenUnlocked *bool
	name, err := a.awsArg("aws ca create", args, func(fs *flag.FlagSet) { onlyWhenUnlocked = onlyWhenUnlockedFlag(fs) })
	if err != nil {
		return a.fail(err)
	}
	self := ""
	if a.selfPath != nil {
		self, err = a.selfPath()
	}
	if err != nil || !processPathRE.MatchString(self) || strings.Contains(self, "//") || strings.Contains(self, "/./") || strings.Contains(self, "/../") {
		return a.fail(control.NewProblem(control.CodeError, "aws ca create: can't tell this nazar's absolute path, or it has a character credential_process does not take (letters, digits, - _ . / and spaces)"))
	}
	var e control.AWSEntry
	if err := a.call(control.CmdAWSCACreate, withOnlyWhenUnlocked(map[string]string{"name": name}, *onlyWhenUnlocked), control.KindAWSEntry, &e); err != nil {
		return a.fail(err)
	}
	if e.CA == nil || !plainCertPEM(e.CA.CertPEM) || e.Identity == nil || !config.ValidAWSUser(e.Identity.User) || e.Name != name {
		return a.fail(control.NewProblem(control.CodeError, "aws ca create: nazar-agent's reply has no usable CA certificate or identity; nazar aws list shows the entry"))
	}
	if *onlyWhenUnlocked && e.CA.WhileLocked {
		return a.fail(a.wrongAccess("the CA of "+name, "nazar aws forget "+name))
	}
	return a.emit(e, func() {
		fmt.Fprintf(a.stdout, "%s is set up: its CA is in %s (SHA-256 %s), config.yaml has aws.%s.\n",
			name, a.traits().Chip, term(e.CA.Fingerprint), name)
		fmt.Fprintln(a.stdout, a.caLockedLine(e.CA.WhileLocked))
		fmt.Fprint(a.stdout, awsSteps(name, term(e.CA.CertFile), e.Identity.User, credentialProcess(self, name), a.traits()))
	})
}

// awsSteps are aws design 10, filled in: what makes AWS trust the CA and the
// AWS CLI use the entry. nazar runs none of it. Step 1 needs jq, to put
// the PEM into the JSON AWS takes; it says so.
func awsSteps(name, certFile, user, process string, tr platform.Traits) string {
	return fmt.Sprintf(`
Next, with your AWS admin credentials (nazar runs none of this; read each step before you run it):

1. A trust anchor holding the CA (this step needs jq: brew install jq):
  aws rolesanywhere create-trust-anchor --name nazar-%[1]s --enabled \
    --source "$(jq -n --rawfile pem %[2]s \
      '{sourceType: "CERTIFICATE_BUNDLE", sourceData: {x509CertificateData: $pem}}')"

2. A role that trusts Roles Anywhere for this trust anchor and this identity only. Save as
   trust.json, with the trust anchor's ARN from step 1:
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
  "Principal": {"Service": "rolesanywhere.amazonaws.com"},
  "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
  "Condition": {
    "ArnEquals": {"aws:SourceArn": "<trust anchor ARN>"},
    "StringEquals": {"aws:PrincipalTag/x509Subject/CN": "%[3]s",
                     "aws:PrincipalTag/x509Issuer/CN": "nazar aws CA %[1]s"}}}]}
  aws iam create-role --role-name %[1]s --assume-role-policy-document file://trust.json
  then attach the permissions the role should have.

3. A profile naming the role:
  aws rolesanywhere create-profile --name nazar-%[1]s --role-arns <role ARN> --duration-seconds 3600 --enabled

4. Connect the entry: add the three ARNs to aws.%[1]s in ~/.nazar/config/config.yaml:
    trustAnchorArn: <trust anchor ARN>
    profileArn: <profile ARN>
    roleArn: <role ARN>
   That loosens access, so it waits for nazar config apply and %[5]s.

5. Add the profile to ~/.aws/config (nazar never edits it):
[profile %[1]s]
%[4]s

6. Check it:
  aws sts get-caller-identity --profile %[1]s
  nazar log --target aws:%[1]s --since 10m
`, name, certFile, user, process, tr.LoginGate)
}

func (a *app) awsList(args []string) int {
	if _, err := a.parse(a.flags("aws list"), args, 0); err != nil {
		return a.fail(err)
	}
	var l control.AWSEntryList
	if err := a.call(control.CmdAWSList, nil, control.KindAWSEntryList, &l); err != nil {
		return a.fail(err)
	}
	return a.emit(l, func() {
		if len(l.Items) == 0 {
			fmt.Fprintln(a.stdout, "No aws entries. nazar aws ca create <name> sets one up.")
		}
		for _, e := range l.Items {
			fmt.Fprintln(a.stdout, term(e.Name))
			if e.Configured && e.Identity != nil {
				fmt.Fprintf(a.stdout, "  CN=%s, sessions of %s\n", term(e.Identity.User), term(e.Duration))
				if e.RoleArn != "" {
					fmt.Fprintf(a.stdout, "  role: %s\n  trust anchor: %s\n  profile: %s\n", term(e.RoleArn), term(e.TrustAnchorArn), term(e.ProfileArn))
				}
				for _, r := range e.Rules {
					fmt.Fprintf(a.stdout, "  rule %s\n", term(r))
				}
			} else if !e.CABroken {
				fmt.Fprintln(a.stdout, "  not in config.yaml: "+term(e.Remedy))
			}
			switch {
			case e.State == control.AWSStateNotConnected:
				fmt.Fprintf(a.stdout, "  %s\n", term(e.Remedy))
			case e.CABroken:
				fmt.Fprintf(a.stdout, "  CA unusable: %s\n  fix: %s\n", term(e.UnusableReason), term(e.Remedy))
			case e.CA == nil && e.Remedy != "":
				fmt.Fprintf(a.stdout, "  no CA: %s\n", term(e.Remedy))
			}
			if e.CA != nil {
				mark := ""
				if !e.CA.WhileLocked {
					mark = ", " + onlyWhenUnlockedMark
				}
				fmt.Fprintf(a.stdout, "  CA: SHA-256 %s, %s%s\n", term(e.CA.Fingerprint), term(e.CA.CertFile), mark)
			}
		}
	})
}

// awsForget is `nazar aws forget <name>`: nazar-agent destroys the CA and
// the config entry on its prompt. AWS and ~/.aws/config are the user's.
func (a *app) awsForget(args []string) int {
	name, err := a.awsArg("aws forget", args, nil)
	if err != nil {
		return a.fail(err)
	}
	var e control.AWSEntry
	if err := a.call(control.CmdAWSForget, map[string]string{"name": name}, control.KindAWSEntry, &e); err != nil {
		return a.fail(err)
	}
	return a.emit(e, func() {
		fmt.Fprintf(a.stdout, "nazar forgot %s: it has no CA and no config.yaml entry now.\n", name)
		fmt.Fprintf(a.stdout, "AWS still trusts the CA's certificate until you disable or delete the trust anchor nazar-%s (nothing can be issued under it any more):\n", name)
		fmt.Fprintf(a.stdout, "  aws rolesanywhere disable-trust-anchor --trust-anchor-id <id>\n")
		fmt.Fprintf(a.stdout, "Remove the credential_process line of [profile %s] from ~/.aws/config too.\n", name)
	})
}
