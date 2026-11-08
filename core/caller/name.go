package caller

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/atas/nazar/core/platform"
)

// DeletedMark follows the name of a process whose executable file is gone
// (the kernel reports no path for it), e.g. Claude Code after it updated
// itself while running.
const DeletedMark = " (file deleted)"

// versionNameRE is a file name that is a version, not a program name:
// Claude Code runs from ~/.local/share/claude/versions/2.1.299.
var versionNameRE = regexp.MustCompile(`^v?[0-9]+([._-][0-9A-Za-z]+)*$`)

// ProcName is the name a person recognises a process by, for display only
// (dialogs, the audit chain, `nazar status`); nothing is matched or
// remembered by it, rules keep using code signatures (since Milestone 5).
//
//   - Normally the executable's file name.
//   - When that is a version number ("2.1.299") or there is no path, and
//     the code is signed by a team (Developer ID, verified by the
//     platform; never ad hoc or Apple, whose identifiers say nothing more),
//     the last component of the signing identifier
//     ("com.anthropic.claude-code" → "claude-code").
//   - With no path and no such identity, the kernel's short name (p_comm).
//
// deleted reports that the kernel gave no executable path, which on macOS
// means the file was deleted while the process runs; callers show
// DeletedMark after the name. The name is caller-controlled text: render
// it through the usual quoting (safeName, the audit formatter).
func ProcName(p platform.ProcessInfo) (name string, deleted bool) {
	base := ""
	if p.Path != "" {
		base = filepath.Base(p.Path)
	}
	if base == "" || versionNameRE.MatchString(base) {
		if id := signingName(p.Code); id != "" {
			return id, p.Path == ""
		}
	}
	if base != "" {
		return base, false
	}
	return p.Comm, true
}

// DisplayName is ProcName with DeletedMark appended for a deleted file.
func DisplayName(p platform.ProcessInfo) string {
	name, deleted := ProcName(p)
	if deleted {
		return name + DeletedMark
	}
	return name
}

// signingName is the last component of a team-signed signing identifier,
// or "" when the code has no verified team identity.
func signingName(c platform.CodeIdentity) string {
	if t := c.Team(); t == "" || t == "apple" || c.SigningID == "" {
		return ""
	}
	id := c.SigningID
	if i := strings.LastIndexByte(id, '.'); i >= 0 && i < len(id)-1 {
		id = id[i+1:]
	}
	return id
}
