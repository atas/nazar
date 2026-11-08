package codesign

import "testing"

// TeamRequirement writes one fixed clause around two checked values; a
// value that could close the quotes or add a clause is refused.
func TestTeamRequirement(t *testing.T) {
	got, err := TeamRequirement("dev.nazar.agent", "ABCDE12345")
	want := `identifier "dev.nazar.agent" and anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"`
	if err != nil || got != want {
		t.Fatalf("TeamRequirement = %q, %v; want %q", got, err, want)
	}
	for _, c := range []struct{ id, team string }{
		{"dev.nazar.agent", ""},
		{"dev.nazar.agent", "abcde12345"},
		{"dev.nazar.agent", "ABCDE1234"},
		{"dev.nazar.agent", "ABCDE123456"},
		{"dev.nazar.agent", `ABCDE1234"`},
		{"dev.nazar.agent", "ABCDE12345\n"},
		{`dev.nazar.agent" or anchor apple or identifier "x`, "ABCDE12345"},
		{"", "ABCDE12345"},
		{"dev nazar", "ABCDE12345"},
		{".dev.nazar", "ABCDE12345"},
	} {
		if r, err := TeamRequirement(c.id, c.team); err == nil {
			t.Errorf("TeamRequirement(%q, %q) = %q, want an error", c.id, c.team, r)
		}
	}
}
