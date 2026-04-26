package version

import "testing"

// Defaults must remain valid printable strings so a non-stamped binary can
// still report something coherent on /version and in error messages.
func TestDefaultsArePresent(t *testing.T) {
	if Commit == "" {
		t.Error("Commit must not be empty by default")
	}
	if CommitDate == "" {
		t.Error("CommitDate must not be empty by default")
	}
}
