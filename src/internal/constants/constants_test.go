// constants_test.go checks that the pre-parsed netip values match the string
// constants they come from, and that the server IP lies inside the default
// subnet, so a typo in either form is caught by tests rather than at startup.
package constants

import "testing"

func TestParsedValuesMatchStrings(t *testing.T) {
	t.Logf("DefaultSubnet=%s DefaultServerIP=%s", DefaultSubnet, DefaultServerIP)
	if got := DefaultSubnet.String(); got != DefaultSubnetString {
		t.Errorf("DefaultSubnet.String() = %q, want %q", got, DefaultSubnetString)
	}
	if got := DefaultServerIP.String(); got != DefaultServerIPString {
		t.Errorf("DefaultServerIP.String() = %q, want %q", got, DefaultServerIPString)
	}
	if !DefaultSubnet.Contains(DefaultServerIP) {
		t.Errorf("DefaultServerIP %s is outside DefaultSubnet %s", DefaultServerIP, DefaultSubnet)
	}
}
