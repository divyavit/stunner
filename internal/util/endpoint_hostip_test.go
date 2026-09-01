package util

import "testing"

// HostIP gates pre-authorizing peers at allocation time: anything wider than a single host must be
// rejected, otherwise a whole prefix would be permitted on the relay without the client asking.
func TestEndpointHostIP(t *testing.T) {
	for _, c := range []struct {
		ep   string
		want string // empty means "must not be enumerable"
	}{
		{"10.112.14.69", "10.112.14.69"},
		{"10.112.14.69/32", "10.112.14.69"},
		{"10.112.14.69:<3478-3479>", "10.112.14.69"},
		{"10.112.0.0/16", ""},
		{"10.112.14.64/31", ""},
		{"0.0.0.0/0", ""},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:db8::1/128", "2001:db8::1"},
		{"2001:db8::/64", ""},
	} {
		e, err := ParseEndpoint(c.ep)
		if err != nil {
			t.Fatalf("ParseEndpoint(%q): %s", c.ep, err)
		}

		ip, ok := e.HostIP()
		if ok != (c.want != "") {
			t.Fatalf("HostIP(%q): enumerable=%v, want %v", c.ep, ok, c.want != "")
		}
		if ok && ip.String() != c.want {
			t.Fatalf("HostIP(%q) = %s, want %s", c.ep, ip, c.want)
		}
	}
}
