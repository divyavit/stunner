package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewListenerProtocol(t *testing.T) {
	valid := map[string]Protocol{
		"udp":       ProtocolUDP,
		"UDP":       ProtocolUDP,
		"tcp":       ProtocolTCP,
		"tls":       ProtocolTLS,
		"dtls":      ProtocolDTLS,
		"stdin":     ProtocolSTDIN,
		"STDIN":     ProtocolSTDIN,
		"turn-udp":  ProtocolTURNUDP,
		"TURN-UDP":  ProtocolTURNUDP,
		"turn-tcp":  ProtocolTURNTCP,
		"turn-tls":  ProtocolTURNTLS,
		"turn-dtls": ProtocolTURNDTLS,
	}
	for raw, want := range valid {
		p, err := NewListenerProtocol(raw)
		assert.NoError(t, err, "listener protocol %q", raw)
		assert.Equal(t, want, p, "listener protocol %q", raw)
	}

	for _, raw := range []string{"", "dummy", "unix", "ip", "file"} {
		_, err := NewListenerProtocol(raw)
		assert.Error(t, err, "invalid listener protocol %q", raw)
	}
}

func TestListenerConfigValidate(t *testing.T) {
	testCases := []struct {
		name string
		conf ListenerConfig
		err  bool
	}{
		{
			name: "default listener",
			conf: ListenerConfig{Name: "listener"},
		},
		{
			name: "turn-udp listener",
			conf: ListenerConfig{Name: "listener", Protocol: "turn-udp"},
		},
		{
			name: "missing name",
			conf: ListenerConfig{Protocol: "turn-udp"},
			err:  true,
		},
		{
			name: "invalid protocol",
			conf: ListenerConfig{Name: "listener", Protocol: "dummy"},
			err:  true,
		},
		{
			name: "turn-tls listener without cert",
			conf: ListenerConfig{Name: "listener", Protocol: "turn-tls", Key: "key"},
			err:  true,
		},
		{
			name: "turn-tls listener without key",
			conf: ListenerConfig{Name: "listener", Protocol: "turn-tls", Cert: "cert"},
			err:  true,
		},
		{
			name: "turn-udp listener ignores the peer address",
			conf: ListenerConfig{Name: "listener", Protocol: "turn-udp",
				PeerAddr: "1.2.3.4:5678"},
		},
		{
			name: "plain udp listener",
			conf: ListenerConfig{Name: "listener", Protocol: "udp",
				PeerAddr: "1.2.3.4:5678"},
		},
		{
			name: "plain tcp listener",
			conf: ListenerConfig{Name: "listener", Protocol: "tcp",
				PeerAddr: "1.2.3.4:5678"},
		},
		{
			name: "plain udp listener with a DNS peer",
			conf: ListenerConfig{Name: "listener", Protocol: "udp",
				PeerAddr: "media.example.com:5678"},
		},
		{
			name: "plain udp listener with a bracketed IPv6 peer",
			conf: ListenerConfig{Name: "listener", Protocol: "udp",
				PeerAddr: "[2001:db8::1]:5678"},
		},
		{
			name: "plain udp listener with a udp peer scheme",
			conf: ListenerConfig{Name: "listener", Protocol: "udp",
				PeerAddr: "udp://1.2.3.4:5678"},
		},
		{
			name: "plain udp listener with a tcp peer scheme",
			conf: ListenerConfig{Name: "listener", Protocol: "udp",
				PeerAddr: "tcp://1.2.3.4:5678"},
		},
		{
			name: "plain udp listener with an uppercase peer scheme",
			conf: ListenerConfig{Name: "listener", Protocol: "udp",
				PeerAddr: "UDP://1.2.3.4:5678"},
		},
		{
			name: "plain udp listener with an invalid peer scheme",
			conf: ListenerConfig{Name: "listener", Protocol: "udp",
				PeerAddr: "dtls://1.2.3.4:5678"},
			err: true,
		},
		{
			name: "plain udp listener with a portless scheme peer",
			conf: ListenerConfig{Name: "listener", Protocol: "udp",
				PeerAddr: "udp://1.2.3.4"},
			err: true,
		},
		{
			name: "plain udp listener without a peer address",
			conf: ListenerConfig{Name: "listener", Protocol: "udp"},
			err:  true,
		},
		{
			name: "plain tcp listener without a peer address",
			conf: ListenerConfig{Name: "listener", Protocol: "tcp"},
			err:  true,
		},
		{
			name: "plain udp listener with a portless peer address",
			conf: ListenerConfig{Name: "listener", Protocol: "udp",
				PeerAddr: "1.2.3.4"},
			err: true,
		},
		{
			name: "plain udp listener with a hostless peer address",
			conf: ListenerConfig{Name: "listener", Protocol: "udp",
				PeerAddr: ":5678"},
			err: true,
		},
		{
			name: "plain udp listener with an invalid peer port",
			conf: ListenerConfig{Name: "listener", Protocol: "udp",
				PeerAddr: "1.2.3.4:notaport"},
			err: true,
		},
		{
			name: "plain udp listener with a zero peer port",
			conf: ListenerConfig{Name: "listener", Protocol: "udp",
				PeerAddr: "1.2.3.4:0"},
			err: true,
		},
		{
			name: "plain udp listener with an out-of-range peer port",
			conf: ListenerConfig{Name: "listener", Protocol: "udp",
				PeerAddr: "1.2.3.4:65536"},
			err: true,
		},
		{
			name: "stdin listener",
			conf: ListenerConfig{Name: "listener", Protocol: "stdin",
				PeerAddr: "1.2.3.4:5678"},
		},
		{
			name: "stdin listener without a peer address",
			conf: ListenerConfig{Name: "listener", Protocol: "stdin"},
			err:  true,
		},
		{
			name: "stdin listener with an address",
			conf: ListenerConfig{Name: "listener", Protocol: "stdin",
				PeerAddr: "1.2.3.4:5678", Addr: "127.0.0.1"},
			err: true,
		},
		{
			name: "stdin listener with a port",
			conf: ListenerConfig{Name: "listener", Protocol: "stdin",
				PeerAddr: "1.2.3.4:5678", Port: 3478},
			err: true,
		},
		{
			name: "stdin listener with TLS credentials",
			conf: ListenerConfig{Name: "listener", Protocol: "stdin",
				PeerAddr: "1.2.3.4:5678", Cert: "cert", Key: "key"},
			err: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.conf.Validate()
			if tc.err {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestListenerConfigValidateDefaults(t *testing.T) {
	c := ListenerConfig{Name: "listener"}
	assert.NoError(t, c.Validate())
	assert.Equal(t, "TURN-UDP", c.Protocol, "protocol default")
	assert.Equal(t, "0.0.0.0", c.Addr, "address default")
	assert.Equal(t, DefaultPort, c.Port, "port default")

	// STDIN listeners have no listener socket: no address/port defaulting
	s := ListenerConfig{Name: "listener", Protocol: "stdin", PeerAddr: "1.2.3.4:5678"}
	assert.NoError(t, s.Validate())
	assert.Equal(t, "STDIN", s.Protocol, "protocol normalized")
	assert.Empty(t, s.Addr, "no address default for stdin")
	assert.Zero(t, s.Port, "no port default for stdin")
}

func TestListenerConfigPeerEndpoint(t *testing.T) {
	for _, tc := range []struct {
		addr     string
		proto    Protocol
		hostport string
	}{
		{"1.2.3.4:5678", ProtocolUDP, "1.2.3.4:5678"},
		{"udp://1.2.3.4:5678", ProtocolUDP, "1.2.3.4:5678"},
		{"tcp://1.2.3.4:5678", ProtocolTCP, "1.2.3.4:5678"},
		{"TCP://media.example.com:5678", ProtocolTCP, "media.example.com:5678"},
		{"udp://[2001:db8::1]:5678", ProtocolUDP, "[2001:db8::1]:5678"},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			c := ListenerConfig{PeerAddr: tc.addr}
			proto, hostport := c.PeerEndpoint()
			assert.Equal(t, tc.proto, proto, "peer transport")
			assert.Equal(t, tc.hostport, hostport, "peer endpoint")
		})
	}
}

func TestListenerConfigStringPeerAddr(t *testing.T) {
	c := ListenerConfig{Name: "listener", Protocol: "udp", PeerAddr: "1.2.3.4:5678"}
	assert.NoError(t, c.Validate())
	assert.Contains(t, c.String(), "peer=1.2.3.4:5678")
}
