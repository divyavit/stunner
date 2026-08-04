package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stnrv1 "github.com/l7mp/stunner/v2/pkg/apis/v1"
)

func noK8s(k8sName) (*stnrv1.StunnerConfig, error) {
	panic("k8s:// server resolution must not be reached")
}

func noPeerK8s(k8sName) (string, error) {
	panic("k8s:// peer resolution must not be reached")
}

// TestParseK8sURI covers the shared k8s:// meta-URI parser of the tunnel-mode server and
// peer arguments.
func TestParseK8sURI(t *testing.T) {
	for _, tc := range []struct {
		name, arg, defaultNS string
		want                 k8sName
		isK8s, wantErr       bool
	}{
		{name: "full form", arg: "k8s://media/gw:l7mp",
			want: k8sName{"media", "gw", "l7mp"}, isK8s: true},
		{name: "default namespace", arg: "k8s:///gw:l7mp", defaultNS: "stunner",
			want: k8sName{"stunner", "gw", "l7mp"}, isK8s: true},
		{name: "port number component", arg: "k8s://media/db:5432",
			want: k8sName{"media", "db", "5432"}, isK8s: true},
		{name: "not a k8s URI", arg: "udp://1.2.3.4:5000"},
		{name: "missing component", arg: "k8s://media/gw", isK8s: true, wantErr: true},
		{name: "no namespace anywhere", arg: "k8s:///gw:l7mp", isK8s: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, isK8s, err := parseK8sURI(tc.arg, tc.defaultNS)
			assert.Equal(t, tc.isK8s, isK8s, "k8s URI detection")
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.isK8s {
				assert.Equal(t, tc.want, u, "parsed URI")
			}
		})
	}
}

// TestTunnelConfig covers the CLI-to-config mapping of tunnel mode: the three turncat-shaped
// positional arguments render one plain (or stdin) listener pinned to the peer, routing to a
// single TURN-* cluster naming the server.
func TestTunnelConfig(t *testing.T) {
	t.Run("udp client with static auth", func(t *testing.T) {
		c, err := tunnelConfig("udp://127.0.0.1:5000", "turn://user:pass@1.2.3.4:3478",
			"udp://10.0.0.1:9000", "", tunnelOptions{}, noK8s, noPeerK8s)
		require.NoError(t, err)

		require.Len(t, c.Listeners, 1)
		l := c.Listeners[0]
		assert.Equal(t, "UDP", l.Protocol, "listener protocol")
		assert.Equal(t, "127.0.0.1", l.Addr, "listener address")
		assert.Equal(t, 5000, l.Port, "listener port")
		assert.Equal(t, "udp://10.0.0.1:9000", l.PeerAddr, "peer address")
		assert.Equal(t, []string{"tunnel-cluster"}, l.Routes, "routes")

		require.Len(t, c.Clusters, 1)
		cl := c.Clusters[0]
		assert.Equal(t, "TURN-UDP", cl.Protocol, "cluster protocol")
		require.NotNil(t, cl.TURNServer, "TURN server")
		assert.Equal(t, "1.2.3.4", cl.TURNServer.Address, "server address")
		assert.Equal(t, 3478, cl.TURNServer.Port, "server port")
		require.NotNil(t, cl.TURNServer.Auth, "server auth")
		assert.Equal(t, "static", cl.TURNServer.Auth.Type, "auth type")
		assert.Equal(t, "user", cl.TURNServer.Auth.Credentials["username"], "username")
		assert.Equal(t, "pass", cl.TURNServer.Auth.Credentials["password"], "password")

		assert.Equal(t, "none", c.Auth.Type, "listener-side auth is off")
	})

	t.Run("bare secret is ephemeral auth", func(t *testing.T) {
		c, err := tunnelConfig("udp://127.0.0.1:5000", "turn://my-secret@1.2.3.4:3478",
			"udp://10.0.0.1:9000", "", tunnelOptions{}, noK8s, noPeerK8s)
		require.NoError(t, err)
		auth := c.Clusters[0].TURNServer.Auth
		require.NotNil(t, auth, "server auth")
		assert.Equal(t, "ephemeral", auth.Type, "auth type")
		assert.Equal(t, "my-secret", auth.Credentials["secret"], "secret")
	})

	t.Run("no auth dials anonymously", func(t *testing.T) {
		c, err := tunnelConfig("udp://127.0.0.1:5000", "turn://1.2.3.4:3478",
			"udp://10.0.0.1:9000", "", tunnelOptions{}, noK8s, noPeerK8s)
		require.NoError(t, err)
		assert.Nil(t, c.Clusters[0].TURNServer.Auth, "no auth block")
	})

	t.Run("tcp client", func(t *testing.T) {
		c, err := tunnelConfig("tcp://0.0.0.0:5001", "turn://1.2.3.4:3478?transport=tcp",
			"udp://10.0.0.1:9000", "", tunnelOptions{}, noK8s, noPeerK8s)
		require.NoError(t, err)
		assert.Equal(t, "TCP", c.Listeners[0].Protocol, "listener protocol")
		assert.Equal(t, "TURN-TCP", c.Clusters[0].Protocol, "cluster protocol")
	})

	t.Run("stdin client", func(t *testing.T) {
		c, err := tunnelConfig("-", "turn://1.2.3.4:3478", "udp://10.0.0.1:9000", "",
			tunnelOptions{}, noK8s, noPeerK8s)
		require.NoError(t, err)
		l := c.Listeners[0]
		assert.Equal(t, "STDIN", l.Protocol, "listener protocol")
		assert.Empty(t, l.Addr, "no listener address")
		assert.Zero(t, l.Port, "no listener port")
		assert.Equal(t, "udp://10.0.0.1:9000", l.PeerAddr, "peer address")
	})

	t.Run("sni and insecure on a TLS transport", func(t *testing.T) {
		c, err := tunnelConfig("udp://127.0.0.1:5000", "turn://1.2.3.4:5349?transport=tls",
			"udp://10.0.0.1:9000", "", tunnelOptions{sni: "turn.example.com", insecure: true}, noK8s, noPeerK8s)
		require.NoError(t, err)
		assert.Equal(t, "TURN-TLS", c.Clusters[0].Protocol, "cluster protocol")
		assert.Equal(t, "turn.example.com", c.Clusters[0].TURNServer.SNI, "SNI")
		assert.True(t, c.Clusters[0].TURNServer.Insecure, "insecure")
	})

	t.Run("sni on a non-TLS transport is refused", func(t *testing.T) {
		_, err := tunnelConfig("udp://127.0.0.1:5000", "turn://1.2.3.4:3478",
			"udp://10.0.0.1:9000", "", tunnelOptions{sni: "turn.example.com"}, noK8s, noPeerK8s)
		assert.Error(t, err)
	})

	t.Run("dns peer host", func(t *testing.T) {
		c, err := tunnelConfig("udp://127.0.0.1:5000", "turn://1.2.3.4:3478",
			"udp://media.example.com:9000", "", tunnelOptions{}, noK8s, noPeerK8s)
		require.NoError(t, err)
		assert.Equal(t, "udp://media.example.com:9000", c.Listeners[0].PeerAddr, "DNS peer")
	})

	t.Run("invalid client scheme", func(t *testing.T) {
		_, err := tunnelConfig("unix:///tmp/x", "turn://1.2.3.4:3478", "udp://10.0.0.1:9000", "",
			tunnelOptions{}, noK8s, noPeerK8s)
		assert.Error(t, err)
	})

	t.Run("tcp peer", func(t *testing.T) {
		c, err := tunnelConfig("udp://127.0.0.1:5000", "turn://1.2.3.4:3478?transport=tcp",
			"tcp://10.0.0.1:9000", "", tunnelOptions{}, noK8s, noPeerK8s)
		require.NoError(t, err)
		assert.Equal(t, "tcp://10.0.0.1:9000", c.Listeners[0].PeerAddr, "TCP peer")
	})

	t.Run("invalid peer scheme", func(t *testing.T) {
		_, err := tunnelConfig("udp://127.0.0.1:5000", "turn://1.2.3.4:3478",
			"dtls://10.0.0.1:9000", "", tunnelOptions{}, noK8s, noPeerK8s)
		assert.Error(t, err)
	})

	t.Run("non-TURN server URI", func(t *testing.T) {
		_, err := tunnelConfig("udp://127.0.0.1:5000", "udp://1.2.3.4:3478",
			"udp://10.0.0.1:9000", "", tunnelOptions{}, noK8s, noPeerK8s)
		assert.Error(t, err)
	})

	t.Run("k8s peer resolution", func(t *testing.T) {
		peerFromK8s := func(u k8sName) (string, error) {
			assert.Equal(t, k8sName{"media", "db", "postgres"}, u, "parsed peer URI")
			return "tcp://10.96.0.12:5432", nil
		}
		c, err := tunnelConfig("udp://127.0.0.1:5000", "turn://1.2.3.4:3478?transport=tcp",
			"k8s://media/db:postgres", "", tunnelOptions{}, noK8s, peerFromK8s)
		require.NoError(t, err)
		assert.Equal(t, "tcp://10.96.0.12:5432", c.Listeners[0].PeerAddr,
			"peer resolved from the service port")
	})

	t.Run("k8s server resolution", func(t *testing.T) {
		fromK8s := func(u k8sName) (*stnrv1.StunnerConfig, error) {
			assert.Equal(t, k8sName{"media", "gw", "l7mp"}, u, "parsed server URI")
			return &stnrv1.StunnerConfig{
				Auth: stnrv1.AuthConfig{Type: "static", Credentials: map[string]string{
					"username": "user", "password": "pass"}},
				Listeners: []stnrv1.ListenerConfig{{
					Name:       "media/gw/l7mp",
					Protocol:   "TURN-UDP",
					PublicAddr: "5.6.7.8",
					PublicPort: 3478,
				}},
			}, nil
		}
		c, err := tunnelConfig("udp://127.0.0.1:5000", "k8s://media/gw:l7mp",
			"udp://10.0.0.1:9000", "", tunnelOptions{}, fromK8s, noPeerK8s)
		require.NoError(t, err)
		cl := c.Clusters[0]
		assert.Equal(t, "TURN-UDP", cl.Protocol, "cluster protocol")
		assert.Equal(t, "5.6.7.8", cl.TURNServer.Address, "server address")
		assert.Equal(t, 3478, cl.TURNServer.Port, "server port")
		require.NotNil(t, cl.TURNServer.Auth, "server auth")
		assert.Equal(t, "static", cl.TURNServer.Auth.Type, "auth type carried over")
	})
}
