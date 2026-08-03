package turnclient

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stnrv1 "github.com/l7mp/stunner/v2/pkg/apis/v1"
)

func TestNewConfig(t *testing.T) {
	t.Run("static auth", func(t *testing.T) {
		s := &stnrv1.TURNServer{Address: "1.2.3.4", Port: 3478,
			Auth: &stnrv1.AuthConfig{Type: "static", Realm: "example.org",
				Credentials: map[string]string{"username": "user", "password": "pass"}}}
		c, err := NewConfig(s, stnrv1.ProtocolTURNUDP)
		require.NoError(t, err)
		assert.Equal(t, stnrv1.ProtocolTURNUDP, c.Protocol)
		assert.Equal(t, "1.2.3.4:3478", c.ServerAddr)
		assert.Equal(t, "user", c.Username)
		assert.Equal(t, "pass", c.Password)
		assert.Equal(t, "example.org", c.Realm, "realm seeded from the auth config")
		assert.Equal(t, "1.2.3.4", c.ServerName)
	})

	t.Run("no auth block dials anonymously", func(t *testing.T) {
		s := &stnrv1.TURNServer{Address: "1.2.3.4", Port: 3478}
		c, err := NewConfig(s, stnrv1.ProtocolTURNTCP)
		require.NoError(t, err)
		assert.Empty(t, c.Username)
		assert.Empty(t, c.Password)
		assert.Empty(t, c.Realm)
	})

	t.Run("explicit none dials anonymously too", func(t *testing.T) {
		// a nil auth block and an explicit "none" must behave identically on the wire:
		// no credentials either way (the realm seed is inert without credentials, no
		// message integrity is ever computed from it)
		s := &stnrv1.TURNServer{Address: "1.2.3.4", Port: 3478,
			Auth: &stnrv1.AuthConfig{Type: "none"}}
		c, err := NewConfig(s, stnrv1.ProtocolTURNUDP)
		require.NoError(t, err)
		assert.Empty(t, c.Username)
		assert.Empty(t, c.Password)
	})

	t.Run("ephemeral auth generates per-call credentials", func(t *testing.T) {
		s := &stnrv1.TURNServer{Address: "2001:db8::1", Port: 3478,
			Auth: &stnrv1.AuthConfig{Type: "ephemeral", Lifetime: "10m",
				Credentials: map[string]string{"secret": "my-secret"}}}
		c, err := NewConfig(s, stnrv1.ProtocolTURNTLS)
		require.NoError(t, err)
		assert.Equal(t, "[2001:db8::1]:3478", c.ServerAddr, "IPv6 host is bracketed")
		_, err = strconv.ParseInt(c.Username, 10, 64)
		assert.NoError(t, err, "time-windowed username")
		assert.NotEmpty(t, c.Password)
	})

	t.Run("broken auth config fails the dial early", func(t *testing.T) {
		s := &stnrv1.TURNServer{Address: "1.2.3.4", Port: 3478,
			Auth: &stnrv1.AuthConfig{Type: "ephemeral"}}
		_, err := NewConfig(s, stnrv1.ProtocolTURNUDP)
		assert.Error(t, err)
	})
}
