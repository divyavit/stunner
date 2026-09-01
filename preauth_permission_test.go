package stunner

import (
	"net"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	"github.com/stretchr/testify/assert"

	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"
)

// The whole point of pre-authorizing routed peers is that a peer may send to the relay address
// before the client has issued a single CreatePermission. This drives that end to end: allocate,
// then have a peer socket send in, without the client ever writing (a write is what would
// otherwise trigger CreatePermission).
//
// It also pins the security boundary: a cluster whose endpoint is a wide prefix must NOT be
// pre-authorized, otherwise the relay becomes a reflector for that whole range.
func TestPreauthorizeRoutedPeers(t *testing.T) {
	for _, c := range []struct {
		name     string
		enabled  bool
		endpoint string
		want     bool // peer packet reaches the client without any CreatePermission
	}{
		{name: "off-by-default", enabled: false, endpoint: "127.0.0.1/32", want: false},
		{name: "host-route-preauthorized", enabled: true, endpoint: "127.0.0.1/32", want: true},
		{name: "wide-prefix-not-preauthorized", enabled: true, endpoint: "0.0.0.0/0", want: false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.enabled {
				t.Setenv(PreauthorizePeersEnvVar, "true")
			}

			s := NewStunner(Options{
				LogOptions:       LogOptions{Level: stunnerTestLoglevel},
				SuppressRollback: true,
			})
			defer s.Close()

			assert.NoError(t, s.Reconcile(&stnrv1.StunnerConfig{
				ApiVersion: stnrv1.ApiVersion,
				Admin:      stnrv1.AdminConfig{LogLevel: stunnerTestLoglevel},
				Auth: stnrv1.AuthConfig{
					Credentials: map[string]string{"username": "user1", "password": "passwd1"},
				},
				Listeners: []stnrv1.ListenerConfig{{
					Name:     "udp",
					Protocol: "turn-udp",
					Addr:     "127.0.0.1",
					Port:     23478,
					Routes:   []string{"peers"},
				}},
				Clusters: []stnrv1.ClusterConfig{{
					Name:      "peers",
					Endpoints: []string{c.endpoint},
				}},
			}), "reconcile")

			lconn, err := net.ListenPacket("udp4", "0.0.0.0:0")
			assert.NoError(t, err, "client socket")
			defer lconn.Close() //nolint:errcheck

			client, err := turn.NewClient(&turn.ClientConfig{
				STUNServerAddr: "127.0.0.1:23478",
				TURNServerAddr: "127.0.0.1:23478",
				Username:       "user1",
				Password:       "passwd1",
				Conn:           lconn,
				LoggerFactory:  logging.NewDefaultLoggerFactory(),
			})
			assert.NoError(t, err, "turn client")
			defer client.Close()
			assert.NoError(t, client.Listen(), "client listen")

			relayConn, err := client.Allocate()
			assert.NoError(t, err, "allocate")
			defer relayConn.Close() //nolint:errcheck

			// No CreatePermission is ever sent: the client only reads.
			peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
			assert.NoError(t, err, "peer socket")
			defer peer.Close() //nolint:errcheck

			relayAddr, err := net.ResolveUDPAddr("udp4", relayConn.LocalAddr().String())
			assert.NoError(t, err, "relay addr")

			_, err = peer.WriteTo([]byte("ping"), relayAddr)
			assert.NoError(t, err, "peer write")

			buf := make([]byte, 64)
			assert.NoError(t, relayConn.SetReadDeadline(time.Now().Add(2*time.Second)), "deadline")
			n, from, err := relayConn.ReadFrom(buf)

			if !c.want {
				assert.Error(t, err, "peer traffic must be dropped without a permission")
				return
			}

			assert.NoError(t, err, "peer traffic must pass on a pre-authorized relay")
			assert.Equal(t, "ping", string(buf[:n]), "payload")
			assert.Equal(t, peer.LocalAddr().String(), from.String(), "peer address")
		})
	}
}
