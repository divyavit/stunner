package stunner

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l7mp/stunner/v2/internal/object/l4"
	stnrv1 "github.com/l7mp/stunner/v2/pkg/apis/v1"
	"github.com/l7mp/stunner/v2/pkg/logger"
)

// plainListenerConfig builds a single-listener stunnerd config with a plain listener relaying
// to the given peer through one cluster.
func plainListenerConfig(proto string, port int, peer string, endpoints []string) *stnrv1.StunnerConfig {
	noHealthCheck := ""
	return &stnrv1.StunnerConfig{
		ApiVersion: stnrv1.ApiVersion,
		Admin: stnrv1.AdminConfig{
			LogLevel:            stunnerTestLoglevel,
			HealthCheckEndpoint: &noHealthCheck,
		},
		Auth: stnrv1.AuthConfig{
			Type:        "static",
			Credentials: map[string]string{"username": "user1", "password": "passwd1"},
		},
		Listeners: []stnrv1.ListenerConfig{{
			Name:     "plain",
			Protocol: proto,
			Addr:     "127.0.0.1",
			Port:     port,
			PeerAddr: peer,
			Routes:   []string{"cluster"},
		}},
		Clusters: []stnrv1.ClusterConfig{{
			Name:      "cluster",
			Endpoints: endpoints,
		}},
	}
}

// startUDPEcho starts a UDP echo server on the given loopback port.
func startUDPEcho(t *testing.T, port int) net.PacketConn {
	t.Helper()
	c, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	require.NoError(t, err, "echo server socket")
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 1600)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteTo(buf[:n], from)
		}
	}()
	return c
}

// TestStunnerPlainListener exercises the plain-listener flow engine end to end through the full
// reconcile machinery: engine dispatch, admission, chunking, idle expiry.
func TestStunnerPlainListener(t *testing.T) {
	lim := test.TimeOut(time.Second * 120)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logger.NewLoggerFactory(stunnerTestLoglevel)
	log := loggerFactory.NewLogger("test")

	t.Run("udp-round-trip", func(t *testing.T) {
		log.Debug("-------------- Running test: plain UDP round trip --------------")
		startUDPEcho(t, 25680)
		s := NewStunner(Options{Name: "plain-udp", LogOptions: LogOptions{Level: stunnerTestLoglevel}, SuppressRollback: true})
		defer closeStunner(s)
		require.NoError(t, s.Reconcile(plainListenerConfig("UDP", 23478,
			"127.0.0.1:25680", []string{"127.0.0.1"})), "server started")

		client, err := net.Dial("udp", "127.0.0.1:23478")
		require.NoError(t, err, "client dial")
		defer client.Close() //nolint:errcheck

		buf := make([]byte, 1600)
		_, err = client.Write([]byte("Hello"))
		require.NoError(t, err, "client write")
		require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))
		n, err := client.Read(buf)
		require.NoError(t, err, "echo")
		assert.Equal(t, "Hello", string(buf[:n]), "echo payload")

		l := s.GetListener("plain")
		require.NotNil(t, l, "listener")
		assert.Equal(t, 1, l.AllocationCount(), "flow counted as allocation")
	})

	t.Run("tcp-client-chunking", func(t *testing.T) {
		log.Debug("-------------- Running test: plain TCP client chunking --------------")
		startUDPEcho(t, 25680)
		s := NewStunner(Options{Name: "plain-tcp", LogOptions: LogOptions{Level: stunnerTestLoglevel}, SuppressRollback: true})
		defer closeStunner(s)
		require.NoError(t, s.Reconcile(plainListenerConfig("TCP", 23478,
			"127.0.0.1:25680", []string{"127.0.0.1"})), "server started")

		client, err := net.Dial("tcp", "127.0.0.1:23478")
		require.NoError(t, err, "client dial")
		defer client.Close() //nolint:errcheck

		// each stream write chunk makes one datagram towards the peer and each echoed
		// datagram makes one chunk back
		buf := make([]byte, 1600)
		require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))
		for _, msg := range []string{"Hello-0", "Hello-1", "Hello-2"} {
			_, err = client.Write([]byte(msg))
			require.NoError(t, err, "client write")
			n, err := client.Read(buf)
			require.NoError(t, err, "echo")
			assert.Equal(t, msg, string(buf[:n]), "echo payload")
		}

		l := s.GetListener("plain")
		require.NotNil(t, l, "listener")
		assert.Equal(t, 1, l.AllocationCount(), "flow counted as allocation")

		// a client FIN tears the flow down
		require.NoError(t, client.Close())
		assert.Eventually(t, func() bool { return l.AllocationCount() == 0 },
			5*time.Second, 10*time.Millisecond, "flow torn down on client close")
	})

	t.Run("unadmitted-peer", func(t *testing.T) {
		log.Debug("-------------- Running test: plain listener unadmitted peer --------------")
		startUDPEcho(t, 25680)
		s := NewStunner(Options{Name: "plain-unadmitted", LogOptions: LogOptions{Level: stunnerTestLoglevel}, SuppressRollback: true})
		defer closeStunner(s)
		require.NoError(t, s.Reconcile(plainListenerConfig("UDP", 23478,
			"127.0.0.1:25680", []string{"9.9.9.9"})), "server started")

		client, err := net.Dial("udp", "127.0.0.1:23478")
		require.NoError(t, err, "client dial")
		defer client.Close() //nolint:errcheck

		buf := make([]byte, 1600)
		_, err = client.Write([]byte("Hello"))
		require.NoError(t, err, "client write")
		require.NoError(t, client.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
		_, err = client.Read(buf)
		assert.Error(t, err, "no echo from an unadmitted peer")

		l := s.GetListener("plain")
		require.NotNil(t, l, "listener")
		assert.Equal(t, 0, l.AllocationCount(), "no flow registered")
	})

	t.Run("peer-change-reconciles-in-place", func(t *testing.T) {
		log.Debug("-------------- Running test: plain listener peer change --------------")
		startUDPEcho(t, 25680)
		// the second peer tags its replies so the serving peer is observable
		tagged, err := net.ListenPacket("udp4", "127.0.0.1:25681")
		require.NoError(t, err, "tagged echo server socket")
		defer tagged.Close() //nolint:errcheck
		go func() {
			buf := make([]byte, 1600)
			for {
				n, from, err := tagged.ReadFrom(buf)
				if err != nil {
					return
				}
				_, _ = tagged.WriteTo(append([]byte("B:"), buf[:n]...), from)
			}
		}()

		s := NewStunner(Options{Name: "plain-peer-change", LogOptions: LogOptions{Level: stunnerTestLoglevel}, SuppressRollback: true})
		defer closeStunner(s)
		require.NoError(t, s.Reconcile(plainListenerConfig("UDP", 23478,
			"127.0.0.1:25680", []string{"127.0.0.1"})), "server started")

		buf := make([]byte, 1600)
		echo := func(c net.Conn, want string) {
			t.Helper()
			_, err := c.Write([]byte("Hello"))
			require.NoError(t, err, "client write")
			require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
			n, err := c.Read(buf)
			require.NoError(t, err, "echo")
			assert.Equal(t, want, string(buf[:n]), "echo payload")
		}

		client1, err := net.Dial("udp", "127.0.0.1:23478")
		require.NoError(t, err, "client 1 dial")
		defer client1.Close() //nolint:errcheck
		echo(client1, "Hello")

		// a peer change reconciles in place: the existing flow stays pinned to the old
		// peer, a new flow goes to the new one
		require.NoError(t, s.Reconcile(plainListenerConfig("UDP", 23478,
			"127.0.0.1:25681", []string{"127.0.0.1"})), "peer change reconciled")

		echo(client1, "Hello")

		client2, err := net.Dial("udp", "127.0.0.1:23478")
		require.NoError(t, err, "client 2 dial")
		defer client2.Close() //nolint:errcheck
		echo(client2, "B:Hello")

		l := s.GetListener("plain")
		require.NotNil(t, l, "listener")
		assert.Equal(t, 2, l.AllocationCount(), "both flows live")
	})

	t.Run("idle-expiry", func(t *testing.T) {
		log.Debug("-------------- Running test: plain listener idle expiry --------------")
		// the flow timeout is a system constant; shorten it for the test
		defer func(d time.Duration) { l4.FlowTimeout = d }(l4.FlowTimeout)
		l4.FlowTimeout = 100 * time.Millisecond

		startUDPEcho(t, 25680)
		s := NewStunner(Options{Name: "plain-idle", LogOptions: LogOptions{Level: stunnerTestLoglevel}, SuppressRollback: true})
		defer closeStunner(s)
		require.NoError(t, s.Reconcile(plainListenerConfig("UDP", 23478,
			"127.0.0.1:25680", []string{"127.0.0.1"})), "server started")

		client, err := net.Dial("udp", "127.0.0.1:23478")
		require.NoError(t, err, "client dial")
		defer client.Close() //nolint:errcheck

		buf := make([]byte, 1600)
		echo := func() {
			_, err := client.Write([]byte("Hello"))
			require.NoError(t, err, "client write")
			require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))
			_, err = client.Read(buf)
			require.NoError(t, err, "echo")
		}

		l := s.GetListener("plain")
		require.NotNil(t, l, "listener")

		echo()
		assert.Equal(t, 1, l.AllocationCount(), "flow created")

		// quiet flow expires
		assert.Eventually(t, func() bool { return l.AllocationCount() == 0 },
			5*time.Second, 10*time.Millisecond, "idle flow torn down")

		// fresh traffic from the same client re-creates the flow
		echo()
		assert.Equal(t, 1, l.AllocationCount(), "flow re-created on traffic")
	})
}

// TestStunnerPlainTunnelChain is the turncat-parity test: a raw UDP client sends to a plain UDP
// listener whose only route is a TURN-* protocol cluster pointing at an upstream stunnerd, so
// the flow is relayed through an upstream TURN allocation (tunnel mode). A successful raw echo
// plus exactly one upstream allocation proves the traversal.
func TestStunnerPlainTunnelChain(t *testing.T) {
	lim := test.TimeOut(time.Second * 120)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logger.NewLoggerFactory(stunnerTestLoglevel)
	log := loggerFactory.NewLogger("test")
	log.Debug("-------------- Running test: plain tunnel chain --------------")

	noHealthCheck := ""

	upstream := NewStunner(Options{Name: "upstream", LogOptions: LogOptions{Level: stunnerTestLoglevel}, SuppressRollback: true})
	defer closeStunner(upstream)
	require.NoError(t, upstream.Reconcile(&stnrv1.StunnerConfig{
		ApiVersion: stnrv1.ApiVersion,
		Admin:      stnrv1.AdminConfig{LogLevel: stunnerTestLoglevel, HealthCheckEndpoint: &noHealthCheck},
		Auth:       stnrv1.AuthConfig{Type: "static", Credentials: map[string]string{"username": "user2", "password": "passwd2"}},
		Listeners: []stnrv1.ListenerConfig{{
			Name: "upstream", Protocol: "turn-udp", Addr: "127.0.0.1", Port: 23479, Routes: []string{"allow-any"},
		}},
		Clusters: []stnrv1.ClusterConfig{{
			Name: "allow-any", Endpoints: []string{"0.0.0.0/0"},
		}},
	}), "upstream server started")

	downstream := NewStunner(Options{Name: "downstream", LogOptions: LogOptions{Level: stunnerTestLoglevel}, SuppressRollback: true})
	defer closeStunner(downstream)
	require.NoError(t, downstream.Reconcile(&stnrv1.StunnerConfig{
		ApiVersion: stnrv1.ApiVersion,
		Admin:      stnrv1.AdminConfig{LogLevel: stunnerTestLoglevel, HealthCheckEndpoint: &noHealthCheck},
		Auth:       stnrv1.AuthConfig{Type: "static", Credentials: map[string]string{"username": "user1", "password": "passwd1"}},
		Listeners: []stnrv1.ListenerConfig{{
			Name: "downstream", Protocol: "UDP", Addr: "127.0.0.1", Port: 23478,
			PeerAddr: "127.0.0.1:25680", Routes: []string{"turn-relay"},
		}},
		Clusters: []stnrv1.ClusterConfig{{
			Name: "turn-relay", Protocol: "turn-udp",
			TURNServer: &stnrv1.TURNServer{Address: "127.0.0.1", Port: 23479,
				Auth: &stnrv1.AuthConfig{Type: "static", Credentials: map[string]string{
					"username": "user2", "password": "passwd2"}}},
		}},
	}), "downstream server started")

	// close the echo before the goroutine-leak check: t.Cleanup would run after it
	echo := startUDPEcho(t, 25680)
	defer echo.Close() //nolint:errcheck

	client, err := net.Dial("udp", "127.0.0.1:23478")
	require.NoError(t, err, "client dial")
	defer client.Close() //nolint:errcheck

	// retry the first round-trip: datagrams may be dropped while the upstream permission is
	// negotiated
	buf := make([]byte, 1600)
	echoed := false
	for i := 0; i < 20 && !echoed; i++ {
		_, err = client.Write([]byte("Hello"))
		require.NoError(t, err, "client write")
		require.NoError(t, client.SetReadDeadline(time.Now().Add(250*time.Millisecond)))
		n, err2 := client.Read(buf)
		if err2 != nil {
			continue
		}
		assert.Equal(t, "Hello", string(buf[:n]), "echo payload")
		echoed = true
	}
	require.True(t, echoed, "raw echo through the tunnel chain")

	// a couple more round-trips over the established flow
	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))
	for _, msg := range []string{"Hello-0", "Hello-1", "Hello-2"} {
		_, err = client.Write([]byte(msg))
		require.NoError(t, err, "client write")
		n, err := client.Read(buf)
		require.NoError(t, err, "echo")
		assert.Equal(t, msg, string(buf[:n]), "echo payload")
	}

	// the flow rides an upstream TURN allocation and counts as a downstream flow
	ul := upstream.GetListener("upstream")
	require.NotNil(t, ul, "upstream listener")
	assert.Equal(t, 1, ul.AllocationCount(), "upstream allocation count")
	dl := downstream.GetListener("downstream")
	require.NotNil(t, dl, "downstream listener")
	assert.Equal(t, 1, dl.AllocationCount(), "downstream flow count")
}
