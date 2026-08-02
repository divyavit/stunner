package router_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l7mp/stunner/internal/object"
	"github.com/l7mp/stunner/internal/router"
	"github.com/l7mp/stunner/internal/runtime"
	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"
	"github.com/l7mp/stunner/pkg/logger"
)

// fakeListener is a minimal listener node carrying only the routes the Router reads.
type fakeListener struct{ conf stnrv1.ListenerConfig }

func (l *fakeListener) Name() string             { return l.conf.Name }
func (l *fakeListener) Type() runtime.ObjectType { return runtime.TypeListener }
func (l *fakeListener) Start() error             { return nil }
func (l *fakeListener) Close(_ bool) error       { return nil }
func (l *fakeListener) GetConfig() stnrv1.Config { return &l.conf }
func (l *fakeListener) Status() stnrv1.Status    { return nil }
func (l *fakeListener) Inspect(_, _ stnrv1.Config, _ *stnrv1.StunnerConfig) (runtime.Action, error) {
	return runtime.ActionNone, nil
}
func (l *fakeListener) Reconcile(_ stnrv1.Config) error { return nil }

func newRuntime(t *testing.T) *runtime.Runtime {
	t.Helper()
	log := logger.NewLoggerFactory("all:ERROR")
	rt := runtime.New(runtime.Config{Logger: log, DryRun: true})
	rt.Router = router.NewRouter(rt)
	return rt
}

// addCluster registers a real cluster object so the Router can resolve it from the registry and
// ask it for admission.
func addCluster(t *testing.T, rt *runtime.Runtime, conf *stnrv1.ClusterConfig) {
	t.Helper()
	c, err := object.NewCluster(conf, rt)
	require.NoError(t, err)
	require.NoError(t, rt.Registry.Add(c, nil))
}

func addListener(t *testing.T, rt *runtime.Runtime, name string, routes ...string) {
	t.Helper()
	l := &fakeListener{conf: stnrv1.ListenerConfig{Name: name, Routes: routes}}
	require.NoError(t, rt.Registry.Add(l, nil))
}

func TestRoute(t *testing.T) {
	rt := newRuntime(t)
	addCluster(t, rt, &stnrv1.ClusterConfig{Name: "cluster-udp",
		Protocol: stnrv1.ClusterProtocolUDP.String(), Endpoints: []string{"10.0.0.0/8"}})
	addCluster(t, rt, &stnrv1.ClusterConfig{Name: "turn-cluster",
		Protocol:   stnrv1.ClusterProtocolTURNUDP.String(),
		TURNServer: &stnrv1.TURNServer{Address: "1.2.3.4", Port: 3478},
	})
	addListener(t, rt, "listener", "nonexistent", "cluster-udp", "turn-cluster")

	// the matcher sees each routed cluster in route order; missing clusters are skipped
	c, ok := rt.Router.Route("listener", func(c runtime.Cluster) bool {
		return c.Protocol().IsTURN()
	})
	require.True(t, ok)
	require.Equal(t, "turn-cluster", c.Name())
	require.NotNil(t, c.TURNServer())

	c, ok = rt.Router.Route("listener", func(c runtime.Cluster) bool {
		return c.Admits(net.ParseIP("10.0.0.1"), 0)
	})
	require.True(t, ok)
	require.Equal(t, "cluster-udp", c.Name())

	// a TURN cluster admits every peer, so it picks up what the direct cluster rejects
	c, ok = rt.Router.Route("listener", func(c runtime.Cluster) bool {
		return c.Admits(net.ParseIP("192.168.0.1"), 0)
	})
	require.True(t, ok)
	require.Equal(t, "turn-cluster", c.Name())

	// unknown listener resolves nothing
	_, ok = rt.Router.Route("unknown", func(runtime.Cluster) bool { return true })
	require.False(t, ok)
}

func TestRoutePeer(t *testing.T) {
	rt := newRuntime(t)
	peer := net.ParseIP("10.0.0.1")

	addCluster(t, rt, &stnrv1.ClusterConfig{Name: "cluster-udp",
		Protocol: stnrv1.ClusterProtocolUDP.String(), Endpoints: []string{"10.0.0.0/8"}})
	addCluster(t, rt, &stnrv1.ClusterConfig{Name: "cluster-tcp",
		Protocol: stnrv1.ClusterProtocolTCP.String(), Endpoints: []string{"10.0.0.0/8"}})
	addCluster(t, rt, &stnrv1.ClusterConfig{Name: "turn-cluster",
		Protocol:   stnrv1.ClusterProtocolTURNUDP.String(),
		TURNServer: &stnrv1.TURNServer{Address: "1.2.3.4", Port: 3478},
	})
	addListener(t, rt, "listener", "cluster-udp", "cluster-tcp", "turn-cluster")

	// protocol-scoped: the same peer resolves per protocol, cached verdicts and all
	for i := 0; i < 2; i++ {
		got, ok := rt.Router.RoutePeer("listener", stnrv1.ClusterProtocolUDP, peer, 1234)
		require.True(t, ok)
		require.Equal(t, "cluster-udp", got)

		got, ok = rt.Router.RoutePeer("listener", stnrv1.ClusterProtocolTCP, peer, 1234)
		require.True(t, ok)
		require.Equal(t, "cluster-tcp", got)

		// a TURN-UDP cluster is not a UDP cluster: the data path does not route to it
		_, ok = rt.Router.RoutePeer("listener", stnrv1.ClusterProtocolUDP,
			net.ParseIP("192.168.0.1"), 0)
		require.False(t, ok)
	}

	// negative verdicts are cached too, and explicit invalidation clears them
	rt.Router.InvalidateCache()
	got, ok := rt.Router.RoutePeer("listener", stnrv1.ClusterProtocolUDP, peer, 80)
	require.True(t, ok)
	require.Equal(t, "cluster-udp", got)
}
