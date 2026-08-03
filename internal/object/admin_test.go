package object_test

import (
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l7mp/stunner/v2/internal/object"
	"github.com/l7mp/stunner/v2/internal/resolver"
	"github.com/l7mp/stunner/v2/internal/runtime"
	stnrv1 "github.com/l7mp/stunner/v2/pkg/apis/v1"
	"github.com/l7mp/stunner/v2/pkg/logger"
)

func TestAdminObjectSemantics(t *testing.T) {
	runObjectSemanticsCase(t, objectSemanticsCase{
		name: "admin",
		setup: func(t *testing.T) (runtime.Object, stnrv1.Config, *stnrv1.StunnerConfig) {
			env := newTestEnv()

			health, err := object.NewHealth(&object.HealthConfig{Endpoint: ""}, env.rt)
			require.NoError(t, err)
			mustAdd(t, env, health)

			metrics, err := object.NewMetrics(&object.MetricsConfig{Endpoint: ""}, env.rt)
			require.NoError(t, err)
			mustAdd(t, env, metrics)

			offload, err := object.NewOffload(&object.OffloadConfig{Engine: stnrv1.OffloadEngineNone.String(), Interfaces: []string{}}, env.rt)
			require.NoError(t, err)
			mustAdd(t, env, offload)

			obj, err := object.NewAdmin(nil, env.rt)
			require.NoError(t, err)

			base := &stnrv1.AdminConfig{
				Name:                stnrv1.DefaultStunnerName,
				LogLevel:            stnrv1.DefaultLogLevel,
				MetricsEndpoint:     "",
				HealthCheckEndpoint: strPtr(""),
				UserQuota:           10,
				OffloadEngine:       stnrv1.OffloadEngineNone.String(),
				OffloadInterfaces:   []string{},
			}

			return obj, base, &stnrv1.StunnerConfig{}
		},
		expectations: []inspectExpectation{
			{
				name: "loglevel-change-reconcile",
				conf: &stnrv1.AdminConfig{
					Name:                stnrv1.DefaultStunnerName,
					LogLevel:            "all:DEBUG",
					MetricsEndpoint:     "",
					HealthCheckEndpoint: strPtr(""),
					UserQuota:           10,
					OffloadEngine:       stnrv1.OffloadEngineNone.String(),
					OffloadInterfaces:   []string{},
				},
				want: runtime.ActionReconcile,
			},
			{
				name: "same-config-none",
				conf: &stnrv1.AdminConfig{
					Name:                stnrv1.DefaultStunnerName,
					LogLevel:            stnrv1.DefaultLogLevel,
					MetricsEndpoint:     "",
					HealthCheckEndpoint: strPtr(""),
					UserQuota:           10,
					OffloadEngine:       stnrv1.OffloadEngineNone.String(),
					OffloadInterfaces:   []string{},
				},
				want: runtime.ActionNone,
			},
		},
	})
}

// TestHealthServerBindsBothFamilies pins the endpoint-URI handling of the health/metrics servers
// through the exported API: the operator's default host-less endpoint ("http://:8086") must bind
// the unspecified address of every available family, IPv6-only clusters included, and a repeated
// Start with an unchanged endpoint must not try to re-bind the port.
func TestHealthServerBindsBothFamilies(t *testing.T) {
	log := logger.NewLoggerFactory(stnrv1.DefaultLogLevel)
	r := resolver.NewMockResolver(map[string][]string{}, log)
	rt := runtime.New(runtime.Config{Logger: log, Resolver: r})

	// grab a free port for the host-less endpoint
	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	h, err := object.NewHealth(&object.HealthConfig{Endpoint: fmt.Sprintf("http://:%d", port)}, rt)
	require.NoError(t, err)
	require.NoError(t, h.Start())
	defer h.Close(false) //nolint:errcheck
	require.NoError(t, h.Start(), "repeated Start with an unchanged endpoint is a no-op")

	hosts := []string{"127.0.0.1"}
	if l6, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		require.NoError(t, l6.Close())
		hosts = append(hosts, "[::1]")
	}
	for _, host := range hosts {
		resp, err := http.Get(fmt.Sprintf("http://%s:%d/live", host, port))
		require.NoErrorf(t, err, "GET /live over %s", host)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	}
}
