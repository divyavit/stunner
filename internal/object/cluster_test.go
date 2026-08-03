package object_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l7mp/stunner/v2/internal/object"
	"github.com/l7mp/stunner/v2/internal/runtime"
	stnrv1 "github.com/l7mp/stunner/v2/pkg/apis/v1"
)

func TestClusterStrictDNSObjectSemantics(t *testing.T) {
	runObjectSemanticsCase(t, objectSemanticsCase{
		name: "cluster-strict-dns",
		setup: func(t *testing.T) (runtime.Object, stnrv1.Config, *stnrv1.StunnerConfig) {
			env := newTestEnv()
			obj, err := object.NewCluster(nil, env.rt)
			require.NoError(t, err)

			base := &stnrv1.ClusterConfig{
				Name:      "cluster-a",
				Type:      stnrv1.ClusterTypeStrictDNS.String(),
				Protocol:  stnrv1.ClusterProtocolUDP.String(),
				Endpoints: []string{"Echo-Server.L7MP.io"},
			}
			return obj, base, &stnrv1.StunnerConfig{}
		},
		expectations: []inspectExpectation{
			{
				name: "strictdns-case-change-reconcile",
				conf: &stnrv1.ClusterConfig{
					Name:      "cluster-a",
					Type:      stnrv1.ClusterTypeStrictDNS.String(),
					Protocol:  stnrv1.ClusterProtocolUDP.String(),
					Endpoints: []string{"echo-server.l7mp.io"},
				},
				want: runtime.ActionReconcile,
			},
			{
				name: "strictdns-endpoint-change-restart",
				conf: &stnrv1.ClusterConfig{
					Name:      "cluster-a",
					Type:      stnrv1.ClusterTypeStrictDNS.String(),
					Protocol:  stnrv1.ClusterProtocolUDP.String(),
					Endpoints: []string{"echo-server.l7mp.io", "dummy.l7mp.io"},
				},
				want: runtime.ActionRestart,
			},
			{
				name: "strictdns-to-static-restart",
				conf: &stnrv1.ClusterConfig{
					Name:      "cluster-a",
					Type:      stnrv1.ClusterTypeStatic.String(),
					Protocol:  stnrv1.ClusterProtocolUDP.String(),
					Endpoints: []string{"0.0.0.0/0"},
				},
				want: runtime.ActionRestart,
			},
		},
	})
}

func TestClusterStaticObjectSemantics(t *testing.T) {
	runObjectSemanticsCase(t, objectSemanticsCase{
		name: "cluster-static",
		setup: func(t *testing.T) (runtime.Object, stnrv1.Config, *stnrv1.StunnerConfig) {
			env := newTestEnv()
			obj, err := object.NewCluster(nil, env.rt)
			require.NoError(t, err)

			base := &stnrv1.ClusterConfig{
				Name:      "cluster-static",
				Type:      stnrv1.ClusterTypeStatic.String(),
				Protocol:  stnrv1.ClusterProtocolUDP.String(),
				Endpoints: []string{"1.2.3.4"},
			}
			return obj, base, &stnrv1.StunnerConfig{}
		},
		expectations: []inspectExpectation{
			{
				name: "static-endpoint-update-reconcile",
				conf: &stnrv1.ClusterConfig{
					Name:      "cluster-static",
					Type:      stnrv1.ClusterTypeStatic.String(),
					Protocol:  stnrv1.ClusterProtocolUDP.String(),
					Endpoints: []string{"5.6.7.8"},
				},
				want: runtime.ActionReconcile,
			},
		},
	})
}

func TestClusterTURNObjectSemantics(t *testing.T) {
	runObjectSemanticsCase(t, objectSemanticsCase{
		name: "cluster-turn",
		setup: func(t *testing.T) (runtime.Object, stnrv1.Config, *stnrv1.StunnerConfig) {
			env := newTestEnv()
			obj, err := object.NewCluster(nil, env.rt)
			require.NoError(t, err)

			base := &stnrv1.ClusterConfig{
				Name:     "cluster-turn",
				Type:     stnrv1.ClusterTypeStatic.String(),
				Protocol: stnrv1.ClusterProtocolTURNUDP.String(),
				TURNServer: &stnrv1.TURNServer{
					Address: "turn.example.com",
					Port:    3478,
					Auth: &stnrv1.AuthConfig{Type: "static", Credentials: map[string]string{
						"username": "user1", "password": "pass1"}},
				},
			}
			return obj, base, &stnrv1.StunnerConfig{}
		},
		expectations: []inspectExpectation{
			{
				// TURN config changes are allocation-scoped: reconcile, no restart
				name: "turn-credential-change-reconcile",
				conf: &stnrv1.ClusterConfig{
					Name:     "cluster-turn",
					Type:     stnrv1.ClusterTypeStatic.String(),
					Protocol: stnrv1.ClusterProtocolTURNUDP.String(),
					TURNServer: &stnrv1.TURNServer{
						Address: "turn.example.com",
						Port:    3478,
						Auth: &stnrv1.AuthConfig{Type: "static", Credentials: map[string]string{
							"username": "user2", "password": "pass2"}},
					},
				},
				want: runtime.ActionReconcile,
			},
			{
				name: "turn-server-address-change-reconcile",
				conf: &stnrv1.ClusterConfig{
					Name:     "cluster-turn",
					Type:     stnrv1.ClusterTypeStatic.String(),
					Protocol: stnrv1.ClusterProtocolTURNUDP.String(),
					TURNServer: &stnrv1.TURNServer{
						Address: "turn2.example.com",
						Port:    5349,
						Auth: &stnrv1.AuthConfig{Type: "static", Credentials: map[string]string{
							"username": "user1", "password": "pass1"}},
					},
				},
				want: runtime.ActionReconcile,
			},
			{
				name: "turn-transport-change-reconcile",
				conf: &stnrv1.ClusterConfig{
					Name:     "cluster-turn",
					Type:     stnrv1.ClusterTypeStatic.String(),
					Protocol: stnrv1.ClusterProtocolTURNTCP.String(),
					TURNServer: &stnrv1.TURNServer{
						Address: "turn.example.com",
						Port:    3478,
						Auth: &stnrv1.AuthConfig{Type: "static", Credentials: map[string]string{
							"username": "user1", "password": "pass1"}},
					},
				},
				want: runtime.ActionReconcile,
			},
			{
				name: "turn-to-direct-protocol-change-reconcile",
				conf: &stnrv1.ClusterConfig{
					Name:      "cluster-turn",
					Type:      stnrv1.ClusterTypeStatic.String(),
					Protocol:  stnrv1.ClusterProtocolUDP.String(),
					Endpoints: []string{"0.0.0.0/0"},
				},
				want: runtime.ActionReconcile,
			},
			{
				name: "turn-to-strict-dns-restart",
				conf: &stnrv1.ClusterConfig{
					Name:      "cluster-turn",
					Type:      stnrv1.ClusterTypeStrictDNS.String(),
					Protocol:  stnrv1.ClusterProtocolUDP.String(),
					Endpoints: []string{"echo-server.l7mp.io"},
				},
				want: runtime.ActionRestart,
			},
		},
	})
}
