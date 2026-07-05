package turn

import (
	"fmt"
	"net"
	"strings"

	"github.com/pion/turn/v5"

	"github.com/l7mp/stunner/internal/netutil"
	objruntime "github.com/l7mp/stunner/internal/runtime"
	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"
)

// Relay adapts the dataplane relay transport to the pion RelayAddressGenerator interface for one
// listener context. All routing/admission and socket handling live in internal/netutil; this is
// only the pion-facing shim.
type Relay struct {
	listener string
	runtime  *objruntime.Runtime
	// addrs are the candidate relay addresses advertised to the client per family; the one
	// matching the allocation family is used.
	addrs    []net.IP
	fallback net.IP
}

// NewRelay creates a relay address generator for a listener context.
func NewRelay(listener string, rt *objruntime.Runtime) *Relay {
	conf := rt.GetConfig(objruntime.TypeListener, listener).(*stnrv1.ListenerConfig)
	addrs, fallback := parseRelayAddrs(conf)
	if fallback == nil && len(addrs) == 0 {
		panic(fmt.Sprintf("turn: no valid relay address for %q: address=%q addresses=%v",
			listener, conf.Addr, conf.Addrs))
	}
	return &Relay{listener: listener, runtime: rt, addrs: addrs, fallback: fallback}
}

// parseRelayAddrs derives a listener's candidate relay addresses (Addrs, at most one per family) and
// the Addr fallback. "localhost" is not an IP literal, so it is treated as the dual-stack loopback so
// relayIPFor can still match either family.
func parseRelayAddrs(conf *stnrv1.ListenerConfig) (addrs []net.IP, fallback net.IP) {
	fallback = net.ParseIP(conf.Addr)
	for _, a := range conf.Addrs {
		if ip := net.ParseIP(a); ip != nil {
			addrs = append(addrs, ip)
		}
	}
	if fallback == nil && len(addrs) == 0 && conf.Addr == "localhost" {
		addrs = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}
	return addrs, fallback
}

// relayIPFor returns the relay address to advertise for an allocation of the given network's family
// ("udp4"/"udp6"/"tcp4"/"tcp6"): the first configured Addrs entry of that family, else the listener
// Addr fallback.
func (r *Relay) relayIPFor(network string) net.IP {
	wantV6 := strings.HasSuffix(network, "6")
	for _, ip := range r.addrs {
		if (ip.To4() == nil) == wantV6 {
			return ip
		}
	}
	return r.fallback
}

// Validate is called on server startup and confirms the RelayAddressGenerator is configured.
func (r *Relay) Validate() error { return nil }

// AllocatePacketConn allocates the UDP relayed transport address of an allocation.
func (r *Relay) AllocatePacketConn(conf turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	return netutil.NewRelayPacketConn(r.runtime, r.listener, r.relayIPFor(conf.Network), conf.Network, conf.RequestedPort)
}

// AllocateConn opens an outgoing connection for an RFC 6062 Connect request, sourced from the
// allocation's relayed transport address.
func (r *Relay) AllocateConn(conf turn.AllocateConnConfig) (net.Conn, error) {
	return netutil.Dial(r.runtime, r.listener, conf.LocalAddr, conf.RemoteAddr)
}

// AllocateListener binds the relayed transport address of an RFC 6062 TCP allocation, admitting
// incoming connections at accept time. It fails early if the listener routes to no cluster of the
// requested protocol.
func (r *Relay) AllocateListener(conf turn.AllocateListenerConfig) (net.Listener, net.Addr, error) {
	if !netutil.HasRoutedCluster(r.runtime, r.listener, netutil.ProtocolFromNetwork(conf.Network)) {
		return nil, nil, netutil.ErrPortProhibited
	}
	return netutil.NewRelayListener(r.runtime, r.listener, r.relayIPFor(conf.Network), conf.Network, conf.RequestedPort)
}
