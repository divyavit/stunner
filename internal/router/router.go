// Package router finds the cluster that serves a request on a listener. The router is
// deliberately dumb: it looks up the listener's routes and walks them in order, handing each
// cluster object to the caller's matcher; what a cluster admits is the cluster's business.
// RoutePeer caches its verdicts in a per-peer LRU that is invalidated explicitly whenever routing
// state changes (listener and cluster reconcile, DNS re-resolution).
package router

import (
	"net"
	"strconv"

	"k8s.io/utils/lru"

	"github.com/pion/logging"

	"github.com/l7mp/stunner/internal/runtime"
	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"
)

const peerRouteCacheSize = 4096

var _ runtime.Router = (*router)(nil)

// router is the default runtime.Router.
type router struct {
	rt        *runtime.Runtime
	peerCache *lru.Cache // listener|proto|peer:port -> *peerVerdict
	log       logging.LeveledLogger
}

type peerVerdict struct {
	cluster string
	ok      bool
}

// NewRouter returns the default Router.
func NewRouter(rt *runtime.Runtime) runtime.Router {
	return &router{
		rt:        rt,
		peerCache: lru.New(peerRouteCacheSize),
		log:       rt.Logger.NewLogger("router"),
	}
}

func (r *router) InvalidateCache() { r.peerCache.Clear() }

// Route returns the first cluster on the listener's routes satisfying the matcher.
func (r *router) Route(listener string, match func(runtime.Cluster) bool) (runtime.Cluster, bool) {
	lconf, ok := r.rt.GetConfig(runtime.TypeListener, listener).(*stnrv1.ListenerConfig)
	if !ok || lconf == nil {
		return nil, false
	}
	for _, name := range lconf.Routes {
		// a route may name a missing cluster (config skew, skipped); anything registered
		// under TypeCluster is a cluster object, so a load bug panics right here
		if o, ok := r.rt.Registry.Get(runtime.TypeCluster, name); ok {
			if c := o.(runtime.Cluster); match(c) {
				return c, true
			}
		}
	}
	return nil, false
}

// RoutePeer returns the name of the first cluster on the listener's routes with the given
// protocol that admits (peer, port). The verdict, positive or negative, is served from the LRU
// until the next invalidation.
func (r *router) RoutePeer(listener string, proto stnrv1.ClusterProtocol, peer net.IP, port int) (string, bool) {
	key := listener + "|" + proto.String() + "|" + peer.String() + ":" + strconv.Itoa(port)
	if v, ok := r.peerCache.Get(key); ok {
		p := v.(*peerVerdict)
		return p.cluster, p.ok
	}

	v := &peerVerdict{}
	if c, ok := r.Route(listener, func(c runtime.Cluster) bool {
		return c.Protocol() == proto && c.Admits(peer, port)
	}); ok {
		v.cluster, v.ok = c.Name(), true
	}
	r.peerCache.Add(key, v)
	return v.cluster, v.ok
}
