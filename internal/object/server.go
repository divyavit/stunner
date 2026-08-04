package object

import (
	"fmt"
	"strings"

	"github.com/l7mp/stunner/v2/internal/object/l4"
	objectturn "github.com/l7mp/stunner/v2/internal/object/turn"
	"github.com/l7mp/stunner/v2/internal/runtime"
	"github.com/l7mp/stunner/v2/internal/util"
	stnrv1 "github.com/l7mp/stunner/v2/pkg/apis/v1"
)

// engine is the packet engine a listener runs: the TURN server for the TURN-* protocols, the
// L4 flow engine for the plain protocols. Engines are created running; the listener-server
// node owns their lifecycle and reports their active session count.
type engine interface {
	// Close shuts the engine down, tearing down its transport listeners and sessions.
	Close() error
	// AllocationCount returns the number of active sessions: TURN allocations on a TURN
	// engine, live flows on the L4 engine.
	AllocationCount() int
}

// ListenerServer is the lifecycle-only child node that owns the packet engine of a Listener.
type ListenerServer struct {
	name     string
	listener *Listener
	rt       *runtime.Runtime
	server   engine
}

// NewListenerServer creates a lifecycle-only listener server child.
func NewListenerServer(listener *Listener, rt *runtime.Runtime) *ListenerServer {
	return &ListenerServer{
		name:     listener.Name(),
		listener: listener,
		rt:       rt,
	}
}

func (s *ListenerServer) Name() string { return s.name }

func (s *ListenerServer) Type() runtime.ObjectType { return runtime.TypeListenerServer }

func (s *ListenerServer) Start() error {
	s.listener.log.Infof("listener %s (re)starting", s.listener.String())
	conf := s.rt.GetConfig(runtime.TypeListener, s.name).(*stnrv1.ListenerConfig)
	proto, err := stnrv1.NewListenerProtocol(conf.Protocol)
	if err != nil {
		return err
	}

	if proto.IsTURN() {
		t, err := objectturn.NewServer(s.name, s.rt)
		if err != nil {
			return fmt.Errorf("failed to start TURN server for listener %s: %w", s.name, err)
		}
		s.server = t
	} else {
		f, err := l4.NewServer(s.name, s.rt)
		if err != nil {
			return fmt.Errorf("failed to start flow engine for listener %s: %w", s.name, err)
		}
		s.server = f
	}
	s.listener.log.Infof("listener %s: listener running", s.name)
	return nil
}

func (s *ListenerServer) Close(_ bool) error {
	if s.server == nil {
		return nil
	}
	err := s.server.Close()
	s.server = nil
	if err != nil && !util.IsClosedErr(err) && !strings.Contains(err.Error(), "already closed") {
		return err
	}
	return nil
}

// AllocationCount returns the number of active sessions on the listener's engine.
func (s *ListenerServer) AllocationCount() int {
	if s.server == nil {
		return 0
	}
	return s.server.AllocationCount()
}
