package stunner

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/pion/logging"

	"github.com/l7mp/stunner/v2/internal/turnclient"
	"github.com/l7mp/stunner/v2/internal/util"
	stnrv1 "github.com/l7mp/stunner/v2/pkg/apis/v1"
	a12n "github.com/l7mp/stunner/v2/pkg/authentication"
)

const UDP_PACKET_SIZE = 1500

// TurncatConfig is the main configuration for the turncat relay.
type TurncatConfig struct {
	// ListenAddr is the listeninging socket address (local tunnel endpoint).
	ListenerAddr string
	// ServerAddr is the TURN server addrees (e.g. "turn://turn.abc.com:3478").
	ServerAddr string
	// PeerAddr specifies the remote peer to connect to.
	PeerAddr string
	// Auth specifies how to authenticate to the TURN server, exactly as in a stunnerd config:
	// "static" with a fixed username/password pair, or "ephemeral" with a shared secret from
	// which a fresh time-windowed credential is generated per client connection, valid for the
	// configured lifetime. A nil config dials anonymously. The realm rides along in the config.
	Auth *stnrv1.AuthConfig
	// ServerName is the SNI used for virtual hosting (unless it is an IP address).
	ServerName string
	// InsecureMode controls whether self-signed TLS certificates are accepted by the TURN
	// client.
	InsecureMode bool
	// LoggerFactory is an optional external logger.
	LoggerFactory logging.LoggerFactory
}

// Turncat is the internal structure for representing a turncat relay.
type Turncat struct {
	listenerAddr  net.Addr
	serverAddr    net.Addr
	serverProto   string
	peerAddr      net.Addr
	auth          *stnrv1.AuthConfig     // How to authenticate to the server.
	listenerConn  interface{}            // net.Conn or net.PacketConn
	connTrack     map[string]*connection // Conntrack table.
	lock          *sync.Mutex            // Sync access to the conntrack state.
	serverName    string
	insecure      bool
	loggerFactory logging.LoggerFactory
	log           logging.LeveledLogger
}

type connection struct {
	clientAddr net.Addr       // Address of the client
	clientConn net.Conn       // Socket connected back to the client
	serverConn net.PacketConn // Relayed UDP connection to the server; owns the TURN session
}

// NewTurncat creates a new turncat relay from the specified config, creating a listener socket for
// clients to connect to and relaying client connections through the speficied STUN/TURN server to
// the peer.
func NewTurncat(config *TurncatConfig) (*Turncat, error) {
	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}
	log := loggerFactory.NewLogger("turncat")

	log.Tracef("resolving TURN server address: %s", config.ServerAddr)
	server, sErr := ParseURI(config.ServerAddr)
	if sErr != nil {
		return nil, fmt.Errorf("error resolving server address %s: %w", config.ServerAddr, sErr)
	}
	if server.Address == "" || server.Port == 0 {
		return nil, fmt.Errorf("error resolving TURN server address %s: empty address (\"%s\") "+
			"or invalid port (%d)", config.ServerAddr, server.Address, server.Port)
	}

	log.Tracef("resolving listener address: %s", config.ListenerAddr)
	listenerURI, lErr := ParseURI(config.ListenerAddr)
	if lErr != nil {
		return nil, fmt.Errorf("error parsing listener address %q: %w", config.ListenerAddr, lErr)
	}
	listenerProtocol := strings.ToLower(listenerURI.Protocol)

	log.Tracef("resolving peer address: %s", config.PeerAddr)
	peerURI, pErr := ParseURI(config.PeerAddr)
	if pErr != nil {
		return nil, fmt.Errorf("error parsing peer address %q: %w", config.PeerAddr, pErr)
	}
	// turncat only relays to a UDP peer; an incompatible protocol late-fails when the relay writes
	// to it (net.PacketConn.WriteTo).
	peerAddress := peerURI.Addr

	// a global listener connection for the local tunnel endpoint
	// per-client connections will connect back to the client
	log.Tracef("setting up listener connection on %s", config.ListenerAddr)

	var listenerConn any
	listenConf := &net.ListenConfig{Control: reuseAddr}
	var listenerAddress net.Addr
	switch listenerProtocol {
	case "file":
		listenerConn = util.NewFileConn(os.Stdin)
	case "udp", "udp4", "unixgram", "ip", "ip4":
		l, err := listenConf.ListenPacket(context.Background(),
			listenerURI.Addr.Network(), listenerURI.Addr.String())
		if err != nil {
			return nil, fmt.Errorf("cannot create listening client packet socket at %s: %s",
				config.ListenerAddr, err)
		}
		listenerAddress = listenerURI.Addr
		listenerConn = l
	case "tcp", "tcp4", "unix", "unixpacket":
		l, err := listenConf.Listen(context.Background(),
			listenerURI.Addr.Network(), listenerURI.Addr.String())
		if err != nil {
			return nil, fmt.Errorf("cannot create listening client socket at %s: %s",
				config.ListenerAddr, err)
		}
		listenerAddress = listenerURI.Addr
		listenerConn = l
	default:
		return nil, fmt.Errorf("unknown client protocol %s", listenerProtocol)
	}

	t := &Turncat{
		listenerAddr:  listenerAddress,
		serverAddr:    server.Addr,
		serverProto:   server.Protocol,
		peerAddr:      peerAddress,
		listenerConn:  listenerConn,
		connTrack:     make(map[string]*connection),
		lock:          new(sync.Mutex),
		auth:          config.Auth,
		serverName:    config.ServerName,
		insecure:      config.InsecureMode,
		loggerFactory: loggerFactory,
		log:           log,
	}

	switch listenerProtocol {
	case "udp", "udp4", "unixgram", "ip", "ip4":
		// client connection is a packet conn, write our own Listen/Accept loop for UDP
		// main loop: for every new packet we create a new connection and connect it back to the client
		go t.runListenPacket()
	case "tcp", "tcp4", "unix", "unixpacket":
		// client connection is bytestream, we are supposed to have a Listen/Accept loop available
		go t.runListen()
	case "file":
		// client connection is file
		go t.runListenFile()
	default:
		t.log.Errorf("internal error: unknown client protocol %q for client %s:%s",
			listenerAddress.Network(), listenerAddress.Network(), listenerAddress.String())
	}

	log.Infof("client listening on %s, TURN server: %s, peer: %s:%s",
		config.ListenerAddr, config.ServerAddr,
		peerAddress.Network(), peerAddress.String())

	return t, nil
}

// Close terminates all relay connections created via turncat and deletes the relay. Errors in this
// phase are not critical and not propagated back to the caller.
func (t *Turncat) Close() {
	t.log.Info("closing Turncat")

	// close all active connections
	for _, conn := range t.connTrack {
		t.deleteConnection(conn)
	}

	// close the global listener socket
	switch t.listenerConn.(type) {
	case net.Listener:
		t.log.Tracef("closing turncat listener connection")
		l := t.listenerConn.(net.Listener)
		if err := l.Close(); err != nil {
			t.log.Warnf("error closing listener connection: %s", err.Error())
		}
	case net.PacketConn:
		t.log.Tracef("closing turncat packet listener connection")
		l := t.listenerConn.(net.PacketConn)
		if err := l.Close(); err != nil {
			t.log.Warnf("error closing listener packet connection: %s", err.Error())
		}
	case *util.FileConn:
		// do nothing
	default:
		t.log.Error("internal error: unknown listener socket type")
	}
}

// Generate a new connection by opening a UDP connection to the server
func (t *Turncat) newConnection(clientConn net.Conn) (*connection, error) {
	clientAddr := clientConn.RemoteAddr()
	t.log.Debugf("new connection from client %s", clientAddr.String())

	conn := new(connection)
	conn.clientAddr = clientAddr
	conn.clientConn = clientConn

	t.log.Tracef("setting up TURN client to server %s:%s", t.serverAddr.Network(), t.serverAddr.String())

	user, passwd, errAuth := a12n.GenerateCredentials(t.auth)
	if errAuth != nil {
		return nil, fmt.Errorf("failed to generate username/password pair for client %s:%s: %s",
			clientAddr.Network(), clientAddr.String(), errAuth)
	}

	realm := ""
	if t.auth != nil {
		realm = t.auth.Realm
	}

	proto, err := stnrv1.NewListenerProtocol(t.serverProto)
	if err != nil {
		return nil, fmt.Errorf("unknown TURN server protocol %q for client %s:%s",
			t.serverProto, clientAddr.Network(), clientAddr.String())
	}

	t.log.Tracef("allocating relay transport for client %s:%s", clientAddr.Network(), clientAddr.String())
	serverConn, err := turnclient.Dialer{Config: turnclient.Config{
		Protocol:      proto,
		ServerAddr:    t.serverAddr.String(),
		Username:      user,
		Password:      passwd,
		Realm:         realm,
		ServerName:    t.serverName,
		Insecure:      t.insecure,
		LoggerFactory: t.loggerFactory,
	}}.ListenPacket(context.Background(), "udp", "")
	if err != nil {
		return nil, fmt.Errorf("failed to allocate TURN relay transport for client %s:%s: %w",
			clientAddr.Network(), clientAddr.String(), err)
	}
	conn.serverConn = serverConn

	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	t.log.Infof("new connection: client-address=%s, relayed-address=%s",
		clientAddr.String(), conn.serverConn.LocalAddr().String())

	return conn, nil
}

// don't err, just warn
func (t *Turncat) deleteConnection(conn *connection) {
	caddr := fmt.Sprintf("%s:%s", conn.clientAddr.Network(), conn.clientAddr.String())

	t.lock.Lock()
	_, found := t.connTrack[caddr]
	if !found {
		t.lock.Unlock()
		t.log.Debugf("deleteConnection: cannot find client connection for %s", caddr)
		return
	}
	delete(t.connTrack, caddr)
	t.lock.Unlock()

	t.log.Infof("closing client connection to %s", caddr)

	if err := conn.serverConn.Close(); err != nil {
		t.log.Warnf("error closing relayed TURN server connection for %s:%s: %s",
			conn.clientAddr.Network(), conn.clientAddr.String(), err.Error())
	}

	if err := conn.clientConn.Close(); err != nil {
		t.log.Warnf("error closing client connection for %s:%s: %s",
			conn.clientAddr.Network(), conn.clientAddr.String(), err.Error())
	}
}

// any error on read/write will delete the connection and terminate the goroutine
func (t *Turncat) runConnection(conn *connection) {
	// Read from server
	go func() {
		buffer := make([]byte, UDP_PACKET_SIZE)
		for {
			n, peerAddr, readErr := conn.serverConn.ReadFrom(buffer[0:])
			if readErr != nil {
				if !util.IsClosedErr(readErr) {
					t.log.Debugf("cannot read from TURN relay connection for client %s:%s: %s",
						conn.clientAddr.Network(), conn.clientAddr.String(), readErr.Error())
					t.deleteConnection(conn)
				}
				return
			}

			// TODO: not sure if this is the recommended way to compare net.Addrs
			if peerAddr.Network() != t.peerAddr.Network() || peerAddr.String() != t.peerAddr.String() {
				t.log.Debugf("received packet of %d bytes from unknown peer %s:%s (expected: "+
					"%s:%s) on TURN relay connection for client %s:%s: ignoring",
					n, peerAddr.Network(), peerAddr.String(),
					t.peerAddr.Network(), t.peerAddr.String(),
					conn.clientAddr.Network(), conn.clientAddr.String())
				continue
			}

			t.log.Tracef("forwarding packet of %d bytes from peer %s:%s on TURN relay connection "+
				"for client %s:%s", n, peerAddr.Network(), peerAddr.String(),
				conn.clientAddr.Network(), conn.clientAddr.String())

			if _, writeErr := conn.clientConn.Write(buffer[0:n]); writeErr != nil {
				t.log.Debugf("cannot write to client connection for client %s:%s: %s",
					conn.clientAddr.Network(), conn.clientAddr.String(), writeErr.Error())
				t.deleteConnection(conn)
				return
			}
		}
	}()

	// Read from client
	go func() {
		buffer := make([]byte, UDP_PACKET_SIZE)
		for {
			n, readErr := conn.clientConn.Read(buffer[0:])
			if readErr != nil {
				if !util.IsClosedErr(readErr) {
					t.log.Debugf("cannot read from client connection for client %s:%s (likely hamrless): %s",
						conn.clientAddr.Network(), conn.clientAddr.String(), readErr.Error())
					t.deleteConnection(conn)
				}
				return
			}

			t.log.Tracef("forwarding packet of %d bytes from client %s:%s to peer %s:%s on TURN relay connection",
				n, conn.clientAddr.Network(), conn.clientAddr.String(),
				t.peerAddr.Network(), t.peerAddr.String())

			if _, writeErr := conn.serverConn.WriteTo(buffer[0:n], t.peerAddr); writeErr != nil {
				t.log.Debugf("cannot write to TURN relay connection for client %s (likely harmless): %s",
					conn.clientAddr.String(), writeErr.Error())
				t.deleteConnection(conn)
				return
			}
		}
	}()
}

func (t *Turncat) runListenPacket() {
	listenerConn, ok := t.listenerConn.(net.PacketConn)
	if !ok {
		t.log.Error("cannot listen on client connection: expected net.PacketConn")
		// terminate go routine
		return
	}

	buffer := make([]byte, UDP_PACKET_SIZE)
	for {
		n, clientAddr, err := listenerConn.ReadFrom(buffer[0:])
		if err != nil {
			if !util.IsClosedErr(err) {
				t.log.Warnf("cannot read from listener connection: %s", err.Error())
			}
			return
		}

		// handle connection
		t.lock.Lock()
		caddr := fmt.Sprintf("%s:%s", clientAddr.Network(), clientAddr.String())
		trackConn, found := t.connTrack[caddr]
		if !found {
			t.log.Tracef("new client connection: read initial packet of %d bytes on listener"+
				"connnection from client %s", n, caddr)

			// create per-client connection, connect back to client, then call runConnection
			t.log.Tracef("connnecting back to client %s", caddr)
			dialer := &net.Dialer{LocalAddr: t.listenerAddr, Control: reuseAddr}
			clientConn, clientErr := dialer.Dial(clientAddr.Network(), clientAddr.String())
			if clientErr != nil {
				t.log.Warnf("cannot connect back to client %s:%s: %s",
					clientAddr.Network(), clientAddr.String(), clientErr.Error())
				continue
			}

			conn, err := t.newConnection(clientConn)
			if err != nil {
				t.lock.Unlock()
				t.log.Warnf("relay setup failed for client %s: %s", caddr, err.Error())
				continue
			}

			t.connTrack[caddr] = conn
			t.lock.Unlock()

			// Fire up routine to manage new connection
			// terminated once we kill their connection
			t.runConnection(conn)

			// and send the packet out
			if _, err := conn.serverConn.WriteTo(buffer[0:n], t.peerAddr); err != nil {
				t.log.Warnf("cannot write initial packet to TURN relay connection for client %s: %s",
					caddr, err.Error())
				t.deleteConnection(conn)
				continue
			}
		} else {
			// received a packet for an established client connection on the main
			// listener: this can happen if the client is too fast and a couple of
			// packets are left stuck in the global listener socket
			t.lock.Unlock()

			t.log.Debugf("received packet from a known client %s on the global listener connection, sender too fast?",
				caddr)
			// send out anyway
			if _, err := trackConn.serverConn.WriteTo(buffer[0:n], t.peerAddr); err != nil {
				t.log.Warnf("cannot write packet to TURN relay connection for client %s: %s",
					caddr, err.Error())
				t.deleteConnection(trackConn)
				continue
			}
		}

	}
}

func (t *Turncat) runListen() {
	listenerConn, ok := t.listenerConn.(net.Listener)
	if !ok {
		t.log.Error("cannot listen on client connection: expected net.Conn")
		// terminate go routine
		return
	}

	for {
		clientConn, err := listenerConn.Accept()
		if err != nil {
			if !util.IsClosedErr(err) {
				t.log.Warnf("cannot accept() in listener connection: %s", err.Error())
				continue
			} else {
				// terminate go routine
				return
			}
		}

		// handle connection
		t.lock.Lock()
		clientAddr := clientConn.RemoteAddr()
		caddr := fmt.Sprintf("%s:%s", clientAddr.Network(), clientAddr.String())
		_, found := t.connTrack[caddr]
		if !found {
			t.log.Tracef("new client connection: %s", caddr)

			conn, err := t.newConnection(clientConn)
			if err != nil {
				t.lock.Unlock()
				t.log.Warnf("relay setup failed for client %s, dropping client connection",
					caddr)
				continue
			}

			t.connTrack[caddr] = conn
			t.lock.Unlock()

			// Fire up routine to manage new connection
			// terminated once we kill their connection
			t.runConnection(conn)
		} else {
			// received a packet for an established client connection on the main
			// listener: this should never happen
			t.lock.Unlock()

			t.log.Errorf("internal error: received packet from a known client %s on the global listener connection",
				caddr)
		}
	}
}

func (t *Turncat) runListenFile() {
	listenerConn, ok := t.listenerConn.(*util.FileConn)
	if !ok {
		t.log.Error("cannot listen on client connection: expected file")
		// terminate go routine
		return
	}

	// handle connection
	caddr := listenerConn.LocalAddr().String()
	t.log.Tracef("new client connection: %s", caddr)
	t.lock.Lock()
	defer t.lock.Unlock()

	conn, err := t.newConnection(listenerConn)
	if err != nil {
		t.log.Warnf("relay setup failed for client %s: %s", caddr, err.Error())
		return
	}

	t.connTrack[caddr] = conn

	t.runConnection(conn)
}
