package l4

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// bufferSize is the pump chunk size: one read makes one datagram on a datagram leg, so a
// stream-to-datagram flow frames the stream into MTU-sized datagrams (and the reverse
// direction preserves datagram boundaries only as chunk boundaries in the stream).
const bufferSize = 1500

// flow is one relayed client flow: the client-side conn, the relay leg towards the pinned
// peer (a packet conn for datagram legs, a conn for stream legs), and the idle machinery.
type flow struct {
	s           *Server
	client      net.Conn
	relayPacket net.PacketConn
	relayStream net.Conn
	peer        net.Addr

	last      atomic.Int64 // UnixNano of the last activity in either direction
	timer     *time.Timer
	closeOnce sync.Once
}

// run starts the peer-side pump and runs the client-side pump; it returns on flow teardown.
func (f *flow) run() {
	go f.pumpPeerToClient()
	f.pumpClientToPeer()
}

func (f *flow) pumpClientToPeer() {
	buf := make([]byte, bufferSize)
	for {
		n, err := f.client.Read(buf)
		if err != nil {
			// io.EOF included: a TCP FIN or stdin EOF ends the flow
			f.close("client side closed")
			return
		}
		f.touch()
		if f.relayPacket != nil {
			_, err = f.relayPacket.WriteTo(buf[:n], f.peer)
		} else {
			_, err = f.relayStream.Write(buf[:n])
		}
		if err != nil {
			f.close("peer side write error: " + err.Error())
			return
		}
	}
}

func (f *flow) pumpPeerToClient() {
	buf := make([]byte, bufferSize)
	for {
		var n int
		var err error
		if f.relayPacket != nil {
			var from net.Addr
			n, from, err = f.relayPacket.ReadFrom(buf)
			// the flow is pinned to its peer: drop datagrams from anyone else (the
			// admission wrapper has already dropped unadmitted sources)
			if err == nil && from.String() != f.peer.String() {
				continue
			}
		} else {
			n, err = f.relayStream.Read(buf)
		}
		if err != nil {
			f.close("peer side closed")
			return
		}
		f.touch()
		if _, err := f.client.Write(buf[:n]); err != nil {
			f.close("client side write error: " + err.Error())
			return
		}
	}
}

func (f *flow) touch() { f.last.Store(time.Now().UnixNano()) }

// checkIdle fires on the coarse per-flow timer: it tears the flow down when it has been quiet
// for the idle timeout in both directions, otherwise re-arms for the remainder.
func (f *flow) checkIdle() {
	elapsed := time.Duration(time.Now().UnixNano() - f.last.Load())
	if elapsed >= f.s.idle {
		f.close("idle timeout")
		return
	}
	f.timer.Reset(f.s.idle - elapsed)
}

func (f *flow) close(reason string) {
	f.closeOnce.Do(func() {
		f.timer.Stop()
		_ = f.client.Close()
		f.closeLeg()
		f.s.removeFlow(f)
		f.s.log.Debugf("flow deleted: client=%s, peer=%s, reason: %s",
			f.client.RemoteAddr().String(), f.peer.String(), reason)
	})
}

func (f *flow) closeLeg() {
	if f.relayPacket != nil {
		_ = f.relayPacket.Close()
	} else {
		_ = f.relayStream.Close()
	}
}
