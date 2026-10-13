package transport

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/quic-go/quic-go"
)

func TestRelayDatagramStartFailureAndClose(t *testing.T) {
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	addr := occupied.LocalAddr().(*net.UDPAddr)
	endpoint := NewRelayDatagram(types.NewServiceIdentityKey("lease", "test"), addr.Port)
	defer endpoint.Close()
	if err := endpoint.Start(); err == nil {
		t.Fatal("Start bound an occupied port")
	}
	_ = occupied.Close()
	if err := endpoint.Start(); err != nil {
		t.Fatalf("Start after releasing port: %v", err)
	}
	if err := endpoint.Start(); err != nil {
		t.Fatalf("repeated Start: %v", err)
	}
	endpoint.Close()
	if err := endpoint.Start(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Start after Close: %v", err)
	}
	rebound, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Close did not release the socket: %v", err)
	}
	_ = rebound.Close()
}

func TestDatagramSessionCloseUnblocksAccept(t *testing.T) {
	session := NewDatagramSession(1, false)
	closed := make(chan error, 1)
	go func() { _, err := session.Accept(nil); closed <- err }()
	session.Close("test complete")
	session.Close("already closed")
	if err := <-closed; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
	if err := session.Send(1, []byte("closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send after Close: %v", err)
	}
}

func TestRelayDatagramConcurrentStartAndClose(t *testing.T) {
	endpoint := NewRelayDatagram(types.NewServiceIdentityKey("lease", "test"), 0)
	var workers sync.WaitGroup
	workers.Go(func() {
		if err := endpoint.Start(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Start racing Close: %v", err)
		}
	})
	workers.Go(endpoint.Close)
	workers.Wait()
	if err := endpoint.Start(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed endpoint restarted: %v", err)
	}
}

func TestRelayDatagramFlowBoundsAndDisconnectedBackhaul(t *testing.T) {
	endpoint := NewRelayDatagram(types.NewServiceIdentityKey("lease", "test"), 0)
	defer endpoint.Close()
	endpoint.maxFlows = 2

	addr1 := netip.MustParseAddrPort("127.0.0.1:10001")
	addr2 := netip.MustParseAddrPort("127.0.0.1:10002")
	addr3 := netip.MustParseAddrPort("127.0.0.1:10003")

	// Disconnected backhaul: no fresh flow state allocated
	id, isNew, ok := endpoint.touchFlow(addr1)
	if ok || id != 0 || isNew {
		t.Fatalf("touchFlow without backhaul returned id=%d, isNew=%v, ok=%v", id, isNew, ok)
	}
	if len(endpoint.flowTable) != 0 || len(endpoint.addrIndex) != 0 {
		t.Fatalf("state allocated without backhaul: table=%d, index=%d", len(endpoint.flowTable), len(endpoint.addrIndex))
	}

	// Mark session connected for test
	endpoint.session.mu.Lock()
	endpoint.session.conn = &quic.Conn{}
	endpoint.session.mu.Unlock()

	// Flow 1 admitted
	id1, isNew1, ok1 := endpoint.touchFlow(addr1)
	if !ok1 || !isNew1 || id1 == 0 {
		t.Fatalf("flow 1 touchFlow: id=%d, isNew=%v, ok=%v", id1, isNew1, ok1)
	}

	// Flow 2 admitted
	id2, isNew2, ok2 := endpoint.touchFlow(addr2)
	if !ok2 || !isNew2 || id2 == 0 {
		t.Fatalf("flow 2 touchFlow: id=%d, isNew=%v, ok=%v", id2, isNew2, ok2)
	}

	// Established flow 1 works at capacity
	id1Again, isNew1Again, ok1Again := endpoint.touchFlow(addr1)
	if !ok1Again || isNew1Again || id1Again != id1 {
		t.Fatalf("flow 1 reuse: id=%d, isNew=%v, ok=%v", id1Again, isNew1Again, ok1Again)
	}

	// Flow 3 rejected (capacity bound)
	id3, isNew3, ok3 := endpoint.touchFlow(addr3)
	if ok3 || id3 != 0 || isNew3 {
		t.Fatalf("flow 3 exceeded capacity: id=%d, isNew=%v, ok=%v", id3, isNew3, ok3)
	}
}

func TestRelayDatagramFlowIDWrapCollisionSafety(t *testing.T) {
	endpoint := NewRelayDatagram(types.NewServiceIdentityKey("lease", "test"), 0)
	defer endpoint.Close()
	endpoint.maxFlows = 5

	endpoint.session.mu.Lock()
	endpoint.session.conn = &quic.Conn{}
	endpoint.session.mu.Unlock()

	// Set nextFlow near wrap
	endpoint.mu.Lock()
	endpoint.nextFlow = ^uint32(0) // max uint32
	endpoint.mu.Unlock()

	addr1 := netip.MustParseAddrPort("127.0.0.1:10001")
	id1, _, ok1 := endpoint.touchFlow(addr1)
	if !ok1 || id1 != ^uint32(0) {
		t.Fatalf("flow 1 id=%d, ok=%v", id1, ok1)
	}

	// Next flow should wrap past 0 to 1
	addr2 := netip.MustParseAddrPort("127.0.0.1:10002")
	id2, _, ok2 := endpoint.touchFlow(addr2)
	if !ok2 || id2 != 1 {
		t.Fatalf("flow 2 did not wrap to 1: id=%d, ok=%v", id2, ok2)
	}

	// Pre-occupy id 2
	addr3 := netip.MustParseAddrPort("127.0.0.1:10003")
	endpoint.mu.Lock()
	endpoint.flowTable[2] = &flowState{addr: addr3, lastSeen: time.Now()}
	endpoint.addrIndex[addr3] = 2
	endpoint.nextFlow = 1 // will try 2 next
	endpoint.mu.Unlock()

	addr4 := netip.MustParseAddrPort("127.0.0.1:10004")
	id4, _, ok4 := endpoint.touchFlow(addr4)
	if !ok4 || id4 == 2 {
		t.Fatalf("flow 4 collided with existing id 2: id=%d", id4)
	}
	if endpoint.flowTable[2].addr != addr3 {
		t.Fatalf("flow 2 was overwritten by wrap")
	}
}

func TestDatagramSessionDrain(t *testing.T) {
	session := NewDatagramSession(10, false)
	defer session.Close("test done")

	session.incoming <- types.DatagramFrame{FlowID: 1}
	session.incoming <- types.DatagramFrame{FlowID: 2}

	session.Drain()

	select {
	case frame := <-session.incoming:
		t.Fatalf("incoming not empty after Drain: %+v", frame)
	default:
	}
}
