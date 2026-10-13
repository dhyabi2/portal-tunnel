package sdk

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestUDPFlowManagerBoundsAndCapacity(t *testing.T) {
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()

	mgr := newUDPFlowManager(origin.LocalAddr().(*net.UDPAddr), nil)
	mgr.maxFlows = 2
	defer mgr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Add flow 1
	conn1, err := mgr.getOrCreate(ctx, types.DatagramFrame{FlowID: 1, Address: "app", RelayURL: "relay"})
	if err != nil {
		t.Fatalf("flow 1 getOrCreate: %v", err)
	}
	// Add flow 2
	conn2, err := mgr.getOrCreate(ctx, types.DatagramFrame{FlowID: 2, Address: "app", RelayURL: "relay"})
	if err != nil {
		t.Fatalf("flow 2 getOrCreate: %v", err)
	}

	// Established flow 1 works at capacity
	conn1Again, err := mgr.getOrCreate(ctx, types.DatagramFrame{FlowID: 1, Address: "app", RelayURL: "relay"})
	if err != nil || conn1Again != conn1 {
		t.Fatalf("flow 1 reuse failed: %v", err)
	}

	// Flow 3 exceeds capacity
	conn3, err := mgr.getOrCreate(ctx, types.DatagramFrame{FlowID: 3, Address: "app", RelayURL: "relay"})
	if !errors.Is(err, errFlowLimitExceeded) {
		t.Fatalf("flow 3 err = %v, want errFlowLimitExceeded (conn=%v)", err, conn3)
	}

	_ = conn2
}

func TestUDPFlowManagerOldReaderCannotDeleteReplacementEntry(t *testing.T) {
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()

	mgr := newUDPFlowManager(origin.LocalAddr().(*net.UDPAddr), nil)
	defer mgr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	frame := types.DatagramFrame{FlowID: 1, Address: "app", RelayURL: "relay"}
	conn1, err := mgr.getOrCreate(ctx, frame)
	if err != nil {
		t.Fatal(err)
	}

	key := udpFlowKey{flowID: 1, address: "app", relayURL: "relay"}

	// Simulate expiry and replacement with conn2
	conn2, err := net.DialUDP("udp", nil, origin.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	mgr.mu.Lock()
	mgr.flows[key] = &udpFlowEntry{
		conn:     conn2,
		lastSeen: time.Now(),
		frame:    frame,
	}
	mgr.mu.Unlock()

	// Old reader error cleanup for conn1 tries to remove key
	mgr.removeFlowIfConn(key, conn1)

	// Verify key was NOT deleted because conn1 != conn2
	mgr.mu.Lock()
	entry := mgr.flows[key]
	mgr.mu.Unlock()

	if entry == nil || entry.conn != conn2 {
		t.Fatalf("old reader deleted successor entry: %+v", entry)
	}
}

func TestUDPFlowManagerLeaseReplacementPrunesStaleFlows(t *testing.T) {
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()

	mgr := newUDPFlowManager(origin.LocalAddr().(*net.UDPAddr), nil)
	defer mgr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	frame1 := types.DatagramFrame{FlowID: 1, Address: "app", RelayURL: "relay", LeaseID: "lease-A"}
	_, err = mgr.getOrCreate(ctx, frame1)
	if err != nil {
		t.Fatal(err)
	}

	key1 := udpFlowKey{flowID: 1, address: "app", relayURL: "relay", leaseID: "lease-A"}
	mgr.mu.Lock()
	if _, ok := mgr.flows[key1]; !ok {
		mgr.mu.Unlock()
		t.Fatal("lease-A flow missing")
	}
	mgr.mu.Unlock()

	// Replaced lease frame arrives
	frame2 := types.DatagramFrame{FlowID: 1, Address: "app", RelayURL: "relay", LeaseID: "lease-B"}
	_, err = mgr.getOrCreate(ctx, frame2)
	if err != nil {
		t.Fatal(err)
	}

	// Verify lease-A flow was pruned
	mgr.mu.Lock()
	_, oldExists := mgr.flows[key1]
	key2 := udpFlowKey{flowID: 1, address: "app", relayURL: "relay", leaseID: "lease-B"}
	_, newExists := mgr.flows[key2]
	mgr.mu.Unlock()

	if oldExists {
		t.Error("stale lease-A flow was not pruned on lease replacement")
	}
	if !newExists {
		t.Error("new lease-B flow was not created")
	}
}

func TestUDPFlowManagerRepeatedCloseReleasesSockets(t *testing.T) {
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < 3; i++ {
		mgr := newUDPFlowManager(origin.LocalAddr().(*net.UDPAddr), nil)
		go mgr.runCleanup(ctx)

		for flow := uint32(1); flow <= 5; flow++ {
			_, err := mgr.getOrCreate(ctx, types.DatagramFrame{FlowID: flow, Address: "app", RelayURL: "relay"})
			if err != nil {
				t.Fatalf("iteration %d getOrCreate: %v", i, err)
			}
		}
		mgr.Close()
		mgr.Close() // Idempotent close
	}
}
