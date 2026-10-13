package e2e_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/portal"
)

func TestUDPPortRelay(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			testUDPPortRelay(t, host, host, host)
		})
	}
}

// Exercise real UDP ingress, authenticated QUIC backhaul, the local UDP
// origin, and the response path. The advertised relay name can differ from
// its bind address so DNS fallback uses the same end-to-end contract.
func testUDPPortRelay(t *testing.T, relayHost, relayName, originHost string) {
	t.Helper()
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(originHost)})
	if err != nil {
		if originHost == "::1" {
			t.Skipf("IPv6 loopback is unavailable: %v", err)
		}
		t.Fatalf("listen UDP origin: %v", err)
	}
	originDone := make(chan struct{})
	go func() {
		defer close(originDone)
		var payload [2048]byte
		for {
			n, peer, err := origin.ReadFromUDP(payload[:])
			if err != nil {
				return
			}
			if _, err := origin.WriteToUDP(payload[:n], peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = origin.Close()
		<-originDone
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	udpPort := harnessPort(t, relayHost)
	port := harnessPort(t, relayHost)
	relayURL := "https://" + net.JoinHostPort(relayName, strconv.Itoa(port))
	relay, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     relayURL,
		StateDir:      t.TempDir(),
		SNIListenAddr: net.JoinHostPort(relayHost, strconv.Itoa(port)),
		SNIPort:       port,
		MinPort:       udpPort,
		MaxPort:       udpPort,
	})
	if err != nil {
		t.Fatalf("create UDP relay: %v", err)
	}
	if err := relay.SetTransportPolicy(true, 0, false, 0); err != nil {
		t.Fatalf("enable UDP transport: %v", err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatalf("start UDP relay: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := relay.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shutdown UDP relay: %v", err)
		}
		if err := relay.Wait(); err != nil {
			t.Errorf("wait for UDP relay: %v", err)
		}
	})

	runtime, err := tunnel.Start(ctx, tunnel.Spec{
		Identity: tunnel.IdentitySpec{Name: "udp"},
		Relays:   tunnel.RelaySpec{URLs: []string{relayURL}},
		Transport: tunnel.TransportSpec{
			Target: origin.LocalAddr().String(),
			UDP:    &tunnel.UDPConfig{},
		},
	})
	if err != nil {
		t.Fatalf("start UDP tunnel: %v", err)
	}
	proxyCtx, proxyCancel := context.WithCancel(ctx)
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- runtime.Run(proxyCtx) }()
	t.Cleanup(func() {
		proxyCancel()
		_ = runtime.Close()
		select {
		case err := <-proxyDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("proxy UDP: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("UDP proxy did not stop")
		}
	})

	readyCtx, readyCancel := context.WithTimeout(ctx, 30*time.Second)
	defer readyCancel()
	ready, err := runtime.Exposure.WaitDatagramReady(readyCtx)
	if err != nil || len(ready) == 0 {
		t.Fatalf("wait for UDP backhaul: %v; relay statuses: %+v", err, runtime.Exposure.Relays())
	}
	_, portText, err := net.SplitHostPort(ready[0].UDPAddr)
	if err != nil {
		t.Fatalf("split public UDP address %q: %v", ready[0].UDPAddr, err)
	}
	publicPort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse public UDP port %q: %v", portText, err)
	}
	for client := range 2 {
		conn, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(relayHost)}, &net.UDPAddr{IP: net.ParseIP(relayHost), Port: publicPort})
		if err != nil {
			t.Fatalf("dial UDP ingress: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		for message := range 3 {
			payload := []byte("udp-" + strconv.Itoa(client) + "-" + strconv.Itoa(message))
			if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("send UDP payload: %v", err)
			}
			var reply [2048]byte
			n, err := conn.Read(reply[:])
			if err != nil {
				t.Fatalf("read UDP reply: %v", err)
			}
			if string(reply[:n]) != string(payload) {
				t.Fatalf("UDP reply = %q, want %q", reply[:n], payload)
			}
		}
	}

	// Send an oversized packet (> 1350 bytes). It must be dropped whole, and a subsequent valid packet must still round-trip.
	oversizedConn, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(relayHost)}, &net.UDPAddr{IP: net.ParseIP(relayHost), Port: publicPort})
	if err != nil {
		t.Fatalf("dial UDP for oversized check: %v", err)
	}
	t.Cleanup(func() { _ = oversizedConn.Close() })
	oversizedPayload := make([]byte, 1400)
	_ = oversizedConn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := oversizedConn.Write(oversizedPayload); err != nil {
		t.Fatalf("write oversized payload: %v", err)
	}
	var dropBuf [2048]byte
	if _, err := oversizedConn.Read(dropBuf[:]); err == nil {
		t.Fatal("oversized packet was not dropped")
	}

	// Subsequent valid packet still round-trips
	validPayload := []byte("udp-after-oversized")
	_ = oversizedConn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := oversizedConn.Write(validPayload); err != nil {
		t.Fatalf("write valid payload after oversized: %v", err)
	}
	n, err := oversizedConn.Read(dropBuf[:])
	if err != nil {
		t.Fatalf("read valid payload after oversized: %v", err)
	}
	if string(dropBuf[:n]) != string(validPayload) {
		t.Fatalf("UDP reply after oversized = %q, want %q", dropBuf[:n], validPayload)
	}
}

func TestUDPLeaseReplacementIsolation(t *testing.T) {
	relayHost := "127.0.0.1"
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(relayHost)})
	if err != nil {
		t.Fatalf("listen UDP origin: %v", err)
	}
	originDone := make(chan struct{})
	go func() {
		defer close(originDone)
		var payload [2048]byte
		for {
			n, peer, err := origin.ReadFromUDP(payload[:])
			if err != nil {
				return
			}
			if _, err := origin.WriteToUDP(payload[:n], peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = origin.Close()
		<-originDone
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	udpPort := harnessPort(t, relayHost)
	port := harnessPort(t, relayHost)
	relayURL := "https://" + net.JoinHostPort(relayHost, strconv.Itoa(port))
	stateDir := t.TempDir()

	startRelay := func() *portal.Server {
		relay, err := portal.NewServer(portal.ServerConfig{
			PortalURL:     relayURL,
			StateDir:      stateDir,
			SNIListenAddr: net.JoinHostPort(relayHost, strconv.Itoa(port)),
			SNIPort:       port,
			MinPort:       udpPort,
			MaxPort:       udpPort,
		})
		if err != nil {
			t.Fatalf("create UDP relay: %v", err)
		}
		if err := relay.SetTransportPolicy(true, 0, false, 0); err != nil {
			t.Fatalf("enable UDP transport: %v", err)
		}
		if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
			t.Fatalf("start UDP relay: %v", err)
		}
		return relay
	}

	relay := startRelay()

	runtime, err := tunnel.Start(ctx, tunnel.Spec{
		Identity: tunnel.IdentitySpec{Name: "udp-iso"},
		Relays:   tunnel.RelaySpec{URLs: []string{relayURL}},
		Transport: tunnel.TransportSpec{
			Target: origin.LocalAddr().String(),
			UDP:    &tunnel.UDPConfig{},
		},
	})
	if err != nil {
		t.Fatalf("start UDP tunnel: %v", err)
	}
	proxyCtx, proxyCancel := context.WithCancel(ctx)
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- runtime.Run(proxyCtx) }()
	t.Cleanup(func() {
		proxyCancel()
		_ = runtime.Close()
		<-proxyDone
	})

	readyCtx, readyCancel := context.WithTimeout(ctx, 30*time.Second)
	defer readyCancel()
	ready, err := runtime.Exposure.WaitDatagramReady(readyCtx)
	if err != nil || len(ready) == 0 {
		t.Fatalf("wait for UDP backhaul: %v", err)
	}

	// Sender 1 communicates with relay 1
	conn1, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(relayHost)}, &net.UDPAddr{IP: net.ParseIP(relayHost), Port: udpPort})
	if err != nil {
		t.Fatalf("dial sender 1: %v", err)
	}
	defer conn1.Close()
	payload1 := []byte("sender-1-msg")
	_ = conn1.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn1.Write(payload1); err != nil {
		t.Fatalf("sender 1 write: %v", err)
	}
	var reply [2048]byte
	n, err := conn1.Read(reply[:])
	if err != nil || string(reply[:n]) != string(payload1) {
		t.Fatalf("sender 1 reply = %q, err = %v", reply[:n], err)
	}

	// Restart relay: stop relay 1 and start relay 2 on same port
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = relay.Shutdown(shutdownCtx)
	_ = relay.Wait()

	relay = startRelay()
	t.Cleanup(func() {
		sCtx, sCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer sCancel()
		_ = relay.Shutdown(sCtx)
		_ = relay.Wait()
	})

	// Wait for SDK to re-register/reconnect against restarted relay
	time.Sleep(1 * time.Second)
	readyCtx2, readyCancel2 := context.WithTimeout(ctx, 30*time.Second)
	defer readyCancel2()
	ready2, err := runtime.Exposure.WaitDatagramReady(readyCtx2)
	if err != nil || len(ready2) == 0 {
		t.Fatalf("wait for restarted UDP backhaul: %v", err)
	}

	// Sender 2 sends to restarted relay (gets FlowID 1 from restarted relay)
	conn2, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(relayHost)}, &net.UDPAddr{IP: net.ParseIP(relayHost), Port: udpPort})
	if err != nil {
		t.Fatalf("dial sender 2: %v", err)
	}
	defer conn2.Close()
	payload2 := []byte("sender-2-msg")
	_ = conn2.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn2.Write(payload2); err != nil {
		t.Fatalf("sender 2 write: %v", err)
	}
	n2, err := conn2.Read(reply[:])
	if err != nil || string(reply[:n2]) != string(payload2) {
		t.Fatalf("sender 2 reply = %q, want %q, err = %v", reply[:n2], payload2, err)
	}

	// Sender 1 should not receive any of sender 2's data
	_ = conn1.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := conn1.Read(reply[:]); err == nil {
		t.Error("sender 1 received unexpected cross-lease traffic")
	}
}
