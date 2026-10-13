package e2e_test

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/gosuda/portal-tunnel/v2/portal"
)

func TestQUICPendingAuthenticationBoundAndShutdown(t *testing.T) {
	port := harnessPort(t, "127.0.0.1")
	leasePort := harnessPort(t, "127.0.0.1")
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	relay, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://" + addr, StateDir: t.TempDir(), SNIListenAddr: addr, SNIPort: port, MinPort: leasePort, MaxPort: leasePort})
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.SetTransportPolicy(true, 0, false, 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := relay.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
		if err := relay.Wait(); err != nil {
			t.Error(err)
		}
	})
	// One address may occupy only eight pending authentication slots. A silent
	// peer and one with partial credentials consume the same source budget.
	var peers []*quic.Conn
	for i := 0; i < 9; i++ {
		dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
		peer, err := quic.DialAddr(dialCtx, addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"portal-tunnel"}}, &quic.Config{EnableDatagrams: true})
		dialCancel()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.CloseWithError(0, "test complete") })
		peers = append(peers, peer)
		if i == 1 {
			stream, err := peer.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Write([]byte(`{"access_token":"`)); err != nil {
				t.Fatal(err)
			}
		}
	}
	select {
	case <-peers[8].Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("connection beyond pending-auth capacity remained open")
	}
	for _, peer := range peers[:8] {
		if err := peer.Context().Err(); err != nil {
			t.Fatalf("connection within pending-auth capacity closed early: %v", context.Cause(peer.Context()))
		}
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := relay.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	if err := relay.Wait(); err != nil {
		t.Fatal(err)
	}
	for _, peer := range peers[:8] {
		select {
		case <-peer.Context().Done():
		case <-shutdownCtx.Done():
			t.Fatal("shutdown left an unauthenticated connection open")
		}
	}
}
