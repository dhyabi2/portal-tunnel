package policy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestControlBodyGateBoundsActiveSourcesAndGlobalWork(t *testing.T) {
	gate := newControlBodyGate()
	source := netip.MustParseAddr("192.0.2.1")
	for range maxActiveControlBodiesPerSource {
		if !gate.acquire(source) {
			t.Fatal("source rejected below its active-body ceiling")
		}
	}
	if gate.acquire(source) {
		t.Fatal("source exceeded its active-body ceiling")
	}
	other := netip.MustParseAddr("192.0.2.2")
	if !gate.acquire(other) {
		t.Fatal("one source exhausted another source's capacity")
	}
	gate.release(source)
	if !gate.acquire(source) {
		t.Fatal("completed body did not release source capacity")
	}

	gate = newControlBodyGate()
	for i := range maxActiveControlBodies {
		address := netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)})
		if !gate.acquire(address) {
			t.Fatal("global capacity rejected early")
		}
	}
	if gate.acquire(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("rotating sources bypassed global capacity")
	}
	gate.release(netip.MustParseAddr("198.51.100.1"))
	if !gate.acquire(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("completed body did not release global capacity")
	}
}

func TestControlBodyGuardTargetsJSONControlRoutes(t *testing.T) {
	for _, path := range []string{
		types.PathSDKRegisterChallenge, types.PathSDKRegister, types.PathSDKRenew,
		types.PathSDKReverse, types.PathSDKUnregister, types.PathDiscoveryAnnounce,
		types.PathV1Sign, types.PathAdminAuthLogin, types.PathPolicy,
		types.PathPolicyLeases, types.PathPolicy + "/",
		types.PathAPIPrefix + "/reputation/vote", types.PathAPIPrefix + "/x402/verify",
	} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{"))
		if !isControlBodyRequest(req) {
			t.Errorf("POST %s was not bounded", path)
		}
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, types.PathSDKConnect},
		{http.MethodPost, types.PathSDKConnect},
		{http.MethodPost, types.PathSDKCache},
		{http.MethodPut, types.PathSDKCache},
		{http.MethodPost, "/application/upload"},
		{http.MethodPost, "/api/unrecognized"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{"))
		if isControlBodyRequest(req) {
			t.Errorf("%s %s must not inherit JSON body deadlines", tc.method, tc.path)
		}
	}
	if isControlBodyRequest(httptest.NewRequest(http.MethodPost, types.PathSDKRegister, nil)) {
		t.Fatal("bodyless request must not occupy a body slot")
	}
}

func TestMuxRejectsReverseUpgradeWithUnexpectedBody(t *testing.T) {
	handler := Mux(nil, http.NotFoundHandler(), nil, nil, nil, types.PreAuthConfig{})
	server := httptest.NewServer(handler)
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+types.PathSDKConnect, strings.NewReader("{"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || !response.Close {
		t.Fatalf("body-bearing reverse upgrade response = %d, close = %t", response.StatusCode, response.Close)
	}
}

func TestMuxRejectsActiveBodiesBeforeReadingMoreData(t *testing.T) {
	started := make(chan struct{}, maxActiveControlBodiesPerSource)
	handler := Mux(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}), nil, nil, nil, types.PreAuthConfig{})
	server := httptest.NewServer(handler)
	defer server.Close()

	connections := make([]net.Conn, 0, maxActiveControlBodiesPerSource)
	defer func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	}()
	for range maxActiveControlBodiesPerSource {
		conn, err := net.Dial("tcp", server.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		if _, err := fmt.Fprint(conn, "POST /api/reputation/vote HTTP/1.1\r\nHost: localhost\r\nContent-Length: 64\r\n\r\n{"); err != nil {
			t.Fatal(err)
		}
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("request was not admitted for body reading")
		}
	}

	extra, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	if err := extra.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(extra, "POST /api/reputation/vote HTTP/1.1\r\nHost: localhost\r\nContent-Length: 64\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(extra), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("saturated gate waited for the unread body: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("saturated gate status = %d, want %d", response.StatusCode, http.StatusTooManyRequests)
	}
	select {
	case <-started:
		t.Fatal("rejected request reached its body decoder")
	default:
	}
}

func TestMuxClosesStalledJSONRequestAtBodyDeadline(t *testing.T) {
	handler := Mux(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := utils.DecodeJSONRequest[map[string]string](w, r, 1024); ok {
			utils.WriteAPIData(w, http.StatusOK, map[string]string{"status": "unexpected"})
		}
	}), nil, nil, nil, types.PreAuthConfig{})
	server := httptest.NewServer(handler)
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(controlBodyReadTimeout + 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := fmt.Fprint(conn, "POST /api/reputation/vote HTTP/1.1\r\nHost: localhost\r\nContent-Length: 64\r\n\r\n{\"x\":\""); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("stalled JSON response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("stalled JSON status = %d, want %d", response.StatusCode, http.StatusRequestTimeout)
	}
	if elapsed := time.Since(started); elapsed < controlBodyReadTimeout-time.Second {
		t.Fatalf("request ended before its body deadline: %v", elapsed)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatalf("read timeout response: %v", err)
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("timed-out HTTP/1 connection should close, got %v", err)
	}
}
