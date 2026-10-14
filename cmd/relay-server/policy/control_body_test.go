package policy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestControlBodyLimiterBoundsActiveSourcesAndGlobalWork(t *testing.T) {
	limiter := NewControlBodyLimiter()
	one := netip.MustParseAddr("192.0.2.1")
	for range controlBodySourceLimit {
		if !limiter.acquire(one) {
			t.Fatal("source capacity rejected an available slot")
		}
	}
	if limiter.acquire(one) {
		t.Fatal("source exceeded its active request limit")
	}

	for i := 2; i <= controlBodyGlobalLimit-controlBodySourceLimit+1; i++ {
		addr := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		if !limiter.acquire(addr) {
			t.Fatalf("global slot %d rejected", i)
		}
	}
	if limiter.acquire(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("global active request limit exceeded")
	}

	limiter.release(one)
	if !limiter.acquire(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("releasing a slot did not restore capacity")
	}
	limiter.release(netip.MustParseAddr("198.51.100.1"))
	for range controlBodySourceLimit - 1 {
		limiter.release(one)
	}
	for i := 2; i <= controlBodyGlobalLimit-controlBodySourceLimit+1; i++ {
		limiter.release(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
	}
	if limiter.active != 0 || len(limiter.sources) != 0 {
		t.Fatalf("released state: active=%d sources=%d, want empty", limiter.active, len(limiter.sources))
	}
}

func TestControlBodyLimiterRejectsWithoutReadingBody(t *testing.T) {
	limiter := NewControlBodyLimiter()
	source := netip.MustParseAddr("127.0.0.1")
	for range controlBodySourceLimit {
		if !limiter.acquire(source) {
			t.Fatal("cannot fill the source capacity")
		}
	}
	defer func() {
		for range controlBodySourceLimit {
			limiter.release(source)
		}
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter.serve(w, r, source, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("rejected request reached its body decoder")
		}))
	}))
	defer server.Close()

	conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4096\r\n\r\n{"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("rejected response blocked on unfinished body: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("rejected response status = %d, want 429", response.StatusCode)
	}
	if !response.Close {
		t.Fatal("rejected request did not close its connection")
	}
	if response.Header.Get("Retry-After") != "1" {
		t.Fatal("rejected request did not advertise retry guidance")
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	var unread [1]byte
	if n, err := conn.Read(unread[:]); n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("rejected body left its socket open: read (%d, %v)", n, err)
	}
}

func TestControlBodyLimiterStopsTrickledJSONAtDeadline(t *testing.T) {
	limiter := NewControlBodyLimiter()
	limiter.timeout = 120 * time.Millisecond
	source := netip.MustParseAddr("127.0.0.1")
	readResult := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter.serve(w, r, source, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := io.Copy(io.Discard, r.Body)
			readResult <- err
			if err != nil {
				http.Error(w, "request body timed out", http.StatusRequestTimeout)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
	}))
	defer server.Close()

	conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4096\r\n\r\n{"); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if _, err := conn.Write([]byte(" ")); err != nil {
					return
				}
			}
		}
	}()

	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("body deadline failed to terminate slow read: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want 408", response.StatusCode)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	var unread [1]byte
	if n, err := conn.Read(unread[:]); n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("timed-out body left its socket open: read (%d, %v)", n, err)
	}
	if err := <-readResult; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("body read error = %v, want deadline exceeded", err)
	}
}

func TestControlBodyLimiterFailsClosedWithoutBodyControls(t *testing.T) {
	limiter := NewControlBodyLimiter()
	req := httptest.NewRequest(http.MethodPost, types.PathSDKRegister, strings.NewReader("{}"))
	w := httptest.NewRecorder() // Does not support ResponseController body controls.
	limiter.serve(w, req, netip.MustParseAddr("192.0.2.1"), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request decoded without a read deadline")
	}))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing read deadline status = %d, want 503", w.Code)
	}
	if limiter.active != 0 {
		t.Fatal("failed deadline retained an active slot")
	}
}

func TestControlBodyLimiterKeepsConnectionAfterCompleteBody(t *testing.T) {
	limiter := NewControlBodyLimiter()
	source := netip.MustParseAddr("127.0.0.1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter.serve(w, r, source, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				http.Error(w, "read failed", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
	}))
	defer server.Close()

	conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	for range 2 {
		if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}"); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
		if err != nil {
			t.Fatalf("completed body did not preserve keep-alive: %v", err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent || response.Close {
			t.Fatalf("completed body response = %d close=%v, want 204 keep-alive", response.StatusCode, response.Close)
		}
	}
}
