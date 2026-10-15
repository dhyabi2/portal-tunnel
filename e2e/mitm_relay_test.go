package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/relay/l4"
)

const (
	mitmVisitorSecret = "portal-e2e-visitor-secret"
	mitmForgedBody    = "relay-forged-response"
)

// mitmIngress sits in front of a real relay and holds that relay's certificate
// key, just as a malicious operator would. Control and reverse connections go
// to the real relay unchanged; tenant TLS can be split into two real sessions.
// Attack decisions use only source addresses, ClientHello, or decrypted bytes.
type mitmIngress struct {
	backend       string
	attack        string
	cert          tls.Certificate
	roots         *x509.CertPool
	probes        chan time.Duration
	workers       sync.WaitGroup
	mu            sync.Mutex
	controlSource string
	probeStarts   int
	reads         int
	writes        int
	bytes         int
}

func startMITMIngress(t *testing.T, parent context.Context, addr, backend, stateDir, attack string) *mitmIngress {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(stateDir, "fullchain.pem"), filepath.Join(stateDir, "privatekey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := os.ReadFile(filepath.Join(stateDir, "fullchain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(chain) {
		t.Fatal("parse relay certificate")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(parent)
	m := &mitmIngress{
		backend: backend, attack: attack, cert: cert, roots: roots,
		probes: make(chan time.Duration, 32),
	}
	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			m.workers.Add(1)
			go func() {
				defer m.workers.Done()
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer stop()
				m.serve(ctx, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		m.workers.Wait()
	})
	return m
}

func (m *mitmIngress) serve(ctx context.Context, raw net.Conn) {
	hello, conn, err := l4.InspectClientHello(raw, 5*time.Second)
	if err != nil {
		return
	}
	// IP-literal relay API requests carry no SNI. They must stay intact so
	// registration, reverse transport and transcript-bound signing are real.
	source, _, _ := net.SplitHostPort(raw.RemoteAddr().String())
	if hello.ServerName == "" {
		m.mu.Lock()
		m.controlSource = source
		m.mu.Unlock()
		m.forward(ctx, conn, nil, "")
		return
	}
	started := time.Now()
	// The evaluator's visitors explicitly offer http/1.1, unlike the current
	// SDK probe. This observation is not a hidden probe label. Only the
	// ClientHello attack uses it to choose whether to terminate a connection.
	if len(hello.ALPNProtocols) == 0 {
		m.mu.Lock()
		m.probeStarts++
		m.mu.Unlock()
		defer func() {
			select {
			case m.probes <- time.Since(started):
			case <-ctx.Done():
			}
		}()
	}
	if m.attack == "reject" && len(hello.ALPNProtocols) == 0 {
		return // Abort before the handshake, so failure is immediate.
	}
	m.mu.Lock()
	controlSource := m.controlSource
	m.mu.Unlock()
	if m.attack == "passthrough" ||
		m.attack == "source" && source == controlSource ||
		m.attack == "target" && source != "127.0.0.2" ||
		m.attack == "hello" && len(hello.ALPNProtocols) == 0 {
		m.forward(ctx, conn, nil, "")
		return
	}
	client := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{m.cert}, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	})
	if err := client.HandshakeContext(ctx); err != nil {
		return
	}
	_ = client.SetDeadline(time.Now().Add(45 * time.Second))
	reader := bufio.NewReader(client)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	defer request.Body.Close()
	// Adapt to the HTTP probe: this rule inspects an ordinary tracing header
	// after TLS termination instead of relying on a raw random frame.
	if request.Method == http.MethodHead && request.Header.Get("Traceparent") != "" {
		switch m.attack {
		case "reset":
			_ = raw.(*net.TCPConn).SetLinger(0)
			return
		case "stall":
			_, _ = io.Copy(io.Discard, reader)
			return
		case "strip":
			request.Header.Del("Traceparent")
		}
		var replay bytes.Buffer
		if err := request.Write(&replay); err != nil {
			return
		}
		m.forward(ctx, client, io.MultiReader(&replay, reader), hello.ServerName)
		return
	}
	secret := request.Header.Get("Authorization")
	m.mu.Lock()
	m.reads++
	m.bytes += len(secret)
	m.mu.Unlock()

	if m.attack != "source" && m.attack != "target" {
		upstream, err := m.dialTenant(ctx, hello.ServerName)
		if err != nil {
			return
		}
		defer upstream.Close()
		stop := context.AfterFunc(ctx, func() { _ = upstream.Close() })
		defer stop()
		_ = upstream.SetDeadline(time.Now().Add(10 * time.Second))
		if err := request.Write(upstream); err != nil {
			return
		}
		response, err := http.ReadResponse(bufio.NewReader(upstream), request)
		if err != nil {
			return
		}
		_, err = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if err != nil {
			return
		}
	}
	// The source-selective operator does not need a live tunnel to forge a
	// page. Other modes forward the request first to start the real probe.
	_, err = fmt.Fprintf(client, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(mitmForgedBody), mitmForgedBody)
	if err == nil {
		m.mu.Lock()
		m.writes++
		m.mu.Unlock()
	}
}

func (m *mitmIngress) dialTenant(ctx context.Context, hostname string) (net.Conn, error) {
	return (&tls.Dialer{Config: &tls.Config{
		ServerName: hostname, RootCAs: m.roots, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}}).DialContext(ctx, "tcp", m.backend)
}

// forward bridges real sockets, replaying any decrypted bytes inspected by
// the attacker. No SDK state, fake transport or signing bypass is involved.
func (m *mitmIngress) forward(ctx context.Context, client net.Conn, reader io.Reader, hostname string) {
	var upstream net.Conn
	var err error
	if hostname == "" {
		upstream, err = (&net.Dialer{}).DialContext(ctx, "tcp", m.backend)
	} else {
		upstream, err = m.dialTenant(ctx, hostname)
	}
	if err != nil {
		return
	}
	defer upstream.Close()
	stop := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stop()
	if reader == nil {
		reader = client
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, reader)
		_ = upstream.Close()
		close(done)
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

// mitmVisit is an ordinary HTTPS client. A local source address models a
// separately identifiable visitor; TLS still verifies the real relay chain.
func mitmVisit(h *harness, publicURL, source string) (string, error) {
	target, err := http.NewRequest(http.MethodGet, publicURL+"/marker", nil)
	if err != nil {
		return "", err
	}
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{
		ServerName: target.URL.Hostname(), RootCAs: h.mitm.roots,
		MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"},
	}}).DialContext(ctx, "tcp", h.sniAddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	target.Header.Set("Authorization", mitmVisitorSecret)
	target.Close = true
	if err := target.Write(conn); err != nil {
		return "", err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), target)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	return strings.TrimSpace(string(content)), err
}
