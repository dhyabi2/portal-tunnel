package sdk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var errMITMDetected = errors.New("tls termination suspected by self-probe")

// keyingMaterialExporter is the direct TLS 1.3 keying material exporter the
// MITM responder side needs from an accepted TLS connection, so both sides
// can compare exporter values. The keyless_tls t13server conn satisfies it
// through its own RFC 8446 Section 7.5 exporter.
// Stock crypto/tls conns cannot satisfy this interface: Go's tls.Conn does
// not expose the method, and its tls.ConnectionState exporter callback is
// unexported, so external TLS implementations cannot populate it. Those
// conns are served through the ConnectionState snapshot instead (see
// probeExporter); tls.ConnectionState is deliberately never called on
// t13server conns, whose snapshot carries no working callback.
type keyingMaterialExporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// probeExporter resolves how the responder side exports keying material from
// an accepted conn. Conns with a native exporter export directly; stock
// crypto/tls conns export through the ConnectionState snapshot, which
// carries Go's own exporter closure. Conns with neither capability report
// false so the caller can skip them before the probe-inspection peek.
func probeExporter(conn net.Conn) (func(label string, context []byte, length int) ([]byte, error), bool) {
	if direct, ok := conn.(keyingMaterialExporter); ok {
		return direct.ExportKeyingMaterial, true
	}
	if stateful, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return func(label string, context []byte, length int) ([]byte, error) {
			state := stateful.ConnectionState()
			return (&state).ExportKeyingMaterial(label, context, length)
		}, true
	}
	return nil, false
}

const (
	mitmProbeExporterLabel = "Portal-MITM-Probe-v1"
	mitmProbePeekTimeout   = 100 * time.Millisecond
	mitmProbeHeaderLimit   = 4096

	defaultMITMProbeCooldown = 30 * time.Second
	defaultMITMProbeTimeout  = 30 * time.Second
)

type mitmProbeReport struct {
	RelayURL  string
	PublicURL string
	Address   string
	Detected  bool
	Reason    string
}

type mitmProbePending struct {
	expected []byte
	resultCh chan string
}

type mitmProbeNonce [16]byte

type mitmManager struct {
	ctx context.Context
	// responderCapable reports whether terminated tenant connections can
	// export keying material. Only then can the listener answer initiator
	// probes; the manager stays dormant otherwise.
	responderCapable bool
	listener         *listener
	ban              bool

	mu          sync.Mutex
	pending     map[mitmProbeNonce]*mitmProbePending
	inFlight    context.Context
	cancelProbe context.CancelFunc
	nextAt      time.Time
}

func newMITMManager(ctx context.Context, listener *listener, ban bool) *mitmManager {
	return &mitmManager{
		ctx:      ctx,
		ban:      ban,
		listener: listener,
		pending:  make(map[mitmProbeNonce]*mitmProbePending),
	}
}

func (m *mitmManager) reset() {
	m.mu.Lock()
	if m.cancelProbe != nil {
		m.cancelProbe()
		m.cancelProbe = nil
	}
	clear(m.pending)
	m.inFlight = nil
	m.nextAt = time.Time{}
	m.mu.Unlock()
}

// setResponderCapable arms the responder side once the tenant TLS client is
// known to support keying material export.
func (m *mitmManager) setResponderCapable(capable bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.responderCapable = capable
	m.mu.Unlock()
}

func (m *mitmManager) probeTLSPassthrough(ctx context.Context) (mitmProbeReport, error) {
	l := m.listener
	if l == nil || l.api == nil || l.api.relayURL == nil {
		return mitmProbeReport{}, errors.New("listener is not ready")
	}

	lease, ok := l.leaseSnapshot()
	if !ok {
		return mitmProbeReport{}, errors.New("listener is not registered")
	}
	if lease.hostname == "" {
		return mitmProbeReport{}, errors.New("listener hostname is unavailable")
	}

	publicURL := l.publicURLForLease(lease)
	if publicURL == "" {
		return mitmProbeReport{}, errors.New("listener is not registered")
	}

	report := mitmProbeReport{
		RelayURL:  l.api.relayURL.String(),
		PublicURL: publicURL,
		Address:   l.identity.Address,
	}

	probeCtx, cancel := context.WithTimeout(ctx, defaultMITMProbeTimeout)
	defer cancel()

	var nonce mitmProbeNonce
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return report, fmt.Errorf("generate probe nonce: %w", err)
	}

	dialAddr, err := m.probeDialAddress(publicURL)
	if err != nil {
		return report, err
	}

	if lease.tenantTLS == nil {
		return report, errors.New("listener relay materials are unavailable")
	}
	relayPool := lease.tenantTLS.RelayCertPool()
	if relayPool == nil {
		return report, errors.New("listener relay certificate pool is unavailable")
	}

	probeTLSConf := &tls.Config{
		ServerName: lease.hostname,
		RootCAs:    relayPool,
		MinVersion: tls.VersionTLS13,
	}

	rawConn, err := (&net.Dialer{Timeout: defaultDialTimeout}).DialContext(probeCtx, "tcp", dialAddr)
	if err != nil {
		return report, fmt.Errorf("dial mitm probe: %w", err)
	}
	tlsConn := tls.Client(rawConn, probeTLSConf)
	defer tlsConn.Close()
	deadline, _ := probeCtx.Deadline()
	if err := rawConn.SetDeadline(deadline); err != nil {
		return report, fmt.Errorf("set mitm probe deadline: %w", err)
	}
	stopClose := context.AfterFunc(probeCtx, func() { _ = rawConn.Close() })
	defer stopClose()

	// Reserve the nonce once the TCP connection exists but before the TLS
	// handshake: the reverse side can hand the connection to Accept as soon
	// as its handshake completes, which can race ahead of the probe side
	// exporting keying material. Reserving after the TCP connect keeps the
	// probe-inspection window off address resolution and connection setup.
	resultCh := m.reserveProbe(nonce)
	defer m.releaseProbe(nonce)
	if err := tlsConn.HandshakeContext(probeCtx); err != nil {
		return report, fmt.Errorf("mitm probe tls handshake: %w", err)
	}

	clientState := tlsConn.ConnectionState()
	expected, err := (&clientState).ExportKeyingMaterial(mitmProbeExporterLabel, nil, 32)
	if err != nil {
		return report, fmt.Errorf("export client probe keying material: %w", err)
	}
	m.attachExpected(nonce, expected)

	var spanID [8]byte
	if _, err := io.ReadFull(rand.Reader, spanID[:]); err != nil {
		return report, fmt.Errorf("generate probe span id: %w", err)
	}
	request, err := http.NewRequestWithContext(probeCtx, http.MethodHead, publicURL, nil)
	if err != nil {
		return report, fmt.Errorf("create mitm probe request: %w", err)
	}
	request.Close = true
	request.Header.Set("Traceparent", "00-"+hex.EncodeToString(nonce[:])+"-"+hex.EncodeToString(spanID[:])+"-01")
	if err := request.Write(tlsConn); err != nil {
		return report, fmt.Errorf("write mitm probe: %w", err)
	}

	select {
	case reason := <-resultCh:
		report.Detected = reason != ""
		report.Reason = reason
	case <-probeCtx.Done():
		report.Reason = types.MITMProbeReasonProbeTimeout
		if !errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return report, probeCtx.Err()
		}
	}
	return report, nil
}

func (m *mitmManager) probeDialAddress(publicURL string) (string, error) {
	l := m.listener
	if l == nil || l.api == nil || l.api.relayURL == nil {
		return "", errors.New("listener is not ready")
	}
	parsedURL, err := url.Parse(publicURL)
	if err != nil {
		return "", fmt.Errorf("parse public url: %w", err)
	}

	dialHost := parsedURL.Host
	entryRelayURL, err := url.Parse(l.api.relayURL.String())
	if err != nil {
		return "", fmt.Errorf("parse ingress relay url: %w", err)
	}
	if utils.IsLocalRelayHost(entryRelayURL.Hostname()) {
		dialHost = entryRelayURL.Host
	}
	return utils.EnsurePort(dialHost), nil
}

func (m *mitmManager) maybeStart() {
	m.mu.Lock()
	capable := m.responderCapable
	m.mu.Unlock()
	if !capable {
		return
	}
	l := m.listener
	if l.cache != nil {
		return // This exposure explicitly permits relay TLS termination.
	}
	select {
	case <-l.doneCh:
		return
	default:
	}

	m.mu.Lock()
	if m.inFlight != nil || time.Now().Before(m.nextAt) {
		m.mu.Unlock()
		return
	}
	probeCtx, cancel := context.WithCancel(m.ctx)
	m.inFlight = probeCtx
	m.cancelProbe = cancel
	m.mu.Unlock()

	go func() {
		defer cancel()
		report, err := m.probeTLSPassthrough(probeCtx)
		cooldown := defaultMITMProbeCooldown
		var jitter [1]byte
		if _, err := io.ReadFull(rand.Reader, jitter[:]); err == nil {
			cooldown += time.Duration(jitter[0]) * defaultMITMProbeCooldown / 256
		}
		m.mu.Lock()
		if m.inFlight != probeCtx {
			m.mu.Unlock()
			return // The lease was cleared while this attempt was running.
		}
		m.inFlight = nil
		m.cancelProbe = nil
		// Failed attempts consume the same budget as completed comparisons.
		// Otherwise a relay can reject each handshake and turn a burst of
		// visitor connections into an unbounded burst of probe retries.
		m.nextAt = time.Now().Add(cooldown)
		m.mu.Unlock()
		m.logResult(report, err)
	}()
}

func (m *mitmManager) logResult(report mitmProbeReport, err error) {
	l := m.listener
	if l == nil {
		return
	}
	closed := false
	select {
	case <-l.doneCh:
		closed = true
	default:
	}
	relayURL := ""
	if l.api != nil && l.api.relayURL != nil {
		relayURL = l.api.relayURL.String()
	}
	switch {
	case closed:
		return
	case err != nil:
		if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
			return
		}
		log.Warn().
			Err(err).
			Str("relay_url", relayURL).
			Str("address", l.identity.Address).
			Msg("tls passthrough self-probe failed")
	case report.Reason == types.MITMProbeReasonProbeTimeout:
		log.Warn().
			Str("relay_url", report.RelayURL).
			Str("public_url", report.PublicURL).
			Str("address", report.Address).
			Msg("tls self-probe timed out before passthrough could be verified")
	case report.Detected:
		event := log.Warn().
			Bool("ban_mitm", m.ban).
			Str("reason", report.Reason).
			Str("relay_url", report.RelayURL).
			Str("public_url", report.PublicURL).
			Str("address", report.Address)
		if m.ban {
			event.Msg("tls termination suspected by self-probe; closing listener")
			l.report(listenerStatus{state: RelayFailed, failure: RelayFailureMITM, err: errMITMDetected})
			_ = l.Close()
			return
		}
		event.Msg("tls termination suspected by self-probe")
	default:
		log.Debug().
			Str("relay_url", report.RelayURL).
			Str("public_url", report.PublicURL).
			Str("address", report.Address).
			Msg("tls passthrough self-probe passed")
	}
}

func (m *mitmManager) maybeHandleConn(conn net.Conn) (net.Conn, bool, error) {
	if conn == nil {
		return conn, false, nil
	}

	m.mu.Lock()
	hasPending := len(m.pending) > 0
	m.mu.Unlock()
	if !hasPending {
		return conn, false, nil
	}

	exportFn, ok := probeExporter(conn)
	if !ok {
		return conn, false, nil
	}

	reader := bufio.NewReaderSize(conn, mitmProbeHeaderLimit)
	_ = conn.SetReadDeadline(time.Now().Add(mitmProbePeekTimeout))
	defer conn.SetReadDeadline(time.Time{})
	var header []byte
	for reader.Buffered() < mitmProbeHeaderLimit {
		if _, err := reader.Peek(reader.Buffered() + 1); err != nil {
			return wrapBufferedConn(conn, reader), false, nil
		}
		buffered, _ := reader.Peek(reader.Buffered())
		if end := bytes.Index(buffered, []byte("\r\n\r\n")); end >= 0 {
			header = buffered[:end+4]
			break
		}
	}
	if header == nil {
		return wrapBufferedConn(conn, reader), false, nil
	}
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
	if err != nil {
		return wrapBufferedConn(conn, reader), false, nil
	}
	defer request.Body.Close()
	trace := strings.Split(request.Header.Get("Traceparent"), "-")
	if request.Method != http.MethodHead || request.RequestURI != "/" ||
		request.ContentLength != 0 || len(request.TransferEncoding) != 0 ||
		len(trace) != 4 || trace[0] != "00" || len(trace[1]) != 32 || len(trace[2]) != 16 || len(trace[3]) != 2 {
		return wrapBufferedConn(conn, reader), false, nil
	}

	var nonce mitmProbeNonce
	if _, err := hex.Decode(nonce[:], []byte(trace[1])); err != nil {
		return wrapBufferedConn(conn, reader), false, nil
	}
	m.mu.Lock()
	_, ok = m.pending[nonce]
	m.mu.Unlock()
	if !ok {
		return wrapBufferedConn(conn, reader), false, nil
	}

	defer conn.Close()

	actual, err := exportFn(mitmProbeExporterLabel, nil, 32)
	if err != nil {
		return nil, true, fmt.Errorf("export server probe keying material: %w", err)
	}

	m.completeProbe(nonce, actual)
	return nil, true, nil
}

// reserveProbe registers the probe nonce before the TLS handshake so the reverse
// side recognizes the connection even if Accept runs the moment the reverse
// handshake completes. attachExpected arms the reservation afterwards; until
// then the entry holds no exporter value and a completion attempt reports a
// mismatch.
func (m *mitmManager) reserveProbe(nonce mitmProbeNonce) <-chan string {
	state := &mitmProbePending{
		resultCh: make(chan string, 1),
	}
	m.mu.Lock()
	m.pending[nonce] = state
	m.mu.Unlock()

	return state.resultCh
}

func (m *mitmManager) releaseProbe(nonce mitmProbeNonce) {
	m.mu.Lock()
	delete(m.pending, nonce)
	m.mu.Unlock()
}

// attachExpected arms a reserved probe with the exporter value the reverse
// side must reproduce for the connection to count as untampered.
func (m *mitmManager) attachExpected(nonce mitmProbeNonce, expected []byte) {
	m.mu.Lock()
	if state := m.pending[nonce]; state != nil {
		state.expected = bytes.Clone(expected)
	}
	m.mu.Unlock()
}

func (m *mitmManager) completeProbe(nonce mitmProbeNonce, actual []byte) {
	m.mu.Lock()
	state := m.pending[nonce]
	if state == nil {
		m.mu.Unlock()
		return
	}
	reason := ""
	if !bytes.Equal(state.expected, actual) {
		reason = types.MITMProbeReasonExporterMismatch
	}
	resultCh := state.resultCh
	m.mu.Unlock()

	select {
	case resultCh <- reason:
	default:
	}
}

type mitmProbeConn struct {
	net.Conn
	manager   *mitmManager
	startOnce sync.Once
}

func (c *mitmProbeConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func (c *mitmProbeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.startOnce.Do(func() {
			c.manager.maybeStart()
		})
	}
	return n, err
}

func (c *mitmProbeConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.startOnce.Do(func() {
			c.manager.maybeStart()
		})
	}
	return n, err
}
