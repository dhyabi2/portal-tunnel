package policy

import (
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	controlBodyReadTimeout = 30 * time.Second
	controlBodyGlobalLimit = 64
	controlBodySourceLimit = 4
)

// controlBodyLimiter bounds live JSON control requests independently of the
// refillable pre-auth request budget. Only active sources occupy map entries.
type controlBodyLimiter struct {
	mu      sync.Mutex
	active  int
	sources map[netip.Addr]int
	timeout time.Duration
}

func newControlBodyLimiter(timeout time.Duration) *controlBodyLimiter {
	return &controlBodyLimiter{sources: make(map[netip.Addr]int), timeout: timeout}
}

func (l *controlBodyLimiter) acquire(source netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= controlBodyGlobalLimit || l.sources[source] >= controlBodySourceLimit {
		return false
	}
	l.active++
	l.sources[source]++
	return true
}

func (l *controlBodyLimiter) release(source netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active--
	if l.sources[source] == 1 {
		delete(l.sources, source)
	} else {
		l.sources[source]--
	}
}

// controlBody tracks body consumption so only complete requests can reuse a
// connection. A failed decode must not leave a socket idle after its deadline
// is cleared.
type controlBody struct {
	io.ReadCloser
	remaining int64
	complete  bool
	header    http.Header
}

func (b *controlBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if b.remaining > 0 {
		b.remaining -= int64(n)
		if b.remaining <= 0 {
			b.complete = true
		}
	}
	if err == io.EOF {
		b.complete = true
	}
	if b.complete {
		b.header.Del("Connection")
	}
	return n, err
}

// serve bounds active requests and body reads. Calls from Mux exclude
// long-lived reverse connections and streaming cache uploads.
func (l *controlBodyLimiter) serve(w http.ResponseWriter, r *http.Request, source netip.Addr, next http.Handler) {
	if !l.acquire(source) {
		// The body is unread; do not let net/http drain it while replying.
		w.Header().Set("Connection", "close")
		_ = http.NewResponseController(w).EnableFullDuplex()
		WriteRetryAfter(w, time.Second, "too many active control requests")
		return
	}
	defer l.release(source)

	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(l.timeout)); err != nil {
		w.Header().Set("Connection", "close")
		_ = controller.EnableFullDuplex()
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "request body deadline unavailable")
		return
	}
	if err := controller.EnableFullDuplex(); err != nil {
		w.Header().Set("Connection", "close")
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "full-duplex request handling unavailable")
		return
	}
	// Rejecting a partially read body must close the connection immediately.
	// A complete body clears this before the handler writes its response, so
	// healthy control requests keep HTTP keep-alive.
	w.Header().Set("Connection", "close")
	body := &controlBody{ReadCloser: r.Body, remaining: r.ContentLength, header: w.Header()}
	r.Body = body
	defer func() {
		if body.complete {
			_ = controller.SetReadDeadline(time.Time{})
		}
	}()
	next.ServeHTTP(w, r)
}

// isControlJSONRequest names the short-lived control requests. Keeping the
// selection here leaves reverse upgrades and streaming cache uploads alone.
func isControlJSONRequest(r *http.Request) bool {
	if r.Method != http.MethodPost || r.Body == http.NoBody {
		return false
	}
	switch strings.TrimSuffix(r.URL.Path, "/") {
	case types.PathSDKRegisterChallenge, types.PathSDKRegister,
		types.PathSDKRenew, types.PathSDKReverse, types.PathSDKUnregister,
		types.PathDiscoveryAnnounce, types.PathV1Sign,
		types.PathAdminAuthLogin, types.PathPolicy, types.PathPolicyLeases:
		return true
	}
	return r.URL.Path == types.PathAPIPrefix+"/reputation/vote" ||
		strings.HasPrefix(r.URL.Path, types.PathAPIPrefix+"/x402/")
}
