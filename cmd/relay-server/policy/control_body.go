package policy

import (
	"io"
	"net/http"
	"net/netip"
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

// ControlBodyLimiter bounds live control requests independently of the
// refillable pre-auth request budget. Only active sources occupy map entries.
type ControlBodyLimiter struct {
	mu      sync.Mutex
	active  int
	sources map[netip.Addr]int
	timeout time.Duration
}

// NewControlBodyLimiter creates one relay's shared active-body budget.
func NewControlBodyLimiter() *ControlBodyLimiter {
	return &ControlBodyLimiter{sources: make(map[netip.Addr]int), timeout: controlBodyReadTimeout}
}

// Handler applies control-body protection and CORS to an owned control handler.
// Share one limiter across the relay's protocol and application control routes.
// Streaming application handlers should retain ownership of their own limits.
func (l *ControlBodyLimiter) Handler(next http.Handler, ingress *Ingress) http.Handler {
	control := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !utils.HandleAPICORS(w, r) {
			next.ServeHTTP(w, r)
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A protocol handler may delegate to an application-owned control
		// handler. The existing body wrapper means it is already protected.
		_, protected := r.Body.(*controlBody)
		if r.Body != nil && r.Body != http.NoBody && !protected {
			l.serve(w, r, ingress.SourceAddr(r), control)
			return
		}
		control.ServeHTTP(w, r)
	})
}

func (l *ControlBodyLimiter) acquire(source netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= controlBodyGlobalLimit || l.sources[source] >= controlBodySourceLimit {
		return false
	}
	l.active++
	l.sources[source]++
	return true
}

func (l *ControlBodyLimiter) release(source netip.Addr) {
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

// serve bounds ordinary request bodies. Cache POST/PUT handlers own their
// read deadlines and concurrency, but still need unread-body cleanup when
// authentication or admission rejects a request before consuming it.
func (l *ControlBodyLimiter) serve(w http.ResponseWriter, r *http.Request, source netip.Addr, next http.Handler) {
	controller := http.NewResponseController(w)
	cacheBody := r.URL.Path == types.PathSDKCache && (r.Method == http.MethodPost || r.Method == http.MethodPut)
	if !cacheBody {
		if !l.acquire(source) {
			w.Header().Set("Connection", "close")
			_ = controller.EnableFullDuplex()
			_ = controller.SetReadDeadline(time.Now())
			WriteRetryAfter(w, time.Second, "too many active control requests")
			return
		}
		defer l.release(source)
	}
	// This defer runs before slot release. net/http closes the original body
	// after the handler returns, even for Connection: close responses.
	body := &controlBody{ReadCloser: r.Body, remaining: r.ContentLength, header: w.Header()}
	r.Body = body
	defer func() {
		if body.complete {
			_ = controller.SetReadDeadline(time.Time{})
		} else {
			_ = controller.SetReadDeadline(time.Now())
		}
	}()
	w.Header().Set("Connection", "close")
	if err := controller.EnableFullDuplex(); err != nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "full-duplex request handling unavailable")
		return
	}
	if !cacheBody {
		if err := controller.SetReadDeadline(time.Now().Add(l.timeout)); err != nil {
			utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "request body deadline unavailable")
			return
		}
	}
	// A reverse upgrade has no HTTP request body. Reject one before hijacking,
	// so the body cleanup deadline cannot affect a live reverse connection.
	if r.URL.Path == types.PathSDKConnect && r.Method == http.MethodGet {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "reverse connect must not include a request body")
		return
	}
	next.ServeHTTP(w, r)
}
