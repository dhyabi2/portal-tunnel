package policy

import (
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	controlBodyReadTimeout          = 10 * time.Second
	maxActiveControlBodies          = 64
	maxActiveControlBodiesPerSource = 8
)

// controlBodyGate bounds unfinished control-plane requests independently of
// the refillable pre-auth rate budget. Only active sources occupy the map.
type controlBodyGate struct {
	mu      sync.Mutex
	active  int
	sources map[netip.Addr]int
}

func newControlBodyGate() *controlBodyGate {
	return &controlBodyGate{sources: make(map[netip.Addr]int)}
}

func (g *controlBodyGate) acquire(source netip.Addr) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active >= maxActiveControlBodies || g.sources[source] >= maxActiveControlBodiesPerSource {
		return false
	}
	g.active++
	g.sources[source]++
	return true
}

func (g *controlBodyGate) release(source netip.Addr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.active--
	if g.sources[source] == 1 {
		delete(g.sources, source)
	} else {
		g.sources[source]--
	}
}

// Root-host control paths belong to the relay, including unknown methods and
// paths. Guard their bodies before route dispatch so an attacker cannot bypass
// the body limit through a non-JSON endpoint such as /api/healthz.
// Application-owned routes outside the reserved prefixes are unaffected.
func isControlBodyRequest(r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return false
	}
	for _, prefix := range types.ReservedRootPrefixes {
		if r.URL.Path == prefix || strings.HasPrefix(r.URL.Path, prefix+"/") {
			return true
		}
	}
	return false
}

func (g *controlBodyGate) wrap(ingress *Ingress, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isControlBodyRequest(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Prevent net/http from draining an unread HTTP/1 request body after
		// this handler releases its in-flight slot.
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
		}
		source := ingress.SourceAddr(r)
		if !g.acquire(source) {
			// A rejected request has no in-flight permit. Fail its unread
			// body immediately so net/http cannot block draining it.
			if err := http.NewResponseController(w).SetReadDeadline(time.Now()); err != nil {
				utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeInternal, "control request body deadline unavailable")
				return
			}
			WriteRetryAfter(w, time.Second, "too many active control requests")
			return
		}
		if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(controlBodyReadTimeout)); err != nil {
			utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeInternal, "control request body deadline unavailable")
			g.release(source)
			return
		}
		defer func() {
			// Preserve the in-flight permit while closing any unread body.
			// net/http also closes the body after the handler returns.
			_ = r.Body.Close()
			g.release(source)
		}()

		if r.URL.Path == types.PathSDKConnect && r.Method == http.MethodGet {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "reverse connect requests must not contain a body")
			return
		}
		next.ServeHTTP(w, r)
	})
}
