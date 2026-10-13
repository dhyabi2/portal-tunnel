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

// Bound short-lived JSON control routes without affecting reverse upgrades,
// cache uploads (which have their own timeouts), or application-owned streams.
func isControlBodyRequest(r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return false
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	switch path {
	case types.PathSDKRegisterChallenge, types.PathSDKRegister,
		types.PathSDKRenew, types.PathSDKReverse, types.PathSDKUnregister,
		types.PathDiscoveryAnnounce, types.PathV1Sign,
		types.PathAdminAuthLogin, types.PathPolicy, types.PathPolicyLeases:
		return true
	}
	return path == types.PathAPIPrefix+"/reputation/vote" ||
		path == types.PathAPIPrefix+"/x402" ||
		strings.HasPrefix(path, types.PathAPIPrefix+"/x402/")
}

func (g *controlBodyGate) wrap(ingress *Ingress, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == types.PathSDKConnect && r.Method == http.MethodGet && r.Body != nil && r.Body != http.NoBody {
			if r.ProtoMajor == 1 {
				w.Header().Set("Connection", "close")
			}
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "reverse connect requests must not contain a body")
			return
		}
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
			WriteRetryAfter(w, time.Second, "too many active control requests")
			return
		}
		defer g.release(source)

		if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(controlBodyReadTimeout)); err != nil {
			utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeInternal, "control request body deadline unavailable")
			return
		}

		// Keep this deadline through net/http's post-handler body cleanup.
		// The server resets it on the next HTTP/1 request; upgrade routes
		// never enter this guard.
		next.ServeHTTP(w, r)
	})
}
