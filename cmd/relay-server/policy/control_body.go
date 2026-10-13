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

// A body deadline applies only to control-plane POSTs. Cache uploads can be
// large, and /sdk/connect upgrades to a long-lived reverse transport.
func isControlBodyRequest(r *http.Request) bool {
	if r.Method != http.MethodPost || r.Body == http.NoBody {
		return false
	}
	path := r.URL.Path
	return (strings.HasPrefix(path, types.PathAPIPrefix+"/") ||
		strings.HasPrefix(path, types.PathSDKPrefix+"/") ||
		path == types.PathDiscoveryAnnounce ||
		path == types.PathV1Sign) &&
		path != types.PathSDKConnect && path != types.PathSDKCache
}

func (g *controlBodyGate) wrap(ingress *Ingress, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isControlBodyRequest(r) {
			next.ServeHTTP(w, r)
			return
		}

		source := ingress.SourceAddr(r)
		if !g.acquire(source) {
			// Do not make net/http drain a rejected, potentially endless
			// HTTP/1 request body before reusing the connection.
			if r.ProtoMajor == 1 {
				w.Header().Set("Connection", "close")
			}
			WriteRetryAfter(w, time.Second, "too many active control requests")
			return
		}
		defer g.release(source)

		if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(controlBodyReadTimeout)); err != nil {
			if r.ProtoMajor == 1 {
				w.Header().Set("Connection", "close")
			}
			utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeInternal, "control request body deadline unavailable")
			return
		}

		// Keep this deadline through net/http's post-handler body cleanup.
		// The server resets it on the next HTTP/1 request; upgrade routes
		// never enter this guard.
		next.ServeHTTP(w, r)
	})
}
