package portal

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestRequestedLeaseTTL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		seconds int
		want    time.Duration
		invalid bool
	}{
		{name: "omitted", seconds: 0, want: defaultLeaseTTL},
		{name: "negative", seconds: -1, want: defaultLeaseTTL},
		{name: "positive", seconds: 180, want: 3 * time.Minute},
		{name: "maximum", seconds: int(maxLeaseTTL / time.Second), want: maxLeaseTTL},
		{name: "above maximum", seconds: int(maxLeaseTTL/time.Second) + 1, invalid: true},
		{name: "overflow", seconds: int(^uint(0) >> 1), invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := requestedLeaseTTL(tc.seconds)
			if tc.invalid {
				if !errors.Is(err, errLeaseTTLExceeded) {
					t.Fatalf("requestedLeaseTTL(%d) error = %v, want TTL exceeded", tc.seconds, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("requestedLeaseTTL(%d) = %v, %v; want %v, nil", tc.seconds, got, err, tc.want)
			}
		})
	}
}

func TestLeaseRegistrationAndRenewalEnforceMaximumTTL(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	identity := newTestLeaseIdentity(t, "bounded")
	source := netip.MustParseAddr("203.0.113.10")
	oversized := int(maxLeaseTTL/time.Second) + 1

	request := types.RegisterChallengeRequest{Identity: identity, TTL: oversized}
	if _, err := registry.issueRegisterChallenge(request, "example.com", "https://example.com"+types.PathSDKRegister, source); !errors.Is(err, errLeaseTTLExceeded) {
		t.Fatalf("issueRegisterChallenge() error = %v, want TTL exceeded", err)
	}
	if _, _, err := registry.Register(request, source, "", types.RelayDescriptor{}, nil); !errors.Is(err, errLeaseTTLExceeded) {
		t.Fatalf("Register() error = %v, want TTL exceeded", err)
	}
	if len(registry.records) != 0 {
		t.Fatalf("rejected request retained %d records", len(registry.records))
	}

	request.TTL = int(maxLeaseTTL / time.Second)
	record, registered, err := registry.Register(request, source, "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register(maximum TTL) error = %v", err)
	}
	if remaining := time.Until(registered.ExpiresAt); remaining < maxLeaseTTL-2*time.Second || remaining > maxLeaseTTL+time.Second {
		t.Fatalf("Register() remaining TTL = %v, want at most %v", remaining, maxLeaseTTL)
	}
	originalExpiry := record.ExpiresAt
	if _, _, err := registry.Renew(types.RenewRequest{AccessToken: registered.AccessToken, TTL: oversized}, source); !errors.Is(err, errLeaseTTLExceeded) {
		t.Fatalf("Renew() error = %v, want TTL exceeded", err)
	}
	if !record.ExpiresAt.Equal(originalExpiry) {
		t.Fatalf("rejected renewal changed expiry from %v to %v", originalExpiry, record.ExpiresAt)
	}
	if _, _, err := registry.Renew(types.RenewRequest{AccessToken: registered.AccessToken, TTL: int(maxLeaseTTL / time.Second)}, source); err != nil {
		t.Fatalf("Renew(maximum TTL) error = %v", err)
	}
}

func TestLeaseRegistryAdmissionCapacity(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		count  int
		source netip.Addr
		client netip.Addr
	}{
		{
			name:   "per source",
			count:  maxLiveLeasesPerSource,
			source: netip.MustParseAddr("203.0.113.10"),
			client: netip.MustParseAddr("203.0.113.10"),
		},
		{
			name:   "global",
			count:  maxLiveLeases,
			source: netip.MustParseAddr("203.0.113.10"),
			client: netip.MustParseAddr("203.0.113.11"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, false, false)
			future := time.Now().Add(maxLeaseTTL)
			for i := range tc.count {
				registry.records = append(registry.records, &leaseRecord{
					Identity: types.Identity{
						Name:    fmt.Sprintf("existing-%d", i),
						Address: fmt.Sprintf("0x%040x", i+1),
					},
					ExpiresAt:  future,
					sourceAddr: tc.source,
					reverse:    transport.NewReversePool(defaultIdleKeepalive, defaultReadyQueueLimit),
				})
			}
			request := types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "overflow")}
			if _, _, err := registry.Register(request, tc.client, "", types.RelayDescriptor{}, nil); !errors.Is(err, errLeaseCapacityExceeded) {
				t.Fatalf("Register() error = %v, want lease capacity exceeded", err)
			}
			if len(registry.records) != tc.count {
				t.Fatalf("rejected registration changed records count to %d, want %d", len(registry.records), tc.count)
			}
		})
	}
}

func TestRegistrationChallengesHaveGlobalCapacity(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	expiresAt := time.Now().Add(defaultRegisterChallengeTTL)
	for range maxPendingRegisterChallenges {
		registry.records = append(registry.records, &leaseRecord{
			ExpiresAt:         expiresAt,
			sourceAddr:        netip.MustParseAddr("203.0.113.10"),
			registerChallenge: &identity.RegisterChallenge{},
		})
	}
	_, err := registry.issueRegisterChallenge(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "overflow"),
	}, "example.com", "https://example.com"+types.PathSDKRegister, netip.MustParseAddr("203.0.113.11"))
	if !errors.Is(err, errRegisterChallengeFull) {
		t.Fatalf("issueRegisterChallenge() error = %v, want global challenge capacity exceeded", err)
	}
	if len(registry.records) != maxPendingRegisterChallenges {
		t.Fatalf("challenge count = %d, want %d", len(registry.records), maxPendingRegisterChallenges)
	}
}

func TestAdministrativeEvictionImmediatelyReclaimsLeaseResources(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	request := types.RegisterChallengeRequest{
		Identity:   newTestLeaseIdentity(t, "evict"),
		UDPEnabled: true,
		TCPEnabled: true,
	}
	record, response, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	udpPort, tcpPort := record.datagram.UDPPort(), record.tcpPort

	if evicted := registry.EvictLease(record.ServiceKey()); evicted != record {
		t.Fatalf("EvictLease() = %p, want %p", evicted, record)
	}
	if got := registry.EvictLease(record.ServiceKey()); got != nil {
		t.Fatalf("second eviction = %p, want nil", got)
	}
	if len(registry.records) != 0 || len(registry.PolicyLeases(time.Now())) != 0 {
		t.Fatalf("eviction retained lease records: %d", len(registry.records))
	}
	if _, err := registry.admitLeaseByToken(response.AccessToken, false); !errors.Is(err, errLeaseNotFound) {
		t.Fatalf("evicted token still admitted: %v", err)
	}
	if _, ok := registry.udpPorts.inUse[udpPort]; ok {
		t.Fatal("evicted UDP port is still owned")
	}
	if _, ok := registry.tcpPorts.inUse[tcpPort]; ok {
		t.Fatal("evicted TCP port is still owned")
	}
	if _, ok := registry.udpPorts.reserved[record.ServiceKey()]; ok {
		t.Fatal("evicted UDP port retained a grace reservation")
	}
	if _, ok := registry.tcpPorts.reserved[record.ServiceKey()]; ok {
		t.Fatal("evicted TCP port retained a grace reservation")
	}
	if !slices.Contains(registry.udpPorts.available, udpPort) || !slices.Contains(registry.tcpPorts.available, tcpPort) {
		t.Fatal("evicted ports were not returned to the available pools")
	}

	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: tcpPort})
	if err != nil {
		t.Fatalf("evicted TCP listener is still active: %v", err)
	}
	_ = tcpListener.Close()
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{Port: udpPort})
	if err != nil {
		t.Fatalf("evicted UDP listener is still active: %v", err)
	}
	_ = udpListener.Close()

	request.Identity = newTestLeaseIdentity(t, "replacement")
	next, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() after eviction error = %v", err)
	}
	if next.datagram.UDPPort() != udpPort || next.tcpPort != tcpPort {
		t.Fatalf("reallocated ports UDP/TCP = %d/%d; want %d/%d", next.datagram.UDPPort(), next.tcpPort, udpPort, tcpPort)
	}
}

func TestPortPoolImmediateReleaseAfterOrdinaryClose(t *testing.T) {
	record := &leaseRecord{Identity: types.Identity{Name: "evicted", Address: "0x1"}}
	pool := newPortPool(10000, 10000, time.Minute)
	port, err := pool.allocate(record)
	if err != nil {
		t.Fatal(err)
	}
	pool.release(port, record)
	pool.releaseImmediately(port, record)
	if !slices.Contains(pool.available, port) || len(pool.reserved) != 0 {
		t.Fatalf("immediate release left port %d reserved", port)
	}
}
