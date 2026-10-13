package portal

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// signLeaseRequest builds the /v1/sign-shaped request the token gate reads.
func signLeaseRequest(t *testing.T, token string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://example.com"+types.PathV1Sign, nil)
	if err != nil {
		t.Fatalf("build sign request: %v", err)
	}
	req.Header.Set(types.HeaderAccessToken, token)
	return req
}

func newTestRegistry(t *testing.T, udpEnabled, tcpPortEnabled bool) *leaseRegistry {
	t.Helper()
	minPort, maxPort := 0, 0
	if udpEnabled || tcpPortEnabled {
		minPort, maxPort = testPortRange(t, 2)
	}
	relay, err := identity.LoadOrCreateRelayIdentity(filepath.Join(t.TempDir(), types.RelayIdentityFilename), "example.com")
	if err != nil {
		t.Fatalf("LoadOrCreateRelayIdentity() error = %v", err)
	}
	relayAuthority := identity.NewLocalAuthority(relay.Identity)
	registry, err := newLeaseRegistry(minPort, maxPort, relay.Name, relayAuthority, "https://example.com")
	if err != nil {
		t.Fatalf("newLeaseRegistry() error = %v", err)
	}
	registry.setUDPPolicy(udpEnabled, 0)
	registry.setTCPPortPolicy(tcpPortEnabled, 0)
	// Registered leases bind UDP and raw-TCP relays; releasing them keeps
	// repeated runs in one process free of port collisions.
	t.Cleanup(func() { registry.CloseAll() })
	return registry
}

func testPortRange(t *testing.T, size int) (int, int) {
	t.Helper()
	for range 100 {
		first, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
		if err != nil {
			t.Fatalf("reserve ephemeral TCP port: %v", err)
		}
		minPort := first.Addr().(*net.TCPAddr).Port
		maxPort := minPort + size - 1
		listeners := []io.Closer{first}
		available := maxPort <= 65535
		for port := minPort; available && port <= maxPort; port++ {
			if port != minPort {
				listener, listenErr := net.ListenTCP("tcp", &net.TCPAddr{Port: port})
				if listenErr != nil {
					available = false
					break
				}
				listeners = append(listeners, listener)
			}
			packet, listenErr := net.ListenUDP("udp", &net.UDPAddr{Port: port})
			if listenErr != nil {
				available = false
				break
			}
			listeners = append(listeners, packet)
		}
		for _, listener := range listeners {
			_ = listener.Close()
		}
		if available {
			return minPort, maxPort
		}
	}
	t.Fatal("could not find an ephemeral port range for raw transport test")
	return 0, 0
}

func newTestLeaseIdentity(t *testing.T, name string) types.Identity {
	t.Helper()
	testIdentity, err := identity.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("identity.ResolveSecp256k1Identity() error = %v", err)
	}
	testIdentity.Name = name
	return testIdentity
}

func TestRegisterOverlayPreferenceFallsBackToDirect(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	record, registered, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "overlay-fallback"),
		Overlay:  true,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !record.Overlay {
		t.Fatal("Register() did not preserve overlay preference")
	}
	if registered.ReverseEndpoint.Overlay || registered.ReverseEndpoint.URL != registry.reverseURL {
		t.Fatalf("Register() reverse endpoint = %#v, want direct fallback", registered.ReverseEndpoint)
	}
}

func TestLeaseRegistryLifecycle(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	_, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "demo"),
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if resp.ReverseEndpoint.URL != "https://example.com/sdk/connect" || resp.ReverseEndpoint.Capability == "" {
		t.Fatalf("Register() reverse endpoint = %#v, want direct capability", resp.ReverseEndpoint)
	}
	leases := registry.PublicLeases(time.Now())
	if len(leases) != 1 || leases[0].Hostname != "demo.example.com" || leases[0].CanonicalHostname != resp.CanonicalHostname || leases[0].Address != resp.Identity.Address {
		t.Fatalf("PublicLeases() = %+v, want the registered demo lease", leases)
	}
	if resp.Hostname != "demo.example.com" || resp.CanonicalHostname == "" {
		t.Fatalf("RegisterResponse hostnames = (%q, %q), want friendly and canonical hostnames", resp.Hostname, resp.CanonicalHostname)
	}
	if _, ok := registry.Lookup(resp.CanonicalHostname); !ok {
		t.Fatal("Lookup(canonical hostname) = false, want registered lease")
	}

	renewed, endpointInput, err := registry.Renew(types.RenewRequest{
		AccessToken: resp.AccessToken,
		TTL:         int((3 * time.Minute) / time.Second),
	}, netip.MustParseAddr("203.0.113.11"))
	if err != nil {
		t.Fatalf("Renew() error = %v", err)
	}
	if !renewed.ExpiresAt.After(resp.ExpiresAt) {
		t.Fatalf("Renew() expires at = %v, want later than register expiry %v", renewed.ExpiresAt, resp.ExpiresAt)
	}
	if _, err := registry.admitLeaseByToken(renewed.AccessToken, false); err != nil {
		t.Fatalf("admitLeaseByToken(renewed access token) error = %v, want admitted", err)
	}
	rotated, err := registry.issueReverseEndpoint(endpointInput, types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("issueReverseEndpoint() after Renew error = %v", err)
	}
	if rotated.Capability == "" || rotated.Capability == resp.ReverseEndpoint.Capability {
		t.Fatal("issueReverseEndpoint() did not rotate the reverse capability")
	}
	if _, err := registry.admitReverseCapability(rotated.Capability); err != nil {
		t.Fatalf("admitReverseCapability(rotated capability) error = %v, want admitted", err)
	}

	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: renewed.AccessToken}); err != nil {
		t.Fatalf("Unregister() error = %v", err)
	}
	if _, ok := registry.Lookup("demo.example.com"); ok {
		t.Fatal("Lookup() after Unregister() = true, want false")
	}
}

func TestLeaseRegistryUnnamedHostnameContract(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	identity := newTestLeaseIdentity(t, "")
	_, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: identity,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	expectedCanonical, err := utils.CanonicalLeaseHostname("", identity.Address, "example.com")
	if err != nil {
		t.Fatalf("CanonicalLeaseHostname error = %v", err)
	}
	if resp.Hostname != "" {
		t.Fatalf("RegisterResponse hostname = %q, want empty friendly hostname for unnamed service", resp.Hostname)
	}
	if resp.CanonicalHostname != expectedCanonical {
		t.Fatalf("RegisterResponse canonical hostname = %q, want %q", resp.CanonicalHostname, expectedCanonical)
	}
	leases := registry.PublicLeases(time.Now())
	if len(leases) != 1 || leases[0].Hostname != "" || leases[0].CanonicalHostname != expectedCanonical || leases[0].Address != identity.Address {
		t.Fatalf("PublicLeases() = %+v, want the registered unnamed lease", leases)
	}
	if _, ok := registry.Lookup(expectedCanonical); !ok {
		t.Fatal("Lookup(canonical hostname) = false, want registered unnamed lease")
	}
}

func TestLeaseRegistryUnnamedReplacementAndNamedCoexistence(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	unnamedIdentity := newTestLeaseIdentity(t, "")
	_, firstUnnamedResp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: unnamedIdentity,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("first unnamed Register() error = %v", err)
	}

	// Re-registering the same unnamed identity replaces the previous one.
	secondUnnamedRecord, secondUnnamedResp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: unnamedIdentity,
	}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("second unnamed Register() error = %v", err)
	}
	if firstUnnamedResp.CanonicalHostname != secondUnnamedResp.CanonicalHostname {
		t.Fatalf("canonical hostname changed across replacement: first=%q second=%q", firstUnnamedResp.CanonicalHostname, secondUnnamedResp.CanonicalHostname)
	}
	if leases := registry.PublicLeases(time.Now()); len(leases) != 1 {
		t.Fatalf("PublicLeases() length = %d, want 1 after unnamed replacement", len(leases))
	}

	// Registering a named service under the same address creates a distinct identity that coexists.
	namedIdentity := unnamedIdentity
	namedIdentity.Name = "myapp"
	_, namedResp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: namedIdentity,
	}, netip.MustParseAddr("203.0.113.12"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("named Register() error = %v", err)
	}
	if namedResp.CanonicalHostname == secondUnnamedResp.CanonicalHostname {
		t.Fatalf("named and unnamed services got the same canonical hostname %q", namedResp.CanonicalHostname)
	}

	leases := registry.PublicLeases(time.Now())
	if len(leases) != 2 {
		t.Fatalf("PublicLeases() length = %d, want 2 for distinct named and unnamed services", len(leases))
	}
	unnamedLookup, ok := registry.Lookup(secondUnnamedResp.CanonicalHostname)
	if !ok || unnamedLookup != secondUnnamedRecord {
		t.Fatalf("Lookup(unnamed) = (%+v, %v), want secondUnnamedRecord", unnamedLookup, ok)
	}
	namedLookup, ok := registry.Lookup(namedResp.CanonicalHostname)
	if !ok || namedLookup.Name != "myapp" {
		t.Fatalf("Lookup(named) = (%+v, %v), want myapp lease", namedLookup, ok)
	}
}

func TestLeaseTokensAreBoundToLeaseInstance(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	leaseIdentity := newTestLeaseIdentity(t, "replace")
	_, firstResponse, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("first Register() error = %v", err)
	}
	second, secondResponse, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("second Register() error = %v", err)
	}
	if firstResponse.CanonicalHostname != secondResponse.CanonicalHostname {
		t.Fatalf("canonical hostname changed across reconnect: first=%q second=%q", firstResponse.CanonicalHostname, secondResponse.CanonicalHostname)
	}
	if _, err := registry.admitReverseCapability(firstResponse.ReverseEndpoint.Capability); !errors.Is(err, errUnauthorized) {
		t.Fatalf("old reverse capability error = %v, want unauthorized", err)
	}
	if _, err := registry.admitLeaseByToken(firstResponse.AccessToken, false); !errors.Is(err, errUnauthorized) {
		t.Fatalf("old access token admission error = %v, want unauthorized", err)
	}
	if _, _, err := registry.Renew(types.RenewRequest{AccessToken: firstResponse.AccessToken}, netip.MustParseAddr("203.0.113.12")); !errors.Is(err, errUnauthorized) {
		t.Fatalf("old access token renew error = %v, want unauthorized", err)
	}
	if _, err := registry.resolveReverseEndpoint(types.ReverseEndpointRequest{AccessToken: firstResponse.AccessToken}); !errors.Is(err, errUnauthorized) {
		t.Fatalf("old access token reverse refresh error = %v, want unauthorized", err)
	}
	if _, ok := registry.verifySigningAccessTokenLease(signLeaseRequest(t, firstResponse.AccessToken)); ok {
		t.Fatal("verifySigningAccessTokenLease() old access token = true, want false")
	}
	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: firstResponse.AccessToken}); !errors.Is(err, errUnauthorized) {
		t.Fatalf("old access token unregister error = %v, want unauthorized", err)
	}
	if second.sourceAddr != netip.MustParseAddr("203.0.113.11") {
		t.Fatalf("replacement lease source = %v after old token operations, want unchanged", second.sourceAddr)
	}
	if _, ok := registry.Lookup("replace.example.com"); !ok {
		t.Fatal("Lookup() after replacement = false, want active replacement lease")
	}
	if _, err := registry.admitReverseCapability(secondResponse.ReverseEndpoint.Capability); err != nil {
		t.Fatalf("new reverse capability admission error = %v, want admitted", err)
	}
	if _, err := registry.admitLeaseByToken(secondResponse.AccessToken, false); err != nil {
		t.Fatalf("new access token admission error = %v, want admitted", err)
	}
	if leaseID, ok := registry.verifySigningAccessTokenLease(signLeaseRequest(t, secondResponse.AccessToken)); !ok || leaseID == "" {
		t.Fatalf("verifySigningAccessTokenLease() new access token = (%q, %v), want live lease", leaseID, ok)
	}
}

func TestLeaseRegistryLegacyClientRejectsHostnameConflict(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	_, first, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "conflict"),
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register(free legacy hostname) error = %v", err)
	}
	if first.Hostname != "conflict.example.com" {
		t.Fatalf("legacy friendly hostname = %q, want conflict.example.com", first.Hostname)
	}
	_, _, err = registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "conflict"),
	}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil)
	if !errors.Is(err, errHostnameConflict) {
		t.Fatalf("Register(conflicting legacy hostname) error = %v, want hostname conflict", err)
	}
}

func TestLeaseRegistryAllowsCanonicalFallbackForSameName(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	firstIdentity := newTestLeaseIdentity(t, "conflict")
	_, first, err := registry.Register(types.RegisterChallengeRequest{
		AllowCanonicalFallback: true,
		Identity:               firstIdentity,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register(conflict first) error = %v", err)
	}
	secondIdentity := newTestLeaseIdentity(t, "conflict")
	_, second, err := registry.Register(types.RegisterChallengeRequest{
		AllowCanonicalFallback: true,
		Identity:               secondIdentity,
	}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register(conflict second) error = %v", err)
	}
	if second.Hostname != "" {
		t.Fatalf("second friendly hostname = %q, want unavailable", second.Hostname)
	}
	if first.CanonicalHostname == second.CanonicalHostname {
		t.Fatalf("different owners received the same canonical hostname %q", first.CanonicalHostname)
	}
	for hostname, wantAddress := range map[string]string{
		first.CanonicalHostname:  firstIdentity.Address,
		second.CanonicalHostname: secondIdentity.Address,
	} {
		record, ok := registry.Lookup(hostname)
		if !ok || record.Address != wantAddress {
			t.Fatalf("Lookup(%q) = (%+v, %v), want address %q", hostname, record, ok, wantAddress)
		}
	}

	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: first.AccessToken}); err != nil {
		t.Fatalf("Unregister(first) error = %v", err)
	}
	_, secondReconnect, err := registry.Register(types.RegisterChallengeRequest{AllowCanonicalFallback: true, Identity: secondIdentity}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register(second reconnect) error = %v", err)
	}
	if secondReconnect.Hostname != "conflict.example.com" || secondReconnect.CanonicalHostname != second.CanonicalHostname {
		t.Fatalf("second reconnect hostnames = (%q, %q), want friendly reuse with stable canonical %q", secondReconnect.Hostname, secondReconnect.CanonicalHostname, second.CanonicalHostname)
	}
	_, firstReconnect, err := registry.Register(types.RegisterChallengeRequest{AllowCanonicalFallback: true, Identity: firstIdentity}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register(first reconnect) error = %v", err)
	}
	if firstReconnect.Hostname != "" || firstReconnect.CanonicalHostname != first.CanonicalHostname {
		t.Fatalf("first reconnect hostnames = (%q, %q), want unavailable friendly name and stable canonical %q", firstReconnect.Hostname, firstReconnect.CanonicalHostname, first.CanonicalHostname)
	}
}

func TestLeaseRegistryPolicyViewsUsePushedAccess(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	identity := newTestLeaseIdentity(t, "demo")
	registry.setIdentityRoutable(identity.ServiceKey(), false, 1)
	record, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: identity,
	}, netip.MustParseAddr("203.0.113.20"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	identityKey := record.ServiceKey()

	// The relay pushes the fail-closed result before registration so a new
	// lease cannot appear in public state before its access decision.
	if leases := registry.PublicLeases(time.Now()); len(leases) != 0 {
		t.Fatalf("PublicLeases() length = %d, want 0 while not routable", len(leases))
	}
	if _, err := registry.admitLeaseByToken(resp.AccessToken, false); !errors.Is(err, errLeaseRejected) {
		t.Fatalf("admitLeaseByToken() error = %v, want lease rejected while not routable", err)
	}

	registry.setIdentityRoutable(identityKey, true, 2)
	if leases := registry.PublicLeases(time.Now()); len(leases) != 1 {
		t.Fatalf("PublicLeases() length = %d, want 1 after the relay routes the identity", len(leases))
	}
	if _, err := registry.admitLeaseByToken(resp.AccessToken, false); err != nil {
		t.Fatalf("admitLeaseByToken() error = %v, want admitted once routable", err)
	}
}

func TestAccessRevisionRejectsInFlightAllow(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	leaseIdentity := newTestLeaseIdentity(t, "revision")
	_, lease, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.20"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := leaseIdentity.ServiceKey()
	registry.setIdentityRoutable(key, true, 1)
	loaded := make(chan struct{})
	resume := make(chan struct{})
	applied := make(chan bool, 1)
	go func() {
		// An old registration has already read revision 1's allow but has
		// not delivered it. Force it to arrive after the denial completes.
		close(loaded)
		<-resume
		applied <- registry.setIdentityRoutable(key, true, 1)
	}()
	<-loaded
	registry.setIdentityRoutable(key, false, 2)
	close(resume)
	if <-applied {
		t.Fatal("stale allow was applied after the newer denial")
	}
	if _, err := registry.admitLeaseByToken(lease.AccessToken, false); !errors.Is(err, errLeaseRejected) {
		t.Fatalf("delayed allow bypassed denial: %v", err)
	}
	registry.setIdentityRoutable(key, true, 3)
	if _, err := registry.admitLeaseByToken(lease.AccessToken, false); err != nil {
		t.Fatalf("newer allow failed to restore access: %v", err)
	}
}

func TestAccessRevisionSurvivesIdleCleanupAndRegistration(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	key := types.NewServiceIdentityKey("revision", "identity")
	registry.setIdentityRoutable(key, false, 2)
	registry.cleanupExpired(time.Now().Add(defaultRegisterChallengeTTL + time.Second))
	if registry.setIdentityRoutable(key, true, 1) {
		t.Fatal("idle cleanup forgot the revision fence")
	}
	registry.setIdentityRoutable(key, true, 3)
	registry.suspendIdentity(key)
	if registry.isRoutable(key) {
		t.Fatal("registration was not fail-closed")
	}
	if registry.setIdentityRoutable(key, true, 2) {
		t.Fatal("registration accepted an older revision")
	}
	if !registry.setIdentityRoutable(key, true, 3) || !registry.isRoutable(key) {
		t.Fatal("current committed revision did not release registration")
	}
}

func TestLeaseRegistryCleanupExpiredPreservesIdentityBPS(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	record, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "expired"),
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	registry.bps.SetIdentityBPS(record.ServiceKey(), 1024)

	registry.mu.Lock()
	record.ExpiresAt = time.Now().Add(-time.Second)
	registry.mu.Unlock()
	registry.cleanupExpired(time.Now())

	if _, ok := registry.Lookup("expired.example.com"); ok {
		t.Fatal("Lookup() after cleanupExpired() = true, want false")
	}
	if bps := registry.bps.IdentityBPS(record.ServiceKey()); bps != 1024 {
		t.Fatalf("IdentityBPS() after cleanupExpired() = %d, want configured limit preserved", bps)
	}
}

func TestIssueRegisterChallengeBoundsPendingPerIP(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	sourceAddr := netip.MustParseAddr("203.0.113.50")
	for i := range defaultRegisterChallengeOutstandingPerIP {
		_, err := registry.issueRegisterChallenge(types.RegisterChallengeRequest{
			Identity: newTestLeaseIdentity(t, fmt.Sprintf("demo-%d", i)),
		}, "example.com", "https://example.com"+types.PathSDKRegister, sourceAddr)
		if err != nil {
			t.Fatalf("issueRegisterChallenge(%d) error = %v", i, err)
		}
	}

	_, err := registry.issueRegisterChallenge(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "overflow"),
	}, "example.com", "https://example.com"+types.PathSDKRegister, sourceAddr)
	if !errors.Is(err, errRegisterChallengePending) {
		t.Fatalf("issueRegisterChallenge() error = %v, want pending limit", err)
	}

	expiredAt := time.Now().Add(-time.Second)
	registry.mu.Lock()
	for _, record := range registry.records {
		if record == nil || record.registerChallenge == nil {
			continue
		}
		record.ExpiresAt = expiredAt
		record.registerChallenge.ExpiresAt = expiredAt
	}
	registry.mu.Unlock()

	_, err = registry.issueRegisterChallenge(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "after-cleanup"),
	}, "example.com", "https://example.com"+types.PathSDKRegister, sourceAddr)
	if err != nil {
		t.Fatalf("issueRegisterChallenge() after expired cleanup error = %v", err)
	}
}

func TestIssueRegisterChallengeAcceptsLongName(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	if _, err := registry.issueRegisterChallenge(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "twenty-three-charactersx"),
	}, "example.com", "https://example.com"+types.PathSDKRegister, netip.MustParseAddr("203.0.113.50")); err != nil {
		t.Fatalf("issueRegisterChallenge(long name) error = %v", err)
	}
}

func TestMissingLeaseRecordReportsLeaseNotFound(t *testing.T) {
	t.Parallel()

	relay, err := identity.LoadOrCreateRelayIdentity(filepath.Join(t.TempDir(), types.RelayIdentityFilename), "example.com")
	if err != nil {
		t.Fatalf("LoadOrCreateRelayIdentity() error = %v", err)
	}
	relayAuthority := identity.NewLocalAuthority(relay.Identity)
	newRegistry := func() *leaseRegistry {
		t.Helper()
		registry, registryErr := newLeaseRegistry(0, 0, relay.Name, relayAuthority, "https://example.com")
		if registryErr != nil {
			t.Fatalf("newLeaseRegistry() error = %v", registryErr)
		}
		return registry
	}
	// The same relay identity in a fresh registry simulates a relay restart:
	// tokens stay verifiable while the in-memory lease records are gone.
	before, restarted := newRegistry(), newRegistry()

	_, resp, err := before.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "restart")}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if resp.AccessToken == "" || resp.ReverseEndpoint.Capability == "" {
		t.Fatalf("register response missing credentials: %+v", resp)
	}

	if _, err := restarted.admitLeaseByToken(resp.AccessToken, false); !errors.Is(err, errLeaseNotFound) {
		t.Fatalf("admitLeaseByToken() after restart = %v, want lease not found", err)
	}
	if _, err := restarted.admitReverseCapability(resp.ReverseEndpoint.Capability); !errors.Is(err, errLeaseNotFound) {
		t.Fatalf("admitReverseCapability() after restart = %v, want lease not found", err)
	}
	if _, _, err := restarted.Renew(types.RenewRequest{AccessToken: resp.AccessToken}, netip.MustParseAddr("203.0.113.10")); !errors.Is(err, errLeaseNotFound) {
		t.Fatalf("Renew() after restart = %v, want lease not found", err)
	}
	if _, err := restarted.resolveReverseEndpoint(types.ReverseEndpointRequest{AccessToken: resp.AccessToken}); !errors.Is(err, errLeaseNotFound) {
		t.Fatalf("RefreshReverseEndpoint() after restart = %v, want lease not found", err)
	}
	if _, ok := restarted.verifySigningAccessTokenLease(signLeaseRequest(t, resp.AccessToken)); ok {
		t.Fatal("verifySigningAccessTokenLease() after restart = true, want false for missing lease")
	}

	if _, err := restarted.admitReverseCapability("forged"); !errors.Is(err, errUnauthorized) {
		t.Fatalf("admitReverseCapability() forged = %v, want unauthorized", err)
	}
	if _, _, err := restarted.Renew(types.RenewRequest{AccessToken: "forged"}, netip.MustParseAddr("203.0.113.10")); !errors.Is(err, errUnauthorized) {
		t.Fatalf("Renew() forged = %v, want unauthorized", err)
	}
}

func TestPortPoolReservesReleasedPortForOwner(t *testing.T) {
	first := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x1"}}
	other := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x2"}}
	pool := newPortPool(10000, 10000, time.Minute)
	port, err := pool.allocate(first)
	if err != nil {
		t.Fatal(err)
	}
	pool.release(port, first)
	if _, err := pool.allocate(other); !errors.Is(err, errPortExhausted) {
		t.Fatalf("another owner consumed reserved port: %v", err)
	}
	if reclaimed, err := pool.allocate(first); err != nil || reclaimed != port {
		t.Fatalf("owner reclaim = %d, %v", reclaimed, err)
	}
}

func TestPortPoolReusesPortAfterReservationExpires(t *testing.T) {
	first := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x1"}}
	other := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x2"}}
	pool := newPortPool(10000, 10000, -time.Second)
	port, err := pool.allocate(first)
	if err != nil {
		t.Fatal(err)
	}
	pool.release(port, first)
	if reused, err := pool.allocate(other); err != nil || reused != port {
		t.Fatalf("expired reservation = %d, %v", reused, err)
	}
}

func TestLeasePortsStayWithServiceIdentityAcrossReconnect(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	firstIdentity := newTestLeaseIdentity(t, "shared")
	request := types.RegisterChallengeRequest{AllowCanonicalFallback: true, Identity: firstIdentity, UDPEnabled: true, TCPEnabled: true}
	firstRecord, first, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: first.AccessToken}); err != nil {
		t.Fatal(err)
	}
	request.Identity = newTestLeaseIdentity(t, "shared")
	_, other, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, firstUDP, _ := net.SplitHostPort(first.UDPAddr)
	_, firstTCP, _ := net.SplitHostPort(first.TCPAddr)
	_, otherUDP, _ := net.SplitHostPort(other.UDPAddr)
	_, otherTCP, _ := net.SplitHostPort(other.TCPAddr)
	if firstUDP == otherUDP || firstTCP == otherTCP {
		t.Fatalf("same-name identity inherited a sticky port: first=%s/%s, other=%s/%s", firstUDP, firstTCP, otherUDP, otherTCP)
	}
	request.Identity = firstIdentity
	_, reconnected, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reconnected.UDPAddr != first.UDPAddr || reconnected.TCPAddr != first.TCPAddr {
		t.Fatalf("reconnect lost reserved addresses: got %s/%s, want %s/%s", reconnected.UDPAddr, reconnected.TCPAddr, first.UDPAddr, first.TCPAddr)
	}
	registry.closeRecord(firstRecord)
	request.Identity = newTestLeaseIdentity(t, "third")
	if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil); !errors.Is(err, errUDPPortExhausted) {
		t.Fatalf("stale cleanup released a live UDP port: %v", err)
	}
	request.UDPEnabled = false
	if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil); !errors.Is(err, errTCPPortExhausted) {
		t.Fatalf("stale cleanup released a live TCP port: %v", err)
	}
}

func TestLeaseRegistrationFailureReleasesPorts(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	request := types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "retry"), UDPEnabled: true, TCPEnabled: true}
	port := registry.tcpPorts.available[0]
	occupied, err := net.ListenTCP("tcp", &net.TCPAddr{Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil); err == nil {
		t.Fatal("registration succeeded with an occupied TCP port")
	}
	_ = occupied.Close()
	_, response, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("registration could not reclaim its resources after failure: %v", err)
	}
	_, actual, _ := net.SplitHostPort(response.TCPAddr)
	if actual != fmt.Sprint(port) {
		t.Fatalf("registration leaked its reserved TCP port: got %s, want %d", actual, port)
	}
}

func TestRequestedLeaseTTLBounds(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		seconds int
		want    time.Duration
		invalid bool
	}{
		{name: "default", seconds: 0, want: defaultLeaseTTL},
		{name: "negative keeps default", seconds: -1, want: defaultLeaseTTL},
		{name: "maximum", seconds: int(maxLeaseTTL / time.Second), want: maxLeaseTTL},
		{name: "above maximum", seconds: int(maxLeaseTTL/time.Second) + 1, invalid: true},
		{name: "overflow size", seconds: math.MaxInt, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := requestedLeaseTTL(tc.seconds)
			if tc.invalid {
				if !errors.Is(err, errLeaseTTLExceeded) {
					t.Fatalf("requestedLeaseTTL(%d) error = %v, want maximum TTL rejection", tc.seconds, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("requestedLeaseTTL(%d) = %s, %v, want %s", tc.seconds, got, err, tc.want)
			}
		})
	}
}

func TestLeaseTTLValidationBeforeAllocationOrRenewal(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	request := types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "ttl-limit")}
	source := netip.MustParseAddr("203.0.113.40")
	for _, invalidTTL := range []int{int(maxLeaseTTL/time.Second) + 1, math.MaxInt} {
		request.TTL = invalidTTL
		if _, err := registry.issueRegisterChallenge(request, "example.com", "https://example.com"+types.PathSDKRegister, source); !errors.Is(err, errLeaseTTLExceeded) {
			t.Fatalf("issueRegisterChallenge(TTL=%d) error = %v", invalidTTL, err)
		}
		if _, _, err := registry.Register(request, source, "", types.RelayDescriptor{}, nil); !errors.Is(err, errLeaseTTLExceeded) {
			t.Fatalf("Register(TTL=%d) error = %v", invalidTTL, err)
		}
		if len(registry.records) != 0 {
			t.Fatal("rejected TTL allocated a registry record")
		}
	}

	request.TTL = int(maxLeaseTTL / time.Second)
	record, response, err := registry.Register(request, source, "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register(maximum TTL) error = %v", err)
	}
	if remaining := time.Until(response.ExpiresAt); remaining <= maxLeaseTTL-time.Minute || remaining > maxLeaseTTL {
		t.Fatalf("registered TTL = %s, want at most %s", remaining, maxLeaseTTL)
	}
	originalExpiry := record.ExpiresAt
	for _, invalidTTL := range []int{int(maxLeaseTTL/time.Second) + 1, math.MaxInt} {
		if _, _, err := registry.Renew(types.RenewRequest{AccessToken: response.AccessToken, TTL: invalidTTL}, source); !errors.Is(err, errLeaseTTLExceeded) {
			t.Fatalf("Renew(TTL=%d) error = %v", invalidTTL, err)
		}
		if !record.ExpiresAt.Equal(originalExpiry) {
			t.Fatal("rejected renewal extended the existing lease")
		}
	}
	if _, err := registry.admitLeaseByToken(response.AccessToken, false); err != nil {
		t.Fatalf("original token invalid after rejected renewal: %v", err)
	}
	renewed, _, err := registry.Renew(types.RenewRequest{AccessToken: response.AccessToken, TTL: int(maxLeaseTTL / time.Second)}, source)
	if err != nil {
		t.Fatalf("Renew(maximum TTL) error = %v", err)
	}
	if remaining := time.Until(renewed.ExpiresAt); remaining <= maxLeaseTTL-time.Minute || remaining > maxLeaseTTL {
		t.Fatalf("renewed TTL = %s, want at most %s", remaining, maxLeaseTTL)
	}
}

func TestLeaseRegistryLiveCapacity(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	identity := newTestLeaseIdentity(t, "quota-client")
	until := time.Now().Add(time.Hour)
	for i := range maxLiveLeases {
		registry.records = append(registry.records, &leaseRecord{
			Identity:   types.Identity{Name: fmt.Sprintf("existing-%d", i), Address: identity.Address},
			ExpiresAt:  until,
			sourceAddr: netip.MustParseAddr("203.0.113.1"),
			reverse:    transport.NewReversePool(defaultIdleKeepalive, defaultReadyQueueLimit),
		})
	}
	_, _, err := registry.Register(types.RegisterChallengeRequest{Identity: identity}, netip.MustParseAddr("203.0.113.2"), "", types.RelayDescriptor{}, nil)
	if !errors.Is(err, errLeaseCapacityExceeded) || len(registry.records) != maxLiveLeases {
		t.Fatalf("Register() at total capacity: records=%d error=%v", len(registry.records), err)
	}

	// Eviction makes a slot available without waiting for the expiry janitor.
	removed := registry.EvictLease(registry.records[0].ServiceKey())
	if removed == nil || len(registry.records) != maxLiveLeases-1 {
		t.Fatal("EvictLease() failed to reclaim a quota slot")
	}
	if _, _, err := registry.Register(types.RegisterChallengeRequest{Identity: identity}, netip.MustParseAddr("203.0.113.2"), "", types.RelayDescriptor{}, nil); err != nil {
		t.Fatalf("Register() after eviction error = %v", err)
	}
}

func TestLeaseRegistryPerSourceCapacityAndImmediateRawEviction(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	identity := newTestLeaseIdentity(t, "quota-raw")
	source := netip.MustParseAddr("203.0.113.40")
	for i := range maxLiveLeasesPerSource {
		registry.records = append(registry.records, &leaseRecord{
			Identity:   types.Identity{Name: fmt.Sprintf("from-source-%d", i), Address: identity.Address},
			ExpiresAt:  time.Now().Add(time.Hour),
			sourceAddr: source,
			reverse:    transport.NewReversePool(defaultIdleKeepalive, defaultReadyQueueLimit),
		})
	}
	request := types.RegisterChallengeRequest{Identity: identity, UDPEnabled: true, TCPEnabled: true}
	if _, _, err := registry.Register(request, source, "", types.RelayDescriptor{}, nil); !errors.Is(err, errLeaseCapacityExceeded) {
		t.Fatalf("Register() at source capacity error = %v", err)
	}
	if len(registry.udpPorts.inUse) != 0 || len(registry.tcpPorts.inUse) != 0 || len(registry.udpPorts.reserved) != 0 || len(registry.tcpPorts.reserved) != 0 {
		t.Fatal("capacity denial allocated raw transport ports")
	}

	otherSource := netip.MustParseAddr("203.0.113.41")
	record, response, err := registry.Register(request, otherSource, "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() from different source error = %v", err)
	}
	udpPort, tcpPort := record.datagram.UDPPort(), record.tcpPort
	if got := registry.EvictLease(identity.ServiceKey()); got != record {
		t.Fatal("EvictLease() returned a different lease")
	}
	if _, ok := registry.Lookup(response.CanonicalHostname); ok {
		t.Fatal("evicted lease is still routable")
	}
	if _, err := registry.admitLeaseByToken(response.AccessToken, false); !errors.Is(err, errLeaseNotFound) {
		t.Fatalf("evicted lease token admitted: %v", err)
	}
	if len(registry.udpPorts.inUse) != 0 || len(registry.tcpPorts.inUse) != 0 || len(registry.udpPorts.reserved) != 0 || len(registry.tcpPorts.reserved) != 0 {
		t.Fatal("eviction retained raw port ownership or grace reservations")
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: tcpPort})
	if err != nil {
		t.Fatalf("eviction did not close TCP listener: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	request.Identity = newTestLeaseIdentity(t, "replacement-raw")
	newRecord, _, err := registry.Register(request, otherSource, "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() after eviction error = %v", err)
	}
	if newRecord.datagram.UDPPort() != udpPort || newRecord.tcpPort != tcpPort {
		t.Fatalf("evicted ports not immediately reusable: UDP %d/%d, TCP %d/%d", newRecord.datagram.UDPPort(), udpPort, newRecord.tcpPort, tcpPort)
	}
}

func TestRegisterChallengeTotalCapacity(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	expiresAt := time.Now().Add(time.Minute)
	for range maxPendingRegisterChallenges {
		registry.records = append(registry.records, &leaseRecord{
			ExpiresAt:         expiresAt,
			sourceAddr:        netip.MustParseAddr("203.0.113.1"),
			registerChallenge: &identity.RegisterChallenge{ExpiresAt: expiresAt},
		})
	}
	request := types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "challenge-limit")}
	source := netip.MustParseAddr("203.0.113.2")
	if _, err := registry.issueRegisterChallenge(request, "example.com", "https://example.com"+types.PathSDKRegister, source); !errors.Is(err, errRegisterChallengeFull) {
		t.Fatalf("issueRegisterChallenge() at total capacity error = %v", err)
	}
	registry.mu.Lock()
	for _, record := range registry.records {
		record.ExpiresAt = time.Now().Add(-time.Second)
	}
	registry.mu.Unlock()
	if _, err := registry.issueRegisterChallenge(request, "example.com", "https://example.com"+types.PathSDKRegister, source); err != nil {
		t.Fatalf("issueRegisterChallenge() after expiry error = %v", err)
	}
}

func TestPortPoolImmediateReleaseAfterNormalClose(t *testing.T) {
	old := &leaseRecord{Identity: types.Identity{Name: "evicted", Address: "0x1"}}
	pool := newPortPool(10000, 10000, time.Minute)
	port, err := pool.allocate(old)
	if err != nil {
		t.Fatal(err)
	}
	pool.release(port, old)
	pool.releaseImmediately(port, old)
	if len(pool.available) != 1 || pool.available[0] != port || len(pool.reserved) != 0 {
		t.Fatalf("immediate release did not return port %d", port)
	}

	next := &leaseRecord{Identity: old.Identity}
	if allocated, err := pool.allocate(next); err != nil || allocated != port {
		t.Fatalf("reallocation = %d, %v; want %d, nil", allocated, err, port)
	}
	pool.releaseImmediately(port, old)
	if pool.inUse[port] != next || len(pool.available) != 0 {
		t.Fatal("stale immediate release reclaimed a different lease's port")
	}
}
