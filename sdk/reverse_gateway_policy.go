package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// A gateway is chosen by an untrusted relay. Its signed descriptor binds the
// endpoint name; the address policy separately protects the local network.
func validateOverlayGateway(endpoint types.ReverseEndpoint) error {
	if endpoint.Gateway == nil {
		return errors.New("relay returned an overlay endpoint without a gateway descriptor")
	}
	gateway, err := discovery.VerifyRelayDescriptor(*endpoint.Gateway)
	if err != nil {
		return fmt.Errorf("relay returned an invalid overlay gateway descriptor: %w", err)
	}
	if !gateway.ExpiresAt.After(time.Now().UTC()) || endpoint.ExpiresAt.After(gateway.ExpiresAt) {
		return errors.New("relay returned an expired overlay gateway authorization")
	}
	gatewayURL, err := url.Parse(gateway.APIHTTPSAddr)
	if err != nil || endpoint.URL != utils.ResolveAPIURL(gatewayURL, types.PathSDKConnect).String() {
		return errors.New("relay reverse endpoint does not match its signed gateway descriptor")
	}
	return validatePublicGatewayHost(gatewayURL.Hostname())
}

func validatePublicGatewayHost(host string) error {
	host = utils.NormalizeHostname(host)
	if utils.IsLocalRelayHost(host) {
		return fmt.Errorf("overlay gateway hostname %q is local", host)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return validatePublicGatewayIP(ip)
	}
	return nil
}

// netip.IsGlobalUnicast includes some non-public ranges; exclude those too.
// Tunnel relay selection remains free to use local addresses directly. Only
// relay-controlled alternate gateways must satisfy this public-address policy.
var excludedGatewayRanges = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

func validatePublicGatewayIP(ip netip.Addr) error {
	ip = ip.Unmap()
	if nonPublicGatewayAddr(ip) {
		return fmt.Errorf("overlay gateway address %s is not public", ip)
	}
	for _, excluded := range excludedGatewayRanges {
		if excluded.Contains(ip) {
			return fmt.Errorf("overlay gateway address %s is not public", ip)
		}
	}
	return nil
}

// nonPublicGatewayAddr reports whether the address is unusable as a public
// overlay gateway: invalid, zoned, non-unicast, or in a local-use range.
func nonPublicGatewayAddr(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return true
	}
	if !ip.IsGlobalUnicast() {
		return true
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// ControlContext runs for each resolved IP immediately before connect, so
// malicious DNS answers and rebinding cannot bypass hostname validation.
func publicGatewayDialControl(_ context.Context, _, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("parse resolved overlay gateway address: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("overlay gateway resolved to invalid IP %q: %w", host, err)
	}
	return validatePublicGatewayIP(ip)
}
