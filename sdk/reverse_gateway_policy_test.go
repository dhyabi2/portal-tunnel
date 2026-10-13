package sdk

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestPublicGatewayHostPolicy(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		host    string
		allowed bool
	}{
		"public domain":      {host: "gateway.example", allowed: true},
		"public ipv4":        {host: "8.8.8.8", allowed: true},
		"public ipv6":        {host: "2606:4700:4700::1111", allowed: true},
		"localhost":          {host: "localhost"},
		"localhost suffix":   {host: "gateway.localhost."},
		"loopback":           {host: "127.0.0.1"},
		"private":            {host: "10.0.1.2"},
		"private ipv6":       {host: "fd00::1"},
		"link local":         {host: "169.254.169.254"},
		"shared ipv4":        {host: "100.64.0.1"},
		"benchmark":          {host: "198.18.0.1"},
		"documentation ipv4": {host: "203.0.113.1"},
		"documentation ipv6": {host: "2001:db8::1"},
		"nat64 mapped ipv4":  {host: "64:ff9b::7f00:1"},
		"ipv4 mapped ipv6":   {host: "::ffff:127.0.0.1"},
		"unspecified":        {host: "0.0.0.0"},
		"unspecified ipv6":   {host: "::"},
		"multicast ipv4":     {host: "224.0.0.1"},
		"multicast ipv6":     {host: "ff02::1"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := validatePublicGatewayHost(test.host); (err == nil) != test.allowed {
				t.Fatalf("validatePublicGatewayHost(%q) error = %v, allowed %v", test.host, err, test.allowed)
			}
		})
	}
}

func TestPublicGatewayDialControlChecksResolvedIPs(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		ip      string
		allowed bool
	}{
		{ip: "8.8.8.8", allowed: true},
		{ip: "2606:4700:4700::1111", allowed: true},
		{ip: "127.0.0.1"},
		{ip: "192.168.0.1"},
		{ip: "169.254.169.254"},
		{ip: "100.64.0.1"},
		{ip: "::ffff:127.0.0.1"},
		{ip: "fc00::1"},
	} {
		t.Run(test.ip, func(t *testing.T) {
			t.Parallel()
			ip := netip.MustParseAddr(test.ip)
			err := publicGatewayDialControl(context.Background(), "tcp", net.JoinHostPort(ip.String(), "443"), nil)
			if (err == nil) != test.allowed {
				t.Fatalf("publicGatewayDialControl(%s) error = %v, allowed %v", ip, err, test.allowed)
			}
		})
	}
}

func TestPublicGatewayDialControlRejectsBeforeConnect(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dialer := &net.Dialer{ControlContext: publicGatewayDialControl}
	conn, err := dialer.DialContext(context.Background(), "tcp", listener.Addr().String())
	if conn != nil {
		conn.Close()
		t.Fatal("private gateway connection was established")
	}
	if err == nil {
		t.Fatal("private gateway dial was accepted")
	}
}
