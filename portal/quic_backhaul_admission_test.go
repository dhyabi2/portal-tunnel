package portal

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestQUICBackhaulAdmissionLimitsOneSource(t *testing.T) {
	t.Parallel()
	var admission quicBackhaulAdmission
	source := netip.MustParseAddr("192.0.2.1")
	other := netip.MustParseAddr("192.0.2.2")
	for range quicBackhaulPerSourceLimit {
		_, cancel := context.WithCancel(t.Context())
		defer cancel()
		slot, evict := admission.admit(source, cancel)
		if slot == nil || evict != nil {
			t.Fatal("rejected a connection within the per-source budget")
		}
		defer admission.release(slot)
	}
	_, cancel := context.WithCancel(t.Context())
	defer cancel()
	if slot, evict := admission.admit(source, cancel); slot != nil || evict != nil {
		t.Fatal("admitted a connection beyond the per-source budget")
	}
	slot, evict := admission.admit(other, cancel)
	if slot == nil || evict != nil {
		t.Fatal("one saturated source prevented another source from authenticating")
	}
	admission.release(slot)
}

func TestQUICBackhaulAdmissionPreemptsSaturatedPool(t *testing.T) {
	t.Parallel()
	var admission quicBackhaulAdmission
	var firstCtx context.Context
	var first *quicBackhaulAuthSlot
	for i := 1; i <= quicBackhaulPendingLimit; i++ {
		source := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		slot, evict := admission.admit(source, cancel)
		if slot == nil || evict != nil {
			t.Fatalf("failed to admit initial source %d", i)
		}
		if i == 1 {
			first, firstCtx = slot, ctx
		}
		if i != 1 {
			defer admission.release(slot)
		}
	}
	_, cancel := context.WithCancel(t.Context())
	defer cancel()
	newSource := netip.MustParseAddr("198.51.100.1")
	slot, evict := admission.admit(newSource, cancel)
	if slot == nil || evict == nil {
		t.Fatal("a new source could not get a slot in a saturated pool")
	}
	evict()
	select {
	case <-firstCtx.Done():
	default:
		t.Fatal("preempted anonymous connection was not canceled")
	}
	admission.release(first)
	admission.release(slot)
	if admission.preempting != 0 || len(admission.active) != quicBackhaulPendingLimit-1 {
		t.Fatal("preemption did not release its accounting")
	}
}

func TestQUICBackhaulAdmissionBoundsPreemptions(t *testing.T) {
	t.Parallel()
	var admission quicBackhaulAdmission
	for i := 1; i <= quicBackhaulPendingLimit; i++ {
		_, cancel := context.WithCancel(t.Context())
		defer cancel()
		slot, _ := admission.admit(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), cancel)
		defer admission.release(slot)
	}
	for i := 1; i <= quicBackhaulPreemptionLimit; i++ {
		_, cancel := context.WithCancel(t.Context())
		defer cancel()
		slot, victim := admission.admit(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), cancel)
		if slot == nil || victim == nil {
			t.Fatalf("preemption %d failed", i)
		}
		defer admission.release(slot)
	}
	_, cancel := context.WithCancel(t.Context())
	defer cancel()
	if slot, victim := admission.admit(netip.MustParseAddr("203.0.113.3"), cancel); slot != nil || victim != nil {
		t.Fatal("admitted more than the bounded number of concurrent preemptions")
	}
}

func TestQUICBackhaulSourceNormalizesIPv4(t *testing.T) {
	t.Parallel()
	got := quicBackhaulSource(&net.UDPAddr{IP: net.ParseIP("192.0.2.3")})
	if want := netip.MustParseAddr("192.0.2.3"); got != want {
		t.Fatalf("source = %s, want %s", got, want)
	}
	if got := quicBackhaulSource(&net.UDPAddr{IP: net.ParseIP("2001:db8:1:2::abcd")}); got != netip.MustParseAddr("2001:db8:1:2::") {
		t.Fatalf("IPv6 source bucket = %s, want 2001:db8:1:2::", got)
	}
	if got := quicBackhaulSource(&net.TCPAddr{}); got.IsValid() {
		t.Fatalf("unexpected source from unsupported address: %s", got)
	}
}
