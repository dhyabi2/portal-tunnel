package portal

import (
	"context"
	"net"
	"net/netip"
	"sync"
)

const (
	quicBackhaulPerSourceLimit  = 8
	quicBackhaulPreemptionLimit = 8
)

type quicBackhaulAuthSlot struct {
	source    netip.Addr
	cancel    context.CancelFunc
	preempted bool // guarded by quicBackhaulAdmission.mu
}

// quicBackhaulAdmission limits untrusted peers without letting a full pool
// permanently exclude new source addresses. Preempted handlers still count
// against a separate bound until their cancellation has completed.
type quicBackhaulAdmission struct {
	mu         sync.Mutex
	active     []*quicBackhaulAuthSlot
	bySource   map[netip.Addr]int
	preempting int
}

func quicBackhaulSource(addr net.Addr) netip.Addr {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.Addr{}
	}
	ip, ok := netip.AddrFromSlice(udp.IP)
	if !ok {
		return netip.Addr{}
	}
	ip = ip.Unmap()
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	return ip
}

// admit returns a slot and an optional older peer to cancel. The caller must
// cancel the victim outside the lock, and release every admitted slot exactly once.
func (a *quicBackhaulAdmission) admit(source netip.Addr, cancel context.CancelFunc) (*quicBackhaulAuthSlot, context.CancelFunc) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !source.IsValid() || a.bySource[source] >= quicBackhaulPerSourceLimit {
		return nil, nil
	}
	if a.bySource == nil {
		a.bySource = make(map[netip.Addr]int)
	}

	var evict context.CancelFunc
	if len(a.active) == quicBackhaulPendingLimit {
		if a.preempting == quicBackhaulPreemptionLimit {
			return nil, nil
		}
		// A source with fewer pending peers may displace the oldest peer
		// from a more represented source. This also lets a new source
		// progress when every existing source occupies exactly one slot.
		victimIndex := -1
		victimCount := a.bySource[source]
		for i, slot := range a.active {
			if count := a.bySource[slot.source]; count > victimCount {
				victimIndex, victimCount = i, count
			}
		}
		if victimIndex < 0 {
			return nil, nil
		}
		victim := a.active[victimIndex]
		victim.preempted = true
		a.active = append(a.active[:victimIndex], a.active[victimIndex+1:]...)
		a.decrement(victim.source)
		a.preempting++
		evict = victim.cancel
	}

	slot := &quicBackhaulAuthSlot{source: source, cancel: cancel}
	a.active = append(a.active, slot)
	a.bySource[source]++
	return slot, evict
}

func (a *quicBackhaulAdmission) release(slot *quicBackhaulAuthSlot) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if slot.preempted {
		a.preempting--
		return
	}
	for i, active := range a.active {
		if active == slot {
			a.active = append(a.active[:i], a.active[i+1:]...)
			a.decrement(slot.source)
			return
		}
	}
	panic("quic backhaul admission: released an unknown slot")
}

// decrement is called with mu held, only for a source with an active slot.
func (a *quicBackhaulAdmission) decrement(source netip.Addr) {
	if a.bySource[source] == 1 {
		delete(a.bySource, source)
		return
	}
	a.bySource[source]--
}
