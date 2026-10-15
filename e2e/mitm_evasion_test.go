package e2e_test

import (
	"context"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/sdk"
)

// The attack fixture sees real public/control connections, ClientHello and
// decrypted payloads, never the SDK's nonce reservations. Visitors offer HTTP/1.1
// and use distinct loopback source addresses; the self-probe uses native defaults.
// These are counterexamples for specified rules, not a model of Internet-wide
// detection probabilities. Repeat trials with go test -count when evaluating.
func TestMITMRelayEvasion(t *testing.T) {
	for _, attack := range []string{"passthrough", "terminate", "strip", "reset", "stall", "source", "target", "hello"} {
		t.Run(attack, func(t *testing.T) {
			t.Parallel()
			h := newHarnessWithName(t, "evasion", "127.0.0.1", attack, sdk.WithMITMProtection(true))
			publicURL := h.waitForPublicURL()
			started := time.Now()
			// A real request reaches the origin and arms the self-probe. A
			// terminating relay may cause exclusion before its response arrives.
			body, err := mitmVisit(h, publicURL, "127.0.0.1")
			if attack != "terminate" && err != nil {
				t.Fatalf("seed visitor: %v", err)
			}
			if attack == "passthrough" || attack == "source" || attack == "target" {
				if body != marker {
					t.Fatalf("honest visitor response = %q, want %q", body, marker)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			var probeDuration time.Duration
			select {
			case probeDuration = <-h.mitm.probes:
			case <-ctx.Done():
				t.Fatal("probe connection did not complete within observation window")
			}
			if attack == "strip" || attack == "reset" || attack == "stall" {
				// A relay-side reset can end its socket before the initiator's
				// response deadline. Observe beyond the documented 30s probe
				// timeout before asserting that suppression did not cause a ban.
				observation := time.NewTimer(max(0, 35*time.Second-time.Since(started)))
				defer observation.Stop()
				select {
				case <-observation.C:
				case <-ctx.Done():
					t.Fatal("inconclusive observation exceeded its budget")
				}
			}
			if attack == "terminate" {
				for {
					statuses := h.exposure.Relays()
					if len(statuses) == 1 && statuses[0].Failure == sdk.RelayFailureMITM {
						break
					}
					select {
					case <-ctx.Done():
						t.Fatal("forwarded TLS termination did not exclude the relay")
					case <-time.After(10 * time.Millisecond):
					}
				}
			} else {
				// The probe has completed or timed out. Let the public request
				// prove service still works, rather than asserting SDK log text.
				for range 3 {
					body, err := mitmVisit(h, publicURL, "127.0.0.2")
					if err != nil {
						t.Fatalf("post-probe visitor: %v", err)
					}
					want := mitmForgedBody
					if attack == "passthrough" {
						want = marker
					}
					if body != want {
						t.Fatalf("post-probe response = %q, want %q", body, want)
					}
				}
				statuses := h.exposure.Relays()
				if len(statuses) != 1 || statuses[0].State != sdk.RelayReady || statuses[0].Failure != "" {
					t.Fatalf("expected a ready, unexcluded relay: %+v", statuses)
				}
			}
			if attack == "target" {
				body, err := mitmVisit(h, publicURL, "127.0.0.3")
				if err != nil || body != marker {
					t.Fatalf("non-target visitor = %q, %v", body, err)
				}
			}
			h.mitm.mu.Lock()
			reads, writes, exposedBytes := h.mitm.reads, h.mitm.writes, h.mitm.bytes
			h.mitm.mu.Unlock()
			if attack == "passthrough" {
				if reads != 0 || writes != 0 || exposedBytes != 0 {
					t.Fatal("passthrough relay observed application plaintext")
				}
			} else if reads == 0 || exposedBytes < len(mitmVisitorSecret) {
				t.Fatal("terminating relay did not recover the visitor secret")
			}
			// Outcomes are derived from the experiment and public exclusion:
			// an honest probe reaches the same TLS endpoint; a forwarded split
			// produces mismatch; a suppressed nonce cannot produce a comparison.
			outcome := "match"
			if attack == "terminate" {
				outcome = "mismatch"
			} else if attack == "strip" || attack == "reset" || attack == "stall" {
				outcome = "inconclusive"
			}
			t.Logf("rule=%s trials=1 visitors_read=%d responses_modified=%d secret_bytes=%d probe=%s probe_duration=%s observation=%s detected=%t",
				attack, reads, writes, exposedBytes, outcome, probeDuration, time.Since(started), attack == "terminate")
			if attack == "source" || attack == "target" {
				if err := h.exposure.Close(); err != nil {
					t.Fatal(err)
				}
				body, err := mitmVisit(h, publicURL, "127.0.0.2")
				if err != nil || body != mitmForgedBody {
					t.Fatalf("relay impersonation after exposure close = %q, %v", body, err)
				}
			}
		})
	}
}

// Failure must not let an operator amplify a burst of ordinary visitor
// connections into a burst of fresh probe connections. The same cooldown
// budget applies whether the previous attempt matched, mismatched or failed.
func TestMITMProbeFailureBudget(t *testing.T) {
	h := newHarnessWithName(t, "failure-budget", "127.0.0.1", "reject", sdk.WithMITMProtection(true))
	publicURL := h.waitForPublicURL()
	started := time.Now()
	if _, err := mitmVisit(h, publicURL, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.mitm.probes:
	case <-time.After(10 * time.Second):
		t.Fatal("relay did not receive the first probe")
	}
	for range 10 {
		if _, err := mitmVisit(h, publicURL, "127.0.0.2"); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(started) >= 30*time.Second {
		t.Fatal("visitor burst exceeded the cooldown observation window")
	}
	h.mitm.mu.Lock()
	probes := h.mitm.probeStarts
	h.mitm.mu.Unlock()
	if probes > 1 {
		t.Fatalf("failed-probe budget exceeded: %d probe connections during one cooldown", probes)
	}
	if statuses := h.exposure.Relays(); len(statuses) != 1 || statuses[0].Failure != "" {
		t.Fatalf("handshake failure must not produce a MITM verdict: %+v", statuses)
	}
	t.Logf("visitors=11 probe_connections=%d observation=%s", probes, time.Since(started))
}
