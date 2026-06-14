package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// okHandler (declared in ratelimit_test.go) is reused as the downstream handler
// to detect whether a request passed the firewall.

func serveFirewall(t *testing.T, allow, deny []string, remoteAddr, xff string, trusted []string) int {
	t.Helper()
	allowNets, err := ParseTrustedProxies(allow)
	if err != nil {
		t.Fatalf("parse allow: %v", err)
	}
	denyNets, err := ParseTrustedProxies(deny)
	if err != nil {
		t.Fatalf("parse deny: %v", err)
	}
	trustedNets, err := ParseTrustedProxies(trusted)
	if err != nil {
		t.Fatalf("parse trusted: %v", err)
	}

	h := Firewall(allowNets, denyNets, trustedNets)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/pathql", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestFirewallNoListsIsPassthrough(t *testing.T) {
	if code := serveFirewall(t, nil, nil, "203.0.113.5:1000", "", nil); code != http.StatusOK {
		t.Fatalf("expected passthrough 200, got %d", code)
	}
}

func TestFirewallDenyBlocks(t *testing.T) {
	if code := serveFirewall(t, nil, []string{"203.0.113.0/24"}, "203.0.113.5:1000", "", nil); code != http.StatusForbidden {
		t.Fatalf("expected 403 for denied IP, got %d", code)
	}
	// An IP outside the deny range passes.
	if code := serveFirewall(t, nil, []string{"203.0.113.0/24"}, "198.51.100.7:1000", "", nil); code != http.StatusOK {
		t.Fatalf("expected 200 for non-denied IP, got %d", code)
	}
}

func TestFirewallAllowIsDefaultDeny(t *testing.T) {
	allow := []string{"10.0.0.0/8"}
	if code := serveFirewall(t, allow, nil, "10.1.2.3:1000", "", nil); code != http.StatusOK {
		t.Fatalf("expected 200 for allowed IP, got %d", code)
	}
	if code := serveFirewall(t, allow, nil, "192.0.2.9:1000", "", nil); code != http.StatusForbidden {
		t.Fatalf("expected 403 for IP outside allowlist, got %d", code)
	}
}

func TestFirewallDenyBeatsAllow(t *testing.T) {
	// IP is in both lists; deny wins.
	code := serveFirewall(t, []string{"10.0.0.0/8"}, []string{"10.1.2.3"}, "10.1.2.3:1000", "", nil)
	if code != http.StatusForbidden {
		t.Fatalf("expected deny to take precedence (403), got %d", code)
	}
}

// TestFirewallIgnoresUntrustedForwardedFor verifies a spoofed X-Forwarded-For
// from an untrusted peer cannot lift the client onto the allowlist: the gate uses
// the real RemoteAddr.
func TestFirewallIgnoresUntrustedForwardedFor(t *testing.T) {
	// RemoteAddr is not allowlisted and not a trusted proxy, so the spoofed XFF is
	// ignored and the request is blocked.
	code := serveFirewall(t, []string{"10.0.0.0/8"}, nil, "192.0.2.9:1000", "10.1.2.3", nil)
	if code != http.StatusForbidden {
		t.Fatalf("expected spoofed XFF to be ignored and blocked (403), got %d", code)
	}
	// When RemoteAddr IS a trusted proxy, the forwarded client IP is honored.
	code = serveFirewall(t, []string{"10.0.0.0/8"}, nil, "192.0.2.9:1000", "10.1.2.3", []string{"192.0.2.9"})
	if code != http.StatusOK {
		t.Fatalf("expected trusted-proxy forwarded IP to be allowed (200), got %d", code)
	}
}
