package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseTrustedProxies(t *testing.T) {
	nets, err := ParseTrustedProxies([]string{"10.0.0.0/8", "192.168.1.5", "::1", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies error: %v", err)
	}
	if len(nets) != 4 {
		t.Fatalf("got %d nets, want 4", len(nets))
	}

	// Bare IPv4 must become a /32.
	if ones, bits := nets[1].Mask.Size(); ones != 32 || bits != 32 {
		t.Errorf("bare IPv4 mask = %d/%d, want 32/32", ones, bits)
	}
	// Bare IPv6 must become a /128.
	if ones, bits := nets[2].Mask.Size(); ones != 128 || bits != 128 {
		t.Errorf("bare IPv6 mask = %d/%d, want 128/128", ones, bits)
	}

	if _, err := ParseTrustedProxies([]string{"not-an-ip"}); err == nil {
		t.Errorf("expected error for invalid CIDR/IP, got nil")
	}
}

func TestClientIP(t *testing.T) {
	trusted, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies error: %v", err)
	}

	t.Run("spoofed XFF from untrusted RemoteAddr is ignored", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "203.0.113.9:5555" // not trusted
		r.Header.Set("X-Forwarded-For", "1.2.3.4")
		r.Header.Set("X-Real-IP", "5.6.7.8")
		if got := ClientIP(r, trusted); got != "203.0.113.9" {
			t.Errorf("ClientIP = %q, want 203.0.113.9 (RemoteAddr)", got)
		}
	})

	t.Run("XFF honored from trusted proxy", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.1.2.3:4444" // trusted
		r.Header.Set("X-Forwarded-For", "1.2.3.4, 9.9.9.9")
		if got := ClientIP(r, trusted); got != "1.2.3.4" {
			t.Errorf("ClientIP = %q, want 1.2.3.4 (left-most XFF)", got)
		}
	})

	t.Run("X-Real-IP honored from trusted proxy when no XFF", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.1.2.3:4444"
		r.Header.Set("X-Real-IP", "5.6.7.8")
		if got := ClientIP(r, trusted); got != "5.6.7.8" {
			t.Errorf("ClientIP = %q, want 5.6.7.8 (X-Real-IP)", got)
		}
	})

	t.Run("no trusted proxies uses RemoteAddr", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.1.2.3:4444"
		r.Header.Set("X-Forwarded-For", "1.2.3.4")
		if got := ClientIP(r, nil); got != "10.1.2.3" {
			t.Errorf("ClientIP = %q, want 10.1.2.3", got)
		}
	})

	t.Run("RemoteAddr without port", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "203.0.113.9"
		if got := ClientIP(r, trusted); got != "203.0.113.9" {
			t.Errorf("ClientIP = %q, want 203.0.113.9", got)
		}
	})
}
