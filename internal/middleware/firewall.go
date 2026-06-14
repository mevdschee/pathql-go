package middleware

import (
	"net"
	"net/http"
)

// forbiddenJSON is the generic 403 body for a firewall rejection. It matches the
// shape of every other error the server returns so a client cannot distinguish a
// firewall block from any other forbidden response.
const forbiddenJSON = `{"type":"Error","message":"forbidden"}`

// Firewall returns middleware that gates requests by resolved client IP. A
// request whose IP matches any deny CIDR is rejected with 403. If allow is
// non-empty, a request whose IP is not in any allow CIDR is also rejected (a
// default-deny allowlist). Deny is evaluated first, so an address in both lists
// is denied. When both lists are empty the middleware is a no-op passthrough.
//
// The client IP is resolved with ClientIP, the same trusted-proxy rules the rate
// limiter uses, so an untrusted peer cannot lift itself onto the allowlist with a
// spoofed X-Forwarded-For.
func Firewall(allow, deny []*net.IPNet, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if len(allow) == 0 && len(deny) == 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIP(r, trustedProxies)
			if firewallBlocks(ip, allow, deny) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(forbiddenJSON))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// firewallBlocks reports whether the client IP should be rejected: it is in the
// deny list, or an allow list is configured and the IP is not in it.
func firewallBlocks(ip string, allow, deny []*net.IPNet) bool {
	if ipInAny(ip, deny) {
		return true
	}
	if len(allow) > 0 && !ipInAny(ip, allow) {
		return true
	}
	return false
}
