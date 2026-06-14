package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ParseTrustedProxies turns CIDR and bare-IP strings from config into a slice of
// *net.IPNet. A bare IPv4 becomes a /32 and a bare IPv6 becomes a /128. An empty
// input yields a nil slice; any unparseable entry returns an error.
func ParseTrustedProxies(cidrs []string) ([]*net.IPNet, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, raw := range cidrs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(s); err == nil {
			out = append(out, ipNet)
			continue
		}
		// Fall back to a bare IP, widened to a single-host mask.
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("trusted proxy %q is not a valid CIDR or IP", raw)
		}
		var mask net.IPMask
		if v4 := ip.To4(); v4 != nil {
			ip = v4
			mask = net.CIDRMask(32, 32)
		} else {
			mask = net.CIDRMask(128, 128)
		}
		out = append(out, &net.IPNet{IP: ip, Mask: mask})
	}
	return out, nil
}

// ClientIP derives the real client IP. It trusts X-Forwarded-For / X-Real-IP
// ONLY when the immediate RemoteAddr is within one of trustedProxies (CIDRs);
// otherwise it returns the IP from RemoteAddr. For X-Forwarded-For the left-most
// address (the original client) is used.
func ClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	remoteIP := remoteAddrIP(r.RemoteAddr)

	if !ipInAny(remoteIP, trustedProxies) {
		return remoteIP
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Left-most entry is the original client.
		first := xff
		if i := strings.IndexByte(xff, ','); i >= 0 {
			first = xff[:i]
		}
		if ip := strings.TrimSpace(first); ip != "" {
			return ip
		}
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}
	return remoteIP
}

// remoteAddrIP extracts the IP portion of a "host:port" RemoteAddr, tolerating a
// bare host with no port.
func remoteAddrIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// ipInAny reports whether ipStr parses to an IP contained in any of nets.
func ipInAny(ipStr string, nets []*net.IPNet) bool {
	if len(nets) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}
