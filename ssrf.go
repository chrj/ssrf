// Package ssrf provides SSRF (Server-Side Request Forgery) protection by
// exposing a Dialer whose DialContext method can be plugged into
// http.Transport.
//
// DNS rebinding protection: hostnames are resolved to IP addresses exactly
// once per dial call using LookupIPAddr, the resolved IPs are validated
// against all configured rules, and then the connection is made to the
// validated raw IP address (not the original hostname). This ensures that a
// second DNS lookup never occurs during the actual TCP connection, so an
// attacker cannot change DNS between the validation step and the connect step.
//
// Rule evaluation order: IPv4/IPv6 restriction → NoPrivateRanges → DenyCIDR →
// AllowCIDR. Deny rules are always evaluated before allow rules so that a
// denied address cannot be permitted by a broader allow range.
package ssrf

import (
	"context"
	"fmt"
	"net"
)

// Error is returned when a connection attempt is blocked by an SSRF protection
// rule. The Reason field describes why the connection was denied.
type Error struct {
	Reason string
}

func (e *Error) Error() string {
	return "ssrf: " + e.Reason
}

// privateRanges contains the well-known private, loopback, link-local, and
// other non-routable IP ranges for both IPv4 and IPv6.
var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		// IPv4 loopback
		"127.0.0.0/8",
		// IPv4 link-local
		"169.254.0.0/16",
		// IPv4 private
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		// IPv4 "this" network
		"0.0.0.0/8",
		// IPv4 CGNAT / Shared Address Space (RFC 6598)
		"100.64.0.0/10",
		// IPv4 documentation / TEST-NET
		"192.0.2.0/24",
		"198.51.100.0/24",
		"203.0.113.0/24",
		// IPv4 CGNAT / Shared Address Space (RFC 6598)
		"100.64.0.0/10",
		// IPv4 benchmark
		"198.18.0.0/15",
		// IPv4 broadcast
		"255.255.255.255/32",
		// IPv6 loopback
		"::1/128",
		// IPv6 link-local
		"fe80::/10",
		// IPv6 unique local (ULA)
		"fc00::/7",
		// IPv6 documentation
		"2001:db8::/32",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("ssrf: failed to parse built-in CIDR %q: %v", cidr, err))
		}
		privateRanges = append(privateRanges, network)
	}
}

// options holds the configuration for the SSRF protection dialer.
type options struct {
	ipv4Only   bool
	ipv6Only   bool
	noPrivate  bool
	allowCIDRs []*net.IPNet
	denyCIDRs  []*net.IPNet
	resolver   *net.Resolver
	dialer     *net.Dialer
}

// Option is a functional option for configuring the SSRF protection dialer.
type Option func(*options)

// IPv4Only restricts connections to IPv4 addresses only.
func IPv4Only() Option {
	return func(o *options) {
		o.ipv4Only = true
	}
}

// IPv6Only restricts connections to IPv6 addresses only.
func IPv6Only() Option {
	return func(o *options) {
		o.ipv6Only = true
	}
}

// NoPrivateRanges blocks connections to loopback, link-local, private, and
// other non-publicly-routable IP ranges for both IPv4 and IPv6.
func NoPrivateRanges() Option {
	return func(o *options) {
		o.noPrivate = true
	}
}

// AllowCIDR restricts outbound connections to the given CIDR ranges. If any
// allow CIDRs are configured, a resolved IP must match at least one of them or
// the connection is denied. Multiple calls to AllowCIDR append to the list.
// Panics immediately if any CIDR string is invalid.
func AllowCIDR(cidrs ...string) Option {
	networks := parseCIDRs("AllowCIDR", cidrs)
	return func(o *options) {
		o.allowCIDRs = append(o.allowCIDRs, networks...)
	}
}

// DenyCIDR blocks connections to the given CIDR ranges. Multiple calls to
// DenyCIDR append to the list.
// Panics immediately if any CIDR string is invalid.
func DenyCIDR(cidrs ...string) Option {
	networks := parseCIDRs("DenyCIDR", cidrs)
	return func(o *options) {
		o.denyCIDRs = append(o.denyCIDRs, networks...)
	}
}

// parseCIDRs parses a list of CIDR strings, panicking on the first invalid one.
func parseCIDRs(caller string, cidrs []string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("ssrf: invalid CIDR %q passed to %s: %v", cidr, caller, err))
		}
		networks = append(networks, network)
	}
	return networks
}

// WithResolver sets a custom DNS resolver to use for hostname resolution.
// If not provided, net.DefaultResolver is used. This is useful in tests to
// inject a fake resolver and to verify DNS rebinding protection, and in
// production to use a specific DNS server.
func WithResolver(r *net.Resolver) Option {
	return func(o *options) {
		o.resolver = r
	}
}

// WithDialer sets the underlying net.Dialer used for TCP connections. This
// allows callers to configure timeouts, keep-alive intervals, local address
// bindings, and other low-level dial options. If not provided, a zero-value
// net.Dialer is used.
func WithDialer(d *net.Dialer) Option {
	return func(o *options) {
		o.dialer = d
	}
}

// Dialer is an SSRF-safe dialer. Its DialContext method resolves hostnames,
// validates the resolved IPs against the configured rules, and dials using
// raw IP addresses to prevent DNS rebinding.
//
// Create one with New and plug it into http.Transport:
//
//	d := ssrf.New(ssrf.NoPrivateRanges())
//	client := &http.Client{
//	    Transport: &http.Transport{DialContext: d.DialContext},
//	}
type Dialer struct {
	opts     *options
	resolver *net.Resolver
	dialer   *net.Dialer
}

// New creates a new Dialer with the given options.
// Panics if the options are contradictory (e.g. both IPv4Only and IPv6Only).
func New(opts ...Option) *Dialer {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	if o.ipv4Only && o.ipv6Only {
		panic("ssrf: IPv4Only and IPv6Only are mutually exclusive")
	}

	resolver := o.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	dialer := o.dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	return &Dialer{
		opts:     o,
		resolver: resolver,
		dialer:   dialer,
	}
}

// CheckIP validates a single IP address against the dialer's configured rules.
// It returns nil if the IP is allowed, or an *Error explaining the denial.
// IPv4-mapped IPv6 addresses (e.g. ::ffff:192.168.1.1) are normalised to
// their 4-byte IPv4 form so that IPv4 private-range rules apply correctly.
func (d *Dialer) CheckIP(ip net.IP) error {
	return checkIP(ip, d.opts)
}

// DialContext resolves the hostname in addr to IP addresses, validates each
// resolved IP against the configured rules, and dials the first allowed IP
// using a raw IP address (preventing DNS rebinding).
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split host port: %w", err)
	}

	// Resolve the host to IP addresses. This is the only DNS lookup that
	// occurs; the validated IP is used directly in the dial below.
	addrs, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}

	if len(addrs) == 0 {
		return nil, &Error{Reason: "no addresses found for host " + host}
	}

	// Find the first IP that passes all checks and attempt to dial it.
	var lastErr error
	for _, ipAddr := range addrs {
		ip := ipAddr.IP

		if err := checkIP(ip, d.opts); err != nil {
			lastErr = err
			continue
		}

		// Dial with the raw IP so we bypass any further DNS resolution and
		// prevent DNS rebinding attacks.
		dialAddr := net.JoinHostPort(ip.String(), port)
		conn, err := d.dialer.DialContext(ctx, network, dialAddr)
		if err != nil {
			lastErr = err
			continue
		}
		return conn, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &Error{Reason: fmt.Sprintf("all resolved addresses for %s were denied", host)}
}

// DialContext returns a DialContext function suitable for use with
// http.Transport.DialContext. It is a convenience wrapper around New; see
// Dialer for the full API.
//
// Deprecated: Use New to create a Dialer and pass d.DialContext to
// http.Transport instead.
func DialContext(opts ...Option) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return New(opts...).DialContext
}

// checkIP validates a single IP address against the configured options.
// It returns nil if the IP is allowed, or an *Error explaining the denial.
func checkIP(ip net.IP, o *options) error {
	// Normalise IPv4-in-IPv6 (e.g. ::ffff:192.168.1.1) → plain IPv4, so that
	// IPv4 range checks fire and the address is not misidentified as IPv6.
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	isIPv4 := len(ip) == net.IPv4len

	if o.ipv4Only && !isIPv4 {
		return &Error{Reason: fmt.Sprintf("IPv6 address %s is not allowed (IPv4 only)", ip)}
	}

	if o.ipv6Only && isIPv4 {
		return &Error{Reason: fmt.Sprintf("IPv4 address %s is not allowed (IPv6 only)", ip)}
	}

	if o.noPrivate {
		for _, r := range privateRanges {
			if r.Contains(ip) {
				return &Error{Reason: fmt.Sprintf("address %s is in a private or reserved range (%s)", ip, r)}
			}
		}
	}

	for _, r := range o.denyCIDRs {
		if r.Contains(ip) {
			return &Error{Reason: fmt.Sprintf("address %s is in a denied range (%s)", ip, r)}
		}
	}

	if len(o.allowCIDRs) > 0 {
		allowed := false
		for _, r := range o.allowCIDRs {
			if r.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			return &Error{Reason: fmt.Sprintf("address %s is not in any allowed range", ip)}
		}
	}

	return nil
}

// DialContext returns a DialContext function suitable for use with
// http.Transport.DialContext. The returned function resolves hostnames to IP
// addresses exactly once per call using LookupIPAddr, validates each resolved
// IP against all configured rules, and then dials using the validated raw IP
// address. Dialing with a raw IP (rather than the original hostname) ensures
// that no second DNS resolution occurs during the TCP connect, which prevents
// DNS rebinding attacks.
func DialContext(opts ...Option) func(ctx context.Context, network, addr string) (net.Conn, error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	resolver := o.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	var dialer net.Dialer

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("split host port: %w", err)
		}

		// Resolve the host to IP addresses. This is the only DNS lookup that
		// occurs; the validated IP is used directly in the dial below.
		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", host, err)
		}

		if len(addrs) == 0 {
			return nil, &Error{Reason: "no addresses found for host " + host}
		}

		// Find the first IP that passes all checks and attempt to dial it.
		var lastErr error
		for _, ipAddr := range addrs {
			ip := ipAddr.IP

			if err := checkIP(ip, o); err != nil {
				lastErr = err
				continue
			}

			// Dial with the raw IP so we bypass any further DNS resolution and
			// prevent DNS rebinding attacks.
			dialAddr := net.JoinHostPort(ip.String(), port)
			conn, err := dialer.DialContext(ctx, network, dialAddr)
			if err != nil {
				lastErr = err
				continue
			}
			return conn, nil
		}

		if lastErr != nil {
			return nil, lastErr
		}
		return nil, &Error{Reason: fmt.Sprintf("all resolved addresses for %s were denied", host)}
	}
}
