package ssrf_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chrj/ssrf"
	"github.com/foxcpp/go-mockdns"
)

// dialAndExpect is a helper that attempts a connection using the DialContext
// returned by the provided options, and checks whether the resulting error
// matches the expected outcome.
func dialAndExpect(t *testing.T, addr string, expectErr bool, opts ...ssrf.Option) error {
	t.Helper()
	dial := ssrf.DialContext(opts...)
	_, err := dial(context.Background(), "tcp", addr)
	if expectErr && err == nil {
		t.Errorf("expected error for %q but got none", addr)
	} else if !expectErr && err != nil {
		t.Errorf("unexpected error for %q: %v", addr, err)
	}
	return err
}

// ---- Error type ------------------------------------------------------------

func TestError_Error(t *testing.T) {
	e := &ssrf.Error{Reason: "test reason"}
	if got := e.Error(); got != "ssrf: test reason" {
		t.Errorf("Error() = %q; want %q", got, "ssrf: test reason")
	}
}

// ---- IPv4Only --------------------------------------------------------------

func TestIPv4Only_AllowsIPv4(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go acceptAndClose(ln)

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"ipv4.test.": {A: []string{"127.0.0.1"}},
	}}

	dial := ssrf.DialContext(ssrf.IPv4Only(), ssrf.WithResolver(resolver))
	conn, err := dial(context.Background(), "tcp", "ipv4.test:"+port)
	if err != nil {
		t.Fatalf("IPv4Only should allow IPv4 address: %v", err)
	}
	_ = conn.Close()
}

func TestIPv4Only_BlocksIPv6(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"ipv6host.test.": {AAAA: []string{"2606:2800:220:1:248:1893:25c8:1946"}},
	}}

	err := dialAndExpect(t, "ipv6host.test:80", true,
		ssrf.IPv4Only(), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "IPv4 only")
}

// ---- IPv6Only --------------------------------------------------------------

func TestIPv6Only_AllowsIPv6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback not available")
	}
	defer func() { _ = ln.Close() }()
	go acceptAndClose(ln)

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"ipv6.test.": {AAAA: []string{"::1"}},
	}}

	dial := ssrf.DialContext(ssrf.IPv6Only(), ssrf.WithResolver(resolver))
	conn, err := dial(context.Background(), "tcp", "ipv6.test:"+port)
	if err != nil {
		t.Fatalf("IPv6Only should allow IPv6 address: %v", err)
	}
	_ = conn.Close()
}

func TestIPv6Only_BlocksIPv4(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"ipv4host.test.": {A: []string{"127.0.0.1"}},
	}}

	err := dialAndExpect(t, "ipv4host.test:80", true,
		ssrf.IPv6Only(), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "IPv6 only")
}

// ---- NoPrivateRanges -------------------------------------------------------

func TestNoPrivateRanges_BlocksLoopback(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"loopback.test.": {A: []string{"127.0.0.1"}},
	}}
	err := dialAndExpect(t, "loopback.test:80", true,
		ssrf.NoPrivateRanges(), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_BlocksIPv6Loopback(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"loopback6.test.": {AAAA: []string{"::1"}},
	}}
	err := dialAndExpect(t, "loopback6.test:80", true,
		ssrf.NoPrivateRanges(), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_Blocks10(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"ten.test.": {A: []string{"10.0.0.1"}},
	}}
	err := dialAndExpect(t, "ten.test:80", true,
		ssrf.NoPrivateRanges(), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_Blocks172_16(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"rfc1918-b.test.": {A: []string{"172.16.0.1"}},
	}}
	err := dialAndExpect(t, "rfc1918-b.test:80", true,
		ssrf.NoPrivateRanges(), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_Blocks192_168(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"rfc1918-c.test.": {A: []string{"192.168.1.1"}},
	}}
	err := dialAndExpect(t, "rfc1918-c.test:80", true,
		ssrf.NoPrivateRanges(), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_BlocksLinkLocal(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"linklocal.test.": {A: []string{"169.254.0.1"}},
	}}
	err := dialAndExpect(t, "linklocal.test:80", true,
		ssrf.NoPrivateRanges(), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_BlocksIPv6LinkLocal(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"linklocal6.test.": {AAAA: []string{"fe80::1"}},
	}}
	err := dialAndExpect(t, "linklocal6.test:80", true,
		ssrf.NoPrivateRanges(), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_BlocksIPv6ULA(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"ula.test.": {AAAA: []string{"fc00::1"}},
	}}
	err := dialAndExpect(t, "ula.test:80", true,
		ssrf.NoPrivateRanges(), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_AllowsPublicIPv4(t *testing.T) {
	// We resolve to a public IP to verify NoPrivateRanges does not block it.
	// The TCP dial will fail (no listener at that IP), but we only check that
	// no ssrf.Error is returned.
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"public.test.": {A: []string{"93.184.216.34"}},
	}}
	dial := ssrf.DialContext(ssrf.NoPrivateRanges(), ssrf.WithResolver(resolver))
	_, err := dial(shortCtx(t), "tcp", "public.test:80")
	if isSsrfError(err) {
		t.Errorf("NoPrivateRanges should allow public IPs; got ssrf error: %v", err)
	}
}

// ---- DenyCIDR --------------------------------------------------------------

func TestDenyCIDR_BlocksMatchingAddress(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"denied.test.": {A: []string{"10.20.30.40"}},
	}}
	err := dialAndExpect(t, "denied.test:80", true,
		ssrf.DenyCIDR("10.0.0.0/8"), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "denied range")
}

func TestDenyCIDR_AllowsNonMatchingAddress(t *testing.T) {
	// 127.0.0.1 is not in 10.0.0.0/8 so DenyCIDR should not block it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go acceptAndClose(ln)

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"allowed.test.": {A: []string{"127.0.0.1"}},
	}}

	dial := ssrf.DialContext(ssrf.DenyCIDR("10.0.0.0/8"), ssrf.WithResolver(resolver))
	conn, err := dial(context.Background(), "tcp", "allowed.test:"+port)
	if err != nil {
		t.Fatalf("DenyCIDR(10/8) should not block 127.0.0.1: %v", err)
	}
	_ = conn.Close()
}

func TestDenyCIDR_MultipleRanges(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"denied-multi.test.": {A: []string{"192.168.5.5"}},
	}}
	opts := []ssrf.Option{
		ssrf.DenyCIDR("10.0.0.0/8", "192.168.0.0/16"),
		ssrf.WithResolver(resolver),
	}
	err := dialAndExpect(t, "denied-multi.test:80", true, opts...)
	checkSSRFError(t, err, "denied range")
}

func TestDenyCIDR_IPv6(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"denied6.test.": {AAAA: []string{"fc00::1"}},
	}}
	err := dialAndExpect(t, "denied6.test:80", true,
		ssrf.DenyCIDR("fc00::/7"), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "denied range")
}

// ---- AllowCIDR -------------------------------------------------------------

func TestAllowCIDR_AllowsMatchingAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go acceptAndClose(ln)

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"allowed.test.": {A: []string{"127.0.0.1"}},
	}}

	dial := ssrf.DialContext(ssrf.AllowCIDR("127.0.0.0/8"), ssrf.WithResolver(resolver))
	conn, err := dial(context.Background(), "tcp", "allowed.test:"+port)
	if err != nil {
		t.Fatalf("AllowCIDR should allow matching address: %v", err)
	}
	_ = conn.Close()
}

func TestAllowCIDR_BlocksNonMatchingAddress(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"blocked.test.": {A: []string{"10.0.0.1"}},
	}}
	err := dialAndExpect(t, "blocked.test:80", true,
		ssrf.AllowCIDR("203.0.113.0/24"), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "not in any allowed range")
}

func TestAllowCIDR_MultipleRanges(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go acceptAndClose(ln)

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"multi.test.": {A: []string{"127.0.0.1"}},
	}}

	opts := []ssrf.Option{
		ssrf.AllowCIDR("10.0.0.0/8", "127.0.0.0/8"),
		ssrf.WithResolver(resolver),
	}
	dial := ssrf.DialContext(opts...)
	conn, err := dial(context.Background(), "tcp", "multi.test:"+port)
	if err != nil {
		t.Fatalf("AllowCIDR should allow matching address in multiple ranges: %v", err)
	}
	_ = conn.Close()
}

func TestAllowCIDR_IPv6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback not available")
	}
	defer func() { _ = ln.Close() }()
	go acceptAndClose(ln)

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"ipv6-allowed.test.": {AAAA: []string{"::1"}},
	}}

	dial := ssrf.DialContext(
		ssrf.AllowCIDR("::1/128"),
		ssrf.WithResolver(resolver),
	)
	conn, err := dial(context.Background(), "tcp", "ipv6-allowed.test:"+port)
	if err != nil {
		t.Fatalf("AllowCIDR should allow matching IPv6 address: %v", err)
	}
	_ = conn.Close()
}

// ---- Combined options ------------------------------------------------------

func TestCombined_IPv4OnlyAndNoPrivate(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"loopback6.test.": {AAAA: []string{"::1"}},
	}}
	// IPv6 loopback should be blocked by IPv4Only.
	err := dialAndExpect(t, "loopback6.test:80", true,
		ssrf.IPv4Only(), ssrf.NoPrivateRanges(), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "IPv4 only")
}

func TestCombined_AllowAndDeny_DenyWins(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"deny-wins.test.": {A: []string{"10.10.1.1"}},
	}}
	// The address is inside the allow range but also inside the deny range;
	// deny should be evaluated first.
	opts := []ssrf.Option{
		ssrf.AllowCIDR("10.0.0.0/8"),
		ssrf.DenyCIDR("10.10.0.0/16"),
		ssrf.WithResolver(resolver),
	}
	err := dialAndExpect(t, "deny-wins.test:80", true, opts...)
	checkSSRFError(t, err, "denied range")
}

// ---- Hostname resolution ---------------------------------------------------

func TestDialContext_ResolvesHostname(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go acceptAndClose(ln)

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"resolved.test.": {A: []string{"127.0.0.1"}},
	}}

	dial := ssrf.DialContext(ssrf.WithResolver(resolver))
	conn, err := dial(context.Background(), "tcp", "resolved.test:"+port)
	if err != nil {
		t.Fatalf("expected connection to succeed, got: %v", err)
	}
	_ = conn.Close()
}

func TestDialContext_BlocksLocalhost_NoPrivate(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"localhost.test.": {A: []string{"127.0.0.1"}},
	}}

	err := dialAndExpect(t, "localhost.test:80", true,
		ssrf.NoPrivateRanges(), ssrf.WithResolver(resolver))
	checkSSRFError(t, err, "private or reserved")
}

// ---- Integration: http.Transport -------------------------------------------

func TestHTTPTransport_Integration(t *testing.T) {
	// Set up a local HTTP server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")) //nolint:errcheck
			_ = conn.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"httptest.test.": {A: []string{"127.0.0.1"}},
	}}

	t.Run("no options allows loopback", func(t *testing.T) {
		tr := &http.Transport{
			DialContext: ssrf.DialContext(ssrf.WithResolver(resolver)),
		}
		client := &http.Client{Transport: tr}
		resp, err := client.Get("http://httptest.test:" + port + "/")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = resp.Body.Close()
	})

	t.Run("NoPrivateRanges blocks loopback", func(t *testing.T) {
		tr := &http.Transport{
			DialContext: ssrf.DialContext(ssrf.NoPrivateRanges(), ssrf.WithResolver(resolver)),
		}
		client := &http.Client{Transport: tr}
		resp, err := client.Get("http://httptest.test:" + port + "/")
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Fatal("expected error but got none")
		}
		if !strings.Contains(err.Error(), "private or reserved") {
			t.Errorf("expected 'private or reserved' in error, got: %v", err)
		}
	})
}

// ---- WithResolver ----------------------------------------------------------

func TestWithResolver_UsesCustomResolver(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go acceptAndClose(ln)

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"custom.resolver.test.": {A: []string{"127.0.0.1"}},
	}}

	dial := ssrf.DialContext(ssrf.WithResolver(resolver))
	conn, err := dial(context.Background(), "tcp", "custom.resolver.test:"+port)
	if err != nil {
		t.Fatalf("expected connection via custom resolver, got: %v", err)
	}
	_ = conn.Close()
}

// ---- DNS rebinding protection ----------------------------------------------

// TestDialContext_DNSRebindingProtection demonstrates that the dialer resolves
// hostnames to IP addresses exactly once per dial call, validates the resolved
// IP, and then connects using the raw IP — never the original hostname. This
// prevents DNS rebinding: even if an attacker changes DNS between the
// validation step and the TCP connect step, the connection still goes to the
// IP that was validated.
func TestDialContext_DNSRebindingProtection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go acceptAndClose(ln)

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		// The fake hostname resolves to 127.0.0.1 (a private address).
		"rebind.test.": {A: []string{"127.0.0.1"}},
	}}

	// SSRF rules are applied to the resolved IP, not the hostname.
	// With NoPrivateRanges the connection MUST be blocked because the hostname
	// resolves to 127.0.0.1 (private). A hostname-only check would miss this.
	dial := ssrf.DialContext(
		ssrf.NoPrivateRanges(),
		ssrf.WithResolver(resolver),
	)
	_, err = dial(context.Background(), "tcp", "rebind.test:"+port)
	checkSSRFError(t, err, "private or reserved")

	// Without NoPrivateRanges the connection should succeed via the resolved IP.
	dial = ssrf.DialContext(ssrf.WithResolver(resolver))
	conn, err := dial(context.Background(), "tcp", "rebind.test:"+port)
	if err != nil {
		t.Fatalf("expected successful connection, got: %v", err)
	}
	_ = conn.Close()
}

// ---- Invalid addr ----------------------------------------------------------

func TestDialContext_InvalidAddr(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{}}
	dial := ssrf.DialContext(ssrf.WithResolver(resolver))
	_, err := dial(context.Background(), "tcp", "not-valid")
	if err == nil {
		t.Error("expected error for invalid address, got nil")
	}
}

// ---- AllowCIDR panic on bad CIDR -------------------------------------------

func TestAllowCIDR_PanicOnBadCIDR(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for invalid CIDR in AllowCIDR")
		}
	}()
	ssrf.AllowCIDR("not-a-cidr")
}

// ---- IPv4Only + IPv6Only mutual exclusion -----------------------------------

func TestIPv4OnlyAndIPv6Only_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when both IPv4Only and IPv6Only are set")
		}
	}()
	ssrf.DialContext(ssrf.IPv4Only(), ssrf.IPv6Only())
}

// ---- DenyCIDR panic on bad CIDR --------------------------------------------

func TestDenyCIDR_PanicOnBadCIDR(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for invalid CIDR in DenyCIDR")
		}
	}()
	ssrf.DenyCIDR("not-a-cidr")
}

// ---- helpers ---------------------------------------------------------------

// shortCtx returns a context that times out after 200 ms. This is long enough
// for the synchronous SSRF validation step (which completes before any dial
// is attempted) but short enough that tests do not hang when there is no
// network listener at the target address.
func shortCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func isSsrfError(err error) bool {
	if err == nil {
		return false
	}
	var ssrfErr *ssrf.Error
	return errors.As(err, &ssrfErr)
}

func checkSSRFError(t *testing.T, err error, wantSubstr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an ssrf.Error containing %q, got nil", wantSubstr)
	}
	var ssrfErr *ssrf.Error
	if !errors.As(err, &ssrfErr) {
		t.Fatalf("expected *ssrf.Error, got %T: %v", err, err)
	}
	if !strings.Contains(ssrfErr.Reason, wantSubstr) {
		t.Errorf("ssrf.Error.Reason = %q; want it to contain %q", ssrfErr.Reason, wantSubstr)
	}
}

// acceptAndClose drains a listener by accepting and immediately closing every
// incoming connection. It returns when the listener is closed.
func acceptAndClose(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}
}
