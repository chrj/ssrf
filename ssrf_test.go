package ssrf_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chrj/ssrf"
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
	// Use a local listener on 127.0.0.1 to verify that IPv4Only does not
	// block IPv4 addresses. (IPv4Only only rejects IPv6; it does not add any
	// private-range blocking on its own.)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go acceptAndClose(ln)

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	dial := ssrf.DialContext(ssrf.IPv4Only())
	conn, err := dial(context.Background(), "tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("IPv4Only should allow IPv4 address: %v", err)
	}
	_ = conn.Close()
}

func TestIPv4Only_BlocksIPv6(t *testing.T) {
	err := dialAndExpect(t, "[2606:2800:220:1:248:1893:25c8:1946]:80", true, ssrf.IPv4Only())
	checkSSRFError(t, err, "IPv4 only")
}

// ---- IPv6Only --------------------------------------------------------------

func TestIPv6Only_AllowsIPv6(t *testing.T) {
	// Use a raw IPv6 address so LookupIPAddr returns immediately.
	// The TCP connect will fail (no listener), but that must not be an
	// *ssrf.Error — only an SSRF rule violation is a test failure here.
	dial := ssrf.DialContext(ssrf.IPv6Only())
	_, err := dial(shortCtx(t), "tcp", "[2606:2800:220:1:248:1893:25c8:1946]:80")
	if isSsrfError(err) {
		t.Errorf("IPv6Only should allow IPv6; got ssrf error: %v", err)
	}
}

func TestIPv6Only_BlocksIPv4(t *testing.T) {
	err := dialAndExpect(t, "93.184.216.34:80", true, ssrf.IPv6Only())
	checkSSRFError(t, err, "IPv6 only")
}

// ---- NoPrivateRanges -------------------------------------------------------

func TestNoPrivateRanges_BlocksLoopback(t *testing.T) {
	err := dialAndExpect(t, "127.0.0.1:80", true, ssrf.NoPrivateRanges())
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_BlocksIPv6Loopback(t *testing.T) {
	err := dialAndExpect(t, "[::1]:80", true, ssrf.NoPrivateRanges())
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_Blocks10(t *testing.T) {
	err := dialAndExpect(t, "10.0.0.1:80", true, ssrf.NoPrivateRanges())
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_Blocks172_16(t *testing.T) {
	err := dialAndExpect(t, "172.16.0.1:80", true, ssrf.NoPrivateRanges())
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_Blocks192_168(t *testing.T) {
	err := dialAndExpect(t, "192.168.1.1:80", true, ssrf.NoPrivateRanges())
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_BlocksLinkLocal(t *testing.T) {
	err := dialAndExpect(t, "169.254.0.1:80", true, ssrf.NoPrivateRanges())
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_BlocksIPv6LinkLocal(t *testing.T) {
	err := dialAndExpect(t, "[fe80::1]:80", true, ssrf.NoPrivateRanges())
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_BlocksIPv6ULA(t *testing.T) {
	err := dialAndExpect(t, "[fc00::1]:80", true, ssrf.NoPrivateRanges())
	checkSSRFError(t, err, "private or reserved")
}

func TestNoPrivateRanges_AllowsPublicIPv4(t *testing.T) {
	// 93.184.216.34 is a well-known public address (example.com).
	// We only care that no ssrf.Error is returned; the TCP dial may fail
	// because this environment has no internet access.
	dial := ssrf.DialContext(ssrf.NoPrivateRanges())
	_, err := dial(shortCtx(t), "tcp", "93.184.216.34:80")
	if isSsrfError(err) {
		t.Errorf("NoPrivateRanges should allow public IPs; got ssrf error: %v", err)
	}
}

// ---- DenyCIDR --------------------------------------------------------------

func TestDenyCIDR_BlocksMatchingAddress(t *testing.T) {
	err := dialAndExpect(t, "10.20.30.40:80", true, ssrf.DenyCIDR("10.0.0.0/8"))
	checkSSRFError(t, err, "denied range")
}

func TestDenyCIDR_AllowsNonMatchingAddress(t *testing.T) {
	// 192.168.1.1 is not in 10.0.0.0/8 so DenyCIDR should not block it.
	// We only verify no ssrf.Error; the TCP dial may fail (no route).
	dial := ssrf.DialContext(ssrf.DenyCIDR("10.0.0.0/8"))
	_, err := dial(shortCtx(t), "tcp", "192.168.1.1:80")
	if isSsrfError(err) {
		t.Errorf("DenyCIDR(10/8) should not block 192.168.1.1; got ssrf error: %v", err)
	}
}

func TestDenyCIDR_MultipleRanges(t *testing.T) {
	opts := []ssrf.Option{ssrf.DenyCIDR("10.0.0.0/8", "192.168.0.0/16")}
	err := dialAndExpect(t, "192.168.5.5:80", true, opts...)
	checkSSRFError(t, err, "denied range")
}

func TestDenyCIDR_IPv6(t *testing.T) {
	err := dialAndExpect(t, "[fc00::1]:80", true, ssrf.DenyCIDR("fc00::/7"))
	checkSSRFError(t, err, "denied range")
}

// ---- AllowCIDR -------------------------------------------------------------

func TestAllowCIDR_AllowsMatchingAddress(t *testing.T) {
	// 203.0.113.5 is inside the allowed range. The TCP dial may fail
	// (no listener at that address), but no ssrf.Error should be returned.
	dial := ssrf.DialContext(ssrf.AllowCIDR("203.0.113.0/24"))
	_, err := dial(shortCtx(t), "tcp", "203.0.113.5:80")
	if isSsrfError(err) {
		t.Errorf("AllowCIDR should allow 203.0.113.5; got ssrf error: %v", err)
	}
}

func TestAllowCIDR_BlocksNonMatchingAddress(t *testing.T) {
	err := dialAndExpect(t, "10.0.0.1:80", true, ssrf.AllowCIDR("203.0.113.0/24"))
	checkSSRFError(t, err, "not in any allowed range")
}

func TestAllowCIDR_MultipleRanges(t *testing.T) {
	opts := []ssrf.Option{ssrf.AllowCIDR("10.0.0.0/8", "192.168.0.0/16")}
	dial := ssrf.DialContext(opts...)
	_, err := dial(shortCtx(t), "tcp", "192.168.5.5:80")
	if isSsrfError(err) {
		t.Errorf("AllowCIDR should allow 192.168.5.5; got ssrf error: %v", err)
	}
}

func TestAllowCIDR_IPv6(t *testing.T) {
	dial := ssrf.DialContext(ssrf.AllowCIDR("2001:db8::/32"))
	_, err := dial(shortCtx(t), "tcp", "[2001:db8::1]:80")
	if isSsrfError(err) {
		t.Errorf("AllowCIDR should allow 2001:db8::1; got ssrf error: %v", err)
	}
}

// ---- Combined options ------------------------------------------------------

func TestCombined_IPv4OnlyAndNoPrivate(t *testing.T) {
	// IPv6 loopback should be blocked by IPv4Only.
	err := dialAndExpect(t, "[::1]:80", true, ssrf.IPv4Only(), ssrf.NoPrivateRanges())
	checkSSRFError(t, err, "IPv4 only")
}

func TestCombined_AllowAndDeny_DenyWins(t *testing.T) {
	// The address is inside the allow range but also inside the deny range;
	// deny should be evaluated first.
	opts := []ssrf.Option{
		ssrf.AllowCIDR("10.0.0.0/8"),
		ssrf.DenyCIDR("10.10.0.0/16"),
	}
	err := dialAndExpect(t, "10.10.1.1:80", true, opts...)
	checkSSRFError(t, err, "denied range")
}

// ---- Hostname resolution ---------------------------------------------------

func TestDialContext_ResolvesHostname(t *testing.T) {
	// Use a local listener so we can verify an actual successful connection.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	addr := net.JoinHostPort("localhost", port)

	// Without options the dial should succeed (localhost resolves to 127.0.0.1).
	dial := ssrf.DialContext()
	conn, err := dial(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("expected connection to succeed, got: %v", err)
	}
	_ = conn.Close()
}

func TestDialContext_BlocksLocalhost_NoPrivate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	addr := net.JoinHostPort("localhost", port)

	err = dialAndExpect(t, addr, true, ssrf.NoPrivateRanges())
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

	t.Run("no options allows loopback", func(t *testing.T) {
		tr := &http.Transport{
			DialContext: ssrf.DialContext(),
		}
		client := &http.Client{Transport: tr}
		resp, err := client.Get("http://127.0.0.1:" + port + "/")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = resp.Body.Close()
	})

	t.Run("NoPrivateRanges blocks loopback", func(t *testing.T) {
		tr := &http.Transport{
			DialContext: ssrf.DialContext(ssrf.NoPrivateRanges()),
		}
		client := &http.Client{Transport: tr}
		resp, err := client.Get("http://127.0.0.1:" + port + "/")
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
	// Build a fake DNS server that maps "custom.resolver.test" → 127.0.0.1.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go acceptAndClose(ln)

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	dns := newFakeDNSServer(t, map[string]net.IP{
		"custom.resolver.test": net.ParseIP("127.0.0.1"),
	})

	dial := ssrf.DialContext(ssrf.WithResolver(dns.resolver(t)))
	conn, err := dial(context.Background(), "tcp", "custom.resolver.test:"+port)
	if err != nil {
		t.Fatalf("expected connection via custom resolver, got: %v", err)
	}
	_ = conn.Close()

	if dns.queryCount() == 0 {
		t.Error("expected custom resolver to be called at least once")
	}
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

	dns := newFakeDNSServer(t, map[string]net.IP{
		// The fake hostname resolves to 127.0.0.1 (a private address).
		"rebind.test": net.ParseIP("127.0.0.1"),
	})

	// Part 1 — SSRF rules are applied to the resolved IP, not the hostname.
	// With NoPrivateRanges the connection MUST be blocked because the hostname
	// resolves to 127.0.0.1 (private). A hostname-only check would miss this.
	dial := ssrf.DialContext(
		ssrf.NoPrivateRanges(),
		ssrf.WithResolver(dns.resolver(t)),
	)
	_, err = dial(context.Background(), "tcp", "rebind.test:"+port)
	checkSSRFError(t, err, "private or reserved")

	// Part 2 — exactly one A-record DNS lookup occurs per dial call.
	// Go's resolver also sends a AAAA query, so total queries per dial is
	// typically 2; counting only A queries gives a stable "exactly 1" check.
	// If the implementation re-resolved the hostname during the actual TCP
	// connect, we would see two A queries for a single dial call.
	before := dns.aQueryCount()
	dial = ssrf.DialContext(ssrf.WithResolver(dns.resolver(t)))
	conn, err := dial(context.Background(), "tcp", "rebind.test:"+port)
	if err != nil {
		t.Fatalf("expected successful connection, got: %v", err)
	}
	_ = conn.Close()

	if got := dns.aQueryCount() - before; got != 1 {
		t.Errorf("got %d A-record DNS queries per dial; want 1 (extra queries indicate re-resolution during connect)", got)
	}
}

// ---- Invalid addr ----------------------------------------------------------

func TestDialContext_InvalidAddr(t *testing.T) {
	dial := ssrf.DialContext()
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

// ---- fakeDNSServer ---------------------------------------------------------
// fakeDNSServer is a minimal UDP DNS server that serves static A records.
// It is used in tests to verify DNS rebinding protection without relying on
// the system resolver.

type fakeDNSServer struct {
	mu       sync.Mutex
	queries  int               // total queries
	aQueries int               // type-A queries only
	records  map[string]net.IP // lowercase hostname → IPv4 address
	conn     net.PacketConn
}

// newFakeDNSServer starts a fake DNS server on a random localhost UDP port and
// registers a cleanup function to stop it when the test ends.
func newFakeDNSServer(t *testing.T, records map[string]net.IP) *fakeDNSServer {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &fakeDNSServer{records: records, conn: conn}
	t.Cleanup(func() { _ = conn.Close() })
	go srv.serve()
	return srv
}

// resolver returns a *net.Resolver that sends all DNS queries to the fake server.
func (s *fakeDNSServer) resolver(t *testing.T) *net.Resolver {
	t.Helper()
	addr := s.conn.LocalAddr().String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", addr)
		},
	}
}

// queryCount returns the total number of DNS queries received so far.
func (s *fakeDNSServer) queryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries
}

// aQueryCount returns the number of type-A DNS queries received so far.
// Go's resolver sends both A and AAAA queries per LookupIPAddr call; counting
// only A queries gives a stable "exactly 1 per dial" assertion.
func (s *fakeDNSServer) aQueryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.aQueries
}

func (s *fakeDNSServer) serve() {
	buf := make([]byte, 512)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		if resp := s.respond(query); resp != nil {
			s.conn.WriteTo(resp, from) //nolint:errcheck
		}
	}
}

// respond builds a minimal DNS wire-format response for a single A (or AAAA)
// question. Non-A queries for known names receive a NOERROR/no-answer reply.
// Queries for unknown names receive NXDOMAIN.
func (s *fakeDNSServer) respond(msg []byte) []byte {
	// Minimum: 12-byte header + at least one byte of question.
	if len(msg) < 13 {
		return nil
	}

	id := msg[0:2]
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	if qdcount != 1 {
		return nil
	}

	// Parse the question name starting at offset 12.
	name, nameEnd, ok := dnsParseQName(msg, 12)
	if !ok || nameEnd+4 > len(msg) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(msg[nameEnd : nameEnd+2])

	s.mu.Lock()
	s.queries++
	if qtype == 1 { // type A
		s.aQueries++
	}
	ip, found := s.records[strings.ToLower(name)]
	s.mu.Unlock()

	// Question section length (name bytes + 4 bytes type/class).
	qsecLen := nameEnd + 4 - 12

	if !found {
		// NXDOMAIN
		resp := make([]byte, 12+qsecLen)
		copy(resp[0:2], id)
		resp[2] = 0x81                           // QR=1 RD=1
		resp[3] = 0x83                           // RA=1 RCODE=NXDOMAIN(3)
		binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT
		copy(resp[12:], msg[12:12+qsecLen])
		return resp
	}

	const typeA = 1
	if qtype != typeA {
		// Known domain but wrong record type → NOERROR, 0 answers.
		resp := make([]byte, 12+qsecLen)
		copy(resp[0:2], id)
		resp[2] = 0x81                           // QR=1 RD=1
		resp[3] = 0x80                           // RA=1 RCODE=NOERROR(0)
		binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT
		copy(resp[12:], msg[12:12+qsecLen])
		return resp
	}

	// A record response.
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil
	}
	resp := make([]byte, 12+qsecLen+16)
	copy(resp[0:2], id)
	resp[2] = 0x81                           // QR=1 RD=1
	resp[3] = 0x80                           // RA=1 RCODE=NOERROR(0)
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT=1
	binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT=1
	copy(resp[12:], msg[12:12+qsecLen])      // question section
	off := 12 + qsecLen
	resp[off+0] = 0xC0
	resp[off+1] = 0x0C                           // name pointer → offset 12
	binary.BigEndian.PutUint16(resp[off+2:], 1)  // type A
	binary.BigEndian.PutUint16(resp[off+4:], 1)  // class IN
	binary.BigEndian.PutUint32(resp[off+6:], 0)  // TTL = 0 (no caching)
	binary.BigEndian.PutUint16(resp[off+10:], 4) // rdlength = 4
	copy(resp[off+12:], ipv4)
	return resp
}

// dnsParseQName parses a DNS label-encoded name from msg starting at offset.
// It returns the dot-separated name (without trailing dot), the offset of the
// first byte after the terminating zero label, and whether parsing succeeded.
func dnsParseQName(msg []byte, offset int) (string, int, bool) {
	var labels []string
	for {
		if offset >= len(msg) {
			return "", 0, false
		}
		l := int(msg[offset])
		offset++
		if l == 0 {
			return strings.Join(labels, "."), offset, true
		}
		if offset+l > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[offset:offset+l]))
		offset += l
	}
}
