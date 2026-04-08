# ssrf

Go package that protects against **Server-Side Request Forgery (SSRF)** by
providing a drop-in `DialContext` for `http.Transport`.

---

## Why you need this

Many applications let users supply URLs — webhook targets, avatar image URLs,
link previews, import-from-URL features, API proxy endpoints, and so on. When
the HTTP request is made server-side, the server's internal network becomes
reachable:

```
User supplies → https://192.168.1.1/admin
                https://169.254.169.254/latest/meta-data  ← AWS metadata
                http://localhost:6379                      ← Redis
                http://10.0.0.1:8080/internal-api
```

None of those URLs look dangerous to a URL validator, but every one of them
hits infrastructure that the public internet should never reach.

**What makes SSRF hard to prevent at the URL level:**

- Hostnames hide the real destination (`internal.corp` → `10.0.0.1`)
- Unicode / encoding tricks slip past regex-based blocklists
- Redirects can bounce an apparently-safe first request to a private address
- **DNS rebinding**: the hostname resolves to a public IP during validation,
  then to a private IP at connection time (after a TTL-0 DNS change)

This package solves the problem at the network layer, where it cannot be
bypassed.

---

## How it works

`ssrf.DialContext` wraps the standard TCP dialer with these steps for every
outgoing connection:

1. **Resolve** the hostname to IP addresses using `LookupIPAddr` (one lookup
   per dial, never more).
2. **Validate** each resolved IP against the configured rules.
3. **Dial** using the raw validated IP address — never the original hostname.

Dialing with a raw IP means the operating system never performs a second DNS
lookup during the TCP connect, which eliminates DNS rebinding attacks.

---

## Installation

```
go get github.com/chrj/ssrf
```

---

## Quick start

```go
import "github.com/chrj/ssrf"

transport := &http.Transport{
    DialContext: ssrf.DialContext(
        ssrf.NoPrivateRanges(), // block loopback, RFC-1918, link-local, …
    ),
}
client := &http.Client{Transport: transport}
```

Any connection attempt to a private or reserved address is rejected before the
TCP handshake with an `*ssrf.Error`.

---

## API reference

### `ssrf.DialContext(opts ...ssrf.Option)`

Returns a `func(ctx context.Context, network, addr string) (net.Conn, error)`
that is directly assignable to `http.Transport.DialContext`. Options are
evaluated in the order listed below.

---

### Options

#### `ssrf.NoPrivateRanges()`

Blocks connections to all non-publicly-routable IP ranges:

| Range | Description |
|---|---|
| `127.0.0.0/8` | IPv4 loopback |
| `10.0.0.0/8` | RFC 1918 private |
| `172.16.0.0/12` | RFC 1918 private |
| `192.168.0.0/16` | RFC 1918 private |
| `169.254.0.0/16` | IPv4 link-local |
| `0.0.0.0/8` | "This" network |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | Documentation (TEST-NET) |
| `198.18.0.0/15` | Benchmarking |
| `255.255.255.255/32` | Broadcast |
| `::1/128` | IPv6 loopback |
| `fe80::/10` | IPv6 link-local |
| `fc00::/7` | IPv6 unique local (ULA) |
| `2001:db8::/32` | IPv6 documentation |

IPv4-mapped IPv6 addresses (e.g. `::ffff:192.168.1.1`) are automatically
normalised to their IPv4 form before checking, so they are covered by the
IPv4 rows above.

This is the option you want for any application that fetches user-supplied
URLs and must not reach internal infrastructure.

---

#### `ssrf.DenyCIDR(cidrs ...string)`

Blocks connections to one or more specific CIDR ranges. Multiple CIDRs can be
passed in a single call or across multiple calls — they are additive.

```go
ssrf.DialContext(
    ssrf.DenyCIDR("10.0.0.0/8"),
    ssrf.DenyCIDR("192.168.0.0/16", "172.16.0.0/12"),
)
```

`DenyCIDR` is evaluated **before** `AllowCIDR`, so a blocked range cannot be
re-opened by an allow rule.

Panics at startup with an invalid CIDR string.

---

#### `ssrf.AllowCIDR(cidrs ...string)`

Restricts connections to a set of permitted CIDR ranges. Once any allow range
is configured, an IP must match at least one of them or the connection is
denied.

```go
// Only allow connections within your own CDN or partner ranges.
ssrf.DialContext(
    ssrf.AllowCIDR("203.0.113.0/24", "198.51.100.0/24"),
)
```

Useful when you know exactly which external IPs your application should reach
and want to enforce that as an allowlist.

Panics at startup with an invalid CIDR string.

---

#### `ssrf.IPv4Only()`

Rejects any resolved IPv6 address. Useful when your infrastructure does not
use IPv6 and you want to prevent unexpected outbound IPv6 connections.

```go
ssrf.DialContext(ssrf.IPv4Only(), ssrf.NoPrivateRanges())
```

---

#### `ssrf.IPv6Only()`

Rejects any resolved IPv4 address.

---

#### `ssrf.WithResolver(r *net.Resolver)`

Substitutes a custom `*net.Resolver` for DNS lookups. When not provided
`net.DefaultResolver` is used.

**Production use — point at a specific DNS server:**

```go
resolver := &net.Resolver{
    PreferGo: true,
    Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
        return (&net.Dialer{}).DialContext(ctx, "udp", "10.0.0.53:53")
    },
}

transport := &http.Transport{
    DialContext: ssrf.DialContext(
        ssrf.NoPrivateRanges(),
        ssrf.WithResolver(resolver),
    ),
}
```

**Testing — inject a fake resolver:**

```go
func TestMyFetch(t *testing.T) {
    resolver := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
            return (&net.Dialer{}).DialContext(ctx, "udp", fakeDNSAddr)
        },
    }

    transport := &http.Transport{
        DialContext: ssrf.DialContext(
            ssrf.NoPrivateRanges(),
            ssrf.WithResolver(resolver),
        ),
    }
    // … exercise your code with the injected resolver
}
```

---

### Rule evaluation order

For each resolved IP the rules are tested in this order:

1. `IPv4Only` / `IPv6Only` — reject wrong address family
2. `NoPrivateRanges` — reject non-routable ranges
3. `DenyCIDR` — reject explicitly blocked ranges
4. `AllowCIDR` — reject anything not in the allowlist (if any allow rules exist)

If a hostname resolves to multiple IP addresses, each is tested in turn. The
first IP that passes all checks is used for the connection. If every IP is
rejected, the last rejection error is returned.

---

### `ssrf.Error`

Every rejection returns an `*ssrf.Error`. The `Reason` field describes exactly
why the connection was denied.

```go
_, err := client.Get(userSuppliedURL)

var ssrfErr *ssrf.Error
if errors.As(err, &ssrfErr) {
    log.Printf("request blocked: %s", ssrfErr.Reason)
}
```

Example `Reason` values:

```
address 127.0.0.1 is in a private or reserved range (127.0.0.0/8)
address 10.1.2.3 is in a denied range (10.0.0.0/8)
address 8.8.8.8 is not in any allowed range
IPv6 address 2001:db8::1 is not allowed (IPv4 only)
```

---

## Common recipes

### Webhook dispatcher

```go
transport := &http.Transport{
    DialContext: ssrf.DialContext(
        ssrf.NoPrivateRanges(), // never hit internal services
        ssrf.IPv4Only(),        // your infra is IPv4-only
    ),
}
client := &http.Client{
    Transport: transport,
    Timeout:   10 * time.Second,
}
```

### URL preview / link unfurler

```go
transport := &http.Transport{
    DialContext: ssrf.DialContext(
        ssrf.NoPrivateRanges(),
    ),
}
// Redirects are followed by http.Client automatically; each hop goes through
// the same DialContext, so a redirect to 192.168.x.x is also blocked.
client := &http.Client{Transport: transport}
```

### Strict allowlist (e.g. third-party API proxy)

```go
transport := &http.Transport{
    DialContext: ssrf.DialContext(
        // Block private ranges first, then restrict to the known partner range.
        ssrf.NoPrivateRanges(),
        ssrf.AllowCIDR("198.51.100.0/24"),
    ),
}
```

### Reusable safe client helper

```go
func SafeHTTPClient() *http.Client {
    return &http.Client{
        Transport: &http.Transport{
            DialContext: ssrf.DialContext(ssrf.NoPrivateRanges()),
        },
        Timeout: 15 * time.Second,
    }
}
```

---

## DNS rebinding

A DNS rebinding attack works in two phases:

1. The attacker's domain initially resolves to a public IP, which passes your
   SSRF validation.
2. The attacker immediately changes the DNS record (TTL 0) to a private IP.
   A naive implementation that re-resolves the hostname at connection time
   will now connect to the internal address — bypassing the earlier check.

This package is **not vulnerable** to DNS rebinding because the hostname is
resolved exactly once per dial call, and the TCP connection is then made
directly to the validated IP address. The operating system never performs a
second DNS lookup, so a DNS change between validation and connect has no
effect.

