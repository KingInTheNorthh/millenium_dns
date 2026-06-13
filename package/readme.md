**MILLENIUM DNS**

A dependency-free DNS server and resolver written in Rust. It parses and writes
DNS packets, resolves records iteratively from the root servers, caches answers
by TTL, hosts authoritative zones, speaks UDP **and** TCP, and can validate
DNSSEC signatures — all with no external crates.

```sh
# Recursively resolve a record
cargo run -- lookup example.com A
cargo run -- lookup example.com MX

# Run the caching/recursive server (UDP + TCP) on a port
cargo run -- serve 127.0.0.1:2053

# Serve authoritative zones, falling back to recursion for everything else
cargo run -- serve 127.0.0.1:2053 zones/example.com.zone

# Validate the DNSSEC chain for a name
cargo run -- verify nlnetlabs.nl A
```

Implemented record types: `A`, `AAAA`, `NS`, `CNAME`, `SOA`, `MX`, `TXT`, plus
the DNSSEC types `DS`, `DNSKEY`, `RRSIG`, `NSEC`, `NSEC3`, and the EDNS(0) `OPT`
pseudo-record.

Features
--------

- **Iterative recursive resolution** from the root servers, with caching.
- **EDNS(0)** — advertises a larger UDP payload and sets the DNSSEC OK (DO) bit.
- **TCP transport** — both serving over TCP and automatically retrying a query
  over TCP when a UDP reply is truncated (`TC=1`). Oversized UDP responses are
  truncated and flagged so clients fall back to TCP.
- **Concurrency** — the server handles UDP and TCP queries on per-request worker
  threads with a shared, mutex-guarded cache.
- **Authoritative zones** — loads a pragmatic subset of the RFC 1035 master-file
  format (`$ORIGIN`, `$TTL`, `@`, relative names, `;` comments, `( )`
  continuations) and answers with the AA bit set, including NODATA and NXDOMAIN.
- **DNSSEC validation** — dependency-free SHA-1/SHA-256, DNSKEY key tags, DS
  digest verification, and RSA/SHA-1 & RSA/SHA-256 signature verification (via a
  small big-integer modexp and canonical RRset reconstruction). `verify` walks
  the **full chain of trust top-down**: it confirms the root DNSKEY against the
  hard-coded IANA root anchor (KSK-2017), then validates each delegation's DS
  and DNSKEY down to the zone that signs the answer, and finally the answer
  itself. It reports each link and an overall status:
  - `SECURE` — chained all the way to the root anchor (e.g. `pir.org`).
  - `INSECURE` — a parent publishes no DS, so the subtree is unsigned.
  - `BOGUS` — a signature or DS that should verify didn't.
  - `INDETERMINATE` — an unsupported algorithm in the path. ECDSA, Ed25519 and
    RSA/SHA-512 are recognised but never falsely reported as secure, so most
    modern zones (e.g. anything under `.com`, which is now ECDSA) land here.

Code layout
-----------

- `src/buffer.rs` — bounded packet reads/writes (up to 65535 bytes for TCP),
  with DNS name compression.
- `src/protocol.rs` — headers, questions, records, packets, and EDNS helpers.
- `src/resolver.rs` — iterative resolution; UDP with retries, TCP on truncation.
- `src/cache.rs` — TTL-aware positive-response cache that rewrites TTLs on hits.
- `src/zone.rs` — authoritative zone parsing and lookup.
- `src/server.rs` — concurrent UDP + TCP server tying zones, cache, and resolver
  together.
- `src/dnssec.rs` — the cryptographic primitives (hashing, key tags, DS digests,
  RSA verification, canonical RRsets) and the hard-coded root trust anchor.
- `src/verify.rs` — walks the full DNSSEC chain of trust from the answer up to
  the root anchor.

                    --skywalker
