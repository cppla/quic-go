# AutoCAR-maintained QUIC compatibility fork

This repository retains the upstream history, copyright and MIT license.
It is not an official quic-go release and is not endorsed by upstream.
The maintained branch is `main`; imported branches and tags are historical
references, not automatically selected updates.

## Source baseline and module identity

The exact starting point is
`HyNetworks/quic-go@a10df75c260cee8161f3261d63a37bd125a6bb2a`,
branch `v0.63.0-mod-rename`, published as
`github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c`.
That lineage includes official quic-go `v0.63.0`. It is not the older
`master` branch inherited when creating the fork.

The module declaration and imports remain `github.com/apernet/quic-go`.
Consumers must select a reviewed, published `github.com/cppla/quic-go`
commit with an exact remote replacement and verified checksum; never import
both paths or use a local replacement in a release.
AutoCAR's native transport continues to use official `github.com/quic-go/quic-go`.

This fork also requires the reviewed `github.com/cppla/utls` compatibility
patches, selected under the original `github.com/refraction-networking/utls`
module identity. Go ignores dependency-module replacements, so consumers
must carry **both** replacements in their own root module. This repository's
`go.mod` and nested integration-test modules pin the uTLS replacement for
standalone validation. Builds require Go 1.27.2 or a reviewed successor.

## Local patch queue

- Add opt-in `Config.ChromeParrotSessionCache`, a caller-owned uTLS-native
  session cache. A nil cache or `TLSConfig.SessionTicketsDisabled` retains
  full handshakes. No standard-library session state is converted or shared.
- Handle native session-store/resume events inside the TLS adapter, retain
  the opaque native state, clear its early-data permission before advancing
  the handshake, and propagate failures through QUIC error events.
- Add a real PSK extension at the end of the custom ClientHello only when a
  valid session is available. The empty-cache cold profile is preserved.
- Reject unexpected early secrets/data and unsupported real-ECH plus custom
  resumption. Translate native TLS alerts without losing the original error.
- Preserve the CRYPTO stream offset after the first ClientHello sends its tail
  before its middle, so a HelloRetryRequest's second ClientHello cannot overlap
  old bytes. Keep the in-flight tail immutable when a later flight is queued.
  This repairs stream bookkeeping without changing the cold packet layout.
- Keep upstream certificate verification and callback restrictions; do not
  weaken trust roots, hostname verification or TLS version requirements.
- Synchronize active send-connection replacement during client path migration
  with exported address accessors, remote-address updates and ConnectionState.
  This repairs unsafe publication of the new path without caching stale
  addresses, disabling migration or changing handshake profiles. Regression
  tests cover gated publication and concurrent metadata access on real paths.

The native cache is the fork's explicit opt-in; the incompatible standard
`tls.Config.ClientSessionCache` is not translated. Callers should allocate a
bounded cache per configured client/security context and never reuse one across
different verification policies. Concurrent use requires a concurrency-safe
cache, such as `utls.NewLRUClientSessionCache`. A cloned QUIC config shares its
cache intentionally. Servers and non-Chrome connections ignore this field.
Applications must still authenticate a new physical connection; TLS resumption
does not authorize replaying application credentials or using QUIC 0-RTT.

The existing dynamic `GetClientCertificate` adapter converts public request
fields but cannot preserve the standard library's unexported callback context.
It is not a promise of full standard-library callback equivalence. Applications
that need that callback context should use the non-Chrome TLS path.

This feature establishes functional TLS resumption, not browser equivalence,
passive indistinguishability, or a current-browser fingerprint. Consumers must
explicitly version a changed warm handshake instead of silently reinterpreting
an existing fixed profile.

## Maintenance and verification

1. Review upstream quic-go, this source lineage, uTLS and Go security changes.
   Preserve history and maintain the smallest patch queue. Remove a patch only
   after verifying an upstream equivalent with its regression tests.
2. Run `go mod verify`, `go mod tidy -diff`, `go build ./...`,
   the complete unit/HTTP3 suites, targeted Chrome cold/resumed/HRR/0-RTT and
   error/cancellation regressions, and race tests with an explicitly installed
   supported compiler. Run nested-module and consumer integration tests too.
3. Require the reviewed PR's Linux/macOS/Windows and integration CI, then check
   the final merged commit and consumer's resolved version/checksum. Consumers
   retain their own TCP/UDP reauthentication and lifecycle gates.
4. Query advisories for official `github.com/quic-go/quic-go@v0.63.0`
   and the original uTLS baseline separately from a scan of this fork. A
   replacement path can hide upstream advisories from the ordinary scanner.
   Review affected source, reachability and fixes against the exact fork
   revision; a module-level query is not a reachability scan or proof of safety.

Core upstream unit, integration, lint and cross-compilation workflows are
retained, with Go 1.27.2 as the supported minimum and actual Linux race testing.
The linter is pinned to v2.14.0 for Go 1.27 export-data compatibility. Narrow
inherited lint repairs are formatting, unused private declarations, explicit
unknown-parameter fallthrough and documented legacy compatibility fields;
they do not change the transport policy.
The STREAM allocation regression still parses and validates frames under race,
but its zero-allocation assertion runs only without race instrumentation:
Go's race runtime intentionally drops `sync.Pool` entries at random. The ACK
allocation check and all functional assertions remain enabled in both builds.
The inherited canceled-accept integration test uses fixed live/canceled groups,
an application-stream send gate and bounded worker joins instead of a random
cancellation-count threshold. It verifies complete payloads and the requested
QUIC version on the real connection; no runtime behavior is changed.
Go 1.27's syntax-only `embedlit` modernization is excluded from `go fix`
to preserve the inherited source layout; all other fix checks remain enabled
apart from the upstream performance-motivated `slicesbackward` exclusion.
Upstream-owned publication, Codecov uploads, hosted benchmark runners and
scheduled fuzz infrastructure are guarded to the upstream repository; this
fork does not inherit their credentials or publish to their accounts.
Fork-specific advisory checks run on changes, not as a promised monitoring
service. Existing `SECURITY.md` remains upstream reporting guidance; for
fork-specific vulnerabilities use
[AutoCAR private reporting](https://github.com/cppla/autocar/security/advisories/new).
