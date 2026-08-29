# Third-Party Notices

The `zhulong-doh-proxy` executable includes third-party Go modules in its
statically linked dependency graph. Versions below are pinned by `go.mod` and
`go.sum`.

## Direct dependencies

- `github.com/AdguardTeam/dnsproxy` tag `v0.84.0`, upstream commit
  `73f4766b8141214aba3b2236163f91e400fa6a22`. Licensed under Apache-2.0. The
  exact license text from the pinned source is in
  `third_party/AdguardTeam-dnsproxy-LICENSE.txt`.
- `github.com/miekg/dns` tag `v1.1.72`, upstream commit
  `cb21f4d26733ca42749cd87a0fe44094ad833a21`. See that module's source for its
  BSD-3-Clause license text.

## Transitive modules

- `github.com/AdguardTeam/dnscrypt` `v0.0.2`
- `github.com/AdguardTeam/golibs` `v0.35.13`
- `github.com/ameshkov/dnsstamps` `v1.0.3`
- `github.com/bluele/gcache` `v0.0.2`
- `github.com/quic-go/qpack` `v0.6.0`
- `github.com/quic-go/quic-go` `v0.60.0`
- `github.com/robfig/cron/v3` `v3.0.1`
- `golang.org/x/crypto` `v0.54.0`
- `golang.org/x/exp` `v0.0.0-20260611194520-c48552f49976`
- `golang.org/x/net` `v0.57.0`
- `golang.org/x/sys` `v0.47.0`
- `golang.org/x/text` `v0.40.0`
- `gonum.org/v1/gonum` `v0.17.0`

This notice is informational and does not replace the license terms shipped by
the corresponding upstream projects.
