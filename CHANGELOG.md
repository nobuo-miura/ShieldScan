# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The published repository could not be built at all.** `backend/.gitignore` had an unanchored `server` pattern, which matched the `backend/cmd/server/` directory and excluded the entire entry point from version control. Anyone cloning the repository hit a failure on both `go run ./cmd/server` and `docker compose up --build`. The pattern is now anchored to `/server`.
- `parseURL` returned a `nil` error alongside an empty URL when the input had no host, letting an empty target reach the scanners.

### Security

- **SSRF protection rewritten.** The previous check resolved DNS once before the request and was bypassable by DNS rebinding, and redirects were followed without re-validation — a public host could simply redirect to `169.254.169.254`. The new `internal/safehttp` package validates the actual resolved IP in a `net.Dialer.Control` hook immediately before every TCP connection, so redirects and rebinding are both covered. Blocked ranges now also include CGNAT, IPv4-mapped IPv6, and other special-use networks.
- `ScanCORS` followed redirects with no limit at all; all scanners now share the same capped, re-validated client.
- Non-`http`/`https` redirect targets (`file://`, `gopher://`) are rejected.
- Environment proxies are ignored, since routing through a proxy would defeat the connect-time IP check.
- **Rate limiting no longer trusts `X-Forwarded-For` by default.** Spoofing that header previously bypassed the limiter entirely. Set `SHIELDSCAN_TRUST_PROXY=true` only when running behind a reverse proxy that overwrites it.
- **Rate limiting under Docker Compose was shared by all users.** nginx set only `X-Real-IP`, which the backend never reads, so every request was attributed to the nginx container's IP and all users competed for a single 30 req/min bucket — one user could lock out everyone. nginx now overwrites `X-Forwarded-For` with `$remote_addr` (not `$proxy_add_x_forwarded_for`, which appends and leaves the client-supplied value first), and the backend is configured to trust it.
- **The backend port is no longer published to the host under Docker Compose.** It uses `expose` instead of `ports`, so nginx is the only route in. Publishing it while trusting `X-Forwarded-For` would have let anyone bypass the proxy and spoof the header at will.
- **NAT64 local-use prefix `64:ff9b:1::/48` (RFC 8215) was not blocked.** It is a separate range from the well-known `64:ff9b::/96` and is not covered by any `net.IP` classification method, so on a NAT64-capable host it could translate to internal IPv4 addresses.
- The rate limiter's IP map grew without bound; expired entries are now swept periodically.
- The HTTP server now sets read/write/idle timeouts, closing a Slowloris exposure.
- The backend container runs as a non-root user.

### Added

- GitHub Actions CI: gofmt, `go vet`, `go test -race` with coverage, `golangci-lint`, ESLint, frontend build, and a Docker Compose build plus smoke test that verifies a clean clone actually runs.
- Dependabot for Go modules, npm, GitHub Actions, and Docker base images.
- Tests for `internal/safehttp`, `internal/handlers`, and `internal/models`, covering SSRF blocking, rate limiting, and history behavior.
- `SECURITY.md`, `CONTRIBUTING.md`, issue and pull request templates.
- `golangci-lint` configuration.
- ESLint configuration and `npm run lint`.
- `.dockerignore` for both services.
- `SHIELDSCAN_ALLOW_PRIVATE` to permit scanning private addresses during local development.
- `PORT` environment variable for the backend listen port, validated at startup.

### Changed

- Scan functions (`Analyze`, `ScanCORS`, `AuditCookies`, `CheckSSL`) now take a `context.Context`, so a client disconnect cancels the outbound scan.
- Frontend bundle is split into separate `recharts` and `react` chunks, improving cache reuse and clearing the 500 kB chunk warning.
- `package.json` renamed from `security-header-analyzer` to `shieldscan-frontend`, with `package-lock.json` regenerated to match.
- Base images pinned: `alpine:3.24`, `nginx:1.30.4-alpine` (the stable line — 1.31 is mainline), `node:24-alpine`.
- All npm dependencies updated; a high-severity `postcss` advisory is resolved.

### Removed

- Dead code found by ESLint: an unused `useRef` import, an unused `severityConfig` map, and an unused `worstSeverity` computation.

## [0.1.0]

Initial release: security header scoring, CORS scan, JWT analyzer, SSL/TLS check, cookie audit, scan history, and Docker Compose setup.
