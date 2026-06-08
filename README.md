# ShieldScan

A web-based security scanning tool that analyzes HTTP response headers, scores them, and assigns a grade.
In addition to security header evaluation, it provides diagnostics for CORS, JWT, SSL/TLS, and Cookies.

![ShieldScan screenshot](images/ss.jpg)

---

## Features

| Tab | Description |
|---|---|
| **Security Headers** | Scores 8 security headers and assigns a grade from A+ to F |
| **CORS Scan** | Detects CORS misconfigurations (origin reflection, null origin, pre/post-domain match) |
| **JWT Analyzer** | Static analysis of JWT tokens (alg:none, kid injection, expiration, sensitive data in payload) |
| **SSL/TLS Check** | Inspects TLS version, cipher suite, certificate expiry, and hostname match |
| **Cookie Audit** | Audits Secure, HttpOnly, and SameSite flag configurations |

Additional features:
- Radar chart visualization of per-header scores
- Improvement advice for each detected issue
- Scan history (latest 50 entries, newest first)

## Tech Stack

- **Backend**: Go
- **Frontend**: React + Vite + Tailwind CSS + Recharts
- **Infrastructure**: Docker / Docker Compose

## Quick Start

### Docker Compose (recommended)

```bash
git clone https://github.com/nobuo-miura/ShieldScan
cd ShieldScan
docker compose up --build
```

Open `http://localhost:3000` in your browser.

### Local Development

```bash
# Backend (port 8080)
cd backend
go run ./cmd/server

# Frontend (separate terminal, port 5173)
cd frontend
npm install
npm run dev
```

Frontend `/api` requests are forwarded to the backend via Vite's development proxy.

## API

### POST /api/analyze — Security Header Scan

```json
// Request
{ "url": "https://example.com" }

// Response
{
  "url": "https://example.com",
  "final_url": "https://example.com/",
  "total_score": 75,
  "max_score": 100,
  "grade": "B",
  "tls_enabled": true,
  "response_time_ms": 312,
  "headers": [
    {
      "name": "Strict-Transport-Security",
      "present": true,
      "value": "max-age=31536000; includeSubDomains",
      "score": 15,
      "max_score": 20,
      "status": "warning",
      "description": "...",
      "advice": "..."
    }
  ]
}
```

### POST /api/cors — CORS Scan

```json
// Request
{ "url": "https://example.com" }
```

### POST /api/jwt — JWT Analysis

```json
// Request
{ "token": "<JWT string>" }
```

### POST /api/ssl — SSL/TLS Check

```json
// Request
{ "host": "example.com", "port": "443" }
// port is optional (default: 443)
```

### POST /api/cookies — Cookie Audit

```json
// Request
{ "url": "https://example.com" }
```

### GET /api/history — Scan History

Returns the latest 50 entries in descending order.

### GET /health — Health Check

```json
{ "status": "ok" }
```

## Directory Structure

```
shieldscan/
├── backend/
│   ├── cmd/server/         # Entry point
│   └── internal/
│       ├── analyzer/       # Scan logic
│       │   ├── analyzer.go # Security header evaluation
│       │   ├── cors.go     # CORS diagnostics
│       │   ├── jwt.go      # JWT analysis
│       │   ├── ssl.go      # SSL/TLS diagnostics
│       │   └── cookie.go   # Cookie audit
│       ├── handlers/       # HTTP handlers
│       └── models/         # In-memory history store
├── frontend/
│   └── src/
│       └── components/     # UI components for each scan tab
└── docker-compose.yml
```

## License

MIT
