# AuraSecurity: Production Scaling & Integration Architecture

> Internal document for team review. Covers how to secure, scale, and make AuraSecurity integrable with exchanges, trading terminals, and bots.

---

## Current State

- **Single EC2** (t3.medium, 54.90.137.98) running PM2 + Node.js
- **Nginx** reverse proxy with SSL at `app.aurasecurity.io`
- **SQLite** database for audit history
- **No API authentication** — all endpoints are open
- **No rate limiting** in application code (nginx has basic limits)
- **Discord + Telegram bots** as AWS Lambda functions calling the API
- **9-agent SLOP swarm** on ports 4000-4008
- **Security tools**: gitleaks, grype, trivy, hadolint installed on EC2

### What Works Well
- Scanning engine is strong (trust-scan, scam-scan, AI verification, X/Twitter analysis)
- Bot integrations live and functional
- Multi-agent architecture already built (SLOP protocol)
- Transparent scoring with explainable checks

### What's Missing
- No API authentication or rate limiting
- No public API for partners
- No embeddable widgets
- No webhook callbacks
- Single point of failure (one EC2)
- Secrets in `.env` exposed in git history
- No usage metering or billing

---

## Competitive Context: zauthx402 RepoScan

| Feature | AuraSecurity | zauthx402 |
|---------|:-----------:|:---------:|
| AI wrapper detection | **Yes (unique)** | No |
| X/Twitter social analysis | **Yes (unique)** | No |
| Solana/pump.fun patterns | **Native** | Generic |
| Discord bot | **Native** | Via Rick only |
| Telegram bot | Yes | Yes |
| Transparent scoring | **Explainable checks** | Black box |
| Embeddable iframe | **No** | Yes |
| REST API with SSE | **No** | Yes |
| Axiom Memescope integration | **No** | Yes |
| Bot partnerships (Rick) | **No** | Yes |
| Code similarity DB | Pattern matching | Millions of repos |

**Bottom line:** Better product, worse distribution. The plan below fixes that.

---

## PHASE 1: Secure the API (Foundation)

**Additional cost: ~$5/month | Timeline: Week 1**

### 1.1 API Key System

Every API request requires an API key via `Authorization: Bearer <key>` header.

**Key format:** `aura_pk_{tier}_{32-random-hex}`
- Example: `aura_pk_pro_a1b2c3d4e5f6789012345678abcdef01`

**Storage:** New `api_keys` table in the database. Keys stored as SHA-256 hashes (never plaintext).

**Public endpoints (no key required):**
- `GET /info` — health check
- `GET /badge/*` — SVG badges (must be embeddable)
- `GET /embed/*` — iframe widgets
- `GET /report/*` — shareable reports
- `GET /docs` — API documentation

### 1.2 Rate Limiting

Per-key sliding window rate limits:

| Tier | Requests/min | Requests/day | Concurrent Scans | Price |
|------|-------------|-------------|------------------|-------|
| **Free** | 5 | 50 | 1 | $0 |
| **Pro** | 30 | 1,000 | 5 | $49/mo |
| **Partner** | 100 | 10,000 | 20 | Custom |
| **Internal** | Unlimited | Unlimited | Unlimited | N/A |

Exceeded limits return `429 Too Many Requests` with `X-RateLimit-Remaining` and `Retry-After` headers.

### 1.3 Usage Metering

Every API call logged with: key ID, endpoint, timestamp, response time, status code, scan target.

This gives us:
- Billing data per partner
- Abuse detection
- Usage analytics for dashboards

### 1.4 Secrets Cleanup (URGENT)

The `.env` file contains live secrets and has been committed to git. All credentials are compromised:
- GITHUB_TOKEN
- ANTHROPIC_API_KEY
- X_BEARER_TOKEN
- BOT_TOKEN (Telegram)

**Action required:**
1. Rotate ALL credentials immediately
2. Move secrets to AWS Secrets Manager (~$2/month)
3. EC2 accesses secrets via IAM instance profile (no keys on disk)

### Phase 1 Files

| File | Action |
|------|--------|
| `src/middleware/auth.ts` | Create — API key validation |
| `src/middleware/rate-limiter.ts` | Create — sliding window limiter |
| `src/aura/server.ts` | Modify — wire auth + rate limiting into request handler |
| `src/database/index.ts` | Modify — add api_keys, usage_logs tables |

---

## PHASE 2: Public API & Embeds

**Additional cost: ~$10/month | Timeline: Weeks 2-4**

### 2.1 New Domain

Set up `api.aurasecurity.io` pointing to the same EC2. Nginx routes by hostname:
- `app.aurasecurity.io` → visualizer + embeds + reports
- `api.aurasecurity.io` → REST API v1

### 2.2 REST API v1

All scan endpoints are **asynchronous** — they return a `scan_id` immediately (`202 Accepted`). Clients poll for results or subscribe via SSE.

```
# Authentication & Keys
POST   /v1/auth/register         — Create account + API key
POST   /v1/auth/keys             — Generate new key
GET    /v1/auth/keys             — List my keys
DELETE /v1/auth/keys/:id         — Revoke key
GET    /v1/auth/usage            — My usage stats

# Scanning (async)
POST   /v1/scan/repo             — Full scan (trust + scam + code)
POST   /v1/scan/x-profile        — X/Twitter profile scan
POST   /v1/scan/compare          — Compare two repos
GET    /v1/scan/:id              — Get scan result (poll)
GET    /v1/scan/:id/stream       — SSE stream for real-time progress

# Reports & Badges (no auth required)
GET    /v1/report/:id            — Shareable HTML report page
GET    /v1/badge/:owner/:repo.svg — SVG trust badge

# Embeds (no auth, restricted by CSP to partner domains)
GET    /v1/embed/scan             — Embeddable scan widget
GET    /v1/embed/result/:id       — Embeddable result display

# Webhooks
POST   /v1/webhooks              — Register callback URL
GET    /v1/webhooks              — List my webhooks
DELETE /v1/webhooks/:id          — Remove webhook
```

### 2.3 SSE Streaming (Real-Time Progress)

Partners connect to `GET /v1/scan/:id/stream` after starting a scan. They receive events as the scan progresses:

```
event: scan_started
data: {"scanId":"abc123","repo":"owner/repo"}

event: progress
data: {"percent":30,"message":"Running trust scan..."}

event: progress
data: {"percent":60,"message":"Running scam detection..."}

event: scan_completed
data: {"scanId":"abc123","score":72,"grade":"B","verdict":"DYOR","reportUrl":"https://app.aurasecurity.io/report/abc123"}
```

This is identical to what zauthx402 offers via their `GET /api/bot/progress/:scanId` endpoint.

### 2.4 Embeddable iframe Widget

**URL:** `https://app.aurasecurity.io/embed/scan?repo=owner/repo&partner=axiom&theme=dark`

A self-contained HTML page that trading terminals embed via iframe:

```html
<iframe src="https://app.aurasecurity.io/embed/scan?repo=coral-xyz/anchor&theme=dark&compact=true"
        width="300" height="200" frameborder="0"></iframe>
```

Features:
- Auto-starts scan on load
- Shows real-time progress via SSE
- Displays score, verdict, top flags
- "Powered by AuraSecurity" footer linking to full report
- **Dark theme** (essential — trading terminals are always dark)
- **Compact mode** (`&compact=true`) for small 300x200px widgets

Security: Partners register their domain. Nginx sets `Content-Security-Policy: frame-ancestors` to only allow registered domains.

### 2.5 SVG Trust Badges

Developers embed in their README:

```markdown
[![AuraSecurity](https://api.aurasecurity.io/v1/badge/coral-xyz/anchor.svg)](https://app.aurasecurity.io/report/abc123)
```

This creates a **viral loop**: devs add badges → degens see them → scan more repos → more devs add badges.

Badge endpoint: `GET /v1/badge/:owner/:repo.svg`
- Triggers scan if no cached result
- Cached for 1 hour
- Shows score + grade + verdict in shield.io style

### 2.6 Shareable Report Pages

**URL:** `https://app.aurasecurity.io/report/:scanId`

A public HTML page showing the full scan report. Includes OpenGraph meta tags so it looks good when shared on Twitter/Discord/Telegram:

```html
<meta property="og:title" content="AuraSecurity: coral-xyz/anchor — 100/100 SAFU" />
<meta property="og:description" content="Established, actively maintained project. No scam patterns, no leaked secrets." />
<meta property="og:image" content="https://api.aurasecurity.io/v1/badge/coral-xyz/anchor.svg" />
```

### 2.7 API Documentation

OpenAPI 3.0 spec served at `GET /docs` via Swagger UI. Partners can explore and test the API interactively.

### Phase 2 Files

| File | Action |
|------|--------|
| `src/api/router.ts` | Create — lightweight path router with middleware |
| `src/api/v1/scan.ts` | Create — async scan endpoints |
| `src/api/v1/auth.ts` | Create — auth/key management |
| `src/api/v1/report.ts` | Create — report + badge endpoints |
| `src/api/v1/embed.ts` | Create — embed page serving |
| `src/api/v1/webhook.ts` | Create — webhook CRUD |
| `src/api/sse.ts` | Create — SSE connection manager |
| `visualizer/embed.html` | Create — embeddable scan widget |
| `visualizer/report.html` | Create — shareable report page |
| `docs/openapi.yaml` | Create — API specification |
| `src/aura/server.ts` | Modify — mount v1 router, add SSE |
| `src/index.ts` | Modify — refactor scans to async |

---

## PHASE 3: Partner Integrations

**Additional cost: ~$5/month | Timeline: Weeks 5-8**

### 3.1 How Trading Terminals Integrate (Axiom, Photon, BullX)

Two options per partner:

**Option A — iframe embed (simplest):**
```html
<iframe src="https://app.aurasecurity.io/embed/scan?repo=owner/repo&partner=axiom&theme=dark&compact=true"
        width="300" height="200" frameborder="0"></iframe>
```

The terminal just drops in our widget. We handle everything — scanning, rendering, progress.

**Option B — API + own UI:**
```
POST https://api.aurasecurity.io/v1/scan/repo
Authorization: Bearer aura_pk_partner_...
{"url": "https://github.com/owner/repo"}

← 202 {"scan_id": "abc123", "stream_url": "/v1/scan/abc123/stream"}
```

The terminal calls our API and renders their own UI using the JSON response. More work for them, but full control over look & feel.

### 3.2 How Bots Integrate (Rick, Trojan, BonkBot)

Bots can't render iframes. They use **API + webhook callbacks**:

```
1. Bot sends scan request:
   POST /v1/scan/repo
   { "url": "https://github.com/...", "callback_url": "https://bot.example.com/hook" }
   ← 202 { "scan_id": "abc123" }

2. Scan runs in background...

3. AuraSecurity calls back when done:
   POST https://bot.example.com/hook
   Headers:
     X-AuraSecurity-Signature: sha256=<HMAC of body using partner's secret>
   Body:
     {
       "event": "scan_completed",
       "scan_id": "abc123",
       "score": 72,
       "grade": "B",
       "verdict": "DYOR",
       "report_url": "https://app.aurasecurity.io/report/abc123",
       "tags": ["#Established", "#ActiveTeam", "#HasTests"],
       "red_flags": [...],
       "green_flags": [...]
     }
```

The bot receives the callback and formats it for their platform (Telegram, Discord, in-app).

### 3.3 Outbound Webhook System

- All webhook payloads signed with HMAC-SHA256 using the partner's secret
- Partners verify the `X-AuraSecurity-Signature` header to confirm authenticity
- Retry 3 times with exponential backoff (1s, 4s, 16s) on failure
- Delivery status tracked in database (pending → sent → failed)

### 3.4 Partner Onboarding Flow

1. Partner contacts us (email/Telegram — manual for now)
2. We create their partner account with API key + webhook secret
3. Partner receives: API key, webhook secret, documentation link, SDK
4. Partner registers their callback URLs and embed domains
5. We whitelist their domain for iframe CSP

### 3.5 Partner Dashboard

Simple web page at `/partner-dashboard` showing:
- API key management (view prefix, rotate, revoke)
- Usage charts (scans/day, top repos)
- Webhook delivery logs (status, retry count)
- Embed configuration (allowed domains, theme)

### Phase 3 Files

| File | Action |
|------|--------|
| `src/api/webhooks/outbound.ts` | Create — delivery + retry logic |
| `src/api/v1/admin.ts` | Create — partner management |
| `src/database/index.ts` | Modify — add partners, webhook_deliveries tables |
| `visualizer/partner-dashboard.html` | Create — partner admin page |

---

## PHASE 4: Horizontal Scaling

**Total cost: ~$120/month | Timeline: When traffic demands it**

### Architecture Diagram

```
                          Internet
                             │
                    ┌────────┴────────┐
                    │   CloudFront    │  (static: badges, embeds, reports)
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    │       ALB       │  Application Load Balancer
                    │  Health checks  │  (~$16/mo)
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
        ┌─────┴─────┐ ┌─────┴─────┐ ┌─────┴─────┐
        │ ECS API 1 │ │ ECS API 2 │ │ ECS API N │  Stateless API servers
        └─────┬─────┘ └─────┬─────┘ └─────┬─────┘  (auto-scale)
              └──────────────┼──────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
        ┌─────┴─────┐ ┌─────┴─────┐ ┌─────┴─────┐
        │  RDS PG   │ │  Redis    │ │   SQS     │
        │ PostgreSQL│ │  Cache    │ │ Scan Jobs │
        │  ~$15/mo  │ │  ~$12/mo  │ │  ~$1/mo   │
        └───────────┘ └───────────┘ └─────┬─────┘
                                          │
                            ┌─────────────┼─────────────┐
                            │             │             │
                      ┌─────┴─────┐ ┌─────┴─────┐ ┌─────┴─────┐
                      │ Worker 1  │ │ Worker 2  │ │ Worker N  │
                      │ gitleaks  │ │           │ │           │  Scan workers
                      │ trivy     │ │           │ │           │  (auto-scale by
                      │ grype     │ │           │ │           │   queue depth)
                      └───────────┘ └───────────┘ └───────────┘
```

### What Changes

| Component | Current (Phase 1-3) | Phase 4 |
|-----------|---------------------|---------|
| API servers | 1x EC2 + PM2 | 2+ ECS Fargate tasks (stateless) |
| Database | SQLite file | RDS PostgreSQL (db.t4g.micro) |
| Cache & rate limits | In-memory | ElastiCache Redis |
| Scan execution | Synchronous in API process | SQS queue → dedicated workers |
| Agent swarm | Fixed ports on same EC2 | Dedicated EC2 or containerized |
| WebSocket state | Single-process memory | Redis pub/sub |
| Failover | None (single instance) | ALB health checks + auto-scaling |

### Scan Job Queue (SQS)

Scans are decoupled from the API:

```
1. API receives POST /v1/scan/repo
2. Creates scan_jobs record in PostgreSQL (status: queued)
3. Sends message to SQS queue
4. Returns 202 { scan_id } immediately

5. Worker picks up message from SQS
6. Runs trust-scan + scam-scan + ai-check
7. Writes result to PostgreSQL (status: completed)
8. Fires SSE notifications + webhook callbacks
```

Benefits:
- API never blocks on long scans
- Workers scale independently based on queue depth
- Failed scans retry automatically via SQS dead-letter queue
- Can process many scans in parallel

### Cost Breakdown

| Service | Spec | Monthly |
|---------|------|---------|
| ALB | Application Load Balancer | ~$16 |
| ECS Fargate (API x2) | 0.25 vCPU, 0.5GB each | ~$18 |
| ECS Fargate (Workers x2) | 0.5 vCPU, 1GB each | ~$27 |
| RDS PostgreSQL | db.t4g.micro | ~$15 |
| ElastiCache Redis | cache.t4g.micro | ~$12 |
| SQS | Standard queue | ~$1 |
| EC2 (Agent swarm) | t3.medium (existing) | ~$30 |
| Secrets Manager | 5 secrets | ~$2 |
| **Total** | | **~$120/month** |

**Budget option (~$50/month):** Skip Redis (use PostgreSQL for caching), run 1 API + 1 worker on Fargate, keep existing EC2 for everything else.

---

## Implementation Priority

| # | What | Phase | Why First |
|---|------|-------|-----------|
| 1 | Rotate exposed secrets | 1 | Live security vulnerability |
| 2 | API key auth + rate limiting | 1 | Foundation for everything else |
| 3 | Usage metering | 1 | Need billing data for partners |
| 4 | Async scan queue (in-memory) | 2 | Decouple HTTP from long scans |
| 5 | SSE streaming | 2 | Partners need real-time progress |
| 6 | Public REST API /v1/scan/* | 2 | Partner integration entry point |
| 7 | Embeddable iframe widget | 2 | Trading terminal integration |
| 8 | SVG badges | 2 | Quick win, viral growth |
| 9 | Outbound webhooks | 3 | Bot integration (Rick, Trojan) |
| 10 | Shareable report pages | 2 | Marketing / social sharing |
| 11 | Partner onboarding + dashboard | 3 | Scale partnerships |
| 12 | API docs (OpenAPI + Swagger) | 2 | Developer experience |
| 13 | Horizontal scaling | 4 | Only when traffic demands it |

---

## Action Items

### Immediate (This Week)
1. **Rotate all credentials** — GITHUB_TOKEN, ANTHROPIC_API_KEY, X_BEARER_TOKEN, BOT_TOKEN are all in git history and must be rotated
2. **Set up api.aurasecurity.io** — Route53 A record + nginx virtual host
3. **Start Phase 1 build** — API key system + rate limiter + usage logging

### Partner Outreach (Once Phase 2 API is live)
4. **Axiom** — Pitch iframe embed for Memescope (they already have zauthx402; show why ours is better: AI detection, X/Twitter analysis, transparent scoring)
5. **Photon / BullX** — Same iframe pitch + API option
6. **Rick Bot / Trojan / BonkBot** — API + webhook integration (simplest integration for bots)
7. **pump.fun / Raydium** — Badge embed on project pages

### Growth Initiatives
8. **Publish `@aurasecurity/sdk`** to npm — thin TypeScript wrapper around the API
9. **OpenAPI docs at /docs** — interactive API explorer for developers
10. **Badge viral loop** — devs embed trust badges in README → degens see them → scan more repos → more devs add badges

---

## How to Verify Each Phase

**Phase 1:**
- `curl` with no auth → `401 Unauthorized`
- `curl` with valid key → `200 OK`
- Spam requests → `429 Too Many Requests` with correct headers
- Check `usage_logs` table has entries

**Phase 2:**
- `POST /v1/scan/repo` returns `scan_id` immediately (not blocking)
- `GET /v1/scan/:id/stream` streams SSE events in real-time
- Embed iframe loads in a test page from registered domain
- Badge SVG renders at `/v1/badge/coral-xyz/anchor.svg`
- Report page at `/report/:id` shows OpenGraph preview on Twitter/Discord

**Phase 3:**
- Register webhook → run scan → callback fires with valid HMAC signature
- Partner dashboard shows usage stats and delivery logs
- iframe works from registered partner domain, blocked from unregistered

**Phase 4:**
- Kill one API instance → ALB routes to another (zero downtime)
- Queue 10 scans simultaneously → workers process in parallel
- Same scan result returned from cache within 1 hour window
