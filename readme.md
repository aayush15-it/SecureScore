# SecureScore

[![Java](https://img.shields.io/badge/Java-17-ED8B00?style=flat&logo=openjdk&logoColor=white)](https://www.oracle.com/java/technologies/downloads/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.0-6DB33F?style=flat&logo=spring&logoColor=white)](https://spring.io/projects/spring-boot)
[![Next.js](https://img.shields.io/badge/Next.js-14-000000?style=flat&logo=next.js&logoColor=white)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?style=flat&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-4169E1?style=flat&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> A **Website Security Health Check** for Small Businesses — not a vulnerability scanner, not a pentesting tool. A translation layer that turns raw security misconfigurations into plain-English fixes.

---

## The Problem

- **43%** of cyberattacks target small businesses.
- **60%** of SMBs close within 6 months of a major breach.
- Average breach cost for SMBs: **$3.31 million**.

Existing tools like Qualys, OWASP ZAP, and testssl.sh output raw technical data for security engineers. A bakery owner, freelancer, or clinic admin sees **"HSTS absent"** and has no idea what to do.

**The gap is not scanning technology. The gap is translation.**

---

## The Solution

SecureScore is a **Website Security Health Check** designed for non-technical business owners.

| Feature | What It Means |
|--------|-------------|
| **Unified 4-Check Scan** | One URL. One scan. SSL, Headers, Redirect, Cookies. |
| **Plain-English Findings** | "HSTS is missing" becomes "Your site is not forcing secure connections." |
| **Copy-Paste Remediation** | Exact config lines for nginx, Apache, and hosting panels. |
| **Verify-Fix Loop** | Apply the fix. Click "Verify." See before/after confirmation. |
| **Security History Timeline** | Track improvements over weeks. See progress, not just current state. |

**Honest Scope:**
- Does NOT perform penetration testing, XSS, or malware detection.
- Does NOT claim to find all vulnerabilities.
- DOES verify that 4 critical external configurations are correct and tells you exactly how to fix them.

---

## The 4 Core Checks

| # | Check | What It Inspects | What It Finds |
|---|-------|-----------------|---------------|
| 1 | **SSL/TLS** | Certificate validity, expiry, hostname match, TLS version, chain trust | Expired certificates, weak TLS versions, broken chains |
| 2 | **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy | Missing headers, weak policies |
| 3 | **HTTPS Redirect** | HTTP→HTTPS redirect, status codes, destination validation, redirect loops | Missing redirects, insecure chains, loops |
| 4 | **Cookie Security** | Secure flag, HttpOnly, SameSite, cookie classification | Session cookies without security flags |

---

## System Architecture

```
User → Next.js Frontend → Spring Boot API → PostgreSQL
                              ↓
                        Scan Orchestrator
                              ↓
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
          SSL/TLS        Security        HTTPS
          Check          Headers         Redirect
              │           Check           Check
              └───────────────┼───────────────┘
                              ▼
                        Cookie Security
                              │
                              ▼
              ┌───────────────────────────┐
              │  Result Aggregator        │
              │  + Finding Generator      │
              │  + Plain-English Engine   │
              └───────────────────────────┘
                              │
                              ▼
              Evidence → Severity → Fix → Verify → History
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | Next.js 14, TypeScript, Tailwind CSS, Recharts |
| **Backend** | Java 17, Spring Boot 3, Spring Data JPA, Maven |
| **Database** | PostgreSQL 15 |
| **Async Execution** | Spring @Async + CompletableFuture |
| **Deployment** | Vercel (Frontend) + Railway/Render (Backend) + Supabase/Neon (DB) |

**Key Design Decisions:**
- No Kafka, no microservices, no message brokers.
- Single deployable backend for 2-week hackathon velocity.
- Modular scanner orchestrator: each check is a pluggable module.
- SSRF protection: strict URL validation, private IP rejection, redirect limits, timeouts.

---

## Database Schema

```
Domain
├── id (PK)
├── url
├── normalized_url
├── created_at
└── updated_at

Scan
├── id (PK)
├── domain_id (FK)
├── status (QUEUED / RUNNING / COMPLETED / FAILED)
├── started_at
├── completed_at
└── error_message

Finding
├── id (PK)
├── scan_id (FK)
├── check_name
├── severity (CRITICAL / HIGH / MEDIUM / LOW / INFO / PASS)
├── status (PASS / FAIL / INFO / UNKNOWN)
├── title
├── description
├── evidence (JSON/Text)
├── why_it_matters
├── remediation (Text/Code)
└── created_at
```

---

## Scan Execution Flow

1. **URL Validation** — Reject private IPs. Enforce format. 10-second timeout.
2. **Scan Queued** — Create record. Status: `QUEUED`.
3. **Parallel Execution** — `@Async` launches 4 checks simultaneously.
4. **Evidence Aggregation** — Collect raw findings + status.
5. **Severity Classification** — `CRITICAL` → `HIGH` → `MEDIUM` → `LOW` → `INFO` → `PASS`.
6. **Finding Generation** — Plain-English explanation + copy-paste remediation.
7. **Report & Verify** — Frontend polls status. User applies fix. Re-scan confirms.

---

## Why SecureScore vs. Enterprise Tools

| | Qualys / ZAP | SecureScore |
|---|---|---|
| **Target User** | Security Engineers | Business Owners |
| **Scope** | Enterprise vulnerability management | 4 focused configuration checks |
| **Output** | Technical dashboards, CVE grades | Plain-English + exact fixes |
| **Installation** | Agents, configuration, training | Enter URL. Done. |
| **Remediation** | Expert interpretation required | Copy-paste config lines |
| **Verification** | Manual re-test | Built-in "Verify Fix" button |

We are not a smaller Qualys. We solve a different problem for a different user.

---

## Hackathon Details

- **Event:** Omnikon National Hackathon 2026
- **Problem Statement:** Omni_CyberTech_2 — Affordable Cybersecurity Assessment for Small Businesses
- **Team:** CodeAlone
- **Team Leader:** Aayush Pitrubhakta


---

## License

[MIT](LICENSE)