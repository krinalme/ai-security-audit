---
name: security-audit
description: >
  Comprehensive security audit for web applications and APIs. Performs a full-stack security review covering authentication, authorization, rate limiting, input validation, secrets management, security headers, cost controls (AI/API spend), email abuse prevention, dependency vulnerabilities, and data exposure risks. Produces a severity-ranked report with specific fix recommendations and code examples.
  Use this skill whenever the user mentions: security audit, security review, penetration test, vulnerability assessment, hardening, "is my app secure", "check for vulnerabilities", "before going live", "production readiness", rate limiting, auth review, API security, or wants to assess the security posture of any web project — even if they just say something like "review my code for security issues" or "what could go wrong if I deploy this". Also trigger for pre-launch checklists that include security concerns.
---

# Security Audit Skill

You are performing a comprehensive security audit of a web application. Your goal is to find real, exploitable vulnerabilities and misconfigurations — not to produce a generic checklist. Every finding should be specific to the codebase you're reviewing, with file paths, line numbers, and concrete proof of the issue.

## Philosophy

A good security audit thinks like an attacker. For each surface area, ask: "If I were a malicious actor who discovered this endpoint/page/config, what's the worst I could do?" That framing produces actionable findings rather than theoretical concerns.

Prioritize findings by actual exploitability and business impact, not by how many security blogs mention the category. A wide-open admin API that leaks customer PII is more urgent than a missing `X-Content-Type-Options` header.

## Audit Workflow

### Step 1: Reconnaissance

Before diving into individual checks, map the application's attack surface. This gives you context for everything that follows.

1. **Identify the framework and stack** — Read `package.json`, `requirements.txt`, `Gemfile`, `go.mod`, or equivalent. Note the framework (Next.js, Express, Django, Rails, FastAPI, etc.), the runtime version, and key dependencies (ORMs, auth libraries, email senders, AI SDKs).

2. **Map all routes/endpoints** — Find every API route, page route, and webhook handler. In Next.js this means scanning `src/app/api/` and `pages/api/`. In Express, look for `app.get/post/put/delete` and `router.*`. Build a complete list with HTTP methods.

3. **Identify data flows** — Trace how user input enters the system (forms, API bodies, query params, headers, file uploads) and where it ends up (database, email, AI prompts, external APIs, rendered HTML).

4. **Catalog external services** — List every third-party service the app talks to (databases, AI providers, email services, payment processors, search APIs, analytics). Each is a potential cost or data exposure vector.

5. **Check environment configuration** — Read `.env.example`, `.env.local`, `docker-compose.yml`, deployment configs. Note what secrets are required and whether any are hardcoded or have insecure defaults.

Save this reconnaissance as a structured summary before proceeding. It becomes the foundation for every subsequent check.

### Step 2: Authentication & Authorization

This is typically the highest-impact area. A broken auth system means everything behind it is exposed.

**What to check:**

- **Auth mechanism** — Is auth present at all? What type (session-based, JWT, API key, OAuth)? Is there a password system, and if so, how are passwords stored? Look for plaintext passwords, weak hashing (MD5, SHA1 without salt), or hardcoded credentials.

- **Session management** — How long do sessions last? Are they invalidated on logout? Is the session token sufficiently random? For JWTs: is the secret strong, is the algorithm locked (no `alg: none`), are tokens short-lived?

- **Route protection** — Go through every route from your reconnaissance. For each one, determine: does it require auth? Should it? Is the auth check actually enforced (middleware vs. per-route)? Look for routes that check auth in some code paths but not others.

- **Authorization (authz)** — Even if a user is authenticated, can they access resources they shouldn't? Check for: missing ownership checks (user A can access user B's data by changing an ID), privilege escalation (regular user accessing admin endpoints), IDOR vulnerabilities.

- **Password reset / account recovery** — If present, is the reset token cryptographically random? Does it expire? Can it be reused? Is the reset link sent over HTTPS?

**Severity guidance:**
- No auth on admin/internal endpoints → CRITICAL
- Hardcoded credentials or plaintext passwords → CRITICAL
- Missing authz checks (IDOR) → HIGH
- Long-lived sessions without rotation → MEDIUM
- Missing CSRF protection on state-changing routes → MEDIUM

### Step 3: Rate Limiting & Abuse Prevention

Unprotected endpoints are an invitation for abuse — from credential stuffing to resource exhaustion to bill-running on AI APIs.

**What to check:**

- **Public endpoints** — Every endpoint reachable without auth needs rate limiting. Period. Check forms, chat endpoints, search, file uploads, webhook receivers.

- **Expensive operations** — AI inference, email sending, PDF generation, external API calls, database-heavy queries. These need tighter limits because each request costs real money or significant compute.

- **Implementation quality** — If rate limiting exists, is it per-IP? Per-user? Per-API-key? In-memory rate limiting resets on deploy and doesn't work across multiple instances — note this as a limitation. Look for bypass vectors (IP spoofing via `X-Forwarded-For` without validation).

- **Response behavior** — When rate limited, does the API return a proper 429 with `Retry-After` header? Or does it silently drop requests or return a 500?

**Severity guidance:**
- No rate limiting on AI/email/expensive endpoints → HIGH
- No rate limiting on auth endpoints (allows credential stuffing) → HIGH
- In-memory only rate limiting in multi-instance deployment → MEDIUM
- Missing `Retry-After` headers → LOW

### Step 4: Input Validation & Injection

Every piece of user input is a potential attack vector. Trace each input from entry to storage to output.

**What to check:**

- **SQL injection** — Is the app using parameterized queries or an ORM? If raw SQL exists anywhere, flag it. Even with an ORM, check for `.raw()` or string interpolation in queries.

- **XSS (Cross-Site Scripting)** — Is user input rendered in HTML without escaping? Check for `dangerouslySetInnerHTML` (React), `|safe` (Django), `raw` (EJS), or direct DOM manipulation. Also check if user input ends up in email HTML bodies.

- **Command injection** — Is `exec()`, `spawn()`, `system()`, or equivalent called with user input? Even indirect paths (user input → database → cron job → shell command) count.

- **Prompt injection** — If the app uses AI, is user input concatenated directly into system prompts? Can a user manipulate the AI's behavior by crafting their input?

- **Server-Side Request Forgery (SSRF)** — Does the app fetch URLs provided by users? Can an attacker make the server request internal resources (`http://localhost`, `http://169.254.169.254` for cloud metadata)?

- **Input length limits** — Are there maximum lengths on all text inputs? Unbounded input can cause memory exhaustion, database issues, or AI cost spikes.

- **File uploads** — If present: is the file type validated (not just by extension but by magic bytes)? Is there a size limit? Is the file stored safely (not in a publicly accessible directory with executable permissions)?

**Severity guidance:**
- SQL injection → CRITICAL
- Stored XSS → HIGH
- Command injection → CRITICAL
- SSRF → HIGH
- No input validation on public endpoints → HIGH
- Missing length limits on AI-bound inputs → MEDIUM

### Step 5: Secrets & Configuration

Leaked secrets are one of the most common causes of breaches. Check thoroughly.

**What to check:**

- **Hardcoded secrets** — Search the entire codebase for API keys, passwords, tokens, connection strings. Check for patterns like `sk-`, `re_`, `ghp_`, `AKIA`, base64-encoded credentials. Don't forget test files and comments.

- **Git history** — If `.git` is accessible, check if secrets were ever committed and later removed. They're still in the history. (`git log --all -p -S "API_KEY"` or similar)

- **Environment variables** — Is `.env` in `.gitignore`? Does `.env.example` contain real values? Are there fallback defaults in code that use real credentials?

- **Client-side exposure** — In frameworks like Next.js, env vars prefixed with `NEXT_PUBLIC_` are bundled into client-side JavaScript. Make sure no secrets use this prefix. Check the build output for leaked vars.

- **Deployment configuration** — Are secrets stored securely in the deployment platform (Vercel, AWS, etc.)? Or are they in plaintext in Docker Compose files, Terraform configs, or CI/CD pipelines?

**Severity guidance:**
- Hardcoded production API keys in code → CRITICAL
- Secrets in git history → HIGH
- Real credentials in `.env.example` → HIGH
- Missing `.env` in `.gitignore` → HIGH
- Client-side secret exposure → CRITICAL

### Step 6: Security Headers & Transport

These are lower-effort fixes but they reduce the attack surface meaningfully.

**What to check:**

- **HTTPS enforcement** — Is HSTS configured? Is there an HTTP → HTTPS redirect?
- **Content Security Policy (CSP)** — Is there a CSP? Is it meaningful (not `*` everywhere)?
- **X-Frame-Options** — Set to `DENY` or `SAMEORIGIN` to prevent clickjacking?
- **X-Content-Type-Options** — Set to `nosniff`?
- **Referrer-Policy** — Configured to avoid leaking URLs to third parties?
- **Permissions-Policy** — Restricting access to browser APIs (camera, microphone, geolocation)?
- **CORS** — Is `Access-Control-Allow-Origin` set to `*`? Are credentials allowed with a wildcard origin? Is the origin validated properly?

**Severity guidance:**
- CORS misconfiguration allowing credential theft → HIGH
- No HTTPS/HSTS → HIGH
- Missing CSP → MEDIUM
- Missing other security headers → LOW

### Step 7: Cost & Resource Controls

This is especially important for applications using AI services, third-party APIs, or sending emails. Uncapped usage can turn a vulnerability into a financial disaster.

**What to check:**

- **AI/LLM spend** — If the app calls AI APIs (Anthropic, OpenAI, etc.): is there a per-user or per-agent budget? Is there a system-wide daily/monthly cap? What happens when the cap is hit — does it fail gracefully or crash? Can an attacker trigger expensive completions (long context, many tool calls) through a public endpoint?

- **Email sending** — Is there a rate limit on outgoing emails? Can an attacker use the app to spam arbitrary addresses? Is the from address verified with the email provider (SPF/DKIM)?

- **External API calls** — Are there limits on how many times the app calls paid external services (search APIs, data providers, etc.)?

- **Database growth** — Can an attacker cause unbounded database growth by repeatedly submitting forms or creating resources?

- **File storage** — If the app stores files, is there a storage quota? Can an attacker upload terabytes?

**Severity guidance:**
- No spend limits on AI with public endpoint → HIGH
- Email system weaponizable for spam → HIGH
- Unbounded external API usage → MEDIUM
- No database growth controls → MEDIUM

### Step 8: Data Exposure

Check what data leaks when it shouldn't.

**What to check:**

- **API responses** — Do endpoints return more data than the client needs? (e.g., returning full user objects with password hashes, or listing all customers when only a count is needed)
- **Error messages** — Do errors expose stack traces, database schemas, file paths, or internal IPs?
- **Logs** — Are PII, tokens, or passwords being logged?
- **Debug endpoints** — Are development/debug routes left enabled? (`/graphql` playground, `/debug`, `/api-docs`, `phpinfo()`)
- **Source maps** — Are production source maps publicly accessible?
- **Database backups** — Are backups encrypted? Who has access?

**Severity guidance:**
- Password hashes or tokens in API responses → CRITICAL
- PII exposed without auth → HIGH
- Stack traces in production errors → MEDIUM
- Source maps publicly accessible → LOW

### Step 9: Dependency Audit

Third-party code is part of your attack surface.

**What to check:**

- **Known vulnerabilities** — Run `npm audit`, `pip audit`, `bundle audit`, or equivalent. Note the severity and whether an exploit is known.
- **Outdated dependencies** — How far behind are major dependencies? Frameworks and auth libraries especially.
- **Supply chain risks** — Are there any dependencies with very few maintainers, recent ownership changes, or suspiciously large install scripts?
- **Lock file integrity** — Is there a lock file (`package-lock.json`, `yarn.lock`, `poetry.lock`) checked into source control?

**Severity guidance:**
- Known critical CVE with public exploit → CRITICAL
- Known high CVE → HIGH
- Significantly outdated framework → MEDIUM
- Missing lock file → MEDIUM

## Report Format

Produce the report as a markdown document with this structure:

```
# Security Audit Report

**Project:** [Name]
**Date:** [Date]
**Auditor:** Claude Security Audit
**Scope:** [What was reviewed — e.g., "Full application codebase, API routes, auth system, deployment config"]

## Executive Summary

[2-3 paragraphs: overall posture, most critical findings, top recommendations. Written for a non-technical stakeholder who needs to understand the risk level and what to prioritize.]

## Risk Score: [CRITICAL / HIGH / MEDIUM / LOW]

[One sentence explaining the score]

## Findings

### CRITICAL

#### [C1] [Finding Title]
- **Location:** `path/to/file.ts:L42`
- **Description:** [What the vulnerability is and why it matters]
- **Exploit scenario:** [How an attacker would exploit this — be specific]
- **Business impact:** [What happens if exploited — data loss, financial cost, reputation]
- **Recommendation:** [How to fix it]
- **Code example:** [Before/after code showing the fix]

### HIGH
[Same format]

### MEDIUM
[Same format]

### LOW
[Same format]

## Architecture Recommendations

[Broader structural recommendations that don't fit into individual findings — e.g., "split the public site from the admin system", "migrate to Redis-backed rate limiting before horizontal scaling"]

## Remediation Priority

[Ordered list: what to fix first, second, third. Group by effort level (quick wins vs. larger refactors). Include rough time estimates.]

## What's Working Well

[Call out things the team got right. This builds trust and helps them understand which patterns to keep using.]
```

## Framework-Specific Guidance

When auditing, read the appropriate reference file for framework-specific checks:

- **Next.js** → Read `references/nextjs.md`
- **Express** → Read `references/express.md`
- **Django / FastAPI** → Read `references/python-web.md`
- **Rails** → Read `references/rails.md`
- **General / Other** → The steps above cover the fundamentals regardless of framework

If no framework-specific reference exists for the project's stack, apply the general audit steps — they cover the core security principles that apply universally.

## Running Automated Checks

Before the manual audit, run the automated scanner script to catch low-hanging fruit:

```bash
python /path/to/security-audit/scripts/scan.py <project-root>
```

This script checks for:
- Hardcoded secrets (API key patterns, passwords in code)
- Missing `.env` in `.gitignore`
- Known dangerous patterns (eval, exec, dangerouslySetInnerHTML, raw SQL)
- Missing security headers in config files
- Dependency vulnerabilities (via npm audit / pip audit)
- Publicly exposed debug routes
- Environment variables leaking to client side

The script output goes into the report as a "Automated Scan Results" appendix. Its findings should inform your manual review — automated tools catch patterns but miss business logic issues, which is where the manual audit adds the most value.

## Important Reminders

- Every finding needs a specific file path and line number when possible. Generic advice like "add rate limiting" without pointing to which endpoints is not useful.
- The exploit scenario is the most important part of each finding. It forces you to prove the vulnerability is real, not theoretical.
- Don't inflate severity. A missing `X-Content-Type-Options` header is not CRITICAL. Accurate severity ratings build credibility.
- If you're unsure whether something is a real vulnerability or a false positive, say so. "Potential issue — needs verification" is more honest than a false alarm.
- The report should be saved as a `.md` file in the user's workspace/output directory.
