# Security Audit Skill

A comprehensive, reusable security audit methodology for web applications and APIs — built for AI agents but useful for any developer shipping to production.

This skill was battle-tested on a real production system with 25+ API routes, 27 AI agents, and real money on the line. The methodology was extracted, generalized, and packaged so anyone can use it.

> If you're building AI agents and shipping to production without a security review, this is for you.

## What It Does

Point it at a codebase and get a structured security audit report covering:

- **Authentication & Authorization** — Route protection gaps, session management, IDOR vulnerabilities
- **Rate Limiting** — Abuse prevention on public endpoints, expensive operations, AI inference
- **Input Validation** — SQL injection, XSS, command injection, prompt injection, SSRF
- **Secrets Management** — Hardcoded keys, git history leaks, client-side exposure
- **Security Headers** — HSTS, CSP, CORS misconfigurations
- **Cost Controls** — AI/LLM spend limits, email abuse prevention, unbounded API usage
- **Data Exposure** — Over-fetched API responses, PII in logs, debug endpoints
- **Dependencies** — Known CVEs, outdated packages, supply chain risks

The output is a severity-ranked report with specific file paths, exploit scenarios, before/after code fixes, and a prioritized remediation roadmap.

## Quick Start

### With Claude (recommended)

1. Copy the `security-audit/` folder into your Claude skills directory
2. Open a conversation and ask:
   ```
   Do a security audit of my project in ./my-app
   ```
3. Claude reads the SKILL.md, runs the automated scanner, performs the 9-step manual audit, and produces a full report

### Standalone (without Claude)

You can use the automated scanner independently:

```bash
python scripts/scan.py /path/to/your/project
```

This catches low-hanging fruit: hardcoded secrets, dangerous code patterns, missing configs, and dependency vulnerabilities. For the full methodology, follow the steps in `SKILL.md` manually.

## What's Inside

```
security-audit/
  SKILL.md                    # Core audit methodology (9 steps + report template)
  scripts/
    scan.py                   # Automated scanner for common vulnerabilities
  references/
    nextjs.md                 # Next.js-specific security checks
    express.md                # Express.js-specific security checks
    python-web.md             # Django & FastAPI security checks
```

### SKILL.md

The heart of the skill. A 9-step audit workflow:

1. **Reconnaissance** — Map the attack surface (routes, data flows, external services)
2. **Authentication & Authorization** — Check auth mechanisms, route protection, IDOR
3. **Rate Limiting & Abuse Prevention** — Public endpoints, expensive operations
4. **Input Validation & Injection** — SQLi, XSS, command injection, prompt injection, SSRF
5. **Secrets & Configuration** — Hardcoded keys, env vars, git history
6. **Security Headers & Transport** — HSTS, CSP, CORS, X-Frame-Options
7. **Cost & Resource Controls** — AI spend caps, email limits, storage quotas
8. **Data Exposure** — API over-fetching, error messages, debug endpoints
9. **Dependency Audit** — Known CVEs, outdated packages, lock files

Each step includes specific things to check, severity guidance, and a structured report format.

### scripts/scan.py

Automated scanner that detects:

- API key patterns in source code (Anthropic, OpenAI, AWS, GitHub, Stripe, etc.)
- Dangerous function calls (`eval`, `exec`, `dangerouslySetInnerHTML`, raw SQL)
- Missing `.env` in `.gitignore`
- Environment files tracked by git
- Missing security headers in framework configs
- Unprotected API routes (heuristic based on auth/rate-limit pattern detection)
- Dependency vulnerabilities via `npm audit` / `pip audit`

```bash
# Text output (human-readable)
python scripts/scan.py ./my-project

# JSON output (for CI/CD pipelines)
python scripts/scan.py ./my-project --format json --output results.json
```

### references/

Framework-specific checklists that complement the main audit:

- **nextjs.md** — Middleware auth patterns, Server Components vs Client Components, `NEXT_PUBLIC_` exposure, Server Actions, `next/image` SSRF, source maps
- **express.md** — Helmet, CORS config, session store, body parsing limits, static file serving
- **python-web.md** — Django settings (`DEBUG`, `SECRET_KEY`, `ALLOWED_HOSTS`), DRF permissions, FastAPI dependency injection auth, Pydantic validation, pickle/YAML deserialization

## Example Report Structure

```
# Security Audit Report

**Project:** [Name]
**Date:** [Date]
**Risk Score:** CRITICAL / HIGH / MEDIUM / LOW

## Executive Summary
[2-3 paragraphs for non-technical stakeholders]

## Findings

### CRITICAL
#### [C1] 22 of 25 API routes lack authentication
- Location: src/app/api/*/route.ts
- Exploit scenario: An attacker can trigger expensive AI operations...
- Business impact: Potential $X,000/day in unauthorized API costs
- Recommendation: Add auth middleware to all internal routes
- Code example: [before/after fix]

### HIGH
[...]

## Remediation Priority
[Ordered list with effort estimates]

## What's Working Well
[Positive findings to build team trust]
```

## Supported Frameworks

The automated scanner works with any web project. The reference guides currently cover:

| Framework | Reference File | Coverage |
|-----------|---------------|----------|
| Next.js (App Router & Pages Router) | `references/nextjs.md` | Middleware, RSC, env vars, Server Actions |
| Express.js | `references/express.md` | Helmet, CORS, sessions, body parsing |
| Django | `references/python-web.md` | Settings, DRF, templates, CSRF |
| FastAPI | `references/python-web.md` | Auth deps, Pydantic, CORS, async |
| Other | Use SKILL.md directly | The 9-step methodology is framework-agnostic |

**Want to add a framework?** See [CONTRIBUTING.md](CONTRIBUTING.md) — Rails, Go, Laravel, and Spring Boot references are the most requested.

## Benchmark Results

Tested across 3 codebases (Next.js, Express, FastAPI) with 10 quality assertions each:

| Metric | With Skill | Without Skill |
|--------|-----------|---------------|
| Assertion pass rate | **96.7%** | 53.3% |
| Structured severity sections | Always | Never |
| Exploit scenarios with file paths | Always | Rarely |
| Remediation roadmap | Always | Sometimes |
| "What's working well" section | Always | Never |

The skill adds ~17% more tokens and ~75% more time per audit, which is a reasonable tradeoff for reports that are actually actionable.

## Who This Is For

- **Developers shipping AI agent systems** — Step 7 (Cost Controls) is specifically designed for apps calling LLM APIs, which most generic security tools completely ignore
- **Solo developers going to production** — Get a structured pre-launch security review without hiring a pentest firm
- **Teams doing internal security reviews** — Use the methodology as a framework and the report template for consistent output
- **Anyone building with Next.js, Express, Django, or FastAPI** — Framework-specific references catch issues the generic methodology misses

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details. The most impactful contributions right now:

1. **New framework references** — Rails, Go (Gin/Echo), Laravel, Spring Boot
2. **Scanner improvements** — New secret patterns, detection for more frameworks
3. **Real-world findings** — If you run the audit and find patterns we missed, open an issue

## License

MIT License — see [LICENSE](LICENSE).

---

Built by [Krinal Mehta](https://krinalmehta.com) ([@krinalme](https://github.com/krinalme)). Battle-tested on a production AI agent system before being extracted and open-sourced.

If this helps you ship a more secure product, that's the whole point.

[Website](https://krinalmehta.com) | [LinkedIn](https://linkedin.com/in/krinal) | [GitHub](https://github.com/krinalme)
