# Contributing to Security Audit Skill

Thanks for wanting to make this better. Here's how to contribute effectively.

## What We Need Most

### 1. New Framework References

The biggest gap right now is framework coverage. Each reference file lives in `references/` and follows a consistent structure:

- Table of contents
- Framework-specific security checks organized by category
- Code examples showing vulnerable vs. secure patterns
- What to flag and at what severity

**Frameworks we'd love references for:**
- Ruby on Rails
- Go (Gin, Echo, Fiber)
- Laravel / PHP
- Spring Boot / Java
- Rust (Actix, Axum)
- SvelteKit
- Remix

To add one: create `references/<framework>.md`, follow the format of `references/nextjs.md`, and update the "Framework-Specific Guidance" section in `SKILL.md` to point to it.

### 2. Scanner Improvements

`scripts/scan.py` catches common patterns but can always be smarter:

- **New secret patterns** — If you know API key formats for services we don't detect, add them to `SECRET_PATTERNS`
- **New dangerous patterns** — Framework-specific dangerous functions we should flag
- **Framework detection** — Better heuristics for identifying the tech stack
- **New framework-specific scans** — Like `scan_nextjs_specific()` but for other frameworks

### 3. Real-World Findings

If you run the audit on a real project and discover a vulnerability pattern the methodology missed, submit it. These are the most valuable contributions because they come from real attack surfaces, not theory.

**Format for new findings:**
- Which audit step it falls under (Steps 1-9)
- The pattern to look for
- Why it matters (exploit scenario)
- Suggested severity level
- Example of the vulnerable code and the fix

## How to Submit

1. Fork the repo
2. Create a branch: `git checkout -b add-rails-reference`
3. Make your changes
4. Test the scanner if you modified it: `python scripts/scan.py /path/to/test/project`
5. Submit a pull request with a clear description of what you added and why

## Code Style

- **SKILL.md and references**: Write like you're explaining to a senior developer who's smart but hasn't thought about this specific security concern before. Be specific, not preachy.
- **scan.py**: Standard Python, type hints where helpful, comments on non-obvious regex patterns.
- **Severity ratings**: Be honest. Don't inflate severity to make findings sound scarier. A missing header is LOW, not HIGH. Accurate ratings build trust.

## What Not to Submit

- Generic security checklists copied from OWASP without framework-specific context
- Findings that require paid tools to reproduce
- Changes that make the scanner dependent on external services or API keys
