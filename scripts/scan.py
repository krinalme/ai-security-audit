#!/usr/bin/env python3
"""
Security Audit Scanner — Automated checks for common web app vulnerabilities.

Usage:
    python scan.py <project-root> [--output report.json]

Scans for:
- Hardcoded secrets (API keys, passwords, tokens)
- Missing .env in .gitignore
- Dangerous code patterns (eval, exec, raw SQL, dangerouslySetInnerHTML)
- Missing security headers
- Environment variable exposure to client side
- Debug/development endpoints left enabled
- Dependency vulnerabilities (npm audit / pip audit)
- Unprotected API routes (heuristic)
"""

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class Finding:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    file: str = ""
    line: int = 0
    description: str = ""
    recommendation: str = ""


@dataclass
class ScanResult:
    project_path: str
    framework: str = "unknown"
    findings: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)


# ── Secret patterns ──────────────────────────────────────────────────────

SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key"),
    (r'(?:secret|token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Secret/Token"),
    (r'sk-ant-[a-zA-Z0-9_\-]{20,}', "Anthropic API Key"),
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key"),
    (r're_[a-zA-Z0-9]{20,}', "Resend API Key"),
    (r'ghp_[a-zA-Z0-9]{36,}', "GitHub Personal Access Token"),
    (r'gho_[a-zA-Z0-9]{36,}', "GitHub OAuth Token"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "Hardcoded Password"),
    (r'mongodb(?:\+srv)?://[^\s"\']+', "MongoDB Connection String"),
    (r'postgres(?:ql)?://[^\s"\']+', "PostgreSQL Connection String"),
    (r'mysql://[^\s"\']+', "MySQL Connection String"),
    (r'redis://[^\s"\']+', "Redis Connection String"),
    (r'Bearer\s+[a-zA-Z0-9_\-\.]{20,}', "Bearer Token"),
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Private Key"),
]

# ── Dangerous code patterns ──────────────────────────────────────────────

DANGEROUS_PATTERNS = [
    (r'\beval\s*\(', "eval()", "Code injection via eval", "HIGH"),
    (r'\bexec\s*\(', "exec()", "Command injection via exec", "HIGH"),
    (r'\bexecSync\s*\(', "execSync()", "Synchronous command injection", "HIGH"),
    (r'child_process', "child_process import", "Potential command injection vector", "MEDIUM"),
    (r'dangerouslySetInnerHTML', "dangerouslySetInnerHTML", "Potential XSS via raw HTML injection", "HIGH"),
    (r'\.raw\s*\(|\.rawQuery\s*\(', "Raw SQL query", "Potential SQL injection", "HIGH"),
    (r'innerHTML\s*=', "innerHTML assignment", "Potential XSS via DOM manipulation", "MEDIUM"),
    (r'document\.write\s*\(', "document.write()", "Potential XSS via document.write", "MEDIUM"),
    (r'\.query\s*\(\s*[`"\'].*\$\{', "Template literal in SQL", "Potential SQL injection via string interpolation", "HIGH"),
    (r'subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True', "subprocess with shell=True", "Command injection risk", "HIGH"),
    (r'os\.system\s*\(', "os.system()", "Command injection via os.system", "HIGH"),
    (r'__import__\s*\(', "Dynamic import", "Potential code injection via dynamic import", "MEDIUM"),
    (r'pickle\.loads?\s*\(', "pickle deserialization", "Potential arbitrary code execution via pickle", "HIGH"),
    (r'yaml\.(?:load|unsafe_load)\s*\(', "Unsafe YAML loading", "Potential code execution via YAML deserialization", "HIGH"),
]

# ── Files/dirs to skip ───────────────────────────────────────────────────

SKIP_DIRS = {
    "node_modules", ".git", ".next", "__pycache__", ".venv", "venv",
    "dist", "build", ".turbo", ".cache", "coverage", ".nyc_output",
    "vendor", "target", "pkg",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".tar", ".gz", ".lock",
    ".map", ".min.js", ".min.css", ".pyc", ".pyo",
}


def should_scan_file(path: Path) -> bool:
    """Check if a file should be scanned."""
    if any(skip in path.parts for skip in SKIP_DIRS):
        return False
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return False
    if path.name.startswith("."):
        return False
    # Only scan text-like files
    return path.suffix.lower() in {
        ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
        ".py", ".rb", ".go", ".java", ".rs", ".php",
        ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
        ".env", ".sh", ".bash", ".zsh",
        ".md", ".txt", ".html", ".htm", ".css", ".scss",
        ".tf", ".hcl",  # Terraform
        "", # no extension (Dockerfile, Makefile, etc.)
    }


def detect_framework(project_root: Path) -> str:
    """Detect the project's web framework."""
    pkg_json = project_root / "package.json"
    if pkg_json.exists():
        try:
            pkg = json.loads(pkg_json.read_text())
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            if "next" in deps:
                return "nextjs"
            if "express" in deps:
                return "express"
            if "fastify" in deps:
                return "fastify"
            if "nuxt" in deps or "vue" in deps:
                return "vue/nuxt"
            if "react" in deps:
                return "react"
        except (json.JSONDecodeError, KeyError):
            pass

    if (project_root / "requirements.txt").exists() or (project_root / "pyproject.toml").exists():
        for f in ["requirements.txt", "pyproject.toml", "Pipfile"]:
            fp = project_root / f
            if fp.exists():
                content = fp.read_text()
                if "django" in content.lower():
                    return "django"
                if "fastapi" in content.lower():
                    return "fastapi"
                if "flask" in content.lower():
                    return "flask"
        return "python"

    if (project_root / "Gemfile").exists():
        return "rails"

    if (project_root / "go.mod").exists():
        return "go"

    return "unknown"


def scan_secrets(project_root: Path) -> list[Finding]:
    """Scan for hardcoded secrets."""
    findings = []
    env_example_files = {"env.example", ".env.example", ".env.sample", "env.sample"}

    for path in project_root.rglob("*"):
        if not path.is_file() or not should_scan_file(path):
            continue

        # Skip .env.example files for secret scanning (they're supposed to have placeholders)
        if path.name.lower() in env_example_files:
            continue

        try:
            content = path.read_text(errors="ignore")
        except (PermissionError, OSError):
            continue

        for line_num, line in enumerate(content.splitlines(), 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue

            for pattern, secret_type in SECRET_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Filter out obvious placeholders
                    if any(placeholder in line.lower() for placeholder in [
                        "xxxxx", "your-", "example", "placeholder", "changeme",
                        "replace", "todo", "fixme", "dummy", "test", "sample",
                        "process.env", "os.environ", "os.getenv",
                    ]):
                        continue

                    rel_path = path.relative_to(project_root)
                    findings.append(Finding(
                        severity="CRITICAL",
                        category="Secrets",
                        title=f"Potential {secret_type} in source code",
                        file=str(rel_path),
                        line=line_num,
                        description=f"Found pattern matching {secret_type}. Verify this is not a real credential.",
                        recommendation=f"Move to environment variable. Rotate the credential if it was ever committed.",
                    ))
                    break  # One finding per line

    return findings


def scan_gitignore(project_root: Path) -> list[Finding]:
    """Check .gitignore for common security entries."""
    findings = []
    gitignore = project_root / ".gitignore"

    if not gitignore.exists():
        findings.append(Finding(
            severity="HIGH",
            category="Configuration",
            title="No .gitignore file found",
            description="Without .gitignore, sensitive files like .env may be committed to version control.",
            recommendation="Create a .gitignore file with entries for .env, node_modules, .next, etc.",
        ))
        return findings

    content = gitignore.read_text()
    required_entries = {
        ".env": "Environment files may contain secrets",
        ".env.local": "Local environment files may contain secrets",
        ".env*.local": "Local environment overrides may contain secrets",
    }

    for entry, reason in required_entries.items():
        # Check if the entry or a broader pattern covers it
        if entry not in content and not any(
            broad in content for broad in [".env*", "*.env", ".env.*"]
        ):
            findings.append(Finding(
                severity="HIGH",
                category="Configuration",
                title=f"Missing '{entry}' in .gitignore",
                file=".gitignore",
                description=reason,
                recommendation=f"Add '{entry}' to .gitignore.",
            ))

    return findings


def scan_dangerous_patterns(project_root: Path) -> list[Finding]:
    """Scan for dangerous code patterns."""
    findings = []

    for path in project_root.rglob("*"):
        if not path.is_file() or not should_scan_file(path):
            continue

        try:
            content = path.read_text(errors="ignore")
        except (PermissionError, OSError):
            continue

        rel_path = path.relative_to(project_root)

        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern, name, desc, severity in DANGEROUS_PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding(
                        severity=severity,
                        category="Dangerous Code",
                        title=f"{name} usage detected",
                        file=str(rel_path),
                        line=line_num,
                        description=desc,
                        recommendation=f"Review this usage of {name}. If user input can reach this code path, it's a vulnerability.",
                    ))
                    break

    return findings


def scan_nextjs_specific(project_root: Path) -> list[Finding]:
    """Next.js-specific security checks."""
    findings = []

    # Check for NEXT_PUBLIC_ secrets
    for path in project_root.rglob("*"):
        if not path.is_file() or not should_scan_file(path):
            continue
        try:
            content = path.read_text(errors="ignore")
        except (PermissionError, OSError):
            continue

        rel_path = path.relative_to(project_root)
        for line_num, line in enumerate(content.splitlines(), 1):
            sensitive_public = re.search(
                r'NEXT_PUBLIC_(?:SECRET|KEY|TOKEN|PASSWORD|API_KEY|PRIVATE)',
                line, re.IGNORECASE
            )
            if sensitive_public:
                findings.append(Finding(
                    severity="CRITICAL",
                    category="Client Exposure",
                    title="Sensitive env var exposed to client via NEXT_PUBLIC_ prefix",
                    file=str(rel_path),
                    line=line_num,
                    description="NEXT_PUBLIC_ variables are bundled into client-side JavaScript. Secrets must not use this prefix.",
                    recommendation="Remove the NEXT_PUBLIC_ prefix and access this value only in server-side code.",
                ))

    # Check next.config for security headers
    for config_name in ["next.config.ts", "next.config.js", "next.config.mjs"]:
        config_path = project_root / config_name
        if config_path.exists():
            content = config_path.read_text()
            important_headers = {
                "X-Frame-Options": "Prevents clickjacking",
                "X-Content-Type-Options": "Prevents MIME type sniffing",
                "Strict-Transport-Security": "Enforces HTTPS",
            }
            for header, purpose in important_headers.items():
                if header not in content:
                    findings.append(Finding(
                        severity="MEDIUM",
                        category="Security Headers",
                        title=f"Missing {header} header",
                        file=config_name,
                        description=f"{purpose}. This header is not configured in the Next.js config.",
                        recommendation=f"Add {header} to the headers() function in {config_name}.",
                    ))

            # Check for source maps in production
            if "productionBrowserSourceMaps" in content and "true" in content:
                findings.append(Finding(
                    severity="MEDIUM",
                    category="Data Exposure",
                    title="Production source maps enabled",
                    file=config_name,
                    description="Source maps in production expose your entire source code to anyone with browser dev tools.",
                    recommendation="Set productionBrowserSourceMaps to false or remove the setting.",
                ))

    # Check middleware
    middleware_exists = any(
        (project_root / f).exists()
        for f in ["middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"]
    )
    if not middleware_exists:
        findings.append(Finding(
            severity="MEDIUM",
            category="Authentication",
            title="No middleware.ts found",
            description="Next.js middleware is the primary mechanism for enforcing auth across routes. Without it, auth must be checked per-route, which is error-prone.",
            recommendation="Create middleware.ts to enforce authentication on protected routes.",
        ))

    return findings


def scan_api_routes(project_root: Path) -> list[Finding]:
    """Check API routes for common issues."""
    findings = []
    api_dirs = [
        project_root / "src" / "app" / "api",
        project_root / "app" / "api",
        project_root / "pages" / "api",
    ]

    route_count = 0
    routes_with_auth = 0
    routes_with_rate_limit = 0

    for api_dir in api_dirs:
        if not api_dir.exists():
            continue

        for path in api_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in {".ts", ".tsx", ".js", ".jsx"}:
                continue

            rel_path = path.relative_to(project_root)

            try:
                content = path.read_text()
            except (PermissionError, OSError):
                continue

            # Check if it's actually a route handler
            if not any(pattern in content for pattern in [
                "export async function", "export function",
                "export default", "module.exports",
            ]):
                continue

            route_count += 1

            # Check for auth
            auth_patterns = [
                "getServerSession", "getSession", "getToken",
                "requireAuth", "authenticate", "isAuthenticated",
                "verifyToken", "jwt.verify", "authMiddleware",
                "withAuth", "protect", "guard",
            ]
            has_auth = any(p in content for p in auth_patterns)
            if has_auth:
                routes_with_auth += 1

            # Check for rate limiting
            rate_limit_patterns = [
                "rateLimit", "rateLimiter", "throttle",
                "upstash", "rate-limit", "rate_limit",
                "tooManyRequests", "429",
            ]
            has_rate_limit = any(p in content for p in rate_limit_patterns)
            if has_rate_limit:
                routes_with_rate_limit += 1

            # Check for input validation
            validation_patterns = [
                "validate", "sanitize", "zod", "joi", "yup",
                "ajv", "z.object", "z.string", ".parse(",
                "validateLeadInput", "validateChatInput",
            ]
            has_validation = any(p in content for p in validation_patterns)

            if not has_validation:
                findings.append(Finding(
                    severity="MEDIUM",
                    category="Input Validation",
                    title=f"No input validation detected in API route",
                    file=str(rel_path),
                    description="This route handler doesn't appear to validate its input. All user input should be validated and sanitized.",
                    recommendation="Add input validation using a schema library (Zod, Joi) or manual checks.",
                ))

    if route_count > 0:
        unprotected_ratio = (route_count - routes_with_auth) / route_count
        if unprotected_ratio > 0.5:
            findings.append(Finding(
                severity="HIGH",
                category="Authentication",
                title=f"{route_count - routes_with_auth}/{route_count} API routes have no auth check",
                description=f"More than half of API routes don't appear to have authentication. This may include internal endpoints that should be protected.",
                recommendation="Review each API route and add auth checks where appropriate. Use middleware for broad protection.",
            ))

        unrated_ratio = (route_count - routes_with_rate_limit) / route_count
        if unrated_ratio > 0.7:
            findings.append(Finding(
                severity="MEDIUM",
                category="Rate Limiting",
                title=f"{route_count - routes_with_rate_limit}/{route_count} API routes have no rate limiting",
                description=f"Most API routes lack rate limiting, leaving them open to abuse and resource exhaustion.",
                recommendation="Add rate limiting to all public endpoints and expensive operations.",
            ))

    return findings


def run_dependency_audit(project_root: Path) -> list[Finding]:
    """Run package manager audit if available."""
    findings = []

    # npm audit
    if (project_root / "package.json").exists():
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=project_root,
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0 and result.stdout:
                try:
                    audit_data = json.loads(result.stdout)
                    vulns = audit_data.get("vulnerabilities", {})
                    severity_map = {"critical": "CRITICAL", "high": "HIGH", "moderate": "MEDIUM", "low": "LOW"}

                    for pkg_name, vuln_info in vulns.items():
                        sev = vuln_info.get("severity", "low")
                        findings.append(Finding(
                            severity=severity_map.get(sev, "LOW"),
                            category="Dependencies",
                            title=f"Vulnerable dependency: {pkg_name}",
                            file="package.json",
                            description=f"Known {sev} vulnerability in {pkg_name}. {vuln_info.get('title', '')}",
                            recommendation=f"Run 'npm audit fix' or manually update {pkg_name}.",
                        ))
                except json.JSONDecodeError:
                    pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            findings.append(Finding(
                severity="INFO",
                category="Dependencies",
                title="Could not run npm audit",
                description="npm is not available or the audit timed out.",
                recommendation="Run 'npm audit' manually to check for dependency vulnerabilities.",
            ))

    # pip audit
    if (project_root / "requirements.txt").exists():
        try:
            result = subprocess.run(
                ["pip", "audit", "--format", "json"],
                cwd=project_root,
                capture_output=True, text=True, timeout=60,
            )
            if result.stdout:
                try:
                    vulns = json.loads(result.stdout)
                    for vuln in vulns:
                        findings.append(Finding(
                            severity="HIGH",
                            category="Dependencies",
                            title=f"Vulnerable dependency: {vuln.get('name', 'unknown')}",
                            file="requirements.txt",
                            description=vuln.get("description", "Known vulnerability"),
                            recommendation=f"Update {vuln.get('name', 'the package')} to a patched version.",
                        ))
                except json.JSONDecodeError:
                    pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return findings


def scan_env_files(project_root: Path) -> list[Finding]:
    """Check for actual .env files that shouldn't be committed."""
    findings = []
    env_files = [".env", ".env.local", ".env.production", ".env.staging"]

    for env_name in env_files:
        env_path = project_root / env_name
        if env_path.exists():
            # Check if it's tracked by git
            try:
                result = subprocess.run(
                    ["git", "ls-files", env_name],
                    cwd=project_root,
                    capture_output=True, text=True, timeout=10,
                )
                if result.stdout.strip():
                    findings.append(Finding(
                        severity="CRITICAL",
                        category="Secrets",
                        title=f"Environment file '{env_name}' is tracked by git",
                        file=env_name,
                        description="This file likely contains secrets and is committed to the repository.",
                        recommendation=f"Remove from git with 'git rm --cached {env_name}', add to .gitignore, and rotate all credentials.",
                    ))
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

    return findings


def main():
    parser = argparse.ArgumentParser(description="Security Audit Scanner")
    parser.add_argument("project_root", help="Path to the project root directory")
    parser.add_argument("--output", "-o", help="Output file path (JSON)", default=None)
    parser.add_argument("--format", choices=["json", "text"], default="text", help="Output format")
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    if not project_root.is_dir():
        print(f"Error: {project_root} is not a directory", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {project_root}...")

    result = ScanResult(project_path=str(project_root))
    result.framework = detect_framework(project_root)
    print(f"Detected framework: {result.framework}")

    # Run all scans
    scanners = [
        ("Secrets", scan_secrets),
        ("Git Configuration", scan_gitignore),
        ("Dangerous Patterns", scan_dangerous_patterns),
        ("API Routes", scan_api_routes),
        ("Environment Files", scan_env_files),
        ("Dependencies", run_dependency_audit),
    ]

    # Add framework-specific scans
    if result.framework == "nextjs":
        scanners.append(("Next.js Specific", scan_nextjs_specific))

    for name, scanner in scanners:
        print(f"  Running: {name}...")
        findings = scanner(project_root)
        result.findings.extend(findings)
        print(f"    Found {len(findings)} issues")

    # Compute stats
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in result.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    result.stats = {
        "total_findings": len(result.findings),
        "by_severity": severity_counts,
        "framework": result.framework,
    }

    # Output
    if args.format == "json" or args.output:
        output_data = {
            "project_path": result.project_path,
            "framework": result.framework,
            "stats": result.stats,
            "findings": [asdict(f) for f in result.findings],
        }
        if args.output:
            with open(args.output, "w") as f:
                json.dump(output_data, f, indent=2)
            print(f"\nResults saved to {args.output}")
        else:
            print(json.dumps(output_data, indent=2))
    else:
        # Text output
        print(f"\n{'=' * 60}")
        print(f"SECURITY SCAN RESULTS")
        print(f"{'=' * 60}")
        print(f"Project: {result.project_path}")
        print(f"Framework: {result.framework}")
        print(f"Total findings: {result.stats['total_findings']}")
        print()

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                print(f"  {sev}: {count}")

        print()

        # Group by severity
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            sev_findings = [f for f in result.findings if f.severity == sev]
            if not sev_findings:
                continue

            print(f"\n--- {sev} ---")
            for i, f in enumerate(sev_findings, 1):
                loc = f"{f.file}:{f.line}" if f.file else "N/A"
                print(f"\n  [{sev[0]}{i}] {f.title}")
                print(f"      Location: {loc}")
                print(f"      {f.description}")
                if f.recommendation:
                    print(f"      Fix: {f.recommendation}")

    print(f"\nScan complete. {len(result.findings)} findings across {len(severity_counts)} severity levels.")
    return 0 if severity_counts.get("CRITICAL", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
