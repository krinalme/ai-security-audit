# Python Web Security Audit — Django & FastAPI

## Table of Contents

1. Django-Specific
2. FastAPI-Specific
3. Common Python Issues

---

## 1. Django-Specific

### Settings (`settings.py`)
- **DEBUG** — Must be `False` in production. When `True`, Django exposes detailed error pages with source code, SQL queries, and environment variables.
- **SECRET_KEY** — Must be strong (50+ chars), unique, and not committed to source control. Check if it's hardcoded or loaded from env.
- **ALLOWED_HOSTS** — Must not be `['*']` in production. Should list specific domains.
- **SECURE_SSL_REDIRECT** — Should be `True` to enforce HTTPS.
- **SESSION_COOKIE_SECURE** — Must be `True` for HTTPS.
- **CSRF_COOKIE_SECURE** — Must be `True` for HTTPS.
- **SECURE_HSTS_SECONDS** — Should be set (31536000 for 1 year).
- **SECURE_BROWSER_XSS_FILTER** / **SECURE_CONTENT_TYPE_NOSNIFF** — Should be `True`.

### Common Django pitfalls:
- **`@csrf_exempt`** — Flag every usage. Each one is a potential CSRF vulnerability.
- **`|safe` template filter** — Disables auto-escaping, enabling XSS.
- **`extra()` and `raw()` ORM methods** — Allow raw SQL, potential injection.
- **Mass assignment** — `Model.objects.create(**request.POST)` lets attackers set any field.
- **File uploads** — Check `MEDIA_ROOT` permissions and whether uploaded files are served with proper Content-Type.

### Django REST Framework (DRF):
- **Authentication** — Check `DEFAULT_AUTHENTICATION_CLASSES`. `SessionAuthentication` alone is vulnerable to CSRF unless `DEFAULT_PERMISSION_CLASSES` includes `IsAuthenticated`.
- **Permissions** — Is `AllowAny` used anywhere it shouldn't be?
- **Throttling** — Is `DEFAULT_THROTTLE_CLASSES` configured?
- **Serializer validation** — Are serializers properly validating all input fields?

## 2. FastAPI-Specific

### Common FastAPI issues:
- **No built-in auth** — FastAPI doesn't include auth by default. Check if a dependency (`fastapi-users`, `python-jose`, etc.) is used, or if auth is custom-built.
- **Dependency injection auth** — Auth should be a `Depends()` on route functions. Check that ALL protected routes include the auth dependency.
- **Pydantic validation** — FastAPI auto-validates request bodies via Pydantic. But check: are query parameters also validated? Are path parameters bounds-checked?
- **CORS** — Check `CORSMiddleware` config. `allow_origins=["*"]` with `allow_credentials=True` is dangerous.
- **Background tasks** — `BackgroundTasks` run without the request context. If they access user data, verify the data is captured before the request ends.

### Async-specific:
- **Resource exhaustion** — Async endpoints can handle many concurrent requests. Without rate limiting, this amplifies abuse.
- **Database connection pool** — Check pool size limits. Async can exhaust connections faster than sync.

## 3. Common Python Issues

- **pickle** — `pickle.loads()` on untrusted data = arbitrary code execution. Flag any usage with user-controlled input.
- **YAML** — `yaml.load()` (without `Loader=SafeLoader`) allows code execution. Must use `yaml.safe_load()`.
- **eval/exec** — Same as any language — never on user input.
- **subprocess** — `shell=True` with user input = command injection. Use array form instead.
- **SQL** — Even with ORMs, check for `execute()`, `text()`, f-string queries.
- **Jinja2** — If using Jinja2 templates, check for `|safe` and `{% autoescape false %}`.
- **Requirements pinning** — Are dependencies pinned to specific versions? Unpinned deps can introduce vulnerabilities on install.
