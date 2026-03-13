# Express.js Security Audit — Framework-Specific Checks

## Table of Contents

1. Middleware Stack
2. Route Security
3. Session & Auth
4. Error Handling
5. Request Parsing
6. Static Files & CORS

---

## 1. Middleware Stack

Express security depends heavily on middleware ordering. Check `app.ts` or `server.ts` for:

- **helmet** — Is `helmet()` applied? It sets 11+ security headers automatically. Without it, manually check each header.
- **cors** — Is CORS configured? Look for `cors({ origin: '*', credentials: true })` — this is dangerous (allows credential theft from any origin). Origin should be a specific domain or validated callback.
- **Middleware order** — Auth middleware must come before route handlers. A common mistake is defining public routes after auth middleware but accidentally protecting them, or worse, defining protected routes before auth middleware.

```javascript
// DANGEROUS — rate limiting after routes means it's never reached
app.get('/api/data', handler);
app.use(rateLimiter); // too late!
```

## 2. Route Security

- **Parameter injection** — Express `req.params`, `req.query`, and `req.body` are all user-controlled. Check for direct use in database queries or shell commands.
- **Route regex** — Express supports regex routes. Complex regexes can cause ReDoS (Regular Expression Denial of Service).
- **Method override** — If `method-override` middleware is installed, attackers can change GET to DELETE via headers or query params.
- **Path traversal** — `req.params.filename` used in file operations without sanitization allows `../../etc/passwd` attacks.

## 3. Session & Auth

- **express-session** — Check `secret` (must be strong, not default), `cookie.secure` (must be true in production), `cookie.httpOnly` (must be true), `cookie.sameSite` (should be 'strict' or 'lax').
- **Session store** — Default MemoryStore leaks memory and doesn't scale. Production should use Redis, MongoDB, or PostgreSQL session store.
- **Passport.js** — If used, check serialization/deserialization. Verify `passport.authenticate()` is actually called on protected routes (easy to forget).

## 4. Error Handling

- **Default error handler** — Express's default error handler sends stack traces in development. Check `NODE_ENV` — if it's not set to 'production', stack traces leak in production.
- **Custom error handler** — Should be the last middleware. Must not expose internal details.
- **Unhandled promises** — Express 4 doesn't catch async errors. Check for `async` handlers without try/catch or an async error wrapper.

```javascript
// VULNERABLE — unhandled rejection crashes the server
app.get('/api/data', async (req, res) => {
  const data = await db.query(req.query.id); // throws = crash
  res.json(data);
});
```

## 5. Request Parsing

- **Body size limits** — Is `express.json({ limit: '...' })` set? Default is 100kb, but if overridden to something large, it's a DoS vector.
- **Content-Type validation** — Does the app validate Content-Type headers? Sending unexpected content types can bypass validation.
- **File uploads** — If using `multer`, check file size limits, allowed MIME types, and storage destination.

## 6. Static Files & CORS

- **express.static()** — Check what directory is served. Serving the project root exposes source code and `.env` files.
- **dotfiles option** — Default is 'ignore' which is safe, but check for `dotfiles: 'allow'`.
- **Directory listing** — `serve-index` middleware enables directory listing — should never be on in production.
