# Next.js Security Audit — Framework-Specific Checks

This reference covers security patterns and pitfalls specific to Next.js (App Router and Pages Router). Read this alongside the main audit workflow when reviewing a Next.js project.

## Table of Contents

1. Route Discovery
2. Middleware & Auth
3. Server Components vs Client Components
4. API Route Patterns
5. Environment Variables
6. Server Actions
7. Image & File Handling
8. Build Output & Source Maps

---

## 1. Route Discovery

### App Router (`src/app/` or `app/`)
- API routes live in `app/api/**/route.ts` — each exports named functions for HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`)
- Page routes are `page.tsx` files — these are server-rendered by default
- `layout.tsx` files can contain auth wrappers but are NOT a security boundary (they don't prevent direct API access)
- Dynamic routes use `[param]` folders — check for IDOR where `[id]` is user-controlled
- Catch-all routes `[...slug]` can expose unexpected paths

### Pages Router (`pages/`)
- API routes in `pages/api/**/*.ts`
- Look for both App Router AND Pages Router — some projects mix them during migration, which creates duplicate or inconsistent endpoints

### What to flag:
- Any API route that lacks auth when it should have it
- Dynamic routes that don't validate the param belongs to the authenticated user
- Route handlers that accept methods they shouldn't (a GET handler that accidentally processes POST bodies)

## 2. Middleware & Auth

### `middleware.ts` (root level)
Next.js middleware runs at the edge before the request hits the route handler. It's the primary place for auth enforcement.

**Check:**
- Does `middleware.ts` exist? If not, auth is handled per-route (more error-prone).
- What does the `config.matcher` array cover? Commonly missed patterns:
  - `/api/:path*` — protects API routes
  - Missing specific routes that should be protected
  - Overly broad matchers that accidentally protect public routes
- Is the middleware actually checking auth, or just doing redirects?
- If using `next-auth`, is `withAuth` wrapper used correctly?

### NextAuth-specific:
- Check `[...nextauth]/route.ts` or `[...nextauth].ts` for configuration
- Look at session strategy (`jwt` vs `database`) — JWT sessions can't be server-side revoked
- Check `maxAge` — sessions lasting 30 days are common and usually too long
- Check `callbacks.jwt` and `callbacks.session` — do they properly propagate roles/permissions?
- Is `NEXTAUTH_SECRET` set and strong? (Should be 32+ random bytes)
- Is `NEXTAUTH_URL` set correctly for production?

### Common pitfalls:
- Auth check in `layout.tsx` but not in `route.ts` — attackers bypass the layout entirely by hitting the API directly
- Using `getSession()` in client components (which trusts the client) instead of `getServerSession()` in server code
- `next-auth` middleware that protects pages but not API routes

## 3. Server Components vs Client Components

### Security implications:
- **Server Components** (default in App Router) run only on the server — safe to use secrets, database queries, etc.
- **Client Components** (`"use client"`) run in the browser — any code here is visible to the user
- **The boundary matters**: if a server component passes data to a client component via props, that data is serialized and visible in the page source

### What to check:
- Are database queries or secret-dependent logic accidentally in client components?
- Are server component props leaking sensitive data into the client-side payload?
- Check the network tab — Next.js RSC payloads can contain data you didn't intend to expose

## 4. API Route Patterns

### Common security issues in Next.js API routes:

**Request body parsing:**
- Next.js App Router requires explicit `await request.json()` — check that errors are caught (malformed JSON shouldn't crash the route)
- Pages Router has automatic body parsing — check `config.api.bodyParser` settings

**Response data:**
- `NextResponse.json()` serializes whatever you pass — make sure you're not accidentally returning entire database objects with sensitive fields
- Check for `return new Response(...)` that might expose raw error details

**Method handling:**
- App Router uses named exports (`export async function GET`, `POST`, etc.) — verify that only intended methods are exported
- Pages Router uses `req.method` checks — look for missing method validation or fallthrough logic

**Error handling:**
- Are errors caught and returned with safe messages?
- Does a 500 response include stack traces or internal details?
- Is there a global error boundary for API routes?

## 5. Environment Variables

### Next.js-specific exposure:
- `NEXT_PUBLIC_*` variables are inlined into the client-side bundle at build time — NEVER use this prefix for secrets
- In `next.config.ts`, the `env` key also exposes values to the client
- `publicRuntimeConfig` in `next.config.ts` is client-accessible
- `serverRuntimeConfig` is server-only — but verify it's actually used correctly

### What to scan for:
```bash
# Find NEXT_PUBLIC_ usage of potentially sensitive vars
grep -r "NEXT_PUBLIC_" --include="*.ts" --include="*.tsx" --include="*.js"

# Find env vars in next.config
grep -A 10 "env:" next.config.*
grep -A 10 "publicRuntimeConfig" next.config.*
```

## 6. Server Actions

### What are they:
Server Actions (`"use server"` directive) allow client components to call server functions directly. They're essentially auto-generated API endpoints.

### Security implications:
- Every server action is a public endpoint — even if it's defined in a seemingly private file
- Auth checks must happen INSIDE the server action, not in the calling component
- Input validation is required — the client can send arbitrary data, not just what the form collects
- CSRF protection: Next.js adds some built-in protection, but verify it's not disabled

### What to check:
- Find all `"use server"` directives — each one is an attack surface
- Does each server action validate its inputs?
- Does each server action check auth?
- Are server actions doing anything destructive (delete, update) without confirmation?

## 7. Image & File Handling

### `next/image`:
- The `next/image` component proxies images through `/_next/image` — check `images.remotePatterns` in `next.config.ts`
- Overly broad patterns (e.g., `hostname: "**"`) allow the server to be used as an image proxy for any domain (SSRF risk)

### File uploads:
- Next.js doesn't have built-in file upload handling — check what library is used
- Look for file writes to the `public/` directory (publicly accessible)
- Check for path traversal in file names (`../../../etc/passwd`)

## 8. Build Output & Source Maps

### Source maps:
- By default, Next.js generates source maps in production — check `next.config.ts` for `productionBrowserSourceMaps`
- If enabled, your entire source code is downloadable via `/_next/static/chunks/*.js.map`
- Recommendation: disable in production or restrict access

### `.next/` directory:
- Should never be committed to git
- Contains server-side code, API routes, and potentially secrets
- Check `.gitignore` for `.next`

### Static exports:
- If using `output: 'export'`, verify no server-side secrets ended up in the static HTML
