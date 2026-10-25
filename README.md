# TrustVault — Secure Document Sharing Platform

A document-sharing app where **the server and database, not the React UI, decide who can see what**.

Stack: React + Vite + TypeScript · Tailwind CSS 4 · Supabase Auth · Supabase PostgreSQL with Row-Level Security · private Supabase Storage · Supabase Edge Functions (Deno/TypeScript) · Vitest.

> **Status honesty.** See [Verification status](#verification-status) for exactly which tests have been executed and which you must still run yourself. Nothing here has been deployed by the author of this file; deployment is a step you perform (instructions below).

---

## 1. How it works (read this before your interview)

```
Browser (React)                       Supabase
─────────────                         ─────────────────────────────────────────────
Sign up / sign in  ───────────────►   Auth (verifies passwords, issues JWT)
                                      └─ trigger: creates profiles row, role = 'owner' ALWAYS

Read lists / details  ────────────►   PostgREST → Postgres, filtered by RLS
(documents, grants)                   (you only get rows you own or were granted)

Upload / download / edit / delete /   Edge Function ─► 1. verify JWT with Auth server
grant / revoke  ──────────────────►                    2. ask DB: document_permission(doc, me)
                                                         3. validate input (size, magic bytes…)
                                                         4. act using the service role
                                                         5. write an audit row (DB adds hash chain)

Direct storage access ────────────►   DENIED (no storage policy; restrictive policy on bucket)
```

**Key ideas**

| Idea | Where |
|---|---|
| Browser can only `SELECT`. No `INSERT/UPDATE/DELETE` privileges exist for browser roles on any sensitive table. | `0002_security_functions_and_rls.sql` |
| RLS limits `SELECT` to owner or grantee. **There is no admin rule**, so admins cannot read documents. | same file |
| One SQL function, `document_permission(doc, user)`, answers "owner / edit / read / none". Edge Functions and RLS use the same logic. | same file |
| Files live in a **private** bucket. Only Edge Functions (service role) touch it. | `0004_private_storage.sql` |
| **Downloads stream bytes through an Edge Function** that re-checks the live grant table on every request. There is no signed URL to outlive a revocation. | `download-document/index.ts` |
| File type is decided by **magic bytes on the server**, not by extension or the browser's claim. | `_shared/validate.ts` |
| Roles are fixed at signup (`owner`), changed only via SQL, and a trigger blocks role changes from any signed-in API user. | `0001_core_schema.sql` |
| Audit log: only Edge Functions insert; `UPDATE/DELETE/TRUNCATE` are blocked by triggers; each row is hash-chained by the **database** (not the function). | `0003_audit_integrity.sql` |
| `verify_jwt = false` in `config.toml`: we verify the token ourselves so *unauthenticated attempts can be audited*, and the public anon key can never pass as a user. | `_shared/auth.ts` |

---

## 2. Project layout

```
supabase/
  config.toml                      function settings
  migrations/0001…0004_*.sql       tables, RLS, audit integrity, private bucket
  functions/_shared/               validate, http, auth, audit, documents helpers
  functions/<name>/index.ts        upload-document, get-document, download-document,
                                   update-document, delete-document,
                                   grant-permission, revoke-permission
src/                               React app (pages, auth context, API client)
tests/unit/                        validation unit tests (no Supabase needed)
tests/db/                          RLS / trigger / audit tests on a real Postgres (PGlite, no Supabase needed)
tests/integration/                 LIVE security tests against YOUR Supabase project
THREATS.md  PROMPTS.md  README.md
```

---

## 3. Setup (about 20–30 minutes)

### 3.1 Prerequisites
Node.js 20+ (22 recommended), a free [Supabase](https://supabase.com) account, a GitHub account, a [Vercel](https://vercel.com) account. Docker is **not** required.

### 3.2 Install
```bash
npm install
```

### 3.3 Create your Supabase project and collect your own values
1. Supabase Dashboard → **New project** (free plan). Save the database password somewhere private.
2. **Project Settings → API** (or **API Keys**). Copy:
   - **Project URL** → `https://<ref>.supabase.co`
   - **anon / publishable key** → safe for the frontend
   - **service_role / secret key** → **SECRET**. Used only for the tests' `.env.test`. Never in the frontend, GitHub or Vercel.
3. **Authentication → Providers → Email**: for quick development you may turn **Confirm email** off. Otherwise real confirmation emails are required, and the free built-in email sender is heavily rate-limited.

### 3.4 Create the database (choose ONE option)

**Option A: SQL Editor (no CLI).** Open Dashboard → **SQL Editor**, then paste and run these files **in order**, one at a time, each must say "Success":
`supabase/migrations/0001_core_schema.sql` → `0002_…` → `0003_…` → `0004_…`

**Option B: CLI.**
```bash
npx supabase login
npx supabase link --project-ref <your-project-ref>
npx supabase db push
```

### 3.5 Deploy the Edge Functions
```bash
npx supabase login                       # skip if already done
npx supabase link --project-ref <your-project-ref>   # skip if already done
npx supabase functions deploy --use-api  # deploys all 7 functions; --use-api avoids needing Docker
```
`SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are injected into functions automatically by Supabase; you do not set them. Check Dashboard → **Edge Functions** shows all 7. (The JWT toggle showing *off* is intentional, see the table above.)

After you know your frontend URL (3.8), restrict browser origins:
```bash
npx supabase secrets set ALLOWED_ORIGINS=https://<your-app>.vercel.app,http://localhost:5173
```

### 3.6 Create the first administrator (SQL only, by design)
There is no UI or API to become admin. Register normally in the app first, then in **SQL Editor** run:
```sql
update public.profiles set role = 'admin' where email = 'you@example.com';
```
(Use `'viewer'` the same way to make a read-only account.)

### 3.7 Configure environment files
```bash
cp .env.example .env              # frontend: URL + anon/publishable key
cp .env.test.example .env.test    # tests only: also contains the service-role key
```
Fill them with **your own** values. `.env*` files are git-ignored.

### 3.8 Run locally
```bash
npm run dev        # http://localhost:5173
```

---

## 4. Tests

| Command | Needs Supabase? | What it covers |
|---|---|---|
| `npm test` | No | Unit tests + database tests (runs the real migrations in an in-process Postgres) |
| `npm run test:unit` | No | File-signature, size, input validation, filename/header safety |
| `npm run test:db` | No | RLS isolation, no direct writes, role-escalation triggers, admin has no document access, audit append-only + hash chain + tamper detection, storage bucket closed |
| `npm run test:security` | **Yes (your project)** | End-to-end: unauthenticated, cross-user, read vs edit grant, revocation, direct REST + Storage access, self-promotion, admin cannot read contents, upload validation, audit trail |

`test:security` creates throw-away users (`tv-…@example.test`) and removes them and their files afterwards. Audit rows remain because the audit log is append-only by design. It **fails loudly** if `.env.test` is missing (it does not silently skip).

Also: `npm run build` (type-check + production build).

---

## 5. Deploy the frontend (Vercel)
1. Push to GitHub (below).
2. Vercel → **Add New → Project** → import the repo. Framework preset: **Vite**. Build `npm run build`, output `dist`.
3. **Environment Variables**: add only `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY`. **Do not add the service-role key.**
4. Deploy. `vercel.json` already rewrites all routes to `index.html`.
5. Supabase → **Authentication → URL Configuration**: set **Site URL** to your Vercel URL and add it to **Redirect URLs**.
6. Set `ALLOWED_ORIGINS` (3.5) to your Vercel URL.
7. Smoke-test the live site: register, upload, share with a second account, revoke, confirm the second account is denied.

## 6. GitHub (no secrets!)
```bash
git init && git add . && git status     # confirm NO .env / .env.test appears
git commit -m "TrustVault: initial secure foundation"
git branch -M main
git remote add origin https://github.com/<you>/trustvault.git
git push -u origin main
```
Commit in small steps as you work: PROMPTS.md needs **real** commit links.

---

## 7. Verification status

Last verified in the authoring sandbox (Node 22, Deno 2.9.6, no internet access to Supabase):

| Check | Result |
|---|---|
| `npm run build` (TypeScript + Vite production build) | Executed: passed |
| Unit tests (`tests/unit`) | Executed: 10 passed |
| Database tests (`tests/db`) on the real migrations in PGlite | Executed: 27 passed |
| Mutation check: breaking the documents policy / adding an admin bypass makes DB tests fail | Executed: 3 and 2 tests failed respectively, as intended |
| Edge Functions type-check (`deno check`, all 7) | Executed: passed |
| Bundle scan for service-role strings | Executed: none found |
| Edge Functions behaviour on real Supabase | **Not executed.** Type-checked only |
| `tests/integration/security.test.ts` (live) | **Written, NOT executed. You must run it** |
| Real Supabase Storage / Auth / PostgREST behaviour | **Not executed** here |
| Vercel deployment | **Not done** |

The PGlite tests prove the SQL logic (policies, privileges, triggers, hash chain). They use a small stub of Supabase's `auth`/`storage` schemas, so they cannot prove everything about hosted Supabase. That is what `test:security` is for.

## 8. Known limitations
See [THREATS.md](THREATS.md), section "Residual risks". In short: no malware scanning, no rate limiting, no MFA, an already-downloaded file cannot be un-downloaded, and the audit log is tamper-**evident** not tamper-**proof**.
