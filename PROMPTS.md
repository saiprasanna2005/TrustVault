# PROMPTS.md — AI usage log

**Rules for this file:** every entry must be something that really happened, in your own words where possible. Add the date, what you asked, what the AI produced, what was wrong or weak, how *you* corrected it, and a link to the **real commit** after you make it. Do not backfill entries that did not happen. Delete the `<…>` placeholders only when you have the real value.

How to add an entry: after each AI-assisted step, `git commit`, copy the commit URL (GitHub → Commits → the commit), and fill in the "Commit" line.

---

## Entry 1 — 2026-10-24 — Project brief and implementation plan

**Prompt (summary).** I asked the AI to act as a senior full-stack developer and application-security mentor and help me build TrustVault with React/Vite/TypeScript, Tailwind, Supabase Auth, PostgreSQL with RLS, private Storage, Edge Functions, Vitest, GitHub and Vercel. I listed the requirements (auth, document management, permissions, backend security, audit trail, security tests, UI, documentation) and the rules (inspect the folder first, work in stages, run what can be run, no fabricated results or credentials, individual original work).

**What the AI produced.** It checked its environment (empty project folder; Node, npm and git available; no Deno, Supabase CLI or Docker; no network route to supabase.com), reported what it could and could not verify, and proposed a five-stage plan. Its first plan said downloads would use **a signed URL that expires in about 30 seconds**, and documented the leftover window as a limitation.

**What was wrong.** That design lets a revoked user keep using a URL that was issued before revocation, which conflicts with the requirement that revoked access be denied on every subsequent download.

**How I corrected it.** I told the AI not to rely on signed URLs and to use an authenticated Edge Function that checks current permissions and returns the file bytes. The AI changed the design: `download-document` re-checks the live grant on every request and streams the bytes; the storage bucket has no client access at all.

**Commit:** `<add the commit URL after you commit the scaffold + migrations>`

---

## Entry 2 — 2026-10-24 — First implementation pass (migrations, Edge Functions, tests, UI)

**Prompt (summary).** I asked the AI to start implementing now, prioritising: (1) schema/RLS/private storage, (2) Edge Functions, (3) security tests, (4) React frontend, (5) docs; to run builds and tests; to separate tests executed from tests only written; and not to invent credentials, commits or deployment status.

**What the AI produced.** Four SQL migrations, seven Edge Functions plus shared helpers, a Postgres-level test suite that runs the real migrations in an in-process database (PGlite), unit tests, a live integration test suite for my own Supabase project, the React app, and README/THREATS.

**Problems found while the AI ran its own tooling (real, from the tool output):**
- A database test helper used one SQL parameter as both `uuid` and `text` → Postgres error `operator does not exist: uuid = text`. The AI fixed the query casts.
- `tsc` reported a variable used before assignment in the live test file (`carolDoc`) and a wrong type in `vitest.config.ts` (`defineConfig` imported from `vite` instead of `vitest/config`). The AI removed the unused variable and fixed the import.
- The AI mutation-tested its own database tests by deliberately breaking the documents policy and adding an admin bypass; the tests failed as they should, then the files were restored.

**Not yet verified (be honest in interview):** the Edge Functions have been type-checked with Deno but **not executed**, and `tests/integration/security.test.ts` has **not been run** against a real Supabase project.

**What I still need to do / record myself:** `<run npm run test:security against my project and write down which tests passed/failed and what I fixed>`

**Commit:** `<add the commit URL(s)>`

---

## Entry 3 — `<date>` — `<title>`

**Prompt:** `<what I asked>`
**AI output:** `<what it produced>`
**What was wrong:** `<real problems I found>`
**How I corrected it:** `<what I changed and why>`
**Commit:** `<commit URL>`
