import { PGlite } from '@electric-sql/pglite'
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto'
import { readFileSync, readdirSync } from 'node:fs'

export type DbRole = 'anon' | 'authenticated' | 'service_role'

/** Fresh in-memory Postgres with the Supabase stub + ALL real migrations applied. */
export async function createDb() {
  const db = new PGlite({ extensions: { pgcrypto } })
  await db.exec(readFileSync('tests/db/supabase-stub.sql', 'utf8'))
  for (const f of readdirSync('supabase/migrations').sort()) {
    await db.exec(readFileSync(`supabase/migrations/${f}`, 'utf8'))
  }
  return db
}

/** Run a callback as a given Postgres role with a given "logged-in user id" (like a JWT would set). */
export async function as<T>(db: PGlite, role: DbRole, uid: string | null, fn: () => Promise<T>): Promise<T> {
  await db.exec(`select set_config('request.jwt.claim.sub', '${uid ?? ''}', false)`)
  await db.exec(`set role ${role}`)
  try {
    return await fn()
  } finally {
    await db.exec('reset role')
    await db.exec(`select set_config('request.jwt.claim.sub', '', false)`)
  }
}

export async function mkUser(db: PGlite, email: string, meta: object = {}) {
  const r = await db.query<{ id: string }>(
    `insert into auth.users (email, raw_user_meta_data) values ($1, $2::jsonb) returning id`,
    [email, JSON.stringify(meta)],
  )
  return r.rows[0].id
}

export async function mkDoc(db: PGlite, ownerId: string, title = 'Doc') {
  const r = await db.query<{ id: string }>(
    `insert into public.documents (owner_id, owner_email, title, original_filename, mime_type, size_bytes, sha256, storage_path)
     select id, email, $2, 'f.pdf', 'application/pdf', 10, repeat('a', 64), id::text || '/' || gen_random_uuid()::text
     from public.profiles where id = $1::uuid returning id`,
    [ownerId, title],
  )
  return r.rows[0].id
}

export async function grant(db: PGlite, docId: string, granteeId: string, by: string, permission: 'read' | 'edit') {
  await db.query(
    `insert into public.document_grants (document_id, grantee_id, permission, granted_by) values ($1,$2,$3,$4)`,
    [docId, granteeId, permission, by],
  )
}

export async function audit(db: PGlite, action = 'document.read', outcome = 'success', actor: string | null = null, details: object = {}) {
  await as(db, 'service_role', null, () =>
    db.query(
      `insert into public.audit_log (request_id, actor_id, action, outcome, details, prev_hash, row_hash)
       values (gen_random_uuid(), $1, $2, $3, $4::jsonb, 'client-supplied', 'client-supplied')`,
      [actor, action, outcome, JSON.stringify(details)],
    ),
  )
}
