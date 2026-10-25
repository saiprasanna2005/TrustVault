import { describe, it, expect, beforeAll } from 'vitest'
import type { PGlite } from '@electric-sql/pglite'
import { createDb, as, mkUser, mkDoc, grant, audit } from './helpers'

// These tests run the REAL migrations inside an in-process Postgres (PGlite) and
// switch between database roles exactly like Supabase does for API requests.
let db: PGlite
let alice: string, bob: string, carol: string, admin: string
let aliceDoc: string

beforeAll(async () => {
  db = await createDb()
  alice = await mkUser(db, 'alice@example.test')
  bob = await mkUser(db, 'bob@example.test')
  carol = await mkUser(db, 'carol@example.test')
  admin = await mkUser(db, 'admin@example.test')
  // Admins are created from the SQL editor (auth.uid() is null there).
  await db.query(`update public.profiles set role = 'admin' where id = $1`, [admin])
  aliceDoc = await mkDoc(db, alice, 'Alice secret')
})

const ids = (rows: any[]) => rows.map((r) => r.id)

describe('roles and self-promotion', () => {
  it('signup always creates role=owner, even if metadata asks for admin', async () => {
    const evil = await mkUser(db, 'evil@example.test', { role: 'admin' })
    const r = await db.query<{ role: string }>(`select role from public.profiles where id = $1`, [evil])
    expect(r.rows[0].role).toBe('owner')
  })

  it('a signed-in user cannot UPDATE their own role (no privilege)', async () => {
    await expect(
      as(db, 'authenticated', bob, () => db.query(`update public.profiles set role = 'admin' where id = $1`, [bob])),
    ).rejects.toThrow(/permission denied/i)
    const r = await db.query<{ role: string }>(`select role from public.profiles where id = $1`, [bob])
    expect(r.rows[0].role).toBe('owner')
  })

  it('even if UPDATE were granted by mistake, the trigger still blocks role changes', async () => {
    await db.exec(`grant update on public.profiles to authenticated`)
    await db.exec(`create policy tmp_oops on public.profiles for update to authenticated using (true) with check (true)`)
    try {
      await expect(
        as(db, 'authenticated', bob, () => db.query(`update public.profiles set role = 'admin' where id = $1`, [bob])),
      ).rejects.toThrow(/cannot be changed/i)
    } finally {
      await db.exec(`drop policy tmp_oops on public.profiles`)
      await db.exec(`revoke update on public.profiles from authenticated`)
    }
    const r = await db.query<{ role: string }>(`select role from public.profiles where id = $1`, [bob])
    expect(r.rows[0].role).toBe('owner')
  })

  it('users cannot insert profiles or delete profiles', async () => {
    await expect(
      as(db, 'authenticated', bob, () => db.query(`insert into public.profiles (id, email, role) values (gen_random_uuid(), 'x@x.test', 'admin')`)),
    ).rejects.toThrow(/permission denied/i)
    await expect(
      as(db, 'authenticated', bob, () => db.query(`delete from public.profiles where id = $1`, [alice])),
    ).rejects.toThrow(/permission denied/i)
  })

  it('users only see their own profile; admin sees all', async () => {
    const asBob = await as(db, 'authenticated', bob, () => db.query<{ id: string }>(`select id from public.profiles`))
    expect(ids(asBob.rows)).toEqual([bob])
    const asAdmin = await as(db, 'authenticated', admin, () => db.query<{ id: string }>(`select id from public.profiles`))
    expect(asAdmin.rows.length).toBeGreaterThanOrEqual(5)
  })
})

describe('documents: row-level security', () => {
  it('owner sees own document; stranger sees nothing', async () => {
    const a = await as(db, 'authenticated', alice, () => db.query<{ id: string }>(`select id from public.documents`))
    expect(ids(a.rows)).toContain(aliceDoc)
    const b = await as(db, 'authenticated', bob, () => db.query<{ id: string }>(`select id from public.documents`))
    expect(b.rows).toHaveLength(0)
  })

  it('anonymous (not signed in) has no access at all', async () => {
    await expect(as(db, 'anon', null, () => db.query(`select * from public.documents`))).rejects.toThrow(/permission denied/i)
    await expect(as(db, 'anon', null, () => db.query(`select * from public.audit_log`))).rejects.toThrow(/permission denied/i)
    await expect(as(db, 'anon', null, () => db.query(`select * from public.document_grants`))).rejects.toThrow(/permission denied/i)
  })

  it('a grant makes the document visible; deleting the grant (revocation) hides it again', async () => {
    await grant(db, aliceDoc, bob, alice, 'read')
    const seen = await as(db, 'authenticated', bob, () => db.query<{ id: string }>(`select id from public.documents`))
    expect(ids(seen.rows)).toContain(aliceDoc)
    await db.query(`delete from public.document_grants where document_id = $1 and grantee_id = $2`, [aliceDoc, bob])
    const after = await as(db, 'authenticated', bob, () => db.query<{ id: string }>(`select id from public.documents`))
    expect(after.rows).toHaveLength(0)
  })

  it('administrators do NOT get access to documents through RLS', async () => {
    const r = await as(db, 'authenticated', admin, () => db.query(`select id from public.documents`))
    expect(r.rows).toHaveLength(0)
  })

  it('signed-in users cannot INSERT / UPDATE / DELETE documents directly, not even their own', async () => {
    await expect(
      as(db, 'authenticated', alice, () => db.query(`update public.documents set title = 'hacked' where id = $1`, [aliceDoc])),
    ).rejects.toThrow(/permission denied/i)
    await expect(
      as(db, 'authenticated', alice, () => db.query(`delete from public.documents where id = $1`, [aliceDoc])),
    ).rejects.toThrow(/permission denied/i)
    await expect(
      as(db, 'authenticated', alice, () =>
        db.query(`insert into public.documents (owner_id, owner_email, title, original_filename, mime_type, size_bytes, sha256, storage_path)
                  values ($1,'a@a.test','t','f.pdf','application/pdf',1,repeat('a',64),'p/q')`, [alice])),
    ).rejects.toThrow(/permission denied/i)
  })

  it('only title/description are editable; owner, hash and storage path are frozen (even for service_role)', async () => {
    await as(db, 'service_role', null, () => db.query(`update public.documents set title = 'New title' where id = $1`, [aliceDoc]))
    await expect(
      as(db, 'service_role', null, () => db.query(`update public.documents set owner_id = $1 where id = $2`, [bob, aliceDoc])),
    ).rejects.toThrow(/only title and description/i)
    await expect(
      as(db, 'service_role', null, () => db.query(`update public.documents set storage_path = 'other/path' where id = $1`, [aliceDoc])),
    ).rejects.toThrow(/only title and description/i)
  })

  it('DB constraints reject bad MIME type and oversized files', async () => {
    await expect(
      db.query(`insert into public.documents (owner_id, owner_email, title, original_filename, mime_type, size_bytes, sha256, storage_path)
                values ($1,'a@a.test','t','f.exe','application/x-msdownload',1,repeat('a',64),'p/z1')`, [alice]),
    ).rejects.toThrow()
    await expect(
      db.query(`insert into public.documents (owner_id, owner_email, title, original_filename, mime_type, size_bytes, sha256, storage_path)
                values ($1,'a@a.test','t','f.pdf','application/pdf',5242881,repeat('a',64),'p/z2')`, [alice]),
    ).rejects.toThrow()
  })
})

describe('document_permission() and grants visibility', () => {
  it('returns owner / edit / read / null, and gives admins nothing', async () => {
    await grant(db, aliceDoc, carol, alice, 'edit')
    const q = (u: string) =>
      as(db, 'service_role', null, () => db.query<{ p: string | null }>(`select public.document_permission($1, $2) as p`, [aliceDoc, u]))
    expect((await q(alice)).rows[0].p).toBe('owner')
    expect((await q(carol)).rows[0].p).toBe('edit')
    expect((await q(bob)).rows[0].p).toBeNull()
    expect((await q(admin)).rows[0].p).toBeNull()
  })

  it('ordinary users cannot call document_permission (no probing other users)', async () => {
    await expect(
      as(db, 'authenticated', bob, () => db.query(`select public.document_permission($1, $2)`, [aliceDoc, alice])),
    ).rejects.toThrow(/permission denied/i)
  })

  it('grantee sees only their own grant; owner sees all grants; a stranger sees none', async () => {
    await grant(db, aliceDoc, bob, alice, 'read')
    const c = await as(db, 'authenticated', carol, () => db.query<{ grantee_id: string }>(`select grantee_id from public.document_grants`))
    expect(c.rows.map((r) => r.grantee_id)).toEqual([carol])
    const a = await as(db, 'authenticated', alice, () => db.query<{ grantee_id: string }>(`select grantee_id from public.document_grants`))
    expect(a.rows.map((r) => r.grantee_id).sort()).toEqual([bob, carol].sort())
    const ad = await as(db, 'authenticated', admin, () => db.query(`select * from public.document_grants`))
    expect(ad.rows).toHaveLength(0)
    await db.query(`delete from public.document_grants where document_id = $1 and grantee_id = $2`, [aliceDoc, bob])
  })

  it('users cannot create grants for themselves directly', async () => {
    await expect(
      as(db, 'authenticated', bob, () =>
        db.query(`insert into public.document_grants (document_id, grantee_id, permission, granted_by) values ($1,$2,'edit',$2)`, [aliceDoc, bob])),
    ).rejects.toThrow(/permission denied/i)
  })

  it('deleting a document cascades to its grants', async () => {
    const d = await mkDoc(db, alice, 'temp')
    await grant(db, d, bob, alice, 'read')
    await db.query(`delete from public.documents where id = $1`, [d])
    const r = await db.query(`select 1 from public.document_grants where document_id = $1`, [d])
    expect(r.rows).toHaveLength(0)
  })
})

describe('audit log: access control, append-only, hash chain', () => {
  it('server-side insert works and the DATABASE (not the caller) sets hashes', async () => {
    await audit(db, 'document.upload', 'success', alice, { size_bytes: 10 })
    await audit(db, 'document.download', 'denied', bob, { reason: 'no_grant' })
    const r = await db.query<{ prev_hash: string; row_hash: string }>(`select prev_hash, row_hash from public.audit_log order by created_at, id`)
    expect(r.rows[0].prev_hash).toBe('0'.repeat(64))
    expect(r.rows[0].row_hash).toMatch(/^[0-9a-f]{64}$/) // 'client-supplied' was overwritten
    expect(r.rows[1].prev_hash).toBe(r.rows[0].row_hash) // chained
  })

  it('ordinary users cannot read, insert, update or delete audit rows', async () => {
    const seen = await as(db, 'authenticated', bob, () => db.query(`select * from public.audit_log`))
    expect(seen.rows).toHaveLength(0)
    for (const sql of [
      `insert into public.audit_log (request_id, action, outcome, prev_hash, row_hash) values (gen_random_uuid(),'document.read','success','x','y')`,
      `update public.audit_log set outcome = 'success'`,
      `delete from public.audit_log`,
    ]) {
      await expect(as(db, 'authenticated', bob, () => db.query(sql))).rejects.toThrow(/permission denied/i)
    }
  })

  it('admins can read the audit log', async () => {
    const r = await as(db, 'authenticated', admin, () => db.query(`select * from public.audit_log`))
    expect(r.rows.length).toBeGreaterThanOrEqual(2)
  })

  it('actions outside the allowed list are rejected (cannot forge arbitrary event names)', async () => {
    await expect(
      as(db, 'service_role', null, () =>
        db.query(`insert into public.audit_log (request_id, action, outcome, prev_hash, row_hash) values (gen_random_uuid(),'admin.is.great','success','x','y')`)),
    ).rejects.toThrow()
  })

  it('UPDATE, DELETE and TRUNCATE are blocked even for the service role', async () => {
    await expect(as(db, 'service_role', null, () => db.query(`update public.audit_log set outcome = 'success'`))).rejects.toThrow(/append-only/i)
    await expect(as(db, 'service_role', null, () => db.query(`delete from public.audit_log`))).rejects.toThrow(/append-only/i)
    await expect(as(db, 'service_role', null, () => db.query(`truncate public.audit_log`))).rejects.toThrow(/append-only/i)
  })

  it('verify_audit_chain is admin-only and reports a valid chain', async () => {
    await expect(as(db, 'authenticated', bob, () => db.query(`select * from public.verify_audit_chain()`))).rejects.toThrow(/permission denied|not authorised/i)
    const r = await as(db, 'authenticated', admin, () => db.query<{ valid: boolean; checked: string }>(`select * from public.verify_audit_chain()`))
    expect(r.rows[0].valid).toBe(true)
    expect(Number(r.rows[0].checked)).toBeGreaterThanOrEqual(2)
  })

  it('TAMPER EVIDENCE: a privileged person who disables the trigger and edits history is detected', async () => {
    // This simulates the honest limitation: the database owner CAN rewrite rows,
    // but the chain then fails verification.
    await db.exec(`alter table public.audit_log disable trigger audit_log_no_update_delete`)
    await db.exec(`update public.audit_log set outcome = 'success' where action = 'document.download'`)
    await db.exec(`alter table public.audit_log enable trigger audit_log_no_update_delete`)
    const r = await as(db, 'authenticated', admin, () => db.query<{ valid: boolean; first_bad_id: string }>(`select * from public.verify_audit_chain()`))
    expect(r.rows[0].valid).toBe(false)
    expect(r.rows[0].first_bad_id).not.toBeNull()
  })
})

describe('private storage bucket', () => {
  it('bucket is private with size and MIME limits', async () => {
    const r = await db.query<any>(`select public, file_size_limit, allowed_mime_types from storage.buckets where id = 'documents'`)
    expect(r.rows[0].public).toBe(false)
    expect(Number(r.rows[0].file_size_limit)).toBe(5242880)
    expect(r.rows[0].allowed_mime_types).toEqual(['application/pdf', 'image/png', 'image/jpeg'])
  })

  it('browser roles cannot list, read or upload objects in the documents bucket', async () => {
    await db.query(`insert into storage.objects (bucket_id, name) values ('documents', 'alice/file1')`)
    for (const [role, uid] of [['authenticated', alice], ['anon', null]] as const) {
      const r = await as(db, role, uid, () => db.query(`select * from storage.objects where bucket_id = 'documents'`))
      expect(r.rows).toHaveLength(0)
      await expect(
        as(db, role, uid, () => db.query(`insert into storage.objects (bucket_id, name) values ('documents', 'x/y')`)),
      ).rejects.toThrow(/row-level security|permission denied/i)
    }
  })

  it('stays closed even if someone later adds an "allow everything" storage policy', async () => {
    await db.exec(`create policy oops_allow_all on storage.objects for all to authenticated using (true) with check (true)`)
    try {
      const r = await as(db, 'authenticated', alice, () => db.query(`select * from storage.objects where bucket_id = 'documents'`))
      expect(r.rows).toHaveLength(0)
    } finally {
      await db.exec(`drop policy oops_allow_all on storage.objects`)
    }
  })
})
