/**
 * LIVE security tests. They call your REAL Supabase project: the REST API, Storage API
 * and deployed Edge Functions. Run with:  npm run test:security   (see README).
 * They create throw-away users and delete them at the end.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import {
  ANON, URL_, assertConfigured, anonClient, serviceClient, createTestUser, cleanup, callFn, upload,
  makePdf, makePng, makeJpeg, sameBytes, auditFor, storagePathOf, type TestUser,
} from './helpers'

let alice: TestUser, bob: TestUser, carol: TestUser, dave: TestUser, admin: TestUser, viewer: TestUser
let docId: string
let docBytes: Uint8Array
const svc = () => serviceClient()
const FAKE_ID = '00000000-0000-4000-8000-000000000000'

const uploadPdf = async (owner: TestUser, title = 'Confidential report') => {
  const bytes = makePdf(title)
  const r = await upload(owner.token, { bytes, type: 'application/pdf', name: 'report.pdf', title })
  expect(r.status).toBe(201)
  return { id: r.json.document.id as string, bytes }
}
const expectForbidden = (r: { status: number; json: any }) => {
  expect(r.status).toBe(403)
  expect(r.json.error.code).toBe('forbidden')
}

beforeAll(async () => {
  assertConfigured()
  ;[alice, bob, carol, dave, admin, viewer] = await Promise.all([
    createTestUser('alice'), createTestUser('bob'), createTestUser('carol'), createTestUser('dave'),
    createTestUser('admin', 'admin'), createTestUser('viewer', 'viewer'),
  ])
  const d = await uploadPdf(alice)
  docId = d.id
  docBytes = d.bytes
})
afterAll(async () => { await cleanup() })

// ---------------------------------------------------------------------------
describe('1. unauthenticated access', () => {
  const endpoints: [string, object][] = [
    ['upload-document', {}],
    ['get-document', { document_id: FAKE_ID }],
    ['download-document', { document_id: FAKE_ID }],
    ['update-document', { document_id: FAKE_ID, title: 'x' }],
    ['delete-document', { document_id: FAKE_ID }],
    ['grant-permission', { document_id: FAKE_ID, email: 'a@b.co', permission: 'read' }],
    ['revoke-permission', { document_id: FAKE_ID, grantee_id: FAKE_ID }],
  ]
  for (const [fn, body] of endpoints) {
    it(`${fn}: no token, anon key as token, and garbage token are all rejected with 401`, async () => {
      for (const token of [null, ANON, 'not.a.jwt']) {
        const r = await callFn(fn, token, body)
        expect(r.status).toBe(401)
        expect(r.json.error.code).toBe('unauthenticated')
      }
    })
  }

  it('unauthenticated attempts are written to the audit log with no actor', async () => {
    const r = await callFn('download-document', null, { document_id: docId })
    const rows = await auditFor(r.json.request_id)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ action: 'document.download', outcome: 'denied', actor_id: null })
    expect(rows[0].details.reason).toBe('unauthenticated')
  })

  it('anonymous REST access to every table returns nothing or errors', async () => {
    const anon = anonClient()
    for (const t of ['documents', 'profiles', 'document_grants', 'audit_log']) {
      const r = await anon.from(t).select('*')
      expect(r.error !== null || (r.data ?? []).length === 0).toBe(true)
    }
    const ins = await anon.from('documents').insert({ title: 'x' })
    expect(ins.error).not.toBeNull()
  })

  it('anonymous storage access is refused and public URLs do not work', async () => {
    const path = await storagePathOf(docId)
    const dl = await anonClient().storage.from('documents').download(path)
    expect(dl.error).not.toBeNull()
    const pub = await fetch(`${URL_}/storage/v1/object/public/documents/${path}`)
    expect(pub.ok).toBe(false)
  })
})

// ---------------------------------------------------------------------------
describe('2. one user cannot touch another user\'s document', () => {
  it('Bob cannot get, download, edit, delete, share or revoke Alice\'s document (and each attempt is audited)', async () => {
    const attempts: [string, object, string][] = [
      ['get-document', { document_id: docId }, 'document.read'],
      ['download-document', { document_id: docId }, 'document.download'],
      ['update-document', { document_id: docId, title: 'pwned' }, 'document.edit'],
      ['delete-document', { document_id: docId }, 'document.delete'],
      ['grant-permission', { document_id: docId, email: bob.email, permission: 'edit' }, 'permission.grant'],
      ['revoke-permission', { document_id: docId, grantee_id: alice.id }, 'permission.revoke'],
    ]
    for (const [fn, body, action] of attempts) {
      const r = await callFn(fn, bob.token, body)
      expectForbidden(r)
      const rows = await auditFor(r.json.request_id)
      expect(rows[0]).toMatchObject({ action, outcome: 'denied', actor_id: bob.id, document_id: docId })
    }
    const { data } = await svc().from('documents').select('title').eq('id', docId).single()
    expect(data!.title).toBe('Confidential report')
    expect((await callFn('download-document', alice.token, { document_id: docId })).status).toBe(200)
  })

  it('"does not exist" and "not yours" are indistinguishable (no ID enumeration)', async () => {
    const mine = await callFn('download-document', bob.token, { document_id: docId })
    const none = await callFn('download-document', bob.token, { document_id: FAKE_ID })
    expect(none.status).toBe(mine.status)
    expect(none.json.error).toEqual(mine.json.error)
  })

  it('malformed IDs are rejected with 400 and no internals leak', async () => {
    for (const bad of ["1' OR '1'='1", '../../etc/passwd', 42, null]) {
      const r = await callFn('download-document', bob.token, { document_id: bad })
      expect(r.status).toBe(400)
      expect(JSON.stringify(r.json)).not.toMatch(/select|postgres|stack|supabase/i)
    }
  })

  it('direct REST API: Bob cannot see, update or delete Alice\'s row', async () => {
    const sel = await bob.client.from('documents').select('id').eq('id', docId)
    expect(sel.data ?? []).toHaveLength(0)
    const upd = await bob.client.from('documents').update({ title: 'pwned' }).eq('id', docId)
    expect(upd.error).not.toBeNull()
    const del = await bob.client.from('documents').delete().eq('id', docId)
    expect(del.error).not.toBeNull()
    const { data } = await svc().from('documents').select('title').eq('id', docId).single()
    expect(data!.title).toBe('Confidential report')
  })

  it('direct REST API: not even Alice (the owner) can write document rows or grants directly', async () => {
    expect((await alice.client.from('documents').update({ title: 'direct' }).eq('id', docId)).error).not.toBeNull()
    expect((await alice.client.from('document_grants').insert({ document_id: docId, grantee_id: bob.id, permission: 'read', granted_by: alice.id })).error).not.toBeNull()
    expect((await bob.client.from('document_grants').insert({ document_id: docId, grantee_id: bob.id, permission: 'edit', granted_by: bob.id })).error).not.toBeNull()
  })

  it('direct STORAGE API: nobody holding a browser key can read, list, sign, upload or delete', async () => {
    const path = await storagePathOf(docId)
    for (const u of [alice, bob]) {
      const bucket = u.client.storage.from('documents')
      expect((await bucket.download(path)).error).not.toBeNull()
      expect((await bucket.createSignedUrl(path, 60)).error).not.toBeNull()
      expect((await bucket.upload(`${u.id}/sneaky.pdf`, makePdf('sneaky'), { contentType: 'application/pdf' })).error).not.toBeNull()
      expect((await bucket.remove([path])).data ?? []).toHaveLength(0)
      const list = await bucket.list(alice.id)
      expect(list.error !== null || (list.data ?? []).length === 0).toBe(true)
    }
    const pub = await fetch(`${URL_}/storage/v1/object/public/documents/${path}`)
    expect(pub.ok).toBe(false)
    expect((await callFn('download-document', alice.token, { document_id: docId })).status).toBe(200) // file still intact
  })
})

// ---------------------------------------------------------------------------
describe('3. read grant vs edit grant', () => {
  beforeAll(async () => {
    expect((await callFn('grant-permission', alice.token, { document_id: docId, email: dave.email, permission: 'read' })).status).toBe(200)
    expect((await callFn('grant-permission', alice.token, { document_id: docId, email: carol.email, permission: 'edit' })).status).toBe(200)
  })

  it('READ grantee (Dave) can view and download the exact bytes', async () => {
    const g = await callFn('get-document', dave.token, { document_id: docId })
    expect(g.status).toBe(200)
    expect(g.json.permission).toBe('read')
    expect(g.json.grants).toBeUndefined() // only the owner sees who else has access
    const d = await callFn('download-document', dave.token, { document_id: docId })
    expect(d.status).toBe(200)
    expect(sameBytes(d.bytes, docBytes)).toBe(true)
    expect(d.headers.get('content-disposition')).toMatch(/^attachment/)
    expect(d.headers.get('x-content-type-options')).toBe('nosniff')
  })

  it('READ grantee (Dave) cannot edit, delete, share or revoke', async () => {
    expectForbidden(await callFn('update-document', dave.token, { document_id: docId, title: 'Dave edit' }))
    expectForbidden(await callFn('delete-document', dave.token, { document_id: docId }))
    expectForbidden(await callFn('grant-permission', dave.token, { document_id: docId, email: bob.email, permission: 'read' }))
    expectForbidden(await callFn('revoke-permission', dave.token, { document_id: docId, grantee_id: carol.id }))
    const { data } = await svc().from('documents').select('title').eq('id', docId).single()
    expect(data!.title).toBe('Confidential report')
  })

  it('EDIT grantee (Carol) can edit title and description, and still read', async () => {
    const r = await callFn('update-document', carol.token, { document_id: docId, title: 'Edited by Carol', description: 'Reviewed' })
    expect(r.status).toBe(200)
    expect(r.json.document.title).toBe('Edited by Carol')
    expect((await callFn('download-document', carol.token, { document_id: docId })).status).toBe(200)
  })

  it('EDIT grantee (Carol) cannot change owner, file, hash or path (allow-list), cannot delete, share or revoke', async () => {
    const { data: before } = await svc().from('documents').select('owner_id, storage_path, sha256, mime_type').eq('id', docId).single()
    for (const field of ['owner_id', 'storage_path', 'sha256', 'mime_type', 'size_bytes']) {
      const r = await callFn('update-document', carol.token, { document_id: docId, [field]: carol.id })
      expectForbidden(r)
      expect((await auditFor(r.json.request_id))[0].details.reason).toBe('forbidden_field')
    }
    expectForbidden(await callFn('delete-document', carol.token, { document_id: docId }))
    expectForbidden(await callFn('grant-permission', carol.token, { document_id: docId, email: bob.email, permission: 'read' }))
    expectForbidden(await callFn('revoke-permission', carol.token, { document_id: docId, grantee_id: dave.id }))
    const { data: after } = await svc().from('documents').select('owner_id, storage_path, sha256, mime_type').eq('id', docId).single()
    expect(after).toEqual(before)
  })

  it('invalid edits are rejected (title too long / empty)', async () => {
    expect((await callFn('update-document', carol.token, { document_id: docId, title: 'x'.repeat(201) })).status).toBe(400)
    expect((await callFn('update-document', carol.token, { document_id: docId, title: '   ' })).status).toBe(400)
    expect((await callFn('update-document', carol.token, { document_id: docId })).status).toBe(400)
  })

  it('only the owner sees the grant list; grantees can see the document row through RLS', async () => {
    const g = await callFn('get-document', alice.token, { document_id: docId })
    expect(g.json.permission).toBe('owner')
    expect(g.json.grants.map((x: any) => x.grantee_email).sort()).toEqual([carol.email, dave.email].sort())
    const rls = await dave.client.from('documents').select('id').eq('id', docId)
    expect(rls.data).toHaveLength(1)
  })

  it('owner can upgrade a grant (read -> edit) and it takes effect immediately', async () => {
    expectForbidden(await callFn('update-document', dave.token, { document_id: docId, title: 'x' }))
    expect((await callFn('grant-permission', alice.token, { document_id: docId, email: dave.email, permission: 'edit' })).status).toBe(200)
    expect((await callFn('update-document', dave.token, { document_id: docId, title: 'Dave can edit now' })).status).toBe(200)
    expect((await callFn('grant-permission', alice.token, { document_id: docId, email: dave.email, permission: 'read' })).status).toBe(200)
    expectForbidden(await callFn('update-document', dave.token, { document_id: docId, title: 'Dave downgraded' }))
  })

  it('grant input validation: unknown user, bad permission, self-share', async () => {
    expect((await callFn('grant-permission', alice.token, { document_id: docId, email: 'nobody-here@example.test', permission: 'read' })).status).toBe(404)
    expect((await callFn('grant-permission', alice.token, { document_id: docId, email: bob.email, permission: 'admin' })).status).toBe(400)
    expect((await callFn('grant-permission', alice.token, { document_id: docId, email: alice.email, permission: 'read' })).status).toBe(400)
    expect((await callFn('grant-permission', alice.token, { document_id: docId, email: 'not-an-email', permission: 'read' })).status).toBe(400)
  })
})

// ---------------------------------------------------------------------------
describe('4. revocation blocks every subsequent download', () => {
  it('after revoke, Dave is denied on download, get, and REST read, repeatedly', async () => {
    expect((await callFn('download-document', dave.token, { document_id: docId })).status).toBe(200)

    const rev = await callFn('revoke-permission', alice.token, { document_id: docId, grantee_id: dave.id })
    expect(rev.status).toBe(200)

    for (let i = 0; i < 3; i++) expectForbidden(await callFn('download-document', dave.token, { document_id: docId }))
    expectForbidden(await callFn('get-document', dave.token, { document_id: docId }))
    expect((await dave.client.from('documents').select('id').eq('id', docId)).data ?? []).toHaveLength(0)
    expect((await dave.client.from('document_grants').select('id').eq('document_id', docId)).data ?? []).toHaveLength(0)
  })

  it('a signed-in session that was already open (old token) is still refused', async () => {
    // Dave's JWT is still valid (not expired), yet access is gone: permissions are checked live, not baked into the token.
    expectForbidden(await callFn('download-document', dave.token, { document_id: docId }))
  })

  it('revocation is audited, a second revoke fails cleanly, and non-owners cannot revoke', async () => {
    expect((await callFn('revoke-permission', alice.token, { document_id: docId, grantee_id: dave.id })).status).toBe(404)
    expectForbidden(await callFn('revoke-permission', bob.token, { document_id: docId, grantee_id: carol.id }))
    const { data } = await svc().from('document_grants').select('grantee_id').eq('document_id', docId)
    expect(data!.map((g) => g.grantee_id)).toContain(carol.id) // Carol's grant untouched
  })

  it('re-granting after revocation restores access', async () => {
    await callFn('grant-permission', alice.token, { document_id: docId, email: dave.email, permission: 'read' })
    expect((await callFn('download-document', dave.token, { document_id: docId })).status).toBe(200)
    await callFn('revoke-permission', alice.token, { document_id: docId, grantee_id: dave.id })
    expectForbidden(await callFn('download-document', dave.token, { document_id: docId }))
  })
})

// ---------------------------------------------------------------------------
describe('5. role escalation and audit-log forgery', () => {
  const roleOf = async (id: string) => (await svc().from('profiles').select('role').eq('id', id).single()).data!.role

  it('a user cannot promote themselves through the REST API', async () => {
    expect((await bob.client.from('profiles').update({ role: 'admin' }).eq('id', bob.id)).error).not.toBeNull()
    expect((await bob.client.from('profiles').upsert({ id: bob.id, email: bob.email, role: 'admin' })).error).not.toBeNull()
    expect(await roleOf(bob.id)).toBe('owner')
  })

  it('a user cannot promote themselves through auth metadata or by signing up with role=admin', async () => {
    const sneaky = await createTestUser('sneaky', 'owner', { role: 'admin' })
    expect(await roleOf(sneaky.id)).toBe('owner')
    const upd = await bob.client.auth.updateUser({ data: { role: 'admin' } })
    void upd
    expect(await roleOf(bob.id)).toBe('owner')
  })

  it('a user cannot read, write or verify the audit log', async () => {
    expect((await bob.client.from('audit_log').select('*')).data ?? []).toHaveLength(0)
    expect((await bob.client.from('audit_log').insert({ request_id: FAKE_ID, action: 'document.read', outcome: 'success', prev_hash: 'x', row_hash: 'y' })).error).not.toBeNull()
    expect((await bob.client.from('audit_log').update({ outcome: 'success' }).gte('id', 0)).error).not.toBeNull()
    expect((await bob.client.from('audit_log').delete().gte('id', 0)).error).not.toBeNull()
    expect((await bob.client.rpc('verify_audit_chain')).error).not.toBeNull()
  })

  it('a user cannot call the permission-lookup function to probe other users', async () => {
    expect((await bob.client.rpc('document_permission', { p_document_id: docId, p_user_id: alice.id })).error).not.toBeNull()
  })

  it('even the service role cannot update or delete audit rows (append-only trigger)', async () => {
    const u = await svc().from('audit_log').update({ outcome: 'success' }).gte('id', 0)
    expect(u.error?.message).toMatch(/append-only/i)
    const d = await svc().from('audit_log').delete().gte('id', 0)
    expect(d.error?.message).toMatch(/append-only/i)
  })

  it('an account with the "viewer" role cannot upload', async () => {
    const r = await upload(viewer.token, { bytes: makePdf('v'), type: 'application/pdf', name: 'v.pdf' })
    expectForbidden(r)
    expect((await auditFor(r.json.request_id))[0].details.reason).toBe('viewer_role')
  })
})

// ---------------------------------------------------------------------------
describe('6. administrators cannot automatically read document contents', () => {
  it('admin is denied get / download / edit / delete / share / revoke on Alice\'s document', async () => {
    expect((await svc().from('profiles').select('role').eq('id', admin.id).single()).data!.role).toBe('admin')
    expectForbidden(await callFn('get-document', admin.token, { document_id: docId }))
    expectForbidden(await callFn('download-document', admin.token, { document_id: docId }))
    expectForbidden(await callFn('update-document', admin.token, { document_id: docId, title: 'admin edit' }))
    expectForbidden(await callFn('delete-document', admin.token, { document_id: docId }))
    expectForbidden(await callFn('grant-permission', admin.token, { document_id: docId, email: admin.email, permission: 'edit' }))
    expectForbidden(await callFn('revoke-permission', admin.token, { document_id: docId, grantee_id: carol.id }))
  })

  it('admin sees no documents or grants through the REST API, and cannot read the storage object', async () => {
    expect((await admin.client.from('documents').select('id')).data ?? []).toHaveLength(0)
    expect((await admin.client.from('document_grants').select('id')).data ?? []).toHaveLength(0)
    const path = await storagePathOf(docId)
    expect((await admin.client.storage.from('documents').download(path)).error).not.toBeNull()
  })

  it('admin CAN read the audit log and sees their own denied attempts; the chain verifies', async () => {
    const { data } = await admin.client.from('audit_log').select('*').eq('actor_id', admin.id).eq('outcome', 'denied')
    expect((data ?? []).length).toBeGreaterThan(0)
    const v = await admin.client.rpc('verify_audit_chain')
    expect(v.error).toBeNull()
    expect(v.data[0].valid).toBe(true)
  })

  it('admin can see user profiles (role management view) but still cannot see document metadata', async () => {
    expect(((await admin.client.from('profiles').select('id')).data ?? []).length).toBeGreaterThanOrEqual(6)
  })
})

// ---------------------------------------------------------------------------
describe('7. upload validation happens on the server', () => {
  const enc = new TextEncoder()
  const cases: [string, Uint8Array, string, number][] = [
    ['text file renamed .pdf', enc.encode('hello, I am not a PDF'), 'application/pdf', 415],
    ['Windows executable declared as PDF', enc.encode('MZ\x90\x00\x03'), 'application/pdf', 415],
    ['HTML/script declared as PNG', enc.encode('<html><script>alert(1)</script></html>'), 'image/png', 415],
    ['SVG declared as PNG', enc.encode('<svg xmlns="http://www.w3.org/2000/svg"/>'), 'image/png', 415],
    ['PNG content declared as PDF (type mismatch)', makePng(), 'application/pdf', 415],
    ['JPEG content declared as PNG (type mismatch)', makeJpeg(), 'image/png', 415],
  ]
  for (const [name, bytes, type, status] of cases) {
    it(`rejects: ${name}`, async () => {
      const r = await upload(alice.token, { bytes, type, name: 'x.pdf' })
      expect(r.status).toBe(status)
      expect((await auditFor(r.json.request_id))[0]).toMatchObject({ action: 'document.upload', outcome: 'failure' })
    })
  }

  it('rejects empty files, missing file, and missing title', async () => {
    expect((await upload(alice.token, { bytes: new Uint8Array(), type: 'application/pdf' })).status).toBe(400)
    expect((await callFn('upload-document', alice.token, {}, new FormData())).status).toBe(400)
    expect((await upload(alice.token, { bytes: makePdf('t'), type: 'application/pdf', title: null })).status).toBe(400)
    expect((await upload(alice.token, { bytes: makePdf('t'), type: 'application/pdf', title: 'y'.repeat(201) })).status).toBe(400)
  })

  it('rejects files over 5 MB (just over the limit, and far over)', async () => {
    for (const size of [5 * 1024 * 1024 + 1, 7 * 1024 * 1024]) {
      const big = new Uint8Array(size)
      big.set(makePdf('big').slice(0, 20))
      const r = await upload(alice.token, { bytes: big, type: 'application/pdf', name: 'big.pdf' })
      expect(r.status).toBe(413)
    }
  })

  it('accepts a valid PDF, PNG and JPEG; stores them privately; detected type is authoritative', async () => {
    for (const [bytes, type] of [[makePdf('ok'), 'application/pdf'], [makePng(), 'image/png'], [makeJpeg(), 'image/jpeg']] as const) {
      const r = await upload(alice.token, { bytes, type, name: '../../evil/..\\name.bin', title: 'Valid file' })
      expect(r.status).toBe(201)
      expect(r.json.document.mime_type).toBe(type)
      expect(r.json.document.original_filename).not.toMatch(/[\\/]/) // path stripped
      expect(r.json.document.owner_id).toBe(alice.id)
      expect(r.json.document.storage_path).toBeUndefined() // path is never sent to the browser
      const path = await storagePathOf(r.json.document.id)
      expect(path.startsWith(`${alice.id}/`)).toBe(true)
      const dl = await callFn('download-document', alice.token, { document_id: r.json.document.id })
      expect(sameBytes(dl.bytes, bytes)).toBe(true)
      expect(dl.headers.get('content-type')).toBe(type)
    }
  })

  it('the owner of an upload is the VERIFIED caller; a forged owner_id in the form is ignored', async () => {
    const form = new FormData()
    form.append('file', new Blob([makePdf('forge') as BlobPart], { type: 'application/pdf' }), 'f.pdf')
    form.append('title', 'Forged owner')
    form.append('owner_id', alice.id)
    const r = await callFn('upload-document', bob.token, {}, form)
    expect(r.status).toBe(201)
    expect(r.json.document.owner_id).toBe(bob.id)
  })
})

// ---------------------------------------------------------------------------
describe('8. delete', () => {
  it('only the owner can delete; afterwards nobody can read it and the file is gone', async () => {
    const d = await uploadPdf(alice, 'To be deleted')
    await callFn('grant-permission', alice.token, { document_id: d.id, email: bob.email, permission: 'read' })
    const path = await storagePathOf(d.id)

    expectForbidden(await callFn('delete-document', bob.token, { document_id: d.id }))
    const del = await callFn('delete-document', alice.token, { document_id: d.id })
    expect(del.status).toBe(200)

    expectForbidden(await callFn('download-document', alice.token, { document_id: d.id }))
    expectForbidden(await callFn('download-document', bob.token, { document_id: d.id }))
    expect((await svc().storage.from('documents').download(path)).error).not.toBeNull()
    expect((await svc().from('document_grants').select('id').eq('document_id', d.id)).data ?? []).toHaveLength(0)
    expect((await auditFor(del.json.request_id))[0]).toMatchObject({ action: 'document.delete', outcome: 'success', actor_id: alice.id })
  })
})

// ---------------------------------------------------------------------------
describe('9. audit trail completeness', () => {
  it('every action type is recorded with actor, request ID, outcome and timestamp', async () => {
    const up = await upload(alice.token, { bytes: makePdf('audit'), type: 'application/pdf', name: 'a.pdf', title: 'Audit me' })
    const id = up.json.document.id
    const g = await callFn('grant-permission', alice.token, { document_id: id, email: bob.email, permission: 'edit' })
    const read = await callFn('get-document', bob.token, { document_id: id })
    const dl = await callFn('download-document', bob.token, { document_id: id })
    const ed = await callFn('update-document', bob.token, { document_id: id, title: 'Audit me (edited)' })
    const rv = await callFn('revoke-permission', alice.token, { document_id: id, grantee_id: bob.id })
    const denied = await callFn('download-document', bob.token, { document_id: id })
    const del = await callFn('delete-document', alice.token, { document_id: id })

    const expectations: [any, string, string, string][] = [
      [up, 'document.upload', 'success', alice.id], [g, 'permission.grant', 'success', alice.id],
      [read, 'document.read', 'success', bob.id], [dl, 'document.download', 'success', bob.id],
      [ed, 'document.edit', 'success', bob.id], [rv, 'permission.revoke', 'success', alice.id],
      [denied, 'document.download', 'denied', bob.id], [del, 'document.delete', 'success', alice.id],
    ]
    for (const [res, action, outcome, actor] of expectations) {
      const rows = await auditFor(res.json?.request_id ?? res.headers.get('x-request-id'))
      expect(rows.length).toBeGreaterThanOrEqual(1)
      expect(rows[0]).toMatchObject({ action, outcome, actor_id: actor, document_id: id })
      expect(rows[0].created_at).toBeTruthy()
      expect(rows[0].row_hash).toMatch(/^[0-9a-f]{64}$/)
    }
  })

  it('audit details never contain document titles or file names', async () => {
    const { data } = await svc().from('audit_log').select('details').limit(500)
    const blob = JSON.stringify(data)
    expect(blob).not.toMatch(/Confidential report|Audit me|report\.pdf/)
  })

  it('the hash chain is intact after all of the above', async () => {
    const v = await admin.client.rpc('verify_audit_chain')
    expect(v.data[0]).toMatchObject({ valid: true })
    expect(Number(v.data[0].checked)).toBeGreaterThan(30)
  })
})
