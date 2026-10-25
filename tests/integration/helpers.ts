import { createClient, type SupabaseClient } from '@supabase/supabase-js'

export const URL_ = process.env.SUPABASE_URL ?? ''
export const ANON = process.env.SUPABASE_ANON_KEY ?? ''
export const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY ?? ''

export function assertConfigured() {
  if (!URL_ || !ANON || !SERVICE) {
    throw new Error(
      'Security tests are NOT configured. Copy .env.test.example to .env.test and fill in ' +
        'SUPABASE_URL, SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY from your own Supabase project.',
    )
  }
}

const noSession = { auth: { persistSession: false, autoRefreshToken: false } }
export const serviceClient = (): SupabaseClient => createClient(URL_, SERVICE, noSession)
export const anonClient = (): SupabaseClient => createClient(URL_, ANON, noSession)

export interface TestUser { id: string; email: string; token: string; client: SupabaseClient }

const RUN = Math.random().toString(36).slice(2, 8)
const created: string[] = []

/** Creates a throw-away confirmed user (service role), optionally sets its role, then signs in as that user. */
export async function createTestUser(label: string, role: 'owner' | 'viewer' | 'admin' = 'owner', metadata: object = {}): Promise<TestUser> {
  const svc = serviceClient()
  const email = `tv-${RUN}-${label}@example.test`
  const password = `Pw-${RUN}-${Math.random().toString(36).slice(2)}!`
  const { data, error } = await svc.auth.admin.createUser({
    email, password, email_confirm: true, user_metadata: metadata, app_metadata: metadata,
  })
  if (error || !data.user) throw new Error(`createUser failed: ${error?.message}`)
  created.push(data.user.id)
  if (role !== 'owner') {
    // allowed here because the service role has no auth.uid(); the API trigger only blocks signed-in users
    const { error: e2 } = await svc.from('profiles').update({ role }).eq('id', data.user.id)
    if (e2) throw new Error(`set role failed: ${e2.message}`)
  }
  const client = anonClient()
  const { data: s, error: e3 } = await client.auth.signInWithPassword({ email, password })
  if (e3 || !s.session) throw new Error(`sign-in failed: ${e3?.message}`)
  return { id: data.user.id, email, token: s.session.access_token, client }
}

/** Delete test users (cascades to documents/grants) and their stored files. Audit rows stay (append-only). */
export async function cleanup() {
  const svc = serviceClient()
  if (created.length === 0) return
  const { data: docs } = await svc.from('documents').select('storage_path').in('owner_id', created)
  const paths = (docs ?? []).map((d) => d.storage_path)
  if (paths.length) await svc.storage.from('documents').remove(paths)
  for (const id of created) await svc.auth.admin.deleteUser(id)
}

export interface FnResult { status: number; json: any; bytes: Uint8Array; headers: Headers }

export async function callFn(name: string, token: string | null, body: unknown = {}, rawBody?: BodyInit, extra: Record<string, string> = {}): Promise<FnResult> {
  const headers: Record<string, string> = { apikey: ANON, ...extra }
  if (token) headers.Authorization = `Bearer ${token}`
  if (rawBody === undefined) headers['Content-Type'] = 'application/json'
  const res = await fetch(`${URL_}/functions/v1/${name}`, {
    method: 'POST', headers, body: rawBody ?? JSON.stringify(body),
  })
  const bytes = new Uint8Array(await res.arrayBuffer())
  let json: any = null
  if ((res.headers.get('content-type') ?? '').includes('application/json')) {
    try { json = JSON.parse(new TextDecoder().decode(bytes)) } catch { /* ignore */ }
  }
  return { status: res.status, json, bytes, headers: res.headers }
}

export async function upload(token: string | null, o: { bytes: Uint8Array; type: string; name?: string; title?: string | null; description?: string }) {
  const form = new FormData()
  form.append('file', new Blob([o.bytes as BlobPart], { type: o.type }), o.name ?? 'file')
  if (o.title !== null) form.append('title', o.title ?? 'Test document')
  if (o.description !== undefined) form.append('description', o.description)
  return callFn('upload-document', token, {}, form)
}

// ---- sample files (valid signatures; content made unique per call) ----
const enc = new TextEncoder()
export const makePdf = (tag = '') => enc.encode(`%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n% ${tag} ${Math.random()}`)
export const makePng = () => Uint8Array.from(atob('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='), (c) => c.charCodeAt(0))
export const makeJpeg = () => Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xd9])
export const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i])

/** Look up audit rows for one API request (service role bypasses RLS; used only for verification). */
export async function auditFor(requestId: string) {
  const { data, error } = await serviceClient().from('audit_log').select('*').eq('request_id', requestId)
  if (error) throw new Error(error.message)
  return data ?? []
}

export async function storagePathOf(docId: string): Promise<string> {
  const { data } = await serviceClient().from('documents').select('storage_path').eq('id', docId).single()
  return data!.storage_path as string
}
