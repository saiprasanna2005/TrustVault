import { audit, type AuditAction } from './audit.ts'
import { fail, type Actor, type Ctx } from './http.ts'

/**
 * Who is calling? We ask the Supabase Auth server to validate the bearer token.
 * The public anon key is NOT a user token, so it fails here. The caller's id
 * comes from this verified token, never from the request body.
 */
export async function authenticate(ctx: Ctx): Promise<Actor | null> {
  const header = ctx.req.headers.get('authorization') ?? ''
  const match = header.match(/^Bearer\s+(\S+)$/i)
  if (!match) return null
  // const { data, error } = await ctx.admin.auth.getUser(match[1])
  // if (error || !data.user) return null
  const { data, error } = await ctx.admin.auth.getUser(match[1])

if (error) {
  console.error('[auth] getUser failed:', error.message)
  return null
}

if (!data.user) {
  console.error('[auth] getUser returned no user')
  return null
}
  // const { data: profile } = await ctx.admin.from('profiles').select('id, email, role').eq('id', data.user.id).maybeSingle()
  // return profile ? (profile as Actor) : null
  const { data: profile, error: profileError } = await ctx.admin
  .from('profiles')
  .select('id, email, role')
  .eq('id', data.user.id)
  .maybeSingle()

if (profileError) {
  console.error('[auth] profile lookup failed:', profileError.message)
  return null
}

if (!profile) {
  console.error('[auth] profile not found for authenticated user')
  return null
}

return profile as Actor
}

/** Authenticate or return a 401 (and write a "denied" audit event with no actor). */
export async function requireActor(
  ctx: Ctx,
  action: AuditAction,
): Promise<{ ok: true; actor: Actor } | { ok: false; response: Response }> {
  const actor = await authenticate(ctx)
  if (actor) return { ok: true, actor }
  await audit(ctx, null, { action, outcome: 'denied', details: { reason: 'unauthenticated' } })
  return { ok: false, response: fail(ctx, 401, 'unauthenticated', 'Please sign in.') }
}

/** 'owner' | 'edit' | 'read' | null, computed by the database function (no admin shortcut exists). */
export async function getPermission(ctx: Ctx, documentId: string, userId: string): Promise<'owner' | 'edit' | 'read' | null> {
  const { data, error } = await ctx.admin.rpc('document_permission', { p_document_id: documentId, p_user_id: userId })
  if (error) throw new Error(`permission lookup failed: ${error.message}`)
  return (data as 'owner' | 'edit' | 'read' | null) ?? null
}
