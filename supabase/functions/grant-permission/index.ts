// POST JSON: { document_id, email, permission: 'read' | 'edit' }   Owner only.
import { serve, fail, json, readJson } from '../_shared/http.ts'
import { getPermission, requireActor } from '../_shared/auth.ts'
import { audit } from '../_shared/audit.ts'
import { denyInsufficient, denyNoAccess } from '../_shared/documents.ts'
import { isUuid, validateEmail } from '../_shared/validate.ts'

serve('grant-permission', async (ctx) => {
  const auth = await requireActor(ctx, 'permission.grant')
  if (!auth.ok) return auth.response
  const actor = auth.actor

  const body = await readJson(ctx)
  if (!body || !isUuid(body.document_id)) return fail(ctx, 400, 'invalid_input', 'A valid document_id is required.')
  const documentId = body.document_id

  // Authorisation first, validation second.
  const permission = await getPermission(ctx, documentId, actor.id)
  if (!permission) return denyNoAccess(ctx, actor, 'permission.grant', documentId)
  if (permission !== 'owner') {
    return denyInsufficient(ctx, actor, 'permission.grant', documentId, 'not_owner', 'Only the owner can share this document.', { permission })
  }

  const email = validateEmail(body.email)
  if (!email.ok) return fail(ctx, 400, 'invalid_input', email.error)
  if (body.permission !== 'read' && body.permission !== 'edit') {
    return fail(ctx, 400, 'invalid_input', "Permission must be 'read' or 'edit'.")
  }

  const { data: target } = await ctx.admin.from('profiles').select('id, email').eq('email', email.value).maybeSingle()
  if (!target) {
    await audit(ctx, actor, { action: 'permission.grant', outcome: 'failure', documentId, details: { reason: 'unknown_user' } })
    return fail(ctx, 404, 'user_not_found', 'No registered user has that email address.')
  }
  if (target.id === actor.id) return fail(ctx, 400, 'invalid_input', 'You already own this document.')

  const { data: before } = await ctx.admin
    .from('document_grants').select('permission').eq('document_id', documentId).eq('grantee_id', target.id).maybeSingle()

  const { data: grant, error } = await ctx.admin.from('document_grants').upsert(
    { document_id: documentId, grantee_id: target.id, permission: body.permission, granted_by: actor.id },
    { onConflict: 'document_id,grantee_id' },
  ).select('grantee_id, permission, created_at').single()
  if (error || !grant) {
    console.error('grant failed', error)
    await audit(ctx, actor, { action: 'permission.grant', outcome: 'failure', documentId, targetUserId: target.id, details: { reason: 'db_error' } })
    return fail(ctx, 500, 'grant_failed', 'The permission could not be saved.')
  }

  await audit(ctx, actor, {
    action: 'permission.grant', outcome: 'success', documentId, targetUserId: target.id,
    details: { permission: body.permission, previous: before?.permission ?? null },
  })
  return json(ctx, { grant: { ...grant, grantee_email: target.email } })
})
