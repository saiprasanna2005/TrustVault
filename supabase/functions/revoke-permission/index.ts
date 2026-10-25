// POST JSON: { document_id, grantee_id }   Owner only.
import { serve, fail, json, readJson } from '../_shared/http.ts'
import { getPermission, requireActor } from '../_shared/auth.ts'
import { audit } from '../_shared/audit.ts'
import { denyInsufficient, denyNoAccess } from '../_shared/documents.ts'
import { isUuid } from '../_shared/validate.ts'

serve('revoke-permission', async (ctx) => {
  const auth = await requireActor(ctx, 'permission.revoke')
  if (!auth.ok) return auth.response
  const actor = auth.actor

  const body = await readJson(ctx)
  if (!body || !isUuid(body.document_id) || !isUuid(body.grantee_id)) {
    return fail(ctx, 400, 'invalid_input', 'document_id and grantee_id must be valid IDs.')
  }
  const documentId = body.document_id

  const permission = await getPermission(ctx, documentId, actor.id)
  if (!permission) return denyNoAccess(ctx, actor, 'permission.revoke', documentId)
  if (permission !== 'owner') {
    return denyInsufficient(ctx, actor, 'permission.revoke', documentId, 'not_owner', 'Only the owner can revoke access.', { permission })
  }

  // Deleting the grant row is the revocation. Every later download re-checks this table.
  const { data: removed, error } = await ctx.admin
    .from('document_grants').delete().eq('document_id', documentId).eq('grantee_id', body.grantee_id).select('permission')
  if (error) {
    console.error('revoke failed', error)
    await audit(ctx, actor, { action: 'permission.revoke', outcome: 'failure', documentId, targetUserId: body.grantee_id, details: { reason: 'db_error' } })
    return fail(ctx, 500, 'revoke_failed', 'The permission could not be revoked.')
  }
  if (!removed || removed.length === 0) {
    await audit(ctx, actor, { action: 'permission.revoke', outcome: 'failure', documentId, targetUserId: body.grantee_id, details: { reason: 'no_such_grant' } })
    return fail(ctx, 404, 'grant_not_found', 'That user does not have access to revoke.')
  }

  await audit(ctx, actor, {
    action: 'permission.revoke', outcome: 'success', documentId, targetUserId: body.grantee_id,
    details: { revoked: removed[0].permission },
  })
  return json(ctx, { revoked: true })
})
