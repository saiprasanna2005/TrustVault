// POST JSON: { document_id }   Owner only.
import { serve, fail, json, readJson } from '../_shared/http.ts'
import { getPermission, requireActor } from '../_shared/auth.ts'
import { audit } from '../_shared/audit.ts'
import { denyInsufficient, denyNoAccess } from '../_shared/documents.ts'
import { isUuid } from '../_shared/validate.ts'

serve('delete-document', async (ctx) => {
  const auth = await requireActor(ctx, 'document.delete')
  if (!auth.ok) return auth.response
  const actor = auth.actor

  const body = await readJson(ctx)
  if (!body || !isUuid(body.document_id)) return fail(ctx, 400, 'invalid_input', 'A valid document_id is required.')
  const documentId = body.document_id

  const permission = await getPermission(ctx, documentId, actor.id)
  if (!permission) return denyNoAccess(ctx, actor, 'document.delete', documentId)
  if (permission !== 'owner') {
    return denyInsufficient(ctx, actor, 'document.delete', documentId, 'not_owner', 'Only the owner can delete this document.', { permission })
  }

  const { data: doc } = await ctx.admin.from('documents').select('storage_path').eq('id', documentId).maybeSingle()
  if (!doc) return denyNoAccess(ctx, actor, 'document.delete', documentId)

  // Delete the database row FIRST: access disappears immediately (grants cascade).
  const { error } = await ctx.admin.from('documents').delete().eq('id', documentId)
  if (error) {
    console.error('document delete failed', error)
    await audit(ctx, actor, { action: 'document.delete', outcome: 'failure', documentId, details: { reason: 'db_error' } })
    return fail(ctx, 500, 'delete_failed', 'The document could not be deleted.')
  }
  // Then remove the file. If this fails the file is unreachable but orphaned; we log it.
  const rm = await ctx.admin.storage.from('documents').remove([doc.storage_path])
  if (rm.error) {
    console.error('storage remove failed', rm.error)
    await audit(ctx, actor, { action: 'document.delete', outcome: 'failure', documentId, details: { reason: 'orphaned_file' } })
    return fail(ctx, 500, 'delete_incomplete', 'The document was removed but its file needs manual cleanup.')
  }

  await audit(ctx, actor, { action: 'document.delete', outcome: 'success', documentId })
  return json(ctx, { deleted: true })
})
