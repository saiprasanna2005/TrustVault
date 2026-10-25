// POST JSON: { document_id, title?, description? }   Owner or edit-grantee only.
import { serve, fail, json, readJson } from '../_shared/http.ts'
import { getPermission, requireActor } from '../_shared/auth.ts'
import { audit } from '../_shared/audit.ts'
import { DOC_COLUMNS, denyInsufficient, denyNoAccess } from '../_shared/documents.ts'
import { isUuid, validateDescription, validateTitle } from '../_shared/validate.ts'

const ALLOWED_KEYS = new Set(['document_id', 'title', 'description']) // allow-list, not block-list

serve('update-document', async (ctx) => {
  const auth = await requireActor(ctx, 'document.edit')
  if (!auth.ok) return auth.response
  const actor = auth.actor

  const body = await readJson(ctx)
  if (!body || !isUuid(body.document_id)) return fail(ctx, 400, 'invalid_input', 'A valid document_id is required.')
  const documentId = body.document_id

  const permission = await getPermission(ctx, documentId, actor.id)
  if (!permission) return denyNoAccess(ctx, actor, 'document.edit', documentId)
  if (permission === 'read') {
    return denyInsufficient(ctx, actor, 'document.edit', documentId, 'read_only', 'You have read-only access to this document.')
  }

  // Trying to change anything else (owner_id, storage_path, ...) is refused AND logged.
  const forbidden = Object.keys(body).filter((k) => !ALLOWED_KEYS.has(k))
  if (forbidden.length > 0) {
    return denyInsufficient(ctx, actor, 'document.edit', documentId, 'forbidden_field',
      'Only the title and description can be edited.',
      { fields: forbidden.slice(0, 10).map((k) => k.slice(0, 50)) })
  }

  const changes: Record<string, string> = {}
  if (body.title !== undefined) {
    const t = validateTitle(body.title)
    if (!t.ok) return fail(ctx, 400, 'invalid_input', t.error)
    changes.title = t.value
  }
  if (body.description !== undefined) {
    const d = validateDescription(body.description)
    if (!d.ok) return fail(ctx, 400, 'invalid_input', d.error)
    changes.description = d.value
  }
  if (Object.keys(changes).length === 0) return fail(ctx, 400, 'invalid_input', 'Nothing to update.')

  const { data: doc, error } = await ctx.admin
    .from('documents').update({ ...changes, updated_at: new Date().toISOString() })
    .eq('id', documentId).select(DOC_COLUMNS).single()
  if (error || !doc) {
    console.error('document update failed', error)
    await audit(ctx, actor, { action: 'document.edit', outcome: 'failure', documentId, details: { reason: 'db_error' } })
    return fail(ctx, 500, 'update_failed', 'The document could not be updated.')
  }

  await audit(ctx, actor, { action: 'document.edit', outcome: 'success', documentId, details: { fields: Object.keys(changes), permission } })
  return json(ctx, { document: doc })
})
