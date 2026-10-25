// POST JSON: { document_id }  ->  metadata + your permission (+ the grant list if you are the owner)
import { serve, fail, json, readJson } from '../_shared/http.ts'
import { getPermission, requireActor } from '../_shared/auth.ts'
import { audit } from '../_shared/audit.ts'
import { DOC_COLUMNS, denyNoAccess } from '../_shared/documents.ts'
import { isUuid } from '../_shared/validate.ts'

serve('get-document', async (ctx) => {
  const auth = await requireActor(ctx, 'document.read')
  if (!auth.ok) return auth.response
  const actor = auth.actor

  const body = await readJson(ctx)
  if (!body || !isUuid(body.document_id)) return fail(ctx, 400, 'invalid_input', 'A valid document_id is required.')
  const documentId = body.document_id

  const permission = await getPermission(ctx, documentId, actor.id)
  if (!permission) return denyNoAccess(ctx, actor, 'document.read', documentId)

  const { data: doc } = await ctx.admin.from('documents').select(DOC_COLUMNS).eq('id', documentId).maybeSingle()
  if (!doc) return denyNoAccess(ctx, actor, 'document.read', documentId)

  // Only the owner may see who else has access.
  let grants: unknown[] | undefined
  if (permission === 'owner') {
    const { data: rows } = await ctx.admin
      .from('document_grants').select('grantee_id, permission, created_at').eq('document_id', documentId).order('created_at')
    const ids = (rows ?? []).map((r) => r.grantee_id)
    const { data: people } = ids.length
      ? await ctx.admin.from('profiles').select('id, email').in('id', ids)
      : { data: [] as { id: string; email: string }[] }
    const emailById = new Map((people ?? []).map((p) => [p.id, p.email]))
    grants = (rows ?? []).map((r) => ({ ...r, grantee_email: emailById.get(r.grantee_id) ?? '' }))
  }

  await audit(ctx, actor, { action: 'document.read', outcome: 'success', documentId, details: { permission } })
  return json(ctx, { document: doc, permission, grants })
})
