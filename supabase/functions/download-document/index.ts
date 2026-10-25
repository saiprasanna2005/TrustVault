// POST JSON: { document_id }  ->  the file bytes, ONLY if the caller currently has access.
// There is deliberately no signed URL: nothing the caller holds can outlive a revocation.
import { serve, fail, readJson } from '../_shared/http.ts'
import { getPermission, requireActor } from '../_shared/auth.ts'
import { audit } from '../_shared/audit.ts'
import { denyNoAccess } from '../_shared/documents.ts'
import { contentDisposition, isUuid } from '../_shared/validate.ts'

serve('download-document', async (ctx) => {
  const auth = await requireActor(ctx, 'document.download')
  if (!auth.ok) return auth.response
  const actor = auth.actor

  const body = await readJson(ctx)
  if (!body || !isUuid(body.document_id)) return fail(ctx, 400, 'invalid_input', 'A valid document_id is required.')
  const documentId = body.document_id

  // Checked on EVERY request against the live grants table.
  const permission = await getPermission(ctx, documentId, actor.id)
  if (!permission) return denyNoAccess(ctx, actor, 'document.download', documentId)

  const { data: doc } = await ctx.admin
    .from('documents').select('storage_path, original_filename, mime_type').eq('id', documentId).maybeSingle()
  if (!doc) return denyNoAccess(ctx, actor, 'document.download', documentId)

  const { data: blob, error } = await ctx.admin.storage.from('documents').download(doc.storage_path)
  if (error || !blob) {
    console.error('storage download failed', error)
    await audit(ctx, actor, { action: 'document.download', outcome: 'failure', documentId, details: { reason: 'storage_error' } })
    return fail(ctx, 500, 'download_failed', 'The file could not be retrieved.')
  }
  const bytes = await blob.arrayBuffer()

  // Log BEFORE handing over the bytes: no log, no file.
  await audit(ctx, actor, { action: 'document.download', outcome: 'success', documentId, details: { permission } })

  return new Response(bytes, {
    status: 200,
    headers: {
      ...ctx.cors,
      'Content-Type': doc.mime_type,
      'Content-Disposition': contentDisposition(doc.original_filename),
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'Cache-Control': 'no-store',
      'X-Request-Id': ctx.requestId,
    },
  })
})
