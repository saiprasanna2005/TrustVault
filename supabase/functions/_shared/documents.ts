import { audit, type AuditAction } from './audit.ts'
import { fail, type Actor, type Ctx } from './http.ts'

// Columns we are willing to send to the browser (storage_path is NOT included).
export const DOC_COLUMNS =
  'id, owner_id, owner_email, title, description, original_filename, mime_type, size_bytes, sha256, created_at, updated_at'

/**
 * Standard "no" answer. The text is identical whether the document does not exist
 * or belongs to someone else, so attackers cannot use it to discover which IDs exist.
 * The audit log (admin-only) keeps the real reason.
 */
export async function denyNoAccess(ctx: Ctx, actor: Actor, action: AuditAction, documentId: string): Promise<Response> {
  await audit(ctx, actor, { action, outcome: 'denied', documentId, details: { reason: 'no_access' } })
  return fail(ctx, 403, 'forbidden', 'You do not have access to this document.')
}

/** For callers who CAN see the document but are not allowed to do this particular thing. */
export async function denyInsufficient(
  ctx: Ctx, actor: Actor, action: AuditAction, documentId: string, reason: string, message: string,
  extra: Record<string, unknown> = {},
): Promise<Response> {
  await audit(ctx, actor, { action, outcome: 'denied', documentId, details: { reason, ...extra } })
  return fail(ctx, 403, 'forbidden', message)
}
