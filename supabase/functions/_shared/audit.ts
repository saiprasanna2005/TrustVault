import type { Actor, Ctx } from './http.ts'

export type AuditAction =
  | 'document.upload' | 'document.read' | 'document.download' | 'document.edit' | 'document.delete'
  | 'permission.grant' | 'permission.revoke'

export interface AuditEvent {
  action: AuditAction
  outcome: 'success' | 'denied' | 'failure'
  documentId?: string | null
  targetUserId?: string | null
  /** Keep this small and free of secrets, tokens and file names/titles. */
  details?: Record<string, unknown>
}

/**
 * Write one audit row. The actor comes from the VERIFIED token (never from the
 * request body). Hashes and timestamps are added by a database trigger.
 * If the write fails we throw, so the caller returns a 500 instead of silently
 * doing something unlogged.
 */
export async function audit(ctx: Ctx, actor: Actor | null, e: AuditEvent): Promise<void> {
  const { error } = await ctx.admin.from('audit_log').insert({
    request_id: ctx.requestId,
    actor_id: actor?.id ?? null,
    actor_email: actor?.email ?? null,
    action: e.action,
    outcome: e.outcome,
    document_id: e.documentId ?? null,
    target_user_id: e.targetUserId ?? null,
    details: e.details ?? {},
    // The trigger overwrites these; they only exist because the columns are NOT NULL.
    prev_hash: 'set-by-trigger',
    row_hash: 'set-by-trigger',
  })
  if (error) throw new Error(`audit write failed: ${error.message}`)
}
