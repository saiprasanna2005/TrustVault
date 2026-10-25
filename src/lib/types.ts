export type Role = 'admin' | 'owner' | 'viewer'
export type Permission = 'owner' | 'edit' | 'read'

export interface Profile { id: string; email: string; role: Role }

export interface DocumentRow {
  id: string
  owner_id: string
  owner_email: string
  title: string
  description: string
  original_filename: string
  mime_type: string
  size_bytes: number
  sha256: string
  created_at: string
  updated_at: string
}

export interface GrantRow { grantee_id: string; grantee_email: string; permission: 'read' | 'edit'; created_at: string }

export interface AuditRow {
  id: number
  created_at: string
  request_id: string
  actor_id: string | null
  actor_email: string | null
  action: string
  outcome: 'success' | 'denied' | 'failure'
  document_id: string | null
  target_user_id: string | null
  details: Record<string, unknown>
}

export const DOC_COLUMNS =
  'id, owner_id, owner_email, title, description, original_filename, mime_type, size_bytes, sha256, created_at, updated_at'
