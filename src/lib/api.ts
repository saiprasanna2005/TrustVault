// Every document write and every file download goes through an Edge Function.
// The browser never talks to Storage directly (it is not allowed to).
import { supabase, SUPABASE_ANON_KEY, SUPABASE_URL } from './supabase'
import type { DocumentRow, GrantRow, Permission } from './types'

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public requestId?: string) {
    super(message)
  }
}

async function headers(extra: Record<string, string> = {}): Promise<Record<string, string>> {
  const { data } = await supabase.auth.getSession()
  const token = data.session?.access_token
  if (!token) throw new ApiError(401, 'unauthenticated', 'Please sign in.')
  return { Authorization: `Bearer ${token}`, apikey: SUPABASE_ANON_KEY, ...extra }
}

async function toError(res: Response): Promise<ApiError> {
  try {
    const body = await res.json()
    return new ApiError(res.status, body?.error?.code ?? 'error', body?.error?.message ?? 'Request failed.', body?.request_id)
  } catch {
    return new ApiError(res.status, 'error', 'Request failed.')
  }
}

async function post<T>(fn: string, body: unknown): Promise<T> {
  const res = await fetch(`${SUPABASE_URL}/functions/v1/${fn}`, {
    method: 'POST',
    headers: await headers({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  })
  if (!res.ok) throw await toError(res)
  return (await res.json()) as T
}

export async function uploadDocument(file: File, title: string, description: string): Promise<DocumentRow> {
  const form = new FormData()
  form.append('file', file)
  form.append('title', title)
  form.append('description', description)
  const res = await fetch(`${SUPABASE_URL}/functions/v1/upload-document`, { method: 'POST', headers: await headers(), body: form })
  if (!res.ok) throw await toError(res)
  return ((await res.json()) as { document: DocumentRow }).document
}

export const getDocument = (document_id: string) =>
  post<{ document: DocumentRow; permission: Permission; grants?: GrantRow[] }>('get-document', { document_id })

export const updateDocument = (document_id: string, title: string, description: string) =>
  post<{ document: DocumentRow }>('update-document', { document_id, title, description })

export const deleteDocument = (document_id: string) => post<{ deleted: boolean }>('delete-document', { document_id })

export const grantPermission = (document_id: string, email: string, permission: 'read' | 'edit') =>
  post<{ grant: GrantRow }>('grant-permission', { document_id, email, permission })

export const revokePermission = (document_id: string, grantee_id: string) =>
  post<{ revoked: boolean }>('revoke-permission', { document_id, grantee_id })

/** Downloads the file bytes (the server re-checks permission on every call) and saves them via the browser. */
export async function downloadDocument(document_id: string, fallbackName: string): Promise<void> {
  const res = await fetch(`${SUPABASE_URL}/functions/v1/download-document`, {
    method: 'POST',
    headers: await headers({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ document_id }),
  })
  if (!res.ok) throw await toError(res)
  const blob = await res.blob()
  const cd = res.headers.get('content-disposition') ?? ''
  const star = cd.match(/filename\*=UTF-8''([^;]+)/i)
  const name = star ? decodeURIComponent(star[1]) : fallbackName
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
