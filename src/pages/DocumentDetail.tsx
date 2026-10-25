import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ApiError, deleteDocument, downloadDocument, getDocument, grantPermission, revokePermission, updateDocument } from '../lib/api'
import type { DocumentRow, GrantRow, Permission } from '../lib/types'
import { errMsg, formatBytes, formatDate, typeLabel } from '../lib/format'
import { Badge, Banner, Spinner, btnDanger, btnPrimary, btnSecondary, card, input } from '../components/ui'
import AccessDenied from '../components/AccessDenied'

type State =
  | { status: 'loading' }
  | { status: 'denied' }
  | { status: 'error'; message: string }
  | { status: 'ready'; doc: DocumentRow; permission: Permission; grants?: GrantRow[] }

export default function DocumentDetail() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const [state, setState] = useState<State>({ status: 'loading' })
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [notice, setNotice] = useState<{ kind: 'error' | 'success'; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [email, setEmail] = useState('')
  const [perm, setPerm] = useState<'read' | 'edit'>('read')

  const load = useCallback(async () => {
    try {
      const r = await getDocument(id)
      setState({ status: 'ready', doc: r.document, permission: r.permission, grants: r.grants })
      setTitle(r.document.title)
      setDescription(r.document.description)
    } catch (e) {
      if (e instanceof ApiError && (e.status === 403 || e.status === 401)) setState({ status: 'denied' })
      else if (e instanceof ApiError && e.status === 400) setState({ status: 'denied' })
      else setState({ status: 'error', message: errMsg(e) })
    }
  }, [id])

  useEffect(() => { void load() }, [load])

  async function run(action: () => Promise<unknown>, success: string, reload = true) {
    setBusy(true); setNotice(null)
    try {
      await action()
      setNotice({ kind: 'success', text: success })
      if (reload) await load()
    } catch (e) {
      // A 403 here means access was revoked while the page was open: show the denied state.
      if (e instanceof ApiError && e.status === 403 && !(state.status === 'ready' && state.permission === 'owner')) setState({ status: 'denied' })
      else setNotice({ kind: 'error', text: errMsg(e) })
    }
    setBusy(false)
  }

  if (state.status === 'loading') return <Spinner />
  if (state.status === 'denied') return <AccessDenied />
  if (state.status === 'error') return <Banner kind="error">{state.message}</Banner>

  const { doc, permission, grants } = state
  const canEdit = permission === 'owner' || permission === 'edit'

  const onSave = (e: FormEvent) => { e.preventDefault(); void run(() => updateDocument(doc.id, title, description), 'Changes saved.') }
  const onShare = (e: FormEvent) => {
    e.preventDefault()
    void run(async () => { await grantPermission(doc.id, email, perm); setEmail('') }, 'Permission saved.')
  }
  const onDelete = () => {
    if (!window.confirm('Delete this document permanently? This cannot be undone.')) return
    void run(async () => { await deleteDocument(doc.id); navigate('/') }, 'Deleted.', false)
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold break-words">{doc.title}</h1>
          <p className="mt-1 text-sm text-slate-500">Your access: <Badge tone={permission === 'owner' ? 'indigo' : permission === 'edit' ? 'amber' : 'green'}>{permission}</Badge></p>
        </div>
        <div className="flex gap-2">
          <button className={btnPrimary} disabled={busy} onClick={() => void run(() => downloadDocument(doc.id, doc.original_filename), 'Download started.', false)}>Download</button>
          {permission === 'owner' && <button className={btnDanger} disabled={busy} onClick={onDelete}>Delete</button>}
        </div>
      </div>

      {notice && <Banner kind={notice.kind}>{notice.text}</Banner>}

      <div className={`${card} grid gap-4 text-sm sm:grid-cols-2`}>
        <div><div className="text-xs uppercase text-slate-400">File</div>{doc.original_filename}</div>
        <div><div className="text-xs uppercase text-slate-400">Type / size</div>{typeLabel(doc.mime_type)} · {formatBytes(doc.size_bytes)}</div>
        <div><div className="text-xs uppercase text-slate-400">Owner</div>{doc.owner_email}</div>
        <div><div className="text-xs uppercase text-slate-400">Updated</div>{formatDate(doc.updated_at)}</div>
        <div className="sm:col-span-2"><div className="text-xs uppercase text-slate-400">SHA-256</div><code className="break-all text-xs">{doc.sha256}</code></div>
        {!canEdit && <div className="sm:col-span-2"><div className="text-xs uppercase text-slate-400">Description</div>{doc.description || '—'}</div>}
      </div>

      {canEdit ? (
        <form onSubmit={onSave} className={`${card} space-y-3`}>
          <h2 className="font-semibold">Edit details</h2>
          <label className="block text-sm font-medium">Title<input className={`${input} mt-1`} required maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} /></label>
          <label className="block text-sm font-medium">Description<textarea className={`${input} mt-1`} rows={3} maxLength={2000} value={description} onChange={(e) => setDescription(e.target.value)} /></label>
          <button className={btnSecondary} disabled={busy}>Save changes</button>
          <p className="text-xs text-slate-400">Only the title and description can be changed.</p>
        </form>
      ) : (
        <Banner kind="info">You have read-only access. You can view and download this document but not change, share or delete it.</Banner>
      )}

      {permission === 'owner' && (
        <section className={`${card} space-y-4`}>
          <h2 className="font-semibold">Sharing</h2>
          <form onSubmit={onShare} className="flex flex-wrap gap-2">
            <input className={`${input} min-w-[220px] flex-1`} type="email" required placeholder="Registered user's email" aria-label="User email" value={email} onChange={(e) => setEmail(e.target.value)} />
            <select className={`${input} w-auto`} aria-label="Permission" value={perm} onChange={(e) => setPerm(e.target.value as 'read' | 'edit')}>
              <option value="read">Can view</option><option value="edit">Can edit</option>
            </select>
            <button className={btnPrimary} disabled={busy}>Grant access</button>
          </form>
          {grants && grants.length === 0 && <p className="text-sm text-slate-500">Not shared with anyone.</p>}
          {grants && grants.length > 0 && (
            <ul className="divide-y divide-slate-100 text-sm">
              {grants.map((g) => (
                <li key={g.grantee_id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                  <span>{g.grantee_email} <Badge tone={g.permission === 'edit' ? 'amber' : 'green'}>{g.permission}</Badge></span>
                  <button className={btnSecondary} disabled={busy} onClick={() => void run(() => revokePermission(doc.id, g.grantee_id), 'Access revoked.')}>Revoke</button>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  )
}
