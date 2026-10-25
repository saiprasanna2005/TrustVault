import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { uploadDocument } from '../lib/api'
import { formatBytes, errMsg } from '../lib/format'
import { Banner, btnPrimary, card, input } from '../components/ui'
import AccessDenied from '../components/AccessDenied'

const MAX = 5 * 1024 * 1024
const OK = ['application/pdf', 'image/png', 'image/jpeg']

export default function Upload() {
  const { profile } = useAuth()
  const navigate = useNavigate()
  const [file, setFile] = useState<File | null>(null)
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  if (profile?.role === 'viewer') return <AccessDenied message="Viewer accounts cannot upload documents." />

  function pick(f: File | null) {
    setError('')
    if (f && !OK.includes(f.type)) { setError('Only PDF, PNG and JPEG files are allowed.'); setFile(null); return }
    if (f && f.size > MAX) { setError('File is larger than 5 MB.'); setFile(null); return }
    setFile(f)
    if (f && !title) setTitle(f.name.replace(/\.[^.]+$/, ''))
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (!file) { setError('Choose a file first.'); return }
    setBusy(true); setError('')
    try {
      // These browser checks are only a convenience: the server re-checks size AND file signature.
      const doc = await uploadDocument(file, title, description)
      navigate(`/documents/${doc.id}`)
    } catch (err) {
      setError(errMsg(err))
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className={`${card} mx-auto max-w-xl space-y-4`}>
      <h1 className="text-2xl font-bold">Upload a document</h1>
      {error && <Banner kind="error">{error}</Banner>}
      <label className="block text-sm font-medium">File (PDF, PNG or JPEG, max 5 MB)
        <input className={`${input} mt-1`} type="file" accept="application/pdf,image/png,image/jpeg" onChange={(e) => pick(e.target.files?.[0] ?? null)} />
      </label>
      {file && <p className="text-xs text-slate-500">{file.name} · {formatBytes(file.size)}</p>}
      <label className="block text-sm font-medium">Title
        <input className={`${input} mt-1`} required maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
      </label>
      <label className="block text-sm font-medium">Description (optional)
        <textarea className={`${input} mt-1`} rows={3} maxLength={2000} value={description} onChange={(e) => setDescription(e.target.value)} />
      </label>
      <button className={btnPrimary} disabled={busy || !file}>{busy ? 'Uploading…' : 'Upload securely'}</button>
    </form>
  )
}
