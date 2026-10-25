import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { useAuth } from '../auth/AuthContext'
import { DOC_COLUMNS, type DocumentRow } from '../lib/types'
import { formatBytes, formatDate, typeLabel } from '../lib/format'
import { Badge, Banner, Spinner, btnPrimary, card, input } from '../components/ui'

export default function Documents() {
  const { session, profile } = useAuth()
  const [docs, setDocs] = useState<DocumentRow[] | null>(null)
  const [myGrants, setMyGrants] = useState<Record<string, 'read' | 'edit'>>({})
  const [error, setError] = useState('')
  const [q, setQ] = useState('')
  const [type, setType] = useState('all')
  const [scope, setScope] = useState<'all' | 'mine' | 'shared'>('all')
  const [sort, setSort] = useState<'updated' | 'title' | 'size'>('updated')

  useEffect(() => {
    if (!session) return
    // Both queries go straight to the database, but Row-Level Security only returns rows this user may see.
    Promise.all([
      supabase.from('documents').select(DOC_COLUMNS).order('updated_at', { ascending: false }),
      supabase.from('document_grants').select('document_id, permission').eq('grantee_id', session.user.id),
    ]).then(([d, g]) => {
      if (d.error) { setError('Could not load documents.'); return }
      setDocs((d.data ?? []) as DocumentRow[])
      setMyGrants(Object.fromEntries((g.data ?? []).map((r) => [r.document_id as string, r.permission as 'read' | 'edit'])))
    })
  }, [session])

  const shown = useMemo(() => {
    if (!docs || !session) return []
    const needle = q.trim().toLowerCase()
    return docs
      .filter((d) => (type === 'all' ? true : d.mime_type === type))
      .filter((d) => (scope === 'all' ? true : scope === 'mine' ? d.owner_id === session.user.id : d.owner_id !== session.user.id))
      .filter((d) => !needle || d.title.toLowerCase().includes(needle) || d.original_filename.toLowerCase().includes(needle) || d.description.toLowerCase().includes(needle))
      .sort((a, b) => sort === 'title' ? a.title.localeCompare(b.title) : sort === 'size' ? b.size_bytes - a.size_bytes : b.updated_at.localeCompare(a.updated_at))
  }, [docs, q, type, scope, sort, session])

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-bold">My documents</h1>
        {profile?.role !== 'viewer' && <Link to="/upload" className={btnPrimary}>Upload document</Link>}
      </div>

      <div className={`${card} grid gap-3 sm:grid-cols-2 lg:grid-cols-4`}>
        <input className={input} type="search" placeholder="Search title, file name, description…" aria-label="Search" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className={input} aria-label="File type" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="all">All types</option><option value="application/pdf">PDF</option><option value="image/png">PNG</option><option value="image/jpeg">JPEG</option>
        </select>
        <select className={input} aria-label="Ownership" value={scope} onChange={(e) => setScope(e.target.value as typeof scope)}>
          <option value="all">Mine and shared with me</option><option value="mine">Owned by me</option><option value="shared">Shared with me</option>
        </select>
        <select className={input} aria-label="Sort" value={sort} onChange={(e) => setSort(e.target.value as typeof sort)}>
          <option value="updated">Recently updated</option><option value="title">Title (A–Z)</option><option value="size">Largest first</option>
        </select>
      </div>

      {error && <Banner kind="error">{error}</Banner>}
      {!docs && !error && <Spinner />}
      {docs && shown.length === 0 && (
        <div className={`${card} text-center text-sm text-slate-500`}>{docs.length === 0 ? 'No documents yet.' : 'No documents match your filters.'}</div>
      )}
      {shown.length > 0 && session && (
        <div className={`${card} overflow-x-auto p-0`}>
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase text-slate-500">
              <tr><th className="px-4 py-3">Title</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Size</th><th className="px-4 py-3">Owner</th><th className="px-4 py-3">Access</th><th className="px-4 py-3">Updated</th></tr>
            </thead>
            <tbody>
              {shown.map((d) => {
                const mine = d.owner_id === session.user.id
                return (
                  <tr key={d.id} className="border-b border-slate-100 last:border-0 hover:bg-slate-50">
                    <td className="px-4 py-3"><Link className="font-medium text-indigo-700 hover:underline" to={`/documents/${d.id}`}>{d.title}</Link></td>
                    <td className="px-4 py-3">{typeLabel(d.mime_type)}</td>
                    <td className="px-4 py-3">{formatBytes(d.size_bytes)}</td>
                    <td className="px-4 py-3">{mine ? 'You' : d.owner_email}</td>
                    <td className="px-4 py-3">{mine ? <Badge tone="indigo">owner</Badge> : <Badge tone={myGrants[d.id] === 'edit' ? 'amber' : 'green'}>{myGrants[d.id] ?? 'shared'}</Badge>}</td>
                    <td className="px-4 py-3 text-slate-500">{formatDate(d.updated_at)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
