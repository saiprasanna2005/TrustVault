import { useCallback, useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'
import type { AuditRow } from '../lib/types'
import { formatDate } from '../lib/format'
import { Badge, Banner, Spinner, btnSecondary, card, input } from '../components/ui'

const PAGE = 25
const ACTIONS = ['document.upload', 'document.read', 'document.download', 'document.edit', 'document.delete', 'permission.grant', 'permission.revoke']
const tone = { success: 'green', denied: 'red', failure: 'amber' } as const

export default function AuditDashboard() {
  const [rows, setRows] = useState<AuditRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [action, setAction] = useState('')
  const [outcome, setOutcome] = useState('')
  const [actor, setActor] = useState('')
  const [error, setError] = useState('')
  const [chain, setChain] = useState<{ valid: boolean; checked: number; first_bad_id: number | null } | null>(null)

  const load = useCallback(async () => {
    // Direct query: the database only returns rows to administrators (RLS policy on audit_log).
    let query = supabase.from('audit_log').select('*', { count: 'exact' }).order('created_at', { ascending: false }).range(page * PAGE, page * PAGE + PAGE - 1)
    if (action) query = query.eq('action', action)
    if (outcome) query = query.eq('outcome', outcome)
    if (actor.trim()) query = query.ilike('actor_email', `%${actor.trim()}%`)
    const { data, count, error } = await query
    if (error) { setError('Could not load the audit log.'); return }
    setError('')
    setRows((data ?? []) as AuditRow[])
    setTotal(count ?? 0)
  }, [page, action, outcome, actor])

  useEffect(() => { void load() }, [load])

  async function verify() {
    const { data, error } = await supabase.rpc('verify_audit_chain')
    if (error || !data?.[0]) { setError('Verification failed or not permitted.'); return }
    setChain({ valid: data[0].valid, checked: Number(data[0].checked), first_bad_id: data[0].first_bad_id })
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-bold">Audit log</h1>
        <button className={btnSecondary} onClick={() => void verify()}>Verify hash chain</button>
      </div>
      {chain && (chain.valid
        ? <Banner kind="success">Chain intact: {chain.checked} events verified. (Tamper-evident, not tamper-proof. See THREATS.md.)</Banner>
        : <Banner kind="error">Chain BROKEN at event #{chain.first_bad_id}. Audit data may have been altered.</Banner>)}

      <div className={`${card} grid gap-3 sm:grid-cols-3`}>
        <select className={input} aria-label="Action" value={action} onChange={(e) => { setPage(0); setAction(e.target.value) }}>
          <option value="">All actions</option>{ACTIONS.map((a) => <option key={a}>{a}</option>)}
        </select>
        <select className={input} aria-label="Outcome" value={outcome} onChange={(e) => { setPage(0); setOutcome(e.target.value) }}>
          <option value="">All outcomes</option><option>success</option><option>denied</option><option>failure</option>
        </select>
        <input className={input} placeholder="Filter by actor email…" aria-label="Actor email" value={actor} onChange={(e) => { setPage(0); setActor(e.target.value) }} />
      </div>

      {error && <Banner kind="error">{error}</Banner>}
      {!rows && !error && <Spinner />}
      {rows && (
        <div className={`${card} overflow-x-auto p-0`}>
          <table className="w-full min-w-[860px] text-left text-xs">
            <thead className="border-b border-slate-200 bg-slate-50 uppercase text-slate-500">
              <tr><th className="px-3 py-3">Time</th><th className="px-3 py-3">Action</th><th className="px-3 py-3">Outcome</th><th className="px-3 py-3">Actor</th><th className="px-3 py-3">Document</th><th className="px-3 py-3">Request ID</th><th className="px-3 py-3">Details</th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className="border-b border-slate-100 align-top last:border-0">
                  <td className="px-3 py-2 whitespace-nowrap">{formatDate(r.created_at)}</td>
                  <td className="px-3 py-2">{r.action}</td>
                  <td className="px-3 py-2"><Badge tone={tone[r.outcome]}>{r.outcome}</Badge></td>
                  <td className="px-3 py-2">{r.actor_email ?? <span className="text-slate-400">unauthenticated</span>}</td>
                  <td className="px-3 py-2 font-mono">{r.document_id?.slice(0, 8) ?? '—'}</td>
                  <td className="px-3 py-2 font-mono">{r.request_id.slice(0, 8)}</td>
                  <td className="px-3 py-2 font-mono text-slate-500">{Object.keys(r.details).length ? JSON.stringify(r.details) : '—'}</td>
                </tr>
              ))}
              {rows.length === 0 && <tr><td colSpan={7} className="px-3 py-6 text-center text-slate-500">No events match.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
      <div className="flex items-center justify-between text-sm text-slate-600">
        <span>{total} events</span>
        <div className="flex gap-2">
          <button className={btnSecondary} disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <button className={btnSecondary} disabled={(page + 1) * PAGE >= total} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      </div>
    </div>
  )
}
