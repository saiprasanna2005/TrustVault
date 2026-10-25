import type { ReactNode } from 'react'

export const btn = 'inline-flex items-center justify-center rounded-md px-3 py-2 text-sm font-medium transition disabled:opacity-50 disabled:cursor-not-allowed'
export const btnPrimary = `${btn} bg-indigo-600 text-white hover:bg-indigo-700`
export const btnSecondary = `${btn} border border-slate-300 bg-white text-slate-700 hover:bg-slate-50`
export const btnDanger = `${btn} bg-red-600 text-white hover:bg-red-700`
export const input = 'w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500'
export const card = 'rounded-lg border border-slate-200 bg-white p-5 shadow-sm'

export function Banner({ kind, children }: { kind: 'error' | 'success' | 'info'; children: ReactNode }) {
  const styles = {
    error: 'border-red-200 bg-red-50 text-red-800',
    success: 'border-green-200 bg-green-50 text-green-800',
    info: 'border-blue-200 bg-blue-50 text-blue-800',
  }[kind]
  return <div role={kind === 'error' ? 'alert' : 'status'} className={`rounded-md border px-4 py-3 text-sm ${styles}`}>{children}</div>
}

export function Badge({ children, tone = 'slate' }: { children: ReactNode; tone?: 'slate' | 'green' | 'red' | 'amber' | 'indigo' }) {
  const tones = {
    slate: 'bg-slate-100 text-slate-700', green: 'bg-green-100 text-green-800', red: 'bg-red-100 text-red-800',
    amber: 'bg-amber-100 text-amber-800', indigo: 'bg-indigo-100 text-indigo-800',
  }
  return <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${tones[tone]}`}>{children}</span>
}

export function Spinner({ label = 'Loading…' }: { label?: string }) {
  return <p className="py-10 text-center text-sm text-slate-500">{label}</p>
}
