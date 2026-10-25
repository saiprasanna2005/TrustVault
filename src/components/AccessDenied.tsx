import { Link } from 'react-router-dom'
import { card } from './ui'

export default function AccessDenied({ message = 'You do not have access to this page or document.' }: { message?: string }) {
  return (
    <div className={`${card} mx-auto mt-10 max-w-lg text-center`}>
      <div className="text-4xl" aria-hidden>🔒</div>
      <h1 className="mt-2 text-xl font-semibold">Access denied</h1>
      <p className="mt-2 text-sm text-slate-600">{message}</p>
      <p className="mt-1 text-xs text-slate-400">This attempt has been recorded.</p>
      <Link to="/" className="mt-4 inline-block text-sm font-medium text-indigo-600 hover:underline">Back to my documents</Link>
    </div>
  )
}
