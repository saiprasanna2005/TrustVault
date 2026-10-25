import { Link, NavLink, Outlet, Navigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { Badge, Spinner } from './ui'
import AccessDenied from './AccessDenied'

const link = ({ isActive }: { isActive: boolean }) =>
  `rounded-md px-3 py-2 text-sm font-medium ${isActive ? 'bg-indigo-50 text-indigo-700' : 'text-slate-600 hover:bg-slate-100'}`

/** Route guard. NOTE: this is only for a nicer UI. The real enforcement is on the server (RLS + Edge Functions). */
export function RequireAuth() {
  const { session, loading } = useAuth()
  if (loading) return <Spinner />
  if (!session) return <Navigate to="/login" replace />
  return <Layout />
}

export function RequireAdmin() {
  const { profile } = useAuth()
  if (profile?.role !== 'admin') return <AccessDenied message="Administrator access is required for the audit dashboard." />
  return <Outlet />
}

function Layout() {
  const { profile, signOut } = useAuth()
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-3 px-4 py-3">
          <Link to="/" className="mr-4 text-lg font-bold text-indigo-700">🔐 TrustVault</Link>
          <nav className="flex flex-wrap gap-1" aria-label="Main">
            <NavLink to="/" end className={link}>Documents</NavLink>
            {profile?.role !== 'viewer' && <NavLink to="/upload" className={link}>Upload</NavLink>}
            {profile?.role === 'admin' && <NavLink to="/admin/audit" className={link}>Audit log</NavLink>}
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm">
            <span className="hidden text-slate-600 sm:inline">{profile?.email}</span>
            {profile && <Badge tone={profile.role === 'admin' ? 'amber' : 'indigo'}>{profile.role}</Badge>}
            <button onClick={() => void signOut()} className="rounded-md border border-slate-300 px-3 py-1.5 text-slate-700 hover:bg-slate-50">Sign out</button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6"><Outlet /></main>
    </div>
  )
}
