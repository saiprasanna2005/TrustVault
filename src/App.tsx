import { Navigate, Route, Routes } from 'react-router-dom'
import { isConfigured } from './lib/supabase'
import { RequireAdmin, RequireAuth } from './components/Layout'
import Login from './pages/Login'
import Documents from './pages/Documents'
import Upload from './pages/Upload'
import DocumentDetail from './pages/DocumentDetail'
import AuditDashboard from './pages/AuditDashboard'
import { Banner } from './components/ui'

export default function App() {
  if (!isConfigured) {
    return (
      <div className="mx-auto max-w-xl p-8">
        <Banner kind="error">
          Supabase is not configured. Copy <code>.env.example</code> to <code>.env</code> and set
          <code> VITE_SUPABASE_URL</code> and <code>VITE_SUPABASE_ANON_KEY</code>, then restart <code>npm run dev</code>.
        </Banner>
      </div>
    )
  }
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<RequireAuth />}>
        <Route path="/" element={<Documents />} />
        <Route path="/upload" element={<Upload />} />
        <Route path="/documents/:id" element={<DocumentDetail />} />
        <Route element={<RequireAdmin />}>
          <Route path="/admin/audit" element={<AuditDashboard />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
