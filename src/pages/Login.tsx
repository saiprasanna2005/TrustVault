import { useState, type FormEvent } from 'react'
import { Navigate } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { useAuth } from '../auth/AuthContext'
import { Banner, btnPrimary, card, input } from '../components/ui'

export default function Login() {
  const { session } = useAuth()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')

  if (session) return <Navigate to="/" replace />

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(''); setInfo('')
    if (password.length < 8) { setError('Password must be at least 8 characters.'); return }
    setBusy(true)
    if (mode === 'login') {
      const { error } = await supabase.auth.signInWithPassword({ email: email.trim(), password })
      if (error) setError('Sign-in failed. Check your email and password.')
    } else {
      // No role is sent. The database always creates new accounts as "owner".
      const { data, error } = await supabase.auth.signUp({ email: email.trim(), password })
      if (error) setError(error.message)
      else if (!data.session) setInfo('Account created. Check your email to confirm it, then sign in.')
    }
    setBusy(false)
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <form onSubmit={submit} className={`${card} w-full max-w-sm space-y-4`}>
        <div className="text-center">
          <div className="text-3xl" aria-hidden>🔐</div>
          <h1 className="text-xl font-bold">TrustVault</h1>
          <p className="text-sm text-slate-500">Secure document sharing</p>
        </div>
        {error && <Banner kind="error">{error}</Banner>}
        {info && <Banner kind="success">{info}</Banner>}
        <label className="block text-sm font-medium">Email
          <input className={`${input} mt-1`} type="email" required autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label className="block text-sm font-medium">Password
          <input className={`${input} mt-1`} type="password" required minLength={8} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <button className={`${btnPrimary} w-full`} disabled={busy}>{busy ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}</button>
        <button type="button" className="w-full text-sm text-indigo-600 hover:underline" onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(''); setInfo('') }}>
          {mode === 'login' ? 'No account? Register' : 'Have an account? Sign in'}
        </button>
      </form>
    </div>
  )
}
