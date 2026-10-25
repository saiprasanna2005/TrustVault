import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import type { Session } from '@supabase/supabase-js'
import { supabase } from '../lib/supabase'
import type { Profile } from '../lib/types'

interface AuthState {
  session: Session | null
  /** undefined = still loading, null = signed out */
  profile: Profile | null | undefined
  loading: boolean
  signOut: () => Promise<void>
}

const Ctx = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null)
  const [initialised, setInitialised] = useState(false)
  const [profile, setProfile] = useState<Profile | null | undefined>(undefined)

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session)
      setInitialised(true)
    })
    const { data: sub } = supabase.auth.onAuthStateChange((_event, s) => setSession(s))
    return () => sub.subscription.unsubscribe()
  }, [])

  // The role shown in the UI is only for display. The server decides what is actually allowed.
  useEffect(() => {
    if (!session) { setProfile(null); return }
    setProfile(undefined)
    supabase.from('profiles').select('id, email, role').eq('id', session.user.id).single()
      .then(({ data }) => setProfile((data as Profile | null) ?? null))
  }, [session])

  const value: AuthState = {
    session, profile,
    loading: !initialised || (session !== null && profile === undefined),
    signOut: async () => { await supabase.auth.signOut() },
  }
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuth(): AuthState {
  const v = useContext(Ctx)
  if (!v) throw new Error('useAuth must be used inside AuthProvider')
  return v
}
