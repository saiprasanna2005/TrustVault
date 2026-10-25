import { createClient } from '@supabase/supabase-js'

// These two values are PUBLIC by design (the anon/publishable key is not a secret).
// Real protection comes from Row-Level Security and the Edge Functions.
// The service-role key must NEVER appear anywhere in this frontend.
export const SUPABASE_URL = (import.meta.env.VITE_SUPABASE_URL as string | undefined) ?? ''
export const SUPABASE_ANON_KEY = (import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined) ?? ''
export const isConfigured = Boolean(SUPABASE_URL && SUPABASE_ANON_KEY)

export const supabase = createClient(SUPABASE_URL || 'http://localhost', SUPABASE_ANON_KEY || 'missing')
