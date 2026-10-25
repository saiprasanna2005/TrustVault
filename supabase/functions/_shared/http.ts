// Shared plumbing for every Edge Function: CORS, safe JSON responses, request IDs,
// and one top-level try/catch so internal errors never leak to the caller.
import { createClient, type SupabaseClient } from 'npm:@supabase/supabase-js@2'

export interface Ctx {
  req: Request
  requestId: string
  /** Service-role client. Bypasses RLS: only use it AFTER checking permissions yourself. */
  admin: SupabaseClient
  cors: Record<string, string>
}

export type Role = 'admin' | 'owner' | 'viewer'
export interface Actor {
  id: string
  email: string
  role: Role
}

function corsHeaders(req: Request): Record<string, string> {
  // Set the ALLOWED_ORIGINS secret (comma-separated) in production, e.g. https://trustvault.vercel.app
  const allowed = (Deno.env.get('ALLOWED_ORIGINS') ?? '*').split(',').map((s) => s.trim()).filter(Boolean)
  const origin = req.headers.get('origin') ?? ''
  const allowOrigin = allowed.includes('*') ? '*' : allowed.includes(origin) ? origin : allowed[0]
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-client-info',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Expose-Headers': 'x-request-id, content-disposition',
    Vary: 'Origin',
  }
}

export function json(ctx: Ctx, body: unknown, status = 200): Response {
  return new Response(JSON.stringify({ ...(body as object), request_id: ctx.requestId }), {
    status,
    headers: { ...ctx.cors, 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Request-Id': ctx.requestId },
  })
}

/** Error responses use short, generic messages: no stack traces, SQL or internal names. */
export function fail(ctx: Ctx, status: number, code: string, message: string): Response {
  return json(ctx, { error: { code, message } }, status)
}

export function serve(name: string, handler: (ctx: Ctx) => Promise<Response>) {
  Deno.serve(async (req) => {
    const cors = corsHeaders(req)
    const requestId = crypto.randomUUID()
    if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })

    const url = Deno.env.get('SUPABASE_URL')
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
    const base = { req, requestId, cors } as Ctx
    if (!url || !serviceKey) {
      console.error(`[${name}] missing SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY`)
      return fail(base, 500, 'server_misconfigured', 'Service is not configured.')
    }
    const ctx: Ctx = {
      ...base,
      admin: createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } }),
    }
    if (req.method !== 'POST') return fail(ctx, 405, 'method_not_allowed', 'Use POST.')

    try {
      return await handler(ctx)
    } catch (e) {
      console.error(`[${name}] request ${requestId} failed:`, e) // details stay in server logs only
      return fail(ctx, 500, 'internal_error', 'Something went wrong. Quote the request ID if you report this.')
    }
  })
}

/** Read a small JSON body. Returns null when it is missing, invalid or not an object. */
export async function readJson(ctx: Ctx): Promise<Record<string, unknown> | null> {
  try {
    const text = await ctx.req.text()
    if (text.length > 20_000) return null
    const parsed = JSON.parse(text)
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null
  } catch {
    return null
  }
}
