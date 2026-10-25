// Pure validation helpers. No Deno/Node APIs on purpose, so the SAME file is
// used by the Edge Functions and by the Vitest unit tests.

export const MAX_FILE_BYTES = 5 * 1024 * 1024 // 5 MB
export const ALLOWED_MIME = ['application/pdf', 'image/png', 'image/jpeg'] as const
export type AllowedMime = (typeof ALLOWED_MIME)[number]

export type Result<T> = { ok: true; value: T } | { ok: false; error: string }

function startsWith(bytes: Uint8Array, signature: number[]): boolean {
  if (bytes.length < signature.length) return false
  return signature.every((b, i) => bytes[i] === b)
}

/**
 * Decide the file type from the FIRST BYTES ("magic number"), never from the
 * file name or the browser-supplied Content-Type (both are trivially faked).
 */
export function detectFileType(bytes: Uint8Array): { mime: AllowedMime; ext: string } | null {
  if (startsWith(bytes, [0x25, 0x50, 0x44, 0x46, 0x2d])) return { mime: 'application/pdf', ext: 'pdf' } // %PDF-
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return { mime: 'image/png', ext: 'png' }
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return { mime: 'image/jpeg', ext: 'jpg' }
  return null
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
export function isUuid(v: unknown): v is string {
  return typeof v === 'string' && UUID_RE.test(v)
}

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/

export function validateTitle(v: unknown): Result<string> {
  if (typeof v !== 'string') return { ok: false, error: 'Title is required.' }
  const t = v.trim()
  if (t.length < 1 || t.length > 200) return { ok: false, error: 'Title must be 1 to 200 characters.' }
  if (CONTROL_CHARS.test(t)) return { ok: false, error: 'Title contains invalid characters.' }
  return { ok: true, value: t }
}

export function validateDescription(v: unknown): Result<string> {
  if (v === undefined || v === null) return { ok: true, value: '' }
  if (typeof v !== 'string') return { ok: false, error: 'Description must be text.' }
  const d = v.trim()
  if (d.length > 2000) return { ok: false, error: 'Description must be at most 2000 characters.' }
  // allow tab / newline / carriage return, block other control characters
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(d)) return { ok: false, error: 'Description contains invalid characters.' }
  return { ok: true, value: d }
}

export function validateEmail(v: unknown): Result<string> {
  if (typeof v !== 'string') return { ok: false, error: 'A valid email is required.' }
  const e = v.trim().toLowerCase()
  if (e.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) return { ok: false, error: 'A valid email is required.' }
  return { ok: true, value: e }
}

/** Keep only the final path segment and strip characters that are dangerous in headers / file systems. */
export function sanitizeFilename(name: string): string {
  const last = String(name ?? '').split(/[\\/]/).pop() ?? ''
  const cleaned = last
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f"\\/:*?<>|]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/^\.+/, '')
    .slice(0, 255)
  return cleaned.length > 0 ? cleaned : 'document'
}

/** Safe Content-Disposition header: always "attachment" so the browser downloads instead of rendering. */
export function contentDisposition(filename: string): string {
  const safe = sanitizeFilename(filename)
  const ascii = safe.replace(/[^\x20-\x7e]/g, '_')
  const encoded = encodeURIComponent(safe).replace(/['()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`
}
