import { describe, it, expect } from 'vitest'
import {
  MAX_FILE_BYTES, detectFileType, isUuid, validateTitle, validateDescription,
  validateEmail, sanitizeFilename, contentDisposition,
} from '../../supabase/functions/_shared/validate'

const bytes = (...n: number[]) => new Uint8Array(n)
const ascii = (s: string) => new TextEncoder().encode(s)

describe('detectFileType (server-side magic bytes)', () => {
  it('accepts PDF, PNG and JPEG signatures', () => {
    expect(detectFileType(ascii('%PDF-1.7\n...'))?.mime).toBe('application/pdf')
    expect(detectFileType(bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0))?.mime).toBe('image/png')
    expect(detectFileType(bytes(0xff, 0xd8, 0xff, 0xe0))?.mime).toBe('image/jpeg')
  })
  it('rejects executables, scripts, HTML, SVG, ZIP and plain text', () => {
    expect(detectFileType(ascii('MZ\x90\x00'))).toBeNull() // Windows .exe
    expect(detectFileType(ascii('#!/bin/sh\nrm -rf /'))).toBeNull()
    expect(detectFileType(ascii('<html><script>alert(1)</script>'))).toBeNull()
    expect(detectFileType(ascii('<svg xmlns="http://www.w3.org/2000/svg"/>'))).toBeNull()
    expect(detectFileType(ascii('PK\x03\x04'))).toBeNull() // zip / docx
    expect(detectFileType(ascii('just text'))).toBeNull()
  })
  it('rejects empty, truncated and look-alike signatures', () => {
    expect(detectFileType(new Uint8Array())).toBeNull()
    expect(detectFileType(bytes(0x89, 0x50, 0x4e, 0x47))).toBeNull() // truncated PNG header
    expect(detectFileType(ascii('%PDF'))).toBeNull() // missing the "-"
    expect(detectFileType(ascii(' %PDF-1.4'))).toBeNull() // signature must be at offset 0
    expect(detectFileType(bytes(0xff, 0xd8))).toBeNull()
  })
})

describe('field validation', () => {
  it('uses a 5 MB limit', () => expect(MAX_FILE_BYTES).toBe(5 * 1024 * 1024))
  it('isUuid', () => {
    expect(isUuid('123e4567-e89b-42d3-a456-426614174000')).toBe(true)
    for (const bad of ['', 'abc', "1' or '1'='1", '../../etc/passwd', null, undefined, 42, {}]) expect(isUuid(bad)).toBe(false)
  })
  it('title: trims, enforces 1..200, blocks control characters', () => {
    expect(validateTitle('  Report Q3  ')).toEqual({ ok: true, value: 'Report Q3' })
    expect(validateTitle('').ok).toBe(false)
    expect(validateTitle('   ').ok).toBe(false)
    expect(validateTitle('a'.repeat(201)).ok).toBe(false)
    expect(validateTitle('a'.repeat(200)).ok).toBe(true)
    expect(validateTitle('bad\u0000title').ok).toBe(false)
    expect(validateTitle(123 as unknown).ok).toBe(false)
    expect(validateTitle(undefined).ok).toBe(false)
  })
  it('description: optional, max 2000, newlines allowed, other control chars blocked', () => {
    expect(validateDescription(undefined)).toEqual({ ok: true, value: '' })
    expect(validateDescription('line1\nline2').ok).toBe(true)
    expect(validateDescription('x'.repeat(2001)).ok).toBe(false)
    expect(validateDescription('bad\u0007bell').ok).toBe(false)
    expect(validateDescription({} as unknown).ok).toBe(false)
  })
  it('email: normalises to lowercase, rejects junk', () => {
    expect(validateEmail('  Bob@Example.COM ')).toEqual({ ok: true, value: 'bob@example.com' })
    for (const bad of ['', 'bob', 'bob@', '@x.com', 'a b@x.com', 'a@b', 42, null]) expect(validateEmail(bad as unknown).ok).toBe(false)
    expect(validateEmail('a'.repeat(250) + '@x.com').ok).toBe(false)
  })
})

describe('filename safety', () => {
  it('strips path traversal and dangerous characters', () => {
    expect(sanitizeFilename('../../etc/passwd')).toBe('passwd')
    expect(sanitizeFilename('C:\\Users\\me\\secret.pdf')).toBe('secret.pdf')
    expect(sanitizeFilename('a"b<c>d|e?.pdf')).toBe('abcde.pdf')
    expect(sanitizeFilename('.hidden')).toBe('hidden')
    expect(sanitizeFilename('')).toBe('document')
    expect(sanitizeFilename('////')).toBe('document')
    expect(sanitizeFilename('x'.repeat(400)).length).toBeLessThanOrEqual(255)
  })
  it('Content-Disposition is always attachment and cannot be header-injected', () => {
    const h = contentDisposition('evil"\r\nSet-Cookie: x=1.pdf')
    expect(h.startsWith('attachment;')).toBe(true)
    expect(h).not.toMatch(/[\r\n]/)
    expect(contentDisposition('résumé.pdf')).toContain("filename*=UTF-8''r%C3%A9sum%C3%A9.pdf")
  })
})
