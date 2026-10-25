export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}
export const formatDate = (iso: string) => new Date(iso).toLocaleString()
export const typeLabel = (mime: string) => (mime === 'application/pdf' ? 'PDF' : mime === 'image/png' ? 'PNG' : mime === 'image/jpeg' ? 'JPEG' : mime)
export const errMsg = (e: unknown) => (e instanceof Error ? e.message : 'Something went wrong.')
