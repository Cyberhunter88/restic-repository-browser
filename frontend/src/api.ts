export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (options.body && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }
  if ((options.method ?? 'GET') !== 'GET') headers.set('X-RRB-Request', '1')
  const response = await fetch(`/api${path}`, {...options, headers, credentials: 'same-origin'})
  if (!response.ok) {
    let message = response.statusText
    const body = await response.text()
    if (body) {
      try {
        const payload = JSON.parse(body)
        if (typeof payload.detail === 'string') message = payload.detail
        else if (payload.detail) message = JSON.stringify(payload.detail)
        else message = body
      } catch {
        message = body
      }
    }
    throw new ApiError(response.status, message)
  }
  if (response.status === 204) return undefined as T
  return response.json()
}

export function mutate<T>(path: string, method: 'POST' | 'PUT' | 'PATCH' | 'DELETE', body?: unknown) {
  return api<T>(path, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
}

export function formatBytes(value = 0): string {
  if (!value) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  return `${(value / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`
}

export function formatDate(value?: string): string {
  return value
    ? new Intl.DateTimeFormat('de-DE', {dateStyle: 'medium', timeStyle: 'short'}).format(new Date(value))
    : '—'
}

export function downloadUrl(snapshotId: string, path: string, zip = false): string {
  const query = new URLSearchParams({path})
  if (zip) query.set('archive', 'zip')
  return `/api/snapshots/${snapshotId}/download?${query.toString()}`
}
