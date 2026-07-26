import {cleanup, render, screen, waitFor} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {MemoryRouter} from 'react-router-dom'
import {afterEach, describe, expect, it, vi} from 'vitest'
import App from './App'
import {downloadUrl, formatBytes} from './api'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), {
  status,
  headers: {'Content-Type': 'application/json'},
})

function renderApp(path = '/') {
  const client = new QueryClient({defaultOptions: {queries: {retry: false}}})
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}><App /></MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('Oberfläche', () => {
  it('zeigt die Anmeldung bei einer nicht authentifizierten Sitzung', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({detail: 'Anmeldung erforderlich'}), {
        status: 401,
        headers: {'Content-Type': 'application/json'},
      }),
    )
    renderApp()
    expect(await screen.findByRole('heading', {name: 'Restic Repository Browser'})).toBeInTheDocument()
    expect(screen.getByRole('button', {name: 'Anmelden'})).toBeInTheDocument()
  })

  it('formatiert Größen und sichere Download-URLs', () => {
    expect(formatBytes(1536)).toBe('1.5 KiB')
    expect(downloadUrl('snapshot', '/Ordner mit Leerzeichen', true)).toBe(
      '/api/snapshots/snapshot/download?path=%2FOrdner+mit+Leerzeichen&archive=zip',
    )
  })

  it('behält gespeicherte Secrets beim Bearbeiten und schließt den Dialog per Escape', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      const url = String(input)
      if (url.endsWith('/api/auth/me')) return json({username: 'admin', must_change_password: false})
      if (url.endsWith('/api/repositories')) {
        return json([{
          id: 'repo-1',
          name: 'Produktiv',
          kind: 'local',
          location_display: '/repositories/prod',
          enabled: true,
          last_error: '',
          snapshot_count: 2,
          created_at: '2026-07-26T12:00:00Z',
          config: {path: '/repositories/prod'},
        }])
      }
      return json({})
    })
    renderApp()
    const edit = await screen.findByTitle('Verbindung bearbeiten')
    await userEvent.click(edit)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByLabelText(/Restic-Repository-Passwort/)).not.toBeRequired()
    expect(screen.getByText(/gespeicherte Passwort beizubehalten/)).toBeInTheDocument()
    await userEvent.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(edit).toHaveFocus()
  })

  it('zeigt Systemstatus und Audit-Protokoll', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      const url = String(input)
      if (url.endsWith('/api/auth/me')) return json({username: 'admin', must_change_password: false})
      if (url.includes('/api/system/status')) {
        return json({
          worker_running: true,
          queued_jobs: 1,
          running_jobs: 0,
          failed_jobs: 0,
          directory_listings: 3,
          cached_entries: 42,
          restic_limit: 2,
          last_cleanup_at: '2026-07-26T12:00:00Z',
        })
      }
      if (url.includes('/api/audit-events')) {
        return json({items: [{
          id: 1,
          user_name: 'admin',
          action: 'auth.login',
          result: 'success',
          detail: '',
          created_at: '2026-07-26T12:00:00Z',
        }], next_cursor: null})
      }
      return json([])
    })
    renderApp('/settings')
    expect(await screen.findByRole('heading', {name: 'Systemstatus'})).toBeInTheDocument()
    expect(await screen.findByText('auth.login')).toBeInTheDocument()
    expect(screen.getByText('3 Ordner · 42 Einträge')).toBeInTheDocument()
  })

  it('verwendet den paginierten Snapshot-Endpunkt', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      const url = String(input)
      if (url.endsWith('/api/auth/me')) return json({username: 'admin', must_change_password: false})
      if (url.endsWith('/api/repositories')) {
        return json([{
          id: 'repo-1',
          name: 'Produktiv',
          kind: 'local',
          location_display: '/repositories/prod',
          enabled: true,
          last_error: '',
          snapshot_count: 1,
          created_at: '2026-07-26T12:00:00Z',
          config: {path: '/repositories/prod'},
        }])
      }
      if (url.includes('/snapshots/page')) return json({items: [], next_cursor: null})
      return json({})
    })
    renderApp('/repositories/repo-1')
    expect(await screen.findByRole('heading', {name: 'Produktiv'})).toBeInTheDocument()
    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/snapshots/page?limit=50'))).toBe(true)
    })
  })
})
