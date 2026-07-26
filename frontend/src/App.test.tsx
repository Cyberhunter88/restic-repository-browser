import {render, screen} from '@testing-library/react'
import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {MemoryRouter} from 'react-router-dom'
import {afterEach, describe, expect, it, vi} from 'vitest'
import App from './App'
import {downloadUrl, formatBytes} from './api'

afterEach(() => vi.restoreAllMocks())

describe('Oberfläche', () => {
  it('zeigt die Anmeldung bei einer nicht authentifizierten Sitzung', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({detail: 'Anmeldung erforderlich'}), {
        status: 401,
        headers: {'Content-Type': 'application/json'},
      }),
    )
    const client = new QueryClient({defaultOptions: {queries: {retry: false}}})
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter><App /></MemoryRouter>
      </QueryClientProvider>,
    )
    expect(await screen.findByRole('heading', {name: 'Restic Repository Browser'})).toBeInTheDocument()
    expect(screen.getByRole('button', {name: 'Anmelden'})).toBeInTheDocument()
  })

  it('formatiert Größen und sichere Download-URLs', () => {
    expect(formatBytes(1536)).toBe('1.5 KiB')
    expect(downloadUrl('snapshot', '/Ordner mit Leerzeichen', true)).toBe(
      '/api/snapshots/snapshot/download?path=%2FOrdner+mit+Leerzeichen&archive=zip',
    )
  })
})

