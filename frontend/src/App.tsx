import {FormEvent, useEffect, useMemo, useRef, useState} from 'react'
import {useInfiniteQuery, useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useVirtualizer} from '@tanstack/react-virtual'
import {
  Activity,
  AlertTriangle,
  Archive,
  ArrowLeft,
  Check,
  ChevronRight,
  Database,
  Download,
  File,
  Folder,
  FolderOpen,
  HardDrive,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  PauseCircle,
  Plus,
  Pencil,
  RefreshCw,
  Search,
  Server,
  Settings,
  ShieldCheck,
  Trash2,
  X,
} from 'lucide-react'
import {Link, Navigate, Route, Routes, useNavigate, useParams} from 'react-router-dom'
import {api, ApiError, downloadUrl, formatBytes, formatDate, mutate} from './api'
import type {
  AuditEvent,
  Page,
  RefreshJob,
  RepositoryKind,
  RepositorySummary,
  SftpHostKey,
  SnapshotEntry,
  SnapshotSummary,
  SystemStatus,
  User,
} from './types'

const kindLabels: Record<RepositoryKind, string> = {
  local: 'Lokal / SMB',
  rest: 'REST',
  sftp: 'SFTP',
  s3: 'S3',
}

function ErrorMessage({error}: {error: unknown}) {
  if (!error) return null
  return (
    <div className="error-message" role="alert">
      <AlertTriangle size={17} />
      <span>{error instanceof Error ? error.message : String(error)}</span>
    </div>
  )
}

function Loading({label = 'Wird geladen …'}: {label?: string}) {
  return (
    <div className="loading">
      <LoaderCircle className="spin" size={22} />
      {label}
    </div>
  )
}

function LoginPage() {
  const queryClient = useQueryClient()
  const login = useMutation({
    mutationFn: (body: {username: string; password: string}) =>
      mutate<User>('/auth/login', 'POST', body),
    onSuccess: user => queryClient.setQueryData(['me'], user),
  })

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    login.mutate({
      username: String(form.get('username') ?? ''),
      password: String(form.get('password') ?? ''),
    })
  }

  return (
    <main className="login-page">
      <section className="login-card">
        <div className="brand-mark large">
          <Archive size={30} />
        </div>
        <p className="eyebrow">READ-ONLY RECOVERY</p>
        <h1>Restic Repository Browser</h1>
        <p className="muted">Snapshots sicher ansehen und Dateien wiederherstellen.</p>
        <form onSubmit={submit} className="stack-form">
          <label>
            Benutzername
            <input name="username" defaultValue="admin" autoComplete="username" required />
          </label>
          <label>
            Passwort
            <input name="password" type="password" autoComplete="current-password" required autoFocus />
          </label>
          <ErrorMessage error={login.error} />
          <button className="primary wide" disabled={login.isPending}>
            {login.isPending ? <LoaderCircle className="spin" size={18} /> : <LockKeyhole size={18} />}
            Anmelden
          </button>
        </form>
        <div className="security-note">
          <ShieldCheck size={18} />
          Zugangsdaten bleiben verschlüsselt auf diesem Server.
        </div>
      </section>
    </main>
  )
}

function PasswordForm({forced = false}: {forced?: boolean}) {
  const queryClient = useQueryClient()
  const change = useMutation({
    mutationFn: (body: {current_password: string; new_password: string}) =>
      mutate<{message: string}>('/auth/password', 'POST', body),
    onSuccess: () => {
      const current = queryClient.getQueryData<User>(['me'])
      if (current) queryClient.setQueryData(['me'], {...current, must_change_password: false})
    },
  })

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const current = String(form.get('current_password') ?? '')
    const next = String(form.get('new_password') ?? '')
    const confirm = String(form.get('confirm_password') ?? '')
    if (next !== confirm) {
      change.reset()
      return
    }
    change.mutate({current_password: current, new_password: next})
  }

  return (
    <section className={forced ? 'login-card password-card' : 'panel compact-panel'}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">{forced ? 'ERSTER START' : 'SICHERHEIT'}</p>
          <h2>{forced ? 'Startpasswort ändern' : 'Passwort ändern'}</h2>
        </div>
        <KeyRound size={24} />
      </div>
      <p className="muted">
        Das neue Passwort muss mindestens 12 Zeichen enthalten.
      </p>
      <form onSubmit={submit} className="stack-form">
        <label>
          Bisheriges Passwort
          <input name="current_password" type="password" autoComplete="current-password" required />
        </label>
        <label>
          Neues Passwort
          <input name="new_password" type="password" minLength={12} autoComplete="new-password" required />
        </label>
        <label>
          Neues Passwort wiederholen
          <input name="confirm_password" type="password" minLength={12} autoComplete="new-password" required />
        </label>
        <ErrorMessage error={change.error} />
        {change.isSuccess && <div className="success-message"><Check size={17} />Passwort wurde geändert.</div>}
        <button className="primary" disabled={change.isPending}>
          {change.isPending && <LoaderCircle className="spin" size={18} />}
          Passwort speichern
        </button>
      </form>
    </section>
  )
}

function ForcedPasswordPage() {
  return (
    <main className="login-page">
      <PasswordForm forced />
    </main>
  )
}

function Shell({user}: {user: User}) {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const logout = useMutation({
    mutationFn: () => mutate<void>('/auth/logout', 'POST'),
    onSettled: () => {
      queryClient.clear()
      navigate('/')
    },
  })

  return (
    <div className="app-shell">
      <header className="topbar">
        <Link to="/" className="brand">
          <span className="brand-mark"><Archive size={20} /></span>
          <span>
            <strong>Restic Browser</strong>
            <small>Repository Recovery</small>
          </span>
        </Link>
        <nav>
          <Link to="/"><Database size={17} /> Repositories</Link>
          <Link to="/settings"><Settings size={17} /> Einstellungen</Link>
        </nav>
        <div className="account">
          <span className="avatar">{user.username.slice(0, 1).toUpperCase()}</span>
          <button className="icon-button" aria-label="Abmelden" title="Abmelden" onClick={() => logout.mutate()}>
            <LogOut size={18} />
          </button>
        </div>
      </header>
      <Routes>
        <Route path="/" element={<RepositoryPage />} />
        <Route path="/repositories/:repositoryId" element={<RepositoryDetailPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  )
}

function RepositoryPage() {
  const [showForm, setShowForm] = useState(false)
  const query = useQuery({
    queryKey: ['repositories'],
    queryFn: () => api<RepositorySummary[]>('/repositories'),
  })

  return (
    <main className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">DEINE BACKUP-ZIELE</p>
          <h1>Repositories</h1>
          <p className="muted">Bestehende Restic-Snapshots öffnen, durchsuchen und herunterladen.</p>
        </div>
        <button className="primary" onClick={() => setShowForm(true)}>
          <Plus size={18} /> Repository verbinden
        </button>
      </div>
      {query.isLoading && <Loading />}
      <ErrorMessage error={query.error} />
      {query.data?.length === 0 && (
        <section className="empty-state">
          <div className="empty-icon"><HardDrive size={30} /></div>
          <h2>Noch kein Repository verbunden</h2>
          <p>Verbinde ein lokales, REST-, SFTP- oder S3-Repository.</p>
          <button className="primary" onClick={() => setShowForm(true)}>
            <Plus size={18} /> Erstes Repository
          </button>
        </section>
      )}
      <div className="repository-grid">
        {query.data?.map(repository => <RepositoryCard key={repository.id} repository={repository} />)}
      </div>
      {showForm && <RepositoryDialog onClose={() => setShowForm(false)} />}
    </main>
  )
}

function RepositoryCard({repository}: {repository: RepositorySummary}) {
  const [showEdit, setShowEdit] = useState(false)
  const queryClient = useQueryClient()
  const remove = useMutation({
    mutationFn: () => mutate<void>(`/repositories/${repository.id}`, 'DELETE'),
    onSuccess: () => queryClient.invalidateQueries({queryKey: ['repositories']}),
  })
  const state = useMutation({
    mutationFn: () => mutate<RepositorySummary>(
      `/repositories/${repository.id}/state`,
      'PATCH',
      {enabled: !repository.enabled},
    ),
    onSuccess: () => queryClient.invalidateQueries({queryKey: ['repositories']}),
  })
  const doDelete = () => {
    if (window.confirm(`„${repository.name}“ aus dem Browser entfernen? Das Restic-Repository bleibt unverändert.`)) {
      remove.mutate()
    }
  }

  return (
    <article className="repository-card">
      <div className="card-top">
        <span className={`kind-icon ${repository.kind}`}><Server size={22} /></span>
        <span className={`status-pill ${!repository.enabled ? 'disabled' : repository.last_error ? 'failed' : 'healthy'}`}>
          <span /> {!repository.enabled ? 'Deaktiviert' : repository.last_error ? 'Fehler' : 'Bereit'}
        </span>
      </div>
      <div>
        <p className="kind-label">{kindLabels[repository.kind]}</p>
        <h2>{repository.name}</h2>
        <p className="location" title={repository.location_display}>{repository.location_display}</p>
      </div>
      {repository.last_error && <p className="inline-error">{repository.last_error}</p>}
      <div className="repository-stats">
        <div><strong>{repository.snapshot_count}</strong><span>Snapshots</span></div>
        <div><strong>{formatDate(repository.last_snapshot_refresh_at)}</strong><span>Aktualisiert</span></div>
      </div>
      <div className="card-actions">
        <Link className="secondary grow" to={`/repositories/${repository.id}`}>
          Öffnen <ChevronRight size={17} />
        </Link>
        <button className="icon-button outlined" aria-label="Verbindung bearbeiten" title="Verbindung bearbeiten" onClick={() => setShowEdit(true)}>
          <Pencil size={17} />
        </button>
        <button
          className="icon-button outlined"
          aria-label={repository.enabled ? 'Repository deaktivieren' : 'Repository aktivieren'}
          title={repository.enabled ? 'Repository deaktivieren' : 'Repository aktivieren'}
          onClick={() => {
            if (window.confirm(
              repository.enabled
                ? `„${repository.name}“ deaktivieren? Gecachte Snapshots bleiben sichtbar.`
                : `„${repository.name}“ wieder aktivieren?`,
            )) state.mutate()
          }}
          disabled={state.isPending}
        >
          {repository.enabled ? <PauseCircle size={17} /> : <Check size={17} />}
        </button>
        <button className="danger-icon" aria-label="Verbindung entfernen" title="Verbindung entfernen" onClick={doDelete} disabled={remove.isPending}>
          <Trash2 size={17} />
        </button>
      </div>
      {showEdit && <RepositoryDialog existing={repository} onClose={() => setShowEdit(false)} />}
    </article>
  )
}

function RepositoryDialog({onClose, existing}: {onClose: () => void; existing?: RepositorySummary}) {
  const [kind, setKind] = useState<RepositoryKind>(existing?.kind ?? 'local')
  const [sftpAuthMethod, setSftpAuthMethod] = useState<'private_key' | 'password'>(
    existing?.config.auth_method === 'password' ? 'password' : 'private_key',
  )
  const [keys, setKeys] = useState<SftpHostKey[]>([])
  const [selectedKey, setSelectedKey] = useState<SftpHostKey>()
  const [confirmed, setConfirmed] = useState(false)
  const dialogRef = useRef<HTMLElement>(null)
  const queryClient = useQueryClient()
  const requiresNewSecrets = !existing || existing.kind !== kind
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    const dialog = dialogRef.current
    const focusable = () => [...(dialog?.querySelectorAll<HTMLElement>(
      'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href]',
    ) ?? [])]
    focusable()[0]?.focus()
    const handleKey = (event: globalThis.KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onClose()
        return
      }
      if (event.key !== 'Tab') return
      const items = focusable()
      if (!items.length) return
      const first = items[0]
      const last = items[items.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', handleKey)
    return () => {
      document.removeEventListener('keydown', handleKey)
      previous?.focus()
    }
  }, [onClose])
  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      mutate<RepositorySummary>(
        existing ? `/repositories/${existing.id}` : '/repositories',
        existing ? 'PUT' : 'POST',
        body,
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({queryKey: ['repositories']})
      onClose()
    },
  })
  const scan = useMutation({
    mutationFn: (body: {host: string; port: number}) =>
      mutate<SftpHostKey[]>('/repositories/sftp/scan-host-key', 'POST', body),
    onSuccess: result => {
      setKeys(result)
      setSelectedKey(result[0])
      setConfirmed(false)
    },
  })

  const scanKeys = (form: HTMLFormElement) => {
    const data = new FormData(form)
    scan.mutate({
      host: String(data.get('sftp_host') ?? ''),
      port: Number(data.get('sftp_port') ?? 22),
    })
  }

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    if (kind === 'sftp' && requiresNewSecrets && (!selectedKey || !confirmed)) return
    const string = (name: string) => {
      const value = String(form.get(name) ?? '').trim()
      return value || undefined
    }
    const clearSecrets = [
      form.get('clear_rest_password') ? 'rest_password' : '',
      form.get('clear_ca_certificate') ? 'ca_certificate' : '',
      form.get('clear_s3_session_token') ? 's3_session_token' : '',
    ].filter(Boolean)
    save.mutate({
      name: string('name'),
      kind,
      repository_password: String(form.get('repository_password') ?? ''),
      local_path: string('local_path'),
      rest_url: string('rest_url'),
      rest_username: string('rest_username'),
      rest_password: string('rest_password'),
      ca_certificate: string('ca_certificate'),
      sftp_host: string('sftp_host'),
      sftp_port: Number(form.get('sftp_port') ?? 22),
      sftp_username: string('sftp_username'),
      sftp_path: string('sftp_path'),
      sftp_auth_method: sftpAuthMethod,
      sftp_private_key: string('sftp_private_key'),
      sftp_password: string('sftp_password'),
      sftp_known_hosts: selectedKey?.known_hosts,
      sftp_fingerprint: selectedKey?.fingerprint,
      s3_endpoint: string('s3_endpoint'),
      s3_bucket: string('s3_bucket'),
      s3_prefix: string('s3_prefix'),
      s3_region: string('s3_region'),
      s3_access_key_id: string('s3_access_key_id'),
      s3_secret_access_key: string('s3_secret_access_key'),
      s3_session_token: string('s3_session_token'),
      clear_secrets: clearSecrets,
    })
  }

  return (
    <div className="modal-backdrop" role="presentation">
      <section ref={dialogRef} className="modal" role="dialog" aria-modal="true" aria-labelledby="connect-title">
        <div className="modal-header">
          <div>
            <p className="eyebrow">{existing ? 'VERBINDUNG ÄNDERN' : 'NEUE VERBINDUNG'}</p>
            <h2 id="connect-title">{existing ? 'Repository bearbeiten' : 'Repository verbinden'}</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Schließen"><X /></button>
        </div>
        <form onSubmit={submit}>
          <div className="kind-tabs">
            {(Object.keys(kindLabels) as RepositoryKind[]).map(value => (
              <button
                key={value}
                type="button"
                className={kind === value ? 'active' : ''}
                onClick={() => {
                  setKind(value)
                  save.reset()
                }}
              >
                {kindLabels[value]}
              </button>
            ))}
          </div>
          <div className="form-grid">
            <label>
              Anzeigename
              <input name="name" defaultValue={existing?.name} placeholder="Produktions-Backups" required />
            </label>
            <label>
              Restic-Repository-Passwort
              <input name="repository_password" type="password" required={requiresNewSecrets} autoComplete="new-password" />
              {existing && !requiresNewSecrets && <small>Leer lassen, um das gespeicherte Passwort beizubehalten.</small>}
            </label>
            {kind === 'local' && (
              <label className="full">
                Pfad innerhalb von /repositories
                <input name="local_path" defaultValue={String(existing?.config.path ?? '')} placeholder="nas/projekt-restic" required />
                <small>Für SMB die Freigabe auf dem Docker-Host mounten und read-only einbinden.</small>
              </label>
            )}
            {kind === 'rest' && (
              <>
                <label className="full">
                  REST-Repository-URL
                  <input name="rest_url" defaultValue={String(existing?.config.url ?? '')} type="url" placeholder="https://backup.example/repo/" required />
                </label>
                <label>
                  REST-Benutzer
                  <input name="rest_username" defaultValue={String(existing?.config.username ?? '')} autoComplete="off" />
                </label>
                <label>
                  REST-Passwort
                  <input name="rest_password" type="password" autoComplete="new-password" />
                  {existing?.kind === 'rest' && <small>Leer lassen = gespeicherten Wert behalten.</small>}
                </label>
                <label className="full">
                  Eigene CA (optional)
                  <textarea name="ca_certificate" rows={4} placeholder="-----BEGIN CERTIFICATE-----" />
                  {existing?.kind === 'rest' && (
                    <small className="inline-check"><input name="clear_ca_certificate" type="checkbox" /> Gespeicherte CA entfernen</small>
                  )}
                </label>
                {existing?.kind === 'rest' && (
                  <label className="full inline-check"><input name="clear_rest_password" type="checkbox" /> Gespeichertes REST-Passwort entfernen</label>
                )}
              </>
            )}
            {kind === 'sftp' && (
              <>
                <label>
                  Host
                  <input name="sftp_host" defaultValue={String(existing?.config.host ?? '')} placeholder="backup.example" required />
                </label>
                <label>
                  Port
                  <input name="sftp_port" type="number" defaultValue={Number(existing?.config.port ?? 22)} min="1" max="65535" required />
                </label>
                <label>
                  Benutzer
                  <input name="sftp_username" defaultValue={String(existing?.config.username ?? '')} required autoComplete="off" />
                </label>
                <label>
                  Absoluter Repository-Pfad
                  <input name="sftp_path" defaultValue={String(existing?.config.path ?? '')} placeholder="/srv/restic/repo" required />
                </label>
                <label className="full">
                  Authentifizierung
                  <select
                    name="sftp_auth_method"
                    value={sftpAuthMethod}
                    onChange={event => setSftpAuthMethod(event.target.value as 'private_key' | 'password')}
                  >
                    <option value="private_key">Privater SSH-Schlüssel</option>
                    <option value="password">Benutzername &amp; Passwort</option>
                  </select>
                </label>
                {sftpAuthMethod === 'private_key' ? (
                  <label className="full">
                    Privater SSH-Schlüssel
                    <textarea
                      name="sftp_private_key"
                      rows={5}
                      required={requiresNewSecrets || existing?.config.auth_method !== sftpAuthMethod}
                      autoComplete="off"
                      placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                    />
                  </label>
                ) : (
                  <label className="full">
                    SFTP-Passwort
                    <input name="sftp_password" type="password" required={requiresNewSecrets || existing?.config.auth_method !== sftpAuthMethod} autoComplete="new-password" />
                    <small>Wird verschlüsselt gespeichert und nicht als Kommandozeilenargument übergeben.</small>
                  </label>
                )}
                <div className="full host-key-box">
                  <button
                    type="button"
                    className="secondary"
                    onClick={event => scanKeys(event.currentTarget.form!)}
                    disabled={scan.isPending}
                  >
                    {scan.isPending ? <LoaderCircle className="spin" size={17} /> : <ShieldCheck size={17} />}
                    Hostschlüssel abrufen
                  </button>
                  <ErrorMessage error={scan.error} />
                  {keys.length > 0 && (
                    <div className="key-list">
                      {keys.map(key => (
                        <label key={`${key.algorithm}-${key.fingerprint}`} className="key-option">
                          <input
                            type="radio"
                            name="host-key"
                            checked={selectedKey?.fingerprint === key.fingerprint}
                            onChange={() => {
                              setSelectedKey(key)
                              setConfirmed(false)
                            }}
                          />
                          <span><strong>{key.algorithm}</strong><code>{key.fingerprint}</code></span>
                        </label>
                      ))}
                      <label className="confirm-row">
                        <input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />
                        Fingerprint über einen zweiten, vertrauenswürdigen Kanal geprüft
                      </label>
                    </div>
                  )}
                </div>
              </>
            )}
            {kind === 's3' && (
              <>
                <label className="full">
                  HTTPS-Endpunkt
                  <input name="s3_endpoint" defaultValue={String(existing?.config.endpoint ?? '')} type="url" placeholder="https://s3.eu-central-1.amazonaws.com" required />
                </label>
                <label>
                  Bucket
                  <input name="s3_bucket" defaultValue={String(existing?.config.bucket ?? '')} required />
                </label>
                <label>
                  Präfix (optional)
                  <input name="s3_prefix" defaultValue={String(existing?.config.prefix ?? '')} placeholder="restic/server-01" />
                </label>
                <label>
                  Region
                  <input name="s3_region" defaultValue={String(existing?.config.region ?? '')} placeholder="eu-central-1" />
                </label>
                <span />
                <label>
                  Access Key ID
                  <input name="s3_access_key_id" type="password" required={requiresNewSecrets} autoComplete="new-password" />
                </label>
                <label>
                  Secret Access Key
                  <input name="s3_secret_access_key" type="password" required={requiresNewSecrets} autoComplete="new-password" />
                </label>
                <label className="full">
                  Session Token (optional)
                  <input name="s3_session_token" type="password" autoComplete="new-password" />
                  {existing?.kind === 's3' && (
                    <small className="inline-check"><input name="clear_s3_session_token" type="checkbox" /> Gespeichertes Token entfernen</small>
                  )}
                </label>
              </>
            )}
          </div>
          <ErrorMessage error={save.error} />
          <div className="modal-actions">
            <button type="button" className="ghost" onClick={onClose}>Abbrechen</button>
            <button className="primary" disabled={save.isPending || (kind === 'sftp' && requiresNewSecrets && !confirmed)}>
              {save.isPending ? <LoaderCircle className="spin" size={18} /> : <Check size={18} />}
              Verbindung testen & speichern
            </button>
          </div>
        </form>
      </section>
    </div>
  )
}

function RepositoryDetailPage() {
  const {repositoryId = ''} = useParams()
  const queryClient = useQueryClient()
  const [selected, setSelected] = useState<SnapshotSummary>()
  const [search, setSearch] = useState('')
  const [host, setHost] = useState('')
  const [tag, setTag] = useState('')
  const [date, setDate] = useState('')
  const [jobId, setJobId] = useState<string>()
  const repositories = useQuery({
    queryKey: ['repositories'],
    queryFn: () => api<RepositorySummary[]>('/repositories'),
  })
  const snapshots = useInfiniteQuery({
    queryKey: ['snapshots-page', repositoryId, search, host, tag, date],
    initialPageParam: '',
    queryFn: ({pageParam}) => {
      const query = new URLSearchParams({limit: '50'})
      if (pageParam) query.set('cursor', pageParam)
      if (search) query.set('q', search)
      if (host) query.set('host', host)
      if (tag) query.set('tag', tag)
      if (date) query.set('date', date)
      return api<Page<SnapshotSummary>>(`/repositories/${repositoryId}/snapshots/page?${query}`)
    },
    getNextPageParam: page => page.next_cursor,
  })
  const refresh = useMutation({
    mutationFn: () => mutate<RefreshJob>(`/repositories/${repositoryId}/refresh`, 'POST'),
    onSuccess: job => setJobId(job.id),
  })
  const job = useQuery({
    queryKey: ['refresh-job', jobId],
    queryFn: () => api<RefreshJob>(`/refresh-jobs/${jobId}`),
    enabled: Boolean(jobId),
    refetchInterval: query => {
      const status = query.state.data?.status
      return status === 'success' || status === 'failed' ? false : 1200
    },
  })
  useEffect(() => {
    if (job.data?.status === 'success') {
      queryClient.invalidateQueries({queryKey: ['snapshots-page', repositoryId]})
      queryClient.invalidateQueries({queryKey: ['repositories']})
    }
  }, [job.data?.status, queryClient, repositoryId])
  useEffect(() => setSelected(undefined), [search, host, tag, date])

  const repository = repositories.data?.find(item => item.id === repositoryId)
  const snapshotItems = useMemo(
    () => snapshots.data?.pages.flatMap(page => page.items) ?? [],
    [snapshots.data],
  )
  const hosts = [...new Set(snapshotItems.map(item => item.hostname).filter(Boolean))].sort()
  const tags = [...new Set(snapshotItems.flatMap(item => item.tags))].sort()
  const snapshotScrollRef = useRef<HTMLDivElement>(null)
  const snapshotVirtualizer = useVirtualizer({
    count: snapshotItems.length,
    getScrollElement: () => snapshotScrollRef.current,
    estimateSize: () => 96,
    overscan: 6,
  })

  if (repositories.isLoading) return <main className="page"><Loading /></main>
  if (!repository) return <Navigate to="/" replace />
  const refreshing = job.data?.status === 'queued' || job.data?.status === 'running'

  return (
    <main className="page detail-page">
      <div className="detail-heading">
        <Link className="back-link" to="/"><ArrowLeft size={17} /> Repositories</Link>
        <div className="detail-title">
          <span className={`kind-icon ${repository.kind}`}><Server size={22} /></span>
          <div>
            <h1>{repository.name}</h1>
            <p className="location">{repository.location_display}</p>
          </div>
        </div>
        <button className="secondary" onClick={() => refresh.mutate()} disabled={!repository.enabled || refresh.isPending || refreshing}>
          <RefreshCw className={refreshing ? 'spin' : ''} size={17} />
          Jetzt aktualisieren
        </button>
      </div>
      {!repository.enabled && (
        <div className="notice-message" role="status">
          <PauseCircle size={18} /> Das Repository ist deaktiviert. Gecachte Snapshot-Metadaten bleiben sichtbar.
        </div>
      )}
      <ErrorMessage error={snapshots.error || refresh.error || (job.data?.status === 'failed' ? new Error(job.data.error) : null)} />
      <div className="browser-layout">
        <aside className="snapshot-panel">
          <div className="panel-title">
            <div><p className="eyebrow">VERLAUF</p><h2>Snapshots</h2></div>
            <span className="count-badge">{snapshotItems.length}</span>
          </div>
          <div className="filters">
            <label className="search-field"><Search size={16} /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Suchen …" /></label>
            <div className="filter-row">
              <input list="snapshot-hosts" value={host} onChange={event => setHost(event.target.value)} placeholder="Alle Hosts" aria-label="Hostfilter" />
              <datalist id="snapshot-hosts">{hosts.map(value => <option key={value} value={value} />)}</datalist>
              <input list="snapshot-tags" value={tag} onChange={event => setTag(event.target.value)} placeholder="Alle Tags" aria-label="Tagfilter" />
              <datalist id="snapshot-tags">{tags.map(value => <option key={value} value={value} />)}</datalist>
            </div>
            <input
              aria-label="Snapshot-Datum"
              type="date"
              value={date}
              onChange={event => setDate(event.target.value)}
            />
          </div>
          {snapshots.isLoading && <Loading label="Snapshots werden geladen …" />}
          <div ref={snapshotScrollRef} className="snapshot-list" role="listbox" aria-label="Snapshots">
            <div className="virtual-content" style={{height: snapshotVirtualizer.getTotalSize()}}>
              {snapshotVirtualizer.getVirtualItems().map(virtualRow => {
                const snapshot = snapshotItems[virtualRow.index]
                return (
                  <button
                    key={snapshot.id}
                    ref={snapshotVirtualizer.measureElement}
                    data-index={virtualRow.index}
                    role="option"
                    aria-selected={selected?.id === snapshot.id}
                    className={`snapshot-item ${selected?.id === snapshot.id ? 'selected' : ''}`}
                    style={{transform: `translateY(${virtualRow.start}px)`}}
                    onClick={() => setSelected(snapshot)}
                    onKeyDown={event => {
                      if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
                      event.preventDefault()
                      const buttons = snapshotScrollRef.current?.querySelectorAll<HTMLButtonElement>('.snapshot-item')
                      const index = [...(buttons ?? [])].indexOf(event.currentTarget)
                      buttons?.[index + (event.key === 'ArrowDown' ? 1 : -1)]?.focus()
                    }}
                  >
                    <span className="snapshot-date">{formatDate(snapshot.time)}</span>
                    <strong>{snapshot.hostname || 'Ohne Hostname'}</strong>
                    <small>{snapshot.short_id} · {snapshot.paths.length} Pfad{snapshot.paths.length === 1 ? '' : 'e'}</small>
                    {snapshot.tags.length > 0 && <span className="tag-row">{snapshot.tags.slice(0, 3).map(value => <em key={value}>{value}</em>)}</span>}
                  </button>
                )
              })}
            </div>
          </div>
          {snapshots.hasNextPage && (
            <button className="ghost load-more" onClick={() => snapshots.fetchNextPage()} disabled={snapshots.isFetchingNextPage}>
              {snapshots.isFetchingNextPage ? 'Wird geladen …' : 'Weitere Snapshots'}
            </button>
          )}
        </aside>
        <section className="file-panel">
          {selected && repository.enabled ? (
            <FileBrowser snapshot={selected} />
          ) : selected ? (
            <div className="empty-browser"><PauseCircle size={42} /><h2>Repository deaktiviert</h2><p>Aktiviere es, um Verzeichnisse zu lesen oder Dateien herunterzuladen.</p></div>
          ) : (
            <div className="empty-browser">
              <FolderOpen size={42} />
              <h2>Snapshot auswählen</h2>
              <p>Wähle links einen Zeitpunkt, um den enthaltenen Dateibaum zu öffnen.</p>
            </div>
          )}
        </section>
      </div>
    </main>
  )
}

function FileBrowser({snapshot}: {snapshot: SnapshotSummary}) {
  const [path, setPath] = useState('/')
  useEffect(() => setPath('/'), [snapshot.id])
  const query = useInfiniteQuery({
    queryKey: ['entries-page', snapshot.id, path],
    initialPageParam: '',
    queryFn: ({pageParam}) => {
      const params = new URLSearchParams({path, limit: '100'})
      if (pageParam) params.set('cursor', pageParam)
      return api<Page<SnapshotEntry>>(`/snapshots/${snapshot.id}/entries/page?${params}`)
    },
    getNextPageParam: page => page.next_cursor,
  })
  const entries = useMemo(
    () => query.data?.pages.flatMap(page => page.items) ?? [],
    [query.data],
  )
  const fileScrollRef = useRef<HTMLDivElement>(null)
  const fileVirtualizer = useVirtualizer({
    count: entries.length,
    getScrollElement: () => fileScrollRef.current,
    estimateSize: () => 54,
    overscan: 10,
  })
  const parts = path.split('/').filter(Boolean)
  const crumbs = [{name: 'Wurzel', path: '/'}]
  parts.forEach((name, index) => crumbs.push({name, path: `/${parts.slice(0, index + 1).join('/')}`}))

  return (
    <>
      <div className="file-toolbar">
        <div>
          <p className="eyebrow">DATEIBROWSER · {snapshot.short_id}</p>
          <nav className="breadcrumbs">
            {crumbs.map((crumb, index) => (
              <span key={crumb.path}>
                {index > 0 && <ChevronRight size={14} />}
                <button onClick={() => setPath(crumb.path)}>{crumb.name}</button>
              </span>
            ))}
          </nav>
        </div>
        <a className="secondary" href={downloadUrl(snapshot.id, path, true)}>
          <Archive size={17} /> Ordner als ZIP
        </a>
      </div>
      {query.isLoading && <Loading label="Ordner wird gelesen …" />}
      <ErrorMessage error={query.error} />
      {!query.isLoading && entries.length === 0 && (
        <div className="empty-folder"><Folder size={28} /><p>Dieser Ordner ist leer.</p></div>
      )}
      <div className="file-table" role="table">
        <div className="file-row header" role="row">
          <span role="columnheader">Name</span><span role="columnheader">Größe</span><span role="columnheader">Geändert</span><span role="columnheader">Aktion</span>
        </div>
        <div ref={fileScrollRef} className="file-scroll">
          <div className="virtual-content" style={{height: fileVirtualizer.getTotalSize()}}>
            {fileVirtualizer.getVirtualItems().map(virtualRow => {
              const entry = entries[virtualRow.index]
              const directory = entry.type === 'dir'
              const name = <><span aria-hidden="true">{directory ? <Folder size={19} /> : <File size={19} />}</span><span><strong>{entry.name}</strong>{entry.linktarget && <small>→ {entry.linktarget}</small>}</span></>
              return (
                <div
                  className="file-row virtual-row"
                  role="row"
                  key={entry.path}
                  ref={fileVirtualizer.measureElement}
                  data-index={virtualRow.index}
                  style={{transform: `translateY(${virtualRow.start}px)`}}
                >
                  <span role="cell">{directory ? <button className="file-name" onClick={() => setPath(entry.path)}>{name}</button> : <span className="file-name">{name}</span>}</span>
                  <span role="cell">{directory ? '—' : formatBytes(entry.size)}</span>
                  <span role="cell">{formatDate(entry.mtime)}</span>
                  <span role="cell">
                    {(directory || entry.type === 'file') && (
                      <a className="download-button" aria-label={directory ? `${entry.name} als ZIP herunterladen` : `${entry.name} herunterladen`} href={downloadUrl(snapshot.id, entry.path, directory)}>
                        {directory ? <Archive size={17} /> : <Download size={17} />}
                      </a>
                    )}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      </div>
      {query.hasNextPage && (
        <button className="ghost load-more" onClick={() => query.fetchNextPage()} disabled={query.isFetchingNextPage}>
          {query.isFetchingNextPage ? 'Wird geladen …' : 'Weitere Einträge'}
        </button>
      )}
    </>
  )
}

function SettingsPage() {
  const status = useQuery({
    queryKey: ['system-status'],
    queryFn: () => api<SystemStatus>('/system/status'),
    refetchInterval: 10_000,
  })
  const audit = useInfiniteQuery({
    queryKey: ['audit-events'],
    initialPageParam: '',
    queryFn: ({pageParam}) => {
      const params = new URLSearchParams({limit: '50'})
      if (pageParam) params.set('cursor', pageParam)
      return api<Page<AuditEvent>>(`/audit-events?${params}`)
    },
    getNextPageParam: page => page.next_cursor,
  })
  const events = audit.data?.pages.flatMap(page => page.items) ?? []

  return (
    <main className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">KONTO</p>
          <h1>Einstellungen</h1>
          <p className="muted">Sicherheitsoptionen für das lokale Administratorkonto.</p>
        </div>
      </div>
      <div className="settings-grid">
        <PasswordForm />
        <section className="panel">
          <div className="section-heading">
            <div><p className="eyebrow">BETRIEB</p><h2>Systemstatus</h2></div>
            <Activity size={24} />
          </div>
          {status.isLoading && <Loading />}
          <ErrorMessage error={status.error} />
          {status.data && (
            <dl className="status-grid">
              <div><dt>Worker</dt><dd>{status.data.worker_running ? 'Aktiv' : 'Gestoppt'}</dd></div>
              <div><dt>Jobs</dt><dd>{status.data.running_jobs} aktiv · {status.data.queued_jobs} wartend</dd></div>
              <div><dt>Cache</dt><dd>{status.data.directory_listings} Ordner · {status.data.cached_entries} Einträge</dd></div>
              <div><dt>Restic-Limit</dt><dd>{status.data.restic_limit} parallel</dd></div>
              <div><dt>Bereinigung</dt><dd>{formatDate(status.data.last_cleanup_at)}</dd></div>
              <div><dt>Fehlgeschlagen</dt><dd>{status.data.failed_jobs}</dd></div>
            </dl>
          )}
        </section>
      </div>
      <section className="panel audit-panel">
        <div className="section-heading">
          <div><p className="eyebrow">SICHERHEIT</p><h2>Audit-Protokoll</h2></div>
          <ShieldCheck size={24} />
        </div>
        <ErrorMessage error={audit.error} />
        {audit.isLoading && <Loading />}
        <div className="audit-table" role="table" aria-label="Audit-Protokoll">
          <div className="audit-row header" role="row">
            <span role="columnheader">Zeit</span><span role="columnheader">Aktion</span><span role="columnheader">Ergebnis</span><span role="columnheader">Ziel</span>
          </div>
          {events.map(event => (
            <div className="audit-row" role="row" key={event.id}>
              <span role="cell">{formatDate(event.created_at)}</span>
              <span role="cell"><strong>{event.action}</strong><small>{event.user_name || 'system'}</small></span>
              <span role="cell" className={event.result === 'success' ? 'audit-success' : 'audit-failed'}>{event.result}</span>
              <span role="cell" title={event.path}>{event.path || event.repository_id || '—'}</span>
            </div>
          ))}
        </div>
        {audit.hasNextPage && (
          <button className="ghost load-more" onClick={() => audit.fetchNextPage()} disabled={audit.isFetchingNextPage}>
            {audit.isFetchingNextPage ? 'Wird geladen …' : 'Weitere Ereignisse'}
          </button>
        )}
      </section>
    </main>
  )
}

export default function App() {
  const me = useQuery({
    queryKey: ['me'],
    queryFn: () => api<User>('/auth/me'),
    retry: false,
  })
  if (me.isLoading) return <main className="login-page"><Loading /></main>
  if (me.error instanceof ApiError && me.error.status === 401) return <LoginPage />
  if (me.error) return <main className="login-page"><ErrorMessage error={me.error} /></main>
  if (me.data?.must_change_password) return <ForcedPasswordPage />
  return me.data ? <Shell user={me.data} /> : <LoginPage />
}
