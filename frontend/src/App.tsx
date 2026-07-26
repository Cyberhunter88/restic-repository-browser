import {FormEvent, useEffect, useMemo, useState} from 'react'
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {
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
  RefreshJob,
  RepositoryKind,
  RepositorySummary,
  SftpHostKey,
  SnapshotEntry,
  SnapshotSummary,
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
          <button className="icon-button" title="Abmelden" onClick={() => logout.mutate()}>
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
  const doDelete = () => {
    if (window.confirm(`„${repository.name}“ aus dem Browser entfernen? Das Restic-Repository bleibt unverändert.`)) {
      remove.mutate()
    }
  }

  return (
    <article className="repository-card">
      <div className="card-top">
        <span className={`kind-icon ${repository.kind}`}><Server size={22} /></span>
        <span className={`status-pill ${repository.last_error ? 'failed' : 'healthy'}`}>
          <span /> {repository.last_error ? 'Fehler' : 'Bereit'}
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
        <button className="icon-button outlined" title="Verbindung bearbeiten" onClick={() => setShowEdit(true)}>
          <Pencil size={17} />
        </button>
        <button className="danger-icon" title="Verbindung entfernen" onClick={doDelete} disabled={remove.isPending}>
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
  const queryClient = useQueryClient()
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
    if (kind === 'sftp' && (!selectedKey || !confirmed)) return
    const string = (name: string) => {
      const value = String(form.get(name) ?? '').trim()
      return value || undefined
    }
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
    })
  }

  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal" role="dialog" aria-modal="true" aria-labelledby="connect-title">
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
              <input name="repository_password" type="password" required autoComplete="new-password" />
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
                </label>
                <label className="full">
                  Eigene CA (optional)
                  <textarea name="ca_certificate" rows={4} placeholder="-----BEGIN CERTIFICATE-----" />
                </label>
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
                      required
                      autoComplete="off"
                      placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                    />
                  </label>
                ) : (
                  <label className="full">
                    SFTP-Passwort
                    <input name="sftp_password" type="password" required autoComplete="new-password" />
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
                  <input name="s3_access_key_id" type="password" required autoComplete="new-password" />
                </label>
                <label>
                  Secret Access Key
                  <input name="s3_secret_access_key" type="password" required autoComplete="new-password" />
                </label>
                <label className="full">
                  Session Token (optional)
                  <input name="s3_session_token" type="password" autoComplete="new-password" />
                </label>
              </>
            )}
          </div>
          <ErrorMessage error={save.error} />
          <div className="modal-actions">
            <button type="button" className="ghost" onClick={onClose}>Abbrechen</button>
            <button className="primary" disabled={save.isPending || (kind === 'sftp' && !confirmed)}>
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
  const snapshots = useQuery({
    queryKey: ['snapshots', repositoryId],
    queryFn: () => api<SnapshotSummary[]>(`/repositories/${repositoryId}/snapshots`),
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
      queryClient.invalidateQueries({queryKey: ['snapshots', repositoryId]})
      queryClient.invalidateQueries({queryKey: ['repositories']})
    }
  }, [job.data?.status, queryClient, repositoryId])

  const repository = repositories.data?.find(item => item.id === repositoryId)
  const hosts = [...new Set(snapshots.data?.map(item => item.hostname).filter(Boolean) ?? [])].sort()
  const tags = [...new Set(snapshots.data?.flatMap(item => item.tags) ?? [])].sort()
  const filtered = useMemo(() => {
    const term = search.toLowerCase()
    return snapshots.data?.filter(item => (
      (!host || item.hostname === host)
      && (!tag || item.tags.includes(tag))
      && (!date || item.time.slice(0, 10) === date)
      && (!term || `${item.short_id} ${item.hostname} ${item.paths.join(' ')} ${item.tags.join(' ')}`.toLowerCase().includes(term))
    )) ?? []
  }, [snapshots.data, search, host, tag, date])

  if (repositories.isLoading) return <main className="page"><Loading /></main>
  if (!repository) return <Navigate to="/" replace />

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
        <button className="secondary" onClick={() => refresh.mutate()} disabled={refresh.isPending || job.data?.status === 'running'}>
          <RefreshCw className={job.data?.status === 'running' ? 'spin' : ''} size={17} />
          Jetzt aktualisieren
        </button>
      </div>
      <ErrorMessage error={snapshots.error || refresh.error || (job.data?.status === 'failed' ? new Error(job.data.error) : null)} />
      <div className="browser-layout">
        <aside className="snapshot-panel">
          <div className="panel-title">
            <div><p className="eyebrow">VERLAUF</p><h2>Snapshots</h2></div>
            <span className="count-badge">{filtered.length}</span>
          </div>
          <div className="filters">
            <label className="search-field"><Search size={16} /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Suchen …" /></label>
            <div className="filter-row">
              <select value={host} onChange={event => setHost(event.target.value)}>
                <option value="">Alle Hosts</option>
                {hosts.map(value => <option key={value}>{value}</option>)}
              </select>
              <select value={tag} onChange={event => setTag(event.target.value)}>
                <option value="">Alle Tags</option>
                {tags.map(value => <option key={value}>{value}</option>)}
              </select>
            </div>
            <input
              aria-label="Snapshot-Datum"
              type="date"
              value={date}
              onChange={event => setDate(event.target.value)}
            />
          </div>
          {snapshots.isLoading && <Loading label="Snapshots werden geladen …" />}
          <div className="snapshot-list">
            {filtered.map(snapshot => (
              <button key={snapshot.id} className={selected?.id === snapshot.id ? 'selected' : ''} onClick={() => setSelected(snapshot)}>
                <span className="snapshot-date">{formatDate(snapshot.time)}</span>
                <strong>{snapshot.hostname || 'Ohne Hostname'}</strong>
                <small>{snapshot.short_id} · {snapshot.paths.length} Pfad{snapshot.paths.length === 1 ? '' : 'e'}</small>
                {snapshot.tags.length > 0 && <span className="tag-row">{snapshot.tags.slice(0, 3).map(value => <em key={value}>{value}</em>)}</span>}
              </button>
            ))}
          </div>
        </aside>
        <section className="file-panel">
          {selected ? (
            <FileBrowser snapshot={selected} />
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
  const query = useQuery({
    queryKey: ['entries', snapshot.id, path],
    queryFn: () => api<SnapshotEntry[]>(`/snapshots/${snapshot.id}/entries?path=${encodeURIComponent(path)}`),
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
      {!query.isLoading && query.data?.length === 0 && (
        <div className="empty-folder"><Folder size={28} /><p>Dieser Ordner ist leer.</p></div>
      )}
      <div className="file-table" role="table">
        <div className="file-row header" role="row">
          <span>Name</span><span>Größe</span><span>Geändert</span><span />
        </div>
        {query.data?.map(entry => {
          const directory = entry.type === 'dir'
          return (
            <div className="file-row" role="row" key={entry.path}>
              <button className="file-name" disabled={!directory} onClick={() => directory && setPath(entry.path)}>
                {directory ? <Folder size={19} /> : <File size={19} />}
                <span><strong>{entry.name}</strong>{entry.linktarget && <small>→ {entry.linktarget}</small>}</span>
              </button>
              <span>{directory ? '—' : formatBytes(entry.size)}</span>
              <span>{formatDate(entry.mtime)}</span>
              {(directory || entry.type === 'file') ? (
                <a className="download-button" title={directory ? 'Ordner als ZIP' : 'Datei herunterladen'} href={downloadUrl(snapshot.id, entry.path, directory)}>
                  {directory ? <Archive size={17} /> : <Download size={17} />}
                </a>
              ) : <span />}
            </div>
          )
        })}
      </div>
    </>
  )
}

function SettingsPage() {
  return (
    <main className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">KONTO</p>
          <h1>Einstellungen</h1>
          <p className="muted">Sicherheitsoptionen für das lokale Administratorkonto.</p>
        </div>
      </div>
      <PasswordForm />
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
