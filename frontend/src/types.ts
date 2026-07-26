export type RepositoryKind = 'local' | 'rest' | 'sftp' | 's3'

export interface User {
  username: string
  must_change_password: boolean
}

export interface RepositorySummary {
  id: string
  name: string
  kind: RepositoryKind
  location_display: string
  enabled: boolean
  last_check_at?: string
  last_snapshot_refresh_at?: string
  last_error: string
  snapshot_count: number
  created_at: string
  config: Record<string, string | number>
}

export interface SnapshotSummary {
  id: string
  repository_id: string
  snapshot_id: string
  short_id: string
  time: string
  hostname: string
  username: string
  paths: string[]
  tags: string[]
  summary: Record<string, number | string>
  cached_at: string
}

export interface SnapshotEntry {
  path: string
  name: string
  type: string
  size: number
  mode?: number | string
  mtime?: string
  uid?: number
  gid?: number
  linktarget?: string
}

export interface RefreshJob {
  id: string
  repository_id: string
  status: 'queued' | 'running' | 'success' | 'failed'
  error: string
  created_at: string
  started_at?: string
  finished_at?: string
  attempt_count: number
}

export interface SftpHostKey {
  algorithm: string
  fingerprint: string
  known_hosts: string
}

export interface Page<T> {
  items: T[]
  next_cursor?: string
}

export interface AuditEvent {
  id: number
  user_name: string
  action: string
  result: string
  repository_id?: string
  snapshot_id?: string
  path?: string
  detail: string
  created_at: string
}

export interface SystemStatus {
  worker_running: boolean
  queued_jobs: number
  running_jobs: number
  failed_jobs: number
  directory_listings: number
  cached_entries: number
  restic_limit: number
  last_cleanup_at?: string
}
