# Restic Repository Browser

Restic Repository Browser ist eine kleine, selbst gehostete Webanwendung zum
Öffnen bestehender Restic-Repositories. Sie zeigt Snapshots und deren Dateibaum
an, lädt einzelne Dateien im Originalformat herunter und streamt ganze Ordner
als ZIP.

Die Anwendung ist bewusst **read-only**: Sie erstellt keine Backups und bietet
keine Befehle für `forget`, `prune`, `unlock`, `check` oder einen Restore auf
Serverpfade an. Alle Leseoperationen verwenden `--no-lock`.

## Funktionen

- lokale und read-only eingebundene SMB-Repositories
- REST-Repositories über HTTPS
- SFTP mit privatem Schlüssel oder Benutzername/Passwort und bestätigtem SSH-Hostschlüssel
- Amazon S3 und S3-kompatible HTTPS-Endpunkte
- Snapshot-Cache mit automatischer und manueller Aktualisierung
- neustartfeste Aktualisierungsjobs und paginierter Verzeichnis-Cache
- Dateibrowser mit Breadcrumbs, Metadaten, Host- und Tag-Filtern
- Originaldownload einzelner Dateien und gestreamte Ordner-ZIPs
- ein lokales Administratorkonto mit Argon2id-Passwort
- AES-256-GCM-verschlüsselte Repository-Zugangsdaten
- lokales Audit-Protokoll, Systemstatus und optionale Ziel-Allowlist
- Docker-Images für AMD64 und ARM64

## Schnellstart

Voraussetzungen sind Docker Engine und das Compose-Plugin auf einem Linux-Host.

```bash
mkdir restic-repository-browser
cd restic-repository-browser
wget -q https://raw.githubusercontent.com/Cyberhunter88/restic-repository-browser/main/compose.yaml
wget -q https://raw.githubusercontent.com/Cyberhunter88/restic-repository-browser/main/.env.example
cp .env.example .env
```

In `.env` ein zufälliges Startpasswort mit mindestens 12, besser 20 oder mehr
Zeichen setzen. Danach:

```bash
mkdir -p data repositories
docker compose pull
docker compose up -d
```

Die Oberfläche liegt unter `http://SERVER:8080`. Die erste Anmeldung erfolgt
mit `admin` und dem Wert aus `RRB_INITIAL_ADMIN_PASSWORD`; anschließend muss das
Passwort geändert werden.

`data/` enthält Datenbank und Master-Key und muss regelmäßig gemeinsam
gesichert werden. Ohne `data/security/master.key` lassen sich gespeicherte
Repository-Zugangsdaten nicht mehr entschlüsseln.

## Betrieb hinter einem Reverse Proxy

Der Standardmodus spricht HTTP und ist für einen TLS-Reverse-Proxy gedacht.
Nur explizit in `RRB_TRUSTED_PROXY_IPS` eingetragene Adressen dürfen
`X-Forwarded-Proto` setzen. Beispiel:

```env
RRB_TRUSTED_PROXY_IPS=172.18.0.0/16
```

Der Proxy muss `Host` und `X-Forwarded-Proto` unverändert weiterreichen. Die
Anwendung setzt das Session-Cookie nur dann als `Secure`, wenn die direkte
Verbindung TLS verwendet oder ein vertrauenswürdiger Proxy HTTPS meldet.

## Direkter HTTPS-Betrieb

Für vorhandene Zertifikatsdateien:

```bash
export RRB_TLS_CERT_HOST_PATH=/etc/letsencrypt/live/backup.example/fullchain.pem
export RRB_TLS_KEY_HOST_PATH=/etc/letsencrypt/live/backup.example/privkey.pem
docker compose -f compose.yaml -f compose.https.yaml up -d
```

Der veröffentlichte Port bleibt über `RRB_HTTP_PORT` konfigurierbar und spricht
in diesem Modus HTTPS.

## Lokale und SMB-Repositories

Lokale Repository-Pfade müssen innerhalb von `/repositories` liegen. Das
Compose-Standardverzeichnis `./repositories` wird read-only eingebunden.

SMB wird absichtlich nicht im Container gemountet. Die Freigabe wird auf dem
Docker-Host bereitgestellt und read-only in den Container gereicht:

```bash
sudo mkdir -p /mnt/restic-nas
sudo mount -t cifs //nas/backup /mnt/restic-nas \
  -o credentials=/root/.smb-restic,ro,nosuid,nodev,noexec
docker compose -f compose.yaml -f compose.smb.example.yaml up -d
```

Danach in der Weboberfläche den lokalen Pfad `nas` eintragen. Die
Mount-Konfiguration des Hosts muss sicherstellen, dass die Freigabe nach einem
Neustart wieder verfügbar ist.

## Repository-Zugänge

- **REST:** Nur HTTPS. Zugangsdaten gehören in die getrennten Formularfelder,
  nicht in die URL. Eine eigene CA kann als PEM hinterlegt werden.
- **SFTP:** Authentifizierung wahlweise mit privatem Schlüssel oder
  Benutzername/Passwort. Der Assistent liest Hostschlüssel aus und verlangt
  eine ausdrückliche Fingerprint-Bestätigung über einen zweiten
  vertrauenswürdigen Kanal.
- **S3:** Nur HTTPS-Endpunkte. Bucket, Präfix, Region und Zugangsdaten werden
  getrennt gespeichert. Temporäre Zugangsdaten können ein Session Token
  enthalten.

Der Browser benötigt Leserechte für die Repository-Daten. Da `--no-lock`
verwendet wird, schreibt er keine Lockdateien. Während `prune` oder anderer
destruktiver Wartung können Lesevorgänge fehlschlagen; sie sollten danach
wiederholt werden.

### Optionale Netzwerk-Allowlist

Mit `RRB_ALLOWED_REMOTE_TARGETS` können entfernte REST-, S3- und SFTP-Ziele
auf exakte Hostnamen, IP-Adressen oder CIDR-Netze begrenzt werden:

```env
RRB_ALLOWED_REMOTE_TARGETS=backup.example,10.20.0.0/16,2001:db8:42::/48
```

Ein leerer Wert erhält das bisherige Verhalten. Die Prüfung ist eine
zusätzliche Schutzschicht; eine Egress-Firewall am Container oder Docker-Host
bleibt die verbindliche Grenze gegen DNS-Rebinding und HTTP-Weiterleitungen.

## Lokaler Build

```bash
docker compose -f compose.yaml -f compose.build.yaml build
docker compose -f compose.yaml -f compose.build.yaml up -d
```

Entwicklung ohne Docker:

```bash
python -m pip install -e ".[dev]"
RRB_INITIAL_ADMIN_PASSWORD='ein-langes-testpasswort' python -m backend.app.bootstrap
uvicorn backend.app.main:app --reload --port 8080

cd frontend
pnpm install
pnpm dev
```

## Prüfungen

```bash
python -m ruff check backend
python -m pytest -q
cd frontend
pnpm test
pnpm build
```

## Sicherheitsgrenzen

- Dieses Werkzeug ersetzt keine regelmäßigen Restore-Tests.
- Repository-Zugangsdaten werden verschlüsselt, aber ein Angreifer mit Zugriff
  auf den laufenden Container oder auf `data/` inklusive Master-Key kann sie
  entschlüsseln.
- Die Anwendung darf nicht ohne TLS über ein nicht vertrauenswürdiges Netz
  veröffentlicht werden.
- Repository-Daten werden nie durch das Löschen einer Verbindung in der
  Oberfläche entfernt.

## Lizenz

[MIT](LICENSE)
