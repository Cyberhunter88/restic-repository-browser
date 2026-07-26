# AGENTS.md

## Projektziel

Dieses Repository enthält einen ausschließlich lesenden Browser für bestehende
Restic-Repositories. Er darf keine Backup-, Forget-, Prune-, Unlock- oder
serverseitigen Restore-Befehle ausführen.

## Regeln

- Secrets niemals in Logs, API-Antworten, Kommandozeilen oder Git schreiben.
- Restic ausschließlich mit Argumentlisten und ohne Shell starten.
- Repository-Pfade müssen innerhalb des konfigurierten Mount-Roots bleiben.
- Alle Repository-Leseoperationen verwenden `--no-lock`.
- Downloads dürfen nicht vollständig auf dem Anwendungsserver materialisiert werden.
- Änderungen an API oder Datenbank benötigen Tests und gegebenenfalls eine
  Alembic-Migration.

## Prüfungen

```bash
python -m ruff check backend
python -m pytest -q
cd frontend
pnpm test
pnpm build
```

