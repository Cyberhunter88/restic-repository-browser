FROM --platform=$BUILDPLATFORM node:24.14.1-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY frontend ./
RUN pnpm build

FROM --platform=$BUILDPLATFORM alpine:3.22 AS restic
ARG RESTIC_VERSION=0.19.1
ARG TARGETARCH
RUN apk add --no-cache bzip2 ca-certificates curl \
    && case "${TARGETARCH:-amd64}" in \
         amd64) restic_arch=amd64 ;; \
         arm64) restic_arch=arm64 ;; \
         *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && restic_asset="restic_${RESTIC_VERSION}_linux_${restic_arch}.bz2" \
    && curl --proto '=https' --tlsv1.2 -fsSLo "/tmp/${restic_asset}" \
       "https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/${restic_asset}" \
    && curl --proto '=https' --tlsv1.2 -fsSLo /tmp/SHA256SUMS \
       "https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/SHA256SUMS" \
    && grep " ${restic_asset}$" /tmp/SHA256SUMS | (cd /tmp && sha256sum -c -) \
    && bzip2 -d "/tmp/${restic_asset}" \
    && install -m 0755 "/tmp/${restic_asset%.bz2}" /restic

FROM python:3.12.11-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RRB_DATA_DIR=/data \
    RRB_REPOSITORY_ROOT=/repositories \
    RRB_FRONTEND_DIR=/app/frontend/dist
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates gosu openssh-client \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md alembic.ini ./
COPY backend ./backend
COPY alembic ./alembic
RUN pip install --no-cache-dir --no-compile . \
    && find /usr/local/lib/python3.12 -type d -name __pycache__ -prune -exec rm -rf '{}' +
COPY --from=frontend /src/frontend/dist ./frontend/dist
COPY --from=restic /restic /usr/local/bin/restic
COPY scripts/entrypoint.sh scripts/healthcheck.py scripts/sftp-askpass.sh /usr/local/bin/
RUN chmod 0755 \
        /usr/local/bin/entrypoint.sh \
        /usr/local/bin/healthcheck.py \
        /usr/local/bin/sftp-askpass.sh \
    && useradd --uid 1000 --create-home --home-dir /home/rrb rrb
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=20s \
    CMD ["python", "/usr/local/bin/healthcheck.py"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
