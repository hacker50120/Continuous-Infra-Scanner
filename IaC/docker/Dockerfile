# InfraScanner Pro – Root-less Container
FROM python:3.11-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/scanner/.local/bin:/usr/local/bin:${PATH}"

WORKDIR /usr/src/app

# ── System packages ─────────────────────────────────────────────
RUN apk update && \
    apk add --no-cache \
        build-base libffi-dev openssl-dev \
        nmap nmap-scripts \
        nodejs npm \
        go git curl wget \
        postgresql-dev musl-dev gcc python3-dev && \
    rm -rf /var/cache/apk/*

# ── Unprivileged user ───────────────────────────────────────────
RUN addgroup -S scanner && adduser -S -G scanner scanner

# ── Nuclei (non-root OK) ────────────────────────────────────────
RUN go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    nuclei -update-templates || true

# ── Python deps & PM2 ───────────────────────────────────────────
COPY ../../app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    npm install -g pm2

# ── Application code ────────────────────────────────────────────
COPY ../../app/ .

# ── Prepare log folders inside the image ────────────────────────
RUN mkdir -p logs/scan_logs logs/nuclei_results logs/app_logs && \
    chown -R scanner:scanner /usr/src/app

USER scanner

EXPOSE 8181

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8180/ || exit 1

CMD ["pm2-runtime", "pm2.config.js"]
