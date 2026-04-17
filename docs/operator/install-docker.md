# Docker install

For teams comfortable with Docker. Easiest path to a running server.

## Prerequisites

- Docker Engine ≥ 24 or Docker Desktop
- A public hostname + optional reverse proxy for TLS

## Quick start

```bash
git clone https://github.com/your-org/vulnforge.git
cd vulnforge

# 1. Copy the example env file
cp .env.server.example .env.server

# 2. Edit .env.server - at minimum set:
#    VULNFORGE_PUBLIC_URL=https://your-host
#    VULNFORGE_JWT_SECRET=$(openssl rand -base64 48)
#    VULNFORGE_BOOTSTRAP_TOKEN=$(openssl rand -hex 24)

# 3. Bring it up
docker compose -f docker-compose.server.yml --env-file .env.server up -d

# 4. Check logs for the bootstrap token echo
docker logs vulnforge-server -f
```

## What you get

- Container: `vulnforge-server` listening on `:3001` (configurable via `VULNFORGE_PORT`).
- Named volume `vulnforge-data` mounted at `/data` holding the SQLite DB + plugin binaries.
- Healthcheck every 30 s.

## Adding TLS via nginx

Uncomment the `nginx:` service block in `docker-compose.server.yml`. Drop your certs into `./nginx/certs/` and a matching vhost into `./nginx/conf.d/`.

Example minimal `./nginx/conf.d/vulnforge.conf`:

```nginx
server {
  listen 443 ssl;
  server_name vulnforge.acme.corp;
  ssl_certificate     /etc/nginx/certs/fullchain.pem;
  ssl_certificate_key /etc/nginx/certs/privkey.pem;

  location / {
    proxy_pass http://vulnforge-server:3001;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

    # WebSocket upgrade for /sync and /ws
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 3600s;  # long sync connections
  }
}
```

## Bootstrap

First run prints the bootstrap token to stdout. Find it with:

```bash
docker logs vulnforge-server 2>&1 | grep -i bootstrap
```

Desktop first-launch → **Team** → paste URL + token → done.

## Upgrades

```bash
docker compose -f docker-compose.server.yml pull
docker compose -f docker-compose.server.yml up -d
```

Schema migrations run automatically on startup (idempotent). If you pin to a specific version tag instead of `:latest`, bump the tag and re-run `up -d`.

## Backups

The DB is a single file at `/data/vulnforge.db` inside the `vulnforge-data` volume. Back it up by:

```bash
docker run --rm -v vulnforge-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/vulnforge-$(date +%F).tgz /data
```

Restore is the inverse - stop the service, wipe the volume, extract.

See [`backup-restore.md`](backup-restore.md) for details and automation.
