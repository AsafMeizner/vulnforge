# Backup & restore

The server's entire state is one SQLite file + the `plugins/` directory. Back up both.

## What matters

| Path                                                                      | Contents                             |
| ------------------------------------------------------------------------- | ------------------------------------ |
| `/var/lib/vulnforge/vulnforge.db` (bare) or `/data/vulnforge.db` (docker) | Entire DB                            |
| `/var/lib/vulnforge/.env`                                                 | JWT secret, OIDC creds, admin config |
| `/opt/vulnforge/plugins/` (bare) or Docker volume `/data/plugins/`        | Plugin binaries the server installed |

Not critical (can be reinstalled): `dist-server/`, `node_modules/`.

## Automated daily backup (bare metal)

```bash
sudo tee /etc/cron.daily/vulnforge-backup <<'EOF'
#!/bin/bash
set -e
DST=/var/backups/vulnforge
mkdir -p $DST
DATE=$(date +%F)
# SQLite online backup - safe while server is running
sqlite3 /var/lib/vulnforge/vulnforge.db ".backup $DST/vulnforge-$DATE.db"
tar czf $DST/env-and-plugins-$DATE.tgz \
  /var/lib/vulnforge/.env \
  /opt/vulnforge/plugins
# Retain 30 days
find $DST -name 'vulnforge-*.db' -mtime +30 -delete
find $DST -name 'env-and-plugins-*.tgz' -mtime +30 -delete
EOF
sudo chmod +x /etc/cron.daily/vulnforge-backup
```

The `sqlite3 ".backup"` command is safe to run while the server is serving traffic - it takes a consistent snapshot without blocking writers for more than milliseconds.

## Docker

```bash
docker run --rm \
  -v vulnforge-data:/data \
  -v "$(pwd)/backups:/backup" \
  alpine sh -c "tar czf /backup/vulnforge-$(date +%F).tgz /data"
```

## Restore

1. Stop the service: `systemctl stop vulnforge-server` (or `docker compose down`).
2. Move the old DB aside: `mv /var/lib/vulnforge/vulnforge.db /var/lib/vulnforge/vulnforge.db.old`.
3. Copy the backup into place: `cp /var/backups/vulnforge/vulnforge-2026-04-15.db /var/lib/vulnforge/vulnforge.db`.
4. Fix ownership: `chown vulnforge:vulnforge /var/lib/vulnforge/vulnforge.db`.
5. Restart: `systemctl start vulnforge-server`.
6. Run `/api/health` and spot-check a few desktops can still sync.

## Disaster recovery checklist

- [ ] Backups are on a **different host** from the server (not the same disk).
- [ ] You've done a restore drill at least once in the last quarter.
- [ ] JWT_SECRET backup is encrypted at rest (it's in `.env`).
- [ ] Desktop clients have `sync_outbox` entries - they will auto-flush on reconnect so a short outage is non-destructive. But a multi-day outage will hit the 5-retry cap per row; alert your team to watch for the sync error banner on return.
