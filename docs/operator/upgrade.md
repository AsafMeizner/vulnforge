# Upgrading

## Server — Docker

```bash
docker compose -f docker-compose.server.yml pull
docker compose -f docker-compose.server.yml up -d
```

Migrations run automatically on startup (`initDb()` → `migrateSchema()` + `backfillSyncColumns()` — all idempotent).

For a specific version:

```bash
# In .env.server or via environment:
VULNFORGE_IMAGE_TAG=0.2.0
docker compose ...
```

## Server — bare metal

```bash
# 1. Stop
sudo systemctl stop vulnforge-server

# 2. Replace payload (keep /var/lib/vulnforge/.env and vulnforge.db untouched)
cd /opt/vulnforge
sudo cp -r /path/to/new/dist-server ./dist-server.new
sudo mv dist-server dist-server.old
sudo mv dist-server.new dist-server
sudo chown -R vulnforge:vulnforge dist-server

# 3. Run migrations
sudo -u vulnforge node scripts/migrate.mjs

# 4. Start
sudo systemctl start vulnforge-server
systemctl status vulnforge-server
```

Once you've verified everything works for a week, `sudo rm -rf /opt/vulnforge/dist-server.old`.

## Desktop

Desktop installers use `electron-updater` pointing at your release provider (GitHub releases by default). Users get a notification banner on version bump and can install in-place.

To update manually:

- **Windows**: download the new `.exe`, run it.
- **macOS**: download the `.dmg`, drag to Applications.
- **Linux**: replace the `.AppImage` or use your package manager.

## Client ↔ server version compatibility

The client sends `X-VulnForge-Version` on every request. Server responses:

- Matching major version → OK.
- Major version skew → `426 Upgrade Required` — user gets a prompt to update.
- Minor skew → `X-Upgrade-Advisory: true` header; advisory banner in UI.

When upgrading a server, plan a rollout: upgrade the server first (clients on N-1 still work via the compat shim), then push the desktop installer to users.
