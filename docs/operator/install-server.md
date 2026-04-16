# Bare-metal server install

For teams running VulnForge on a VM, physical server, or Windows box (without Docker).

## Prerequisites

- Linux (Debian/Ubuntu/RHEL) or Windows Server 2019+
- Node.js ≥ 20
- Python ≥ 3.10 (scanner plugins)
- Git
- A public hostname reachable by all desktops
- Root / Administrator access

## Linux / macOS

```bash
# 1. Download + extract
wget https://.../vulnforge-server-0.1.0.tar.gz
tar xf vulnforge-server-0.1.0.tar.gz
cd vulnforge-server-0.1.0

# 2. Run installer
sudo ./scripts/install-server.sh
```

The installer will:

1. Verify Node ≥ 20, Python ≥ 3.10, git.
2. Prompt for **public URL** (e.g. `https://vulnforge.acme.corp`).
3. Create `vulnforge` system user + `/opt/vulnforge` install dir + `/var/lib/vulnforge` data dir.
4. Run `npm ci --omit=dev`.
5. Generate `JWT_SECRET` (48 random bytes) and `BOOTSTRAP_TOKEN` (24 random hex bytes) in `/var/lib/vulnforge/.env`.
6. Install systemd unit `vulnforge-server.service`.
7. Start the service.
8. Print the bootstrap token.

Verify:

```bash
systemctl status vulnforge-server
journalctl -u vulnforge-server -f     # follow logs
curl https://vulnforge.acme.corp/api/health
```

## Windows

```powershell
# PowerShell as Administrator
.\scripts\install-server.ps1
```

Creates a Windows service `VulnForgeServer` with auto-start. Env file at `C:\ProgramData\VulnForge\.env`.

## Bootstrap — first admin

After the install finishes you'll see:

```
Bootstrap URL:   https://vulnforge.acme.corp/api/session/bootstrap
Bootstrap token:
    a1b2c3d4e5f6a7b8...
```

On your desktop, install VulnForge and run the first-launch wizard. Pick **Team**, enter the public URL, paste the bootstrap token, choose your admin username + password.

**Important:** after bootstrap, remove `VULNFORGE_BOOTSTRAP_TOKEN=...` from `/var/lib/vulnforge/.env` (or the Windows equivalent) and restart the service. The token is single-use but leaving it in the env file is still a bad practice.

## Upgrading

See [`upgrade.md`](upgrade.md).

## Non-standard directories

Override via environment before running the installer:

```bash
VULNFORGE_INSTALL_DIR=/srv/vulnforge \
VULNFORGE_DATA_DIR=/data/vulnforge \
VULNFORGE_USER=vf \
  sudo -E ./scripts/install-server.sh
```

## Troubleshooting

### Service won't start

- `journalctl -u vulnforge-server -n 100 --no-pager` — read the last 100 log lines.
- Common causes: DB path unwritable by `vulnforge` user, missing `VULNFORGE_JWT_SECRET`, port 3001 already in use.

### Desktop can't connect

- Check the public URL resolves from the desktop host.
- Check the server's firewall / security group allows inbound TCP 3001 (or whatever port you set).
- Check `curl -k https://your-url/api/health` from the desktop machine.

### Bootstrap token rejected

- The token is single-use. Once consumed it's removed from `process.env`.
- If you lost it, `systemctl stop vulnforge-server`, edit the `.env` file, add a new `VULNFORGE_BOOTSTRAP_TOKEN=...` (any random hex), restart, retry.
