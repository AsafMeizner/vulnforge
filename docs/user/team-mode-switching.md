# Switching between solo and team mode

You can switch modes at any time from **Settings → Deployment**. No data is lost either direction.

## Solo → Team

1. Settings → Deployment → **Switch to Team**.
2. Enter the public URL of the team server.
3. Authenticate (username/password or SSO).
4. **Choose what to do with existing data:**
   - *Keep as private* — everything stays scoped `private` (default). You can promote rows to `team` individually later.
   - *Promote my rows to team* — all your existing rows become `team`. Use this only if you were a "solo" user who's now joining a team and want everything shared immediately.

The app reconnects, streams the team server's existing rows down, and your new `team` writes start flowing up.

## Team → Solo

1. Settings → Deployment → **Switch to Solo**.
2. Confirm — you'll be disconnected from the server. Your local DB is untouched.
3. Team-scoped rows remain on your desktop (read-only from your perspective — you're no longer pushing updates). They remain on the server and visible to your team.

To rejoin later, repeat the Solo → Team flow. Your device_id changes (new first-login) so admins see it as a new device in the sign-in list.

## Gotchas

### Mixed scopes after switching

Rows you created before joining a team stay `private` by default. If your workflow now assumes everything is shared, bulk-promote via Settings → Deployment → **Bulk scope change** → "My rows, all scopes → team".

### Two desktops, one account, different modes

Not supported — a single user account can be logged in team-mode on multiple devices, but mixing solo + team under the same account will confuse sync. Use two local OS accounts or two installs if you need both.

### What about team-mode tokens you saved offline?

Refresh tokens you saved while in team mode are revoked automatically when you switch to solo. Re-logging into team later mints fresh tokens.
