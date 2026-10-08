# Eagle Talon — Runbook

How to run, release and roll back Eagle Talon on **core**. Run commands one at a
time. Nothing in this file touches prod except the sections marked **PROD**.

## Environments

| | Prod | Staging |
|---|---|---|
| UI | http://core:8088 | http://core:8098 |
| API (behind nginx) | 0.0.0.0:8000 | 127.0.0.1:8100 (loopback only) |
| Compose project / containers | `eagle-talon` / `eagle-talon-api`, `eagle-talon-web` | `eagle-talon-staging` / `eagle-talon-staging-api`, `-web` |
| Data volume | `eagle-talon-data` (Eagle Eye also mounts this) | `eagle-talon-staging-data` |
| Checkout on core | `/home/eddy/eagle-talon-asm` | `~/eagle-talon-staging` (branch `staging`) |
| Git | `main`, deployed only from tags `vX.Y.Z` | `staging` branch |
| Scheduled monitoring | on | off ("Check now" still works) |
| Identity file | `deploy/env/prod.env` | `deploy/env/staging.env` |

Staging shows an amber **STAGING · vX.Y.Z** chip and a striped top edge.
Prod shows a plain `vX.Y.Z` chip.

Secrets never go in git. Each checkout keeps them in `deploy/secrets.env`
(gitignored, chmod 600). A legacy `deploy/.env` is still read, but
`env/<env>.env` is loaded last and always decides names, ports and volume.

## Branches and versions

- Work happens on `staging`, or on short feature branches merged into `staging`.
- `main` only receives releases from `staging`, and each release is tagged `vX.Y.Z`.
- `VERSION` holds the version. On `staging` it carries a `-dev` suffix
  (e.g. `0.2.0-dev`); it is set to the plain number at release.
- Semver: **minor** for features, **patch** for fixes. Go to 1.0.0 when a client depends on it.
- `v0.1.0` is the baseline: the code prod ran before staging existed (commit `954da2d`).

## One-time setup

### On the Mac: apply the change set and push
```
cd <your eagle-talon-asm clone>
```
```
git checkout main
```
```
git pull
```
```
git tag v0.1.0 954da2d
```
```
git push origin v0.1.0
```
```
git checkout -b staging
```
```
git am ~/Downloads/<patch file>
```
```
git push -u origin staging
```

### On core: create the staging checkout
```
git clone --branch staging https://github.com/almata-eagle/eagle-talon-asm ~/eagle-talon-staging
```
```
cd ~/eagle-talon-staging/deploy
```
Copy the NVD key in without echoing it:
```
read -s NVD_API_KEY && echo "NVD_API_KEY=$NVD_API_KEY" >> secrets.env
```
```
chmod 600 secrets.env
```
Open the staging UI port on Tailscale only:
```
sudo ufw allow in on tailscale0 to any port 8098 proto tcp
```
Seed staging with a copy of prod's data. Prod is only read, through a read-only mount.
```
./seed-staging-db.sh
```
Build and start staging:
```
./deploy.sh staging
```
Then open http://core:8098 and confirm the amber STAGING chip.

## Everyday: ship to staging
On the Mac, commit to `staging` (always `git add -A` before `git commit`), then add
a line under **Unreleased** in `CHANGELOG.md` and push. On core:
```
cd ~/eagle-talon-staging
```
```
git pull
```
```
deploy/deploy.sh staging
```
The script prints the running version and commit, plus HTTP checks for the API and the web.

Refresh staging data from prod at any time with `deploy/seed-staging-db.sh`.
It backs up staging's current DB first.

## Release: promote staging → prod (**PROD**)
On the Mac, on `staging`:
1. Set `VERSION` to the release number, e.g. `0.2.0`.
2. In `CHANGELOG.md`, rename **Unreleased** to `[0.2.0] - YYYY-MM-DD` and open a new empty **Unreleased** section.
3. Commit and push, then deploy staging once more and check it.

Merge and tag:
```
git checkout main
```
```
git merge --no-ff staging
```
```
git tag v0.2.0
```
```
git push origin main v0.2.0
```
On core, in the **prod** checkout (`cd ~/eagle-talon-asm`):
```
git fetch --tags
```
```
git checkout v0.2.0
```
```
deploy/deploy.sh prod
```
`deploy.sh prod` refuses to run unless HEAD is exactly tag `v$(cat VERSION)` and
the tree is clean. It always backs up the prod DB to
`~/eagle-talon-backups/prod/` before restarting anything.

Finally, on the Mac, return `staging` to the next dev version (`0.3.0-dev`), commit and push.

## Roll back prod (**PROD**)
Code: in the prod checkout, check out the previous tag and deploy it.
```
git checkout v0.2.0
```
```
deploy/deploy.sh prod
```
Exception: `v0.1.0` predates `deploy.sh`. To go back to it, use the old way,
which uses the same container and volume names:
```
git checkout v0.1.0
```
```
cd deploy
```
```
docker compose up -d --build
```

Data: schema migrations here only **add** columns, so older code runs on a
newer DB. If a release damaged data, restore the backup taken just before it:
```
ls -lt ~/eagle-talon-backups/prod/ | head
```
```
docker stop eagle-talon-api
```
```
docker run --rm -v eagle-talon-data:/dst -v ~/eagle-talon-backups/prod/<file>.db:/seed.db:ro python:3.12-slim cp /seed.db /dst/eagle_talon.db
```
```
docker start eagle-talon-api
```
Eagle Eye reads the same volume, so restart it too if it misbehaves.

## Backups
- `deploy/backup-db.sh prod` (or `staging`) uses SQLite's online backup API on a
  read-only mount, so it is safe on live prod. It runs an integrity check and keeps the newest 30.
- Run it from cron daily at an off-minute (eddy's crontab):
  `17 3 * * * $HOME/eagle-talon-asm/deploy/backup-db.sh prod >> $HOME/eagle-talon-backups/backup.log 2>&1`
- Once a NAS share is mounted, point backups at it with `BACKUP_DIR=/mnt/nas/<share>/eagle-talon-backups`.

## SOC cases and Claude triage
Since v0.5.0, detection and triage run inside both the prod and the staging API
(`SOC_DETECT=on`, `SOC_TRIAGE=on` in `env/<env>.env`). Staging gets 5 triages an
hour, prod gets 20. The Claude key is `ANTHROPIC_API_KEY` in each checkout's
`deploy/secrets.env`, using the `eagle-soc` workspace.

First time in prod, copy the key from the staging checkout without printing it:
```
grep '^ANTHROPIC_API_KEY=' ~/eagle-talon-staging/deploy/secrets.env >> ~/eagle-talon-asm/deploy/secrets.env
```
```
chmod 600 ~/eagle-talon-asm/deploy/secrets.env
```
Check that it's there (prints `1`, never the key):
```
grep -c '^ANTHROPIC_API_KEY=' ~/eagle-talon-asm/deploy/secrets.env
```
 To stop Claude calls, set
`SOC_TRIAGE=off` and redeploy, or disable the key in the Console. Details,
costs and kill switches are in [SOC-TRIAGE.md](SOC-TRIAGE.md).

## SOC log collector
Deploy, the FortiGate setup, health checks and retention are in
[SOC-COLLECTOR.md](SOC-COLLECTOR.md). There is one collector per host. Start with
`soc/preflight.sh`; its output is safe to paste for help.

## Troubleshooting
- **Check what's running:** `curl -s http://127.0.0.1:8000/api/version` (prod) or `:8100` (staging).
- **Container logs:** `docker logs --tail 100 eagle-talon-staging-api`.
- **`http://core:8098` won't load in Chrome:** set Secure DNS to "With your current service provider" (MagicDNS issue), and confirm the UFW rule above exists.
- **Preview a deploy without changing anything:** `deploy/deploy.sh staging --dry-run` prints the resolved compose config.
