# Brote Backup Bot — public controller

This repository contains generic backup code and synthetic tests only. Do not upload application code, configuration JSON, database dumps, backup assets or credentials here.

Daily backups and manual runs execute only on the approved commit of protected `main`, with Environment Secrets restricted to that branch. Lock `main` including administrators after reviewing the installed code. Set the repository variable `BACKUP_APPROVED_SHA` to the full reviewed commit SHA. Updating code requires explicit review, unlocking/relocking main and approving the new SHA. No second account or daily reviewer is required for an owner-operated frozen installation. This is owner review, not independent two-person approval.

Create `backup-production` and `backup-monitor` environments with Selected branches and tags: exactly branch `main`, no tags. Use no repository-level production secrets. Configuration remains an Environment Secret named `BACKUP_CONFIG` in both environments. Never paste it into Issues, workflow inputs, Variables, source code or PRs.

Actions exposes execution dates, workflow stages and success/failure publicly. Detailed status, backup/restore dates, object counts and notifications live exclusively in the private vault. The public summary contains no private links, hashes, names, counts or database contents. No backup artifacts are uploaded to public Actions. Exceptions from production tools are suppressed.

The manual operations are `daily`, `restore-latest` and `pre-migration`. The last operation consumes an immutable, hash-pinned private rehearsal specification; it executes the approved SQL only inside a disposable networkless PostgreSQL container. There is no remote migration or remote restore command.

GitHub Free supports protection and Environment Secrets for public repositories. A private repository using unrestricted repository Secrets does not provide the same boundary. This controller does not change visibility of any existing repository and requires no paid integration.

A monthly workflow without Environments or private secrets writes only the public month to `automation-heartbeat`, keeping activity off the locked code branch. Its temporary GITHUB_TOKEN can write this public repository; branch protection must include administrators, disable bypass, force pushes and deletion. It never writes main. Public scheduled workflows can be disabled after 60 days of inactivity; check Actions if the heartbeat fails. GitHub cron and provider outages have no guaranteed delivery. Private vault PATs require renewal; no system on these constraints can honestly promise zero maintenance forever.

Backup retention: 14 daily, 8 weekly, 6 monthly, pre-migration 30 days, `[KEEP]` releases indefinitely. Only encrypted assets go to private Releases. Releases are not WORM/PITR or a separate provider. Preserve the encryption password offline. Recovery of external Auth, Storage service configuration and keys needs a separately authorized administrative procedure.
