# Backup and restore

## Recovery plan

The private repository runs two GitHub Actions workflows. The backup workflow
starts every day at 01:00 in `America/Sao_Paulo`. The restore workflow starts
manually from GitHub Actions.

The backup workflow reaches the Debian host through an ephemeral Tailscale
runner and SSH. A root-owned helper stops the Compose containers briefly, copies
the selected application paths and active Docker volumes, then resumes the
containers. This gives PostgreSQL, MongoDB, and SQLite files a consistent
point-in-time copy.

The helper encrypts the archive with age on the server. GitHub Actions receives
only ciphertext and uploads it to a private Cloud Storage bucket in
`us-west1`. The bucket keeps objects for 14 days. The restore workflow checks
the archive manifest and every file checksum before it sends the archive to a
replacement Debian host.

## Included state

- Compose files and their adjacent environment files.
- Application configuration and persistent application state.
- Database files and active Docker volume data.
- Reverse-proxy configuration and TLS state.
- Container image references pinned to registry digests.

The archive contains application secrets and TLS private keys. Age encryption
protects the archive before it leaves the server. Keep the age identity outside
this public repository and keep a recovery copy outside GitHub.

## Excluded state

- Manga and other media libraries or downloads.
- Samba and File Browser user-share contents.
- Docker image layers.
- Host operating-system packages, firmware, and account-level Tailscale or DNS
  configuration.

Connect the original media and share disks to the replacement host and mount
them at the paths expected by the private deployment configuration before
starting dependent services.

## Recovery limits

GitHub Actions schedules at the requested local time, but GitHub can delay a
scheduled run when its runners are busy. A manual backup trigger is available.
An expired or corrupt restore point is rejected before the target changes.

Restore refuses a populated target by default. Enabling overwrite requires a
local rollback archive before replacement begins. Image digests must still be
available from their registries. A missing image, required mount, or failed
rollback check stops the restore.

## Related documentation

- [Service inventory](../inventory/services.yaml)
- [GitHub Actions schedule syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onschedule)
- [Tailscale GitHub Action](https://tailscale.com/docs/integrations/github/github-action)
- [Cloud Storage lifecycle management](https://docs.cloud.google.com/storage/docs/lifecycle)
- [age encryption](https://github.com/FiloSottile/age)
