# Manifest privileges

`--manifest` and `--manifest-json` can run as a non-privileged user.
Non-root users automatically get reduced collection. The script never invokes sudo automatically.

| Information | Non-privileged collection | Root collection |
| --- | --- | --- |
| SSH host-key fingerprints | SHA256 hashes of readable conventional public host-key files; omissions remain unknown. | Same public-file-only collection; private keys are never read. |
| Packages, runtimes and websites | Collects installed packages and readable configuration and application metadata. | More configuration and application files may be readable. |
| Listeners | Reports addresses and ports; process ownership is unknown. | Also collects process names where available. |
| Service state | Infers running state from visible process names and enablement from available SysV startup links. | Also uses native service-status and enablement checks where available. |
| Mail storage | Reports discoverable paths; skips size scans and spool counts. | Performs bounded measurements unless disabled. |
| Scheduled jobs and migration paths | Private cron jobs and unreadable paths may be omitted. | Can inspect more private paths, including root's cron files. |

Text and JSON output warn when collection is unprivileged. Missing service and
application results remain unknown until checked with sufficient access and coverage.
Root collection also has scan limits and can return incomplete results.

For fuller visibility, run as root or explicitly use `sudo bash distrorejuve.sh --manifest`.
When already root, use `bash` directly.

Add `--unprivileged` or set `DR_UNPRIVILEGED=true` to force reduced collection,
including when running as root. This restricts collection operations; it does not drop
root privileges or hide files root can read.

## Collection for upgrade assessments

When the operator authorizes full root collection, use normal `--manifest` or
`--manifest-json` with DNS, HTTP status probes and mail metrics enabled. Clear action overrides and
use a reviewed script in a controlled environment as described in
[collection controls](upgrade-and-migration.md#collect-evidence).

Use reduced collection for restricted access or an explicit collection limit.
Assessments should name websites and their vhost/document-root/version-file paths,
service/listener roles and upgrade implications. Investigate relevant missing
service state or application use through bounded metadata checks. Keep private
configuration values and command arguments out of reports.

The first pass also collects root disk/inode capacity, memory/swap counters, fixed
database/mail unit states and bounded interpreter-use hints from process names
and cron. See the [inventory record guide](inventory.md#first-pass-upgrade-information)
for fields, panel-generated config paths and HTTP probe controls.
Resolver records identify `/etc/resolv.conf` as a regular file or symlink and
report numeric nameserver addresses. Full collection also queries bounded
`resolvectl dns` upstream addresses. An observed zero count identifies a resolver
with no configured upstream; failed or partially parsed queries retain their status.
Search domains and TLS server names are omitted.
