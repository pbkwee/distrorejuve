# Upgrade review checks

The default disk floor is 2048 MiB on each checked package/cache/state filesystem.
This is a guard for small servers, not a transaction-size guarantee. Review the
next-release APT simulation, download volume, installed growth, separate mounts
and backup/log requirements. Raise `DR_MIN_FREE_DISK_MIB` for larger transactions;
do not bypass the check merely because the server is small.

Preflight reports duplicate `iface` definitions in `/etc/network/interfaces` and
quota options in `/etc/fstab`, duplicate literal logrotate paths, and conventional
Monit ports/program paths with file/line evidence. Scans stop at 200 files and
1 MiB per file. Wildcard overlap, nested custom includes and complex syntax remain
unknown. It does not follow custom network includes or fix
configuration. Review quota utilities and target boot dependencies before any
activation. Custom PHP pools/sockets, monitoring listener health and
provider boot selection still require the explicit review described in the output.

For running MySQL/MariaDB, privileged preflight and the post-upgrade service gate
also test a local root query. Socket authentication is tried first, then root's
client option files for existing password administration. No credentials or raw
client errors are printed. Nonstandard administration accounts or socket locations
require a reviewed local procedure. InnoDB buffer pools using at least 70% of
physical RAM get a warning; cgroup limits and other memory consumers still need
review. A running process alone does not establish maintenance access.

[MariaDB's authentication rules](https://mariadb.com/docs/server/reference/plugins/authentication-plugins/authentication-plugin-unix-socket)
change in 11.6. [Debian trixie packages MariaDB 11.8](https://packages.debian.org/trixie/mariadb-server).
The conventional `mysql.global_priv` root `unix_socket` identity is checked
for compatibility with MariaDB 11.6 and newer. An unexpected external identity
blocks the Debian trixie target (MariaDB 11.8) without showing its value or changing grants.
Other targets produce a compatibility warning. Older grant layouts
produce an explicit review warning. Alternative-authentication arrays and custom
accounts still require review. Authenticated queries do not establish completed
table upgrades: inspect database startup/upgrade logs and the vendor upgrade state.

The existing dpkg policy prefers packaged configuration and restores missing
conffiles. Preflight now prints that policy. `UCF_FORCE_CONFFOLD` affects ucf only;
it does not change dpkg's policy. Merge custom service settings and validate
runtime identities, sockets and permissions after the package transaction.

Manifest output adds per-collector `probe_status` records (observed, partial or
unknown, with command exit status and coverage requiring review), plus a `collection_status` record with `core_collectors_failed`,
`warning_count` and `completeness=requires_review`. Exit-zero partial inventories
are preserved. A false failure flag does not imply complete coverage; inspect
warnings. Virtualmin configuration without a conventional module installation is
reported as `panel_remnant`, with installation/runtime state unknown. This is not
removal authority; inspect custom installations and package state separately.
Ambiguous Virtualmin configuration or a surviving command still blocks generic
release upgrades until the operator reconciles installation state.

Offline regression checks (no production operations):

```sh
bash -n distrorejuve.sh
python3 tests/test-upgrade-review.py
shellcheck -S error distrorejuve.sh
```
