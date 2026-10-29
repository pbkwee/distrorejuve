# Upgrade review checks

## Package repository coverage

Before APT package upgrades and crossgrades, source preparation pins release
aliases and fills entirely missing update/security pockets for recognized native
base repositories. Release changes apply the same check to the target, including
retries that already have target-only sources. Both `.list` and Deb822 `.sources`
files retain their signing options, architecture filters and component choices.
Complete same-release sources and existing backports are preserved. Release-hop
backports handling keeps its existing explicit review requirement.

Existing update/security sources must cover each base component and architecture
filter. Partial coverage stops for review rather than creating duplicate or
conflicting definitions. Debian optional components keep their existing security
policy; archived releases do not gain security support, and removed archive
pockets are not added. Sources are staged and backed up before replacement.
No source completion is performed by read-only checks.

See the [Ubuntu repository example](https://ubuntu.com/server/docs/tutorial/managing-software/)
and [Debian source configuration](https://www.debian.org/releases/trixie/release-notes/upgrading.html).
RPM repository requirements are described in [RPM updates](rpm-upgrades.md).

## Other upgrade checks

The default disk floor is 2048 MiB on each checked package/cache/state filesystem.
This floor catches low free space on small servers. Size the actual transaction using the
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
hosting provider boot selection still require the explicit review described in the output.

For running MySQL/MariaDB, privileged preflight and the post-upgrade service gate
also test a local root query. Socket authentication is tried first, then root's
client option files for existing password administration. No credentials or raw
client errors are printed. Nonstandard administration accounts or socket locations
require a reviewed local procedure. InnoDB buffer pools using at least 70% of
physical RAM get a warning; cgroup limits and other memory consumers still need
review. Verify maintenance access with an authenticated administrative query.

[MariaDB's authentication rules](https://mariadb.com/docs/server/reference/plugins/authentication-plugins/authentication-plugin-unix-socket)
change in 11.6. [Debian trixie packages MariaDB 11.8](https://packages.debian.org/trixie/mariadb-server).
The conventional `mysql.global_priv` root `unix_socket` identity is checked
for compatibility with MariaDB 11.6 and newer. An unexpected external identity
blocks the Debian trixie target (MariaDB 11.8) without showing its value or changing grants.
Other targets produce a compatibility warning. Older grant layouts
produce an explicit review warning. Alternative-authentication arrays and custom
accounts still require review. Verify table upgrades separately from authenticated
queries: inspect database startup/upgrade logs and the vendor upgrade state.

The existing dpkg policy prefers packaged configuration and restores missing
conffiles. Preflight now prints that policy. `UCF_FORCE_CONFFOLD` affects ucf only;
it does not change dpkg's policy. Merge custom service settings and validate
runtime identities, sockets and permissions after the package transaction.

Manifest output adds per-collector `probe_status` records (observed, partial or
unknown, with command exit status and coverage requiring review), plus a `collection_status` record with `core_collectors_failed`,
`warning_count` and `completeness=requires_review`. Exit-zero partial inventories
are preserved. A false failure flag reports no core collector failures; inspect
warnings and per-collector coverage for gaps. Virtualmin configuration without a conventional module installation is
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
