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
Virtualmin and ISPConfig use normal distro upgrade checks, including when Virtualmin
configuration remnants or a custom command survive. Review panel configuration and
complete the [panel follow-up](hosting-panels.md#panels-using-distro-packages).

Offline regression checks (no production operations):

```sh
bash -n distrorejuve.sh
python3 tests/test-upgrade-review.py
python3 tests/test-manifest-firstpass.py
python3 tests/test-manifest-upgrade-assets.py
python3 tests/test-manifest-packaged-wordpress.py
python3 tests/test-manifest-resolver.py
shellcheck -S error distrorejuve.sh
```

Use these standard commands rather than separate per-job discovery scripts.
`--upgrade-report` includes the manifest's tool availability and conventional
application/database/cache/backup sizes. `--check-upgrade` evaluates the target
path, package health and disk floor. Resolve its reported condition before
starting the approved action; do not bypass a disk floor to hide a removable cache.

Configuration repair preserves removed database services. Residual server
configuration alongside old core binaries does not trigger installation of a new
MySQL or MariaDB server; select database replacement through the job plan.

PHP dependency migration recognizes a planned same-architecture `t64` library
replacement only after verifying the exact archive candidate and its `Provides`
and `Replaces` relationships. It pins that version for the transaction and
records the selection for retries; unrelated package removals remain guarded.

When separate old-PHP removal would drop applications or install target runtimes
early, use the checked combined transaction. Any installs in the separate plan
must exactly match the combined plan: names, old/new versions and archive
architectures. Reject purges, downgrades and unapproved combined removals.
Retain installed applications and verify the persistent systemd Apache mask
with the service inactive immediately before package changes. The ordinary
separate handoff remains available.

Obsolete-package cleanup distinguishes recognized APT dependency conflicts from
index and access failures. Dependency conflicts enter protected subset planning
so retained packages keep their required libraries. If that subset still cannot
resolve dependencies, cleanup records a deferral; other simulation failures stop
with the exit status and plan path.

APT index refresh checks both the exit status and failed-index diagnostics. A
zero exit with failed downloads triggers the existing IPv4 retry; persistent
failures stop before PHP selection. Target PHP selectors and runtimes require
archive-backed candidates, rather than versions present only in dpkg status.
Failed full-upgrade simulations retain their plan and print the exit status,
plan path and final diagnostics before any PHP change.

## APT simulation of package splits

The PHP migration compares its proposed removals with a normal full-upgrade
plan. That normal plan starts with `apt-get --simulate dist-upgrade`.
The failure-only validator below can check a complete proposal when configuration replay fails.

Ubuntu 26.04 splits coreutils and sudo into provider/common packages. The new
selector Pre-Depends on its provider; the provider has versioned Breaks and
Replaces against the installed predecessor. Real APT uses dpkg automatic
deconfiguration for that transition. APT simulation can instead report
`E: Conf Broken coreutils-from-uutils:amd64` or `E: Conf Broken sudo-common:amd64`
before replaying the scheduled predecessor upgrade. Ubuntu tracks the same
transition errors in [confirmed bug 2170692](https://bugs.launchpad.net/bugs/2170692).
See [package split relationships](https://www.debian.org/doc/debian-policy/ch-relationships.html#overwriting-files-and-replacing-packages-replaces)
and the [APT simulator](https://github.com/Debian/apt/blob/main/apt-pkg/algorithms.cc).

An isolated synthetic split reproduces simulation failure and ordinary successful
installation with a clean audit. Preinstalling the payload, changing immediate
configuration, selecting the alternate solver and configuring all packages
still produce the simulation error. Adding the provider explicitly also uses
the same transition. Check package origins and relationships before classifying
a real failure; the error text alone does not select a remedy.

The native dependency validator is a failure-only fallback for this normal
full-upgrade plan. Successful simulations retain their existing path. An APT
status of 100, install/configure records and only `E: Conf Broken` errors must
pass a shell check before Python starts. Interruptions and unrelated failures
stop there; the validator rejects incomplete or inconsistent proposals.

The fallback checks for `python3` and `timeout`, requires Python 3.7 or newer,
then verifies importable `python3-apt`, its required APIs and the same libapt
version as `apt-get` before opening a package cache. These checks never install
prerequisites. Python provides access to APT's dependency library without
reimplementing that logic in Bash.
It applies the same supported options and marks the exact CLI proposal
in an in-memory package cache. Automatic resolution is disabled. It then checks
the dependency graph and exact action equality: names, architectures and old/new
versions. It makes no new package choices. It rejects broken final dependencies,
changed holds, essential or protected removals, downgrades, untrusted candidates and package/index changes
during planning. A versioned Breaks relationship must be resolved by the
planned predecessor upgrade. It has no package-name or bug-number allowlist.

The helper reads package data and writes private plan/provenance files. It
never downloads or installs packages. It retains the failed transcript and
creates records for the existing removal/application checks. The ordinary
installer and service/recovery handling continue afterward. Cached fallback
plans are regenerated before reuse.

Install a matching distro-provided binding through the reviewed normal package
procedure when required. Its prerequisites can advance the OS version file
before all target packages are installed. Resume the recorded target and
remaining steps; do not select another release merely from that version file.

Regression fixtures cover valid selection and ordinary removal, unsupported
options, mismatched versions/actions/architectures, malformed or partial output,
holds, trust, protected removals, unresolved relationships and state changes.
An isolated real-APT package fixture also verifies fallback planning and normal
installation without customer operations. See the
[python-apt API](https://apt-team.pages.debian.net/python-apt/library/apt.cache.html).

## Retained init helpers during a release transition

Before target package changes, the release flow checks an installed systemd
against its target archive candidate and full-upgrade plan. A held or kept-back
older helper stops the action. The tool retains a pinned prerequisite simulation
and status for review; it does not execute that separate proposal. This catches
transitions where target package scripts use newer helper syntax while their
unversioned dependencies still permit the installed helper.
