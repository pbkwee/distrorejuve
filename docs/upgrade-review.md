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
also test authenticated maintenance access. By default, socket root authentication
is tried first, then root's client option files for password administration. When a specific
maintenance file is authorized, set `DR_DATABASE_DEFAULTS_FILE` to its absolute
path. The client consumes it directly; the script does not read credentials or
fall back to another account after that selection fails. Its account and socket
are preserved. No credentials or raw client errors are printed. Custom administration
still requires a reviewed local procedure. InnoDB buffer pools using at least 70% of
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

Set `DR_UPGRADE_MANIFEST=false` when the agreed upgrade scope excludes the
optional full application inventory. This prevents automatic captures and
comparisons, including comparison against an existing inventory. Supply scoped
application baselines and acceptance checks separately. Required package,
service and web-runtime checks remain enabled and still need permission for
their configuration inputs. This setting does not restrict explicit manifest
or upgrade-report actions, or replace the data-access review for other steps.

APT refreshes automatically repair recognized missing Debian archive signers for
releases 10–13, including newer signatures on older archived releases. Keys come
from Debian's HTTPS publisher endpoint and must match pinned full primary
fingerprints before activation. Only the selected key is exported into an
APT-compatible keyring. Unknown/vendor keys, custom APT paths, expired or revoked
downloaded keys and failed verification stop the repair without weakening trust.
Existing source-specific `Signed-By` restrictions are preserved.

Old APT can return zero after rejecting signed indexes and retaining old lists.
Signature failures therefore trigger repair and one authenticated retry even
with that exit status. Remaining signature failures are errors under the default
authentication policy. The existing explicitly enabled, validated archive-only
authentication exception retains its behavior. An archive
signed only by expired keys still requires separate review; automatic repair
does not enable `DR_ALLOW_UNAUTHENTICATED_ARCHIVES`. Maintain the pinned key
table when Debian publishes another release's signing keys.

Removed/configuration-only MySQL records, client libraries and an existing
configuration directory do not establish an installed database server. Generic
configuration repairs do not recreate a server from those clues. Use approved
pre-upgrade package/service evidence for missing-server recovery. The udev repair
checks its exact package state and leaves installed or held packages alone.
Legacy MySQL log/configuration repairs require a real installed or pending
server package; dormant RC data and client-only installations are skipped.

## /usr merge collision recovery

Debian 12 requires the merged `/usr` layout. Debian's converter stops when both
regular files exist at paths such as `/bin/replace` and `/usr/bin/replace`.
Resolve the collision, then rerun the packaged converter before installing or
updating other packages. See [Debian's release notes](https://www.debian.org/releases/bookworm/amd64/release-notes/ch-information.en.html#a-merged-usr-is-now-required)
and [converter implementation](https://sources.debian.org/src/usrmerge/39%2Bnmu2/convert-usrmerge/).

distrorejuve's default policy now automates a bounded case: exactly one top-level
`/bin` or `/sbin` executable is unowned and the other belongs to one configured
package. The retained file must match the package's stored digest. Both must be
root-owned regular files without group/other write permission. The existing
digest probe limits the retained file and md5sums input to 1 MiB; missing or unverifiable digests
require manual review. The packaged copy can be at either path.

Before moving anything, the tool records its baseline, package inventory and
SHA256 hashes. A private attempt under `<baseline>.usrmerge/files.*` holds an
archive of **both** copies with ACLs and extended attributes. Archive comparison
and hash checks must pass. Ownership and packaged content are rechecked before
the unowned file moves into `originals/`, preserving it for recovery. The selected
packaged executable then serves both paths after conversion. Its behavior may
differ from the archived local executable; use application acceptance checks.

The tool rescans collisions and runs `/usr/lib/usrmerge/convert-usrmerge` when
available. A failed or incomplete conversion blocks further APT work. Pending
usrmerge configuration is finished only after canonical directory links pass.
If usrmerge is not installed, its normal package installation performs conversion
after collision preparation. Backup failure or a changed/ambiguous file stops
before conversion. A later failure leaves the private attempt and moved originals
available for review; do not restore them blindly over a converted filesystem.

Set `DR_PREFER_PACKAGED_USRMERGE_FILES=false` to require manual resolution instead.
Read-only `--check-upgrade` reports required collision repair without moving files,
even when the preference is inherited as true. Two owned copies, two unowned
copies, modified packaged files, unrelated symlinks and library/nested collisions
remain outside this automatic recipe. Follow the converter's diagnostics for
those cases; do not use broad deletion or `dpkg --force-overwrite` as a repair.

## Precompiled Debian locales

Before configuring packages, Debian upgrades automatically install `locales-all`
when at least 100 distinct standard locales are enabled in `/etc/locale.gen`.
This avoids repeated compilation during successive release transitions.
The threshold keeps small, selective installations on normal locale generation;
the precompiled package adds roughly 200 MiB of installed data.
See [Debian's package description](https://packages.debian.org/bullseye/locales-all)
and [the locales maintainer script](https://sources.debian.org/src/glibc/2.31-13%2Bdeb11u11/debian/debhelper.in/locales.postinst/).

Preparation runs after the authenticated index refresh and configuration baseline,
before `dpkg --configure -a` or the package upgrade. It preserves `/etc/locale.gen`
and verifies its checksum afterward. Existing or pending `locales-all` installations
are left to normal package handling. Held `locales` or `locales-all` packages, custom locale paths,
local supported-locale definitions and unknown configured or available locales
retain the normal path. Ubuntu and read-only checks do not install this package.

The simulated native-architecture install must contain only `locales-all` and
its `libc-l10n` dependency, with no removals. Unavailable packages or broader plans
produce a warning and retain generation. Installation requires authentication
and disables removals and recommendations. An actual install failure, an incomplete
package after installation or a changed selection stops the upgrade for review.
Preparation is skipped when the archive authentication exception is enabled.

Set `DR_PRECOMPILED_LOCALES=false` to retain generation for large selections.
This leaves an already installed `locales-all` package in place.

## Before/after review

Review the original job evidence against the final server before handoff, then
repeat the runtime checks after reboot. Follow the
[handoff procedure](upgrade-and-migration.md#verify-hand-over-and-retire).
`--show-changes` is useful evidence for this review. It writes a new private
`/root/distrorejuveinfo/postupgrade.dpkg.*` snapshot and reports package
availability, state differences and existing configuration sidecars. It does
not repair configuration or establish application acceptance.

Verify the source identity, reviewed tool revision and original baseline path
and date first. Set `DR_CONFIG_BASELINE` to the verified original file for a job
with multiple invocations or release hops. An explicitly selected file has no
age limit and never falls back to global history. Without that setting, the
automatic selector uses the oldest baseline within
`DR_CONFIGURATION_HISTORY_DAYS` (default seven days), including legacy
`/root/deghostinfo` files. Check that this is the job's original baseline across
all hops, rather than another run's evidence. If it is missing, expired or
ambiguous, record the gap and use verified job evidence separately. Never
reconstruct a before-state from the upgraded server. Record any preparation
changes made before the tool's baseline, using the initial assessment.

Use the established collection environment with `DR_ACTION`, `BASH_ENV` and
`ENV` removed. Disable optional application inventory with
`DR_UPGRADE_MANIFEST=false` when excluded by the agreed scope. Capture stdout
and stderr privately on the source with directory permissions `u=rwx,go=` and
file permissions `u=rw,go=`. The full report can contain process arguments,
configuration values and application inventory; do not paste it into an AI
session. Use an approved extractor to return only necessary package names and
versions, service/listener facts, configuration paths and selected non-secret
settings. The reporting snapshot is a write and needs the execution scope;
this command is not initial read-only discovery.

Interpret the findings before putting them in a handoff:

- Compare installed package name/architecture identities and versions. Renames
  and replacements are not application removals. Identify removed interpreters
  and utilities that custom jobs may use, plus retained packages absent from
  the current repositories. A clean dependency audit does not prove those
  retained packages are maintained or unused.
- Check listener ownership, binding and actual protocol against the baseline.
  A bound 443 port does not prove TLS works. An active/exited service unit does
  not prove a daemon or authentication backend is running. Confirm application
  functions separately from port checks and expected error responses.
- Compare conffiles only with installed package records; removed/config-files
  records can retain old foreign-architecture digests for the same active path.
  Current-package differences are not necessarily upgrade changes. Historical
  `.dpkg-old` and similar files are clues, not an original job baseline. Check
  their change time against the baseline, distinguish templates from active
  settings, and never restore them wholesale. Comment-stripped diffs can omit
  meaningful syntax such as sudo's `#includedir` directive.
- Record expected changes, repairs of existing faults, suspected regressions
  and unverified behavior separately. Give material findings an impact,
  evidence reference, acceptance check and owner. Put customer effects in the
  owner handoff and exact versions, paths and recovery details in the sysadmin
  handoff. State configuration-baseline gaps explicitly.

The dpkg completion summary retains the path-only configuration replacement review
when automatic application comparison is disabled or unavailable. It does not
read application content for that fallback. `--show-changes` also retains this
review, in addition to its private detailed diffs. Observations require review;
they do not authorize automatic restoration, cleanup or service activation.

## Package cleanup at completion

Include cleanup review before finishing a release upgrade. The release-hop path
already performs provenance-based obsolete-package removal and guarded APT
autoremove after the target is configured and verified. Record what was removed,
what was retained and why; rerun affected service/application and post-boot checks.
An empty upgrade simulation does not mean obsolete packages or residual configs
have disappeared. See [Debian's cleanup guidance](https://www.debian.org/releases/trixie/release-notes/upgrading.en.html#cleanup-after-the-upgrade).

There are three different cases:

| Case | Meaning | Treatment |
| --- | --- | --- |
| Unused dependency | APT marks it automatic and no package requires it | Guarded autoremove, subject to custom-software use and existing system/service protections |
| Obsolete or unavailable installed package | No binary version in the configured indexes | Prefer a supported replacement; proven old official origin permits bounded cleanup, while unknown/vendor/local origin needs review |
| Configuration-only record | Binaries have been removed, configuration/maintainer metadata remains | Separate purge decision; do not treat it as an installed runtime or silently reinstall it |

`--remove-deprecated-packages` now uses the same guarded obsolete cleanup for a
recorded transition ending at the current release, followed by guarded autoremove
and an availability report. It checks current repository consistency, refreshes
authenticated indexes and stops on incomplete package work or check/refresh
failure. It does not install
`apt-show-versions`, discard architecture qualifiers, guess a replacement server,
or purge configuration. Without original provenance it preserves unknown-origin
packages and still evaluates ordinary unused dependencies. Remaining older-hop
or custom packages may need explicit review; this is not a promise to remove every
unavailable package. Historical script revisions retain the broader legacy
implementation, so verify the selected artifact before recommending the command.
`--remove-leftover-packages` is a separate legacy crossgrade helper; do not use
it as interchangeable final cleanup.

Absence from indexes is not proof that removal is harmless: a source may be
missing, stale, disabled, architecture-filtered or intentionally private. A
custom executable under `/usr/local`, manual runtime, dlopen plugin or scheduled
script can use an old library without declaring a dpkg dependency. A new library
with a different SONAME is not an automatic substitute. Held packages, kernels,
services, essential packages and files under data/service paths need the existing
protections and a reviewed migration. Packages owning conventional `dig`, `host`
or `nslookup` executables are also retained, including legacy package names.
This protects installed diagnostic capabilities; it does not install missing
clients or prove that custom tools have no consumers. Review the actual removal
plan and before/after package evidence when investigating a lost utility.
The tool's APT checks and file preservation
do not prove that unregistered application consumers are absent.

For example, dpkg's `ic python:i386` means desired action Install and current
state Config-files, not Installed. `grep '^i'` selects the desired action, not
the installed state. Inspect the full machine-readable status instead:

```bash
dpkg-query -W -f='${Package}\t${Architecture}\t${Status}\t${Version}\n' python:i386
apt-get -s purge python:i386
```

The second command is a simulation, not permission to purge. Residual records
are included in the manifest's `package_state` output. Review shared/native-arch
configuration ownership and maintainer scripts, retained settings/data and
recovery needs before an actual purge of an exact package. Purge removes
configuration and can run maintainer cleanup; simulation does not execute those
scripts or prove their effects harmless. Do not purge every `?obsolete` or
`?config-files` match automatically. See [dpkg state columns](https://manpages.debian.org/trixie/dpkg/dpkg-query.1.en.html)
and [APT remove/purge semantics](https://manpages.debian.org/trixie/apt/apt-get.8.en.html).

The manifest includes package states and availability observations, not raw
conffile diffs. Use the [handoff commands](handoff-reports.md) to compare original
and final package records, list deferred cleanup with owners, and refresh both
reports after changes. A cleanup authorization still requires the verified
source/job, approved scope and current package plan.

Offline regression checks (no production operations):

```sh
bash -n distrorejuve.sh
python3 tests/test-upgrade-review.py
python3 tests/test-run-lessons.py
python3 tests/test-manifest-firstpass.py
python3 tests/test-manifest-upgrade-assets.py
python3 tests/test-manifest-packaged-wordpress.py
python3 tests/test-manifest-resolver.py

python3 tests/test-usrmerge.py

python3 tests/test-manifest-processes.py
python3 tests/test-lighttpd-parser.py
python3 tests/test-lighttpd-manifest.py
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
