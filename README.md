# distrorejuve

distrorejuve is a Bash utility for upgrading Debian and Ubuntu systems. It can perform
release upgrades, update packages, check upgrade preconditions and report configuration changes.
It also includes experimental 32-bit to 64-bit crossgrades and legacy CentOS/Yum helpers.

- Upgrade Debian one major release at a time, or Ubuntu to its next release or LTS.
- Handle classic and deb822 APT source files, including archived distribution repositories.
- Compare configuration, packages, listening ports and running processes before and after an upgrade.
- Inspect and remove packages left over from older releases or architectures.
- Collect a read-only inventory of services, websites, mail storage and application versions.

Take a full backup before running commands that change the system. Review third-party repositories
and vendor upgrade requirements before starting a release upgrade. Crossgrades are experimental.

## Getting started

Download the script and inspect the system before upgrading:

```sh
wget -O distrorejuve.sh https://raw.githubusercontent.com/pbkwee/distrorejuve/master/distrorejuve.sh
sudo bash distrorejuve.sh --check
```

To upgrade Debian to the latest supported release, or Ubuntu to the latest supported LTS:

```sh
sudo bash distrorejuve.sh --dist-upgrade
```

## Main options

| Option | Purpose |
| --- | --- |
| `--check` (or no argument) | Report system information and upgrade preconditions. Leave `REMOVEX11` unset for a check that does not remove packages. |
| `--upgrade` | Upgrade packages on the current release. |
| `--dist-update` | Perform a full package upgrade on the current release. |
| `--dist-upgrade` | Upgrade through successive releases to the latest supported Debian release or Ubuntu LTS. |
| `--to-debian-release [6-13]` | Upgrade Debian to a specific release. |
| `--to-latest-lts` | Upgrade Ubuntu to the latest supported LTS. |
| `--to-next-ubuntu` | Upgrade Ubuntu to its next release, or next LTS when starting from an LTS. |
| `--crossgrade` | Add to a release upgrade to permit i386 → amd64 conversion at the last native i386 release, then continue. Requires a running x86_64 kernel. |
| `--to-64bit` | Attempt an experimental crossgrade from 32-bit to 64-bit. |
| `--upgrade-report` | Collect a read-only developer handover with package, repository, configuration and application facts. Add `--no-dns` to skip DNS checks. |
| `--manifest` / `--manifest-json` | Report applications and services as text or JSON. Add `--no-dns` to skip DNS checks. |
| `--show-changes` | Report differences from the pre-upgrade configuration and system state. |
| `--show-cruft` | List packages left over from older releases or architectures. |
| `--remove-cruft` | Remove those leftover packages. |
| `--remove-deprecated-packages` | Remove packages left over from older releases. |
| `--pause` / `--resume` | Pause or resume a running upgrade at its next pause check. |

Run `bash distrorejuve.sh --usage` for all options, including older release shortcuts.
Upgrade commands keep private detailed logs in `/root/distrorejuveinfo/runs` and show concise progress.
Add `--verbose` to display command output, or `--trace` to retain a separate Bash trace.

## Environment variables

Set variables when invoking the script, for example:

```sh
sudo env MIN_FREE_DISK_MIB=6144 bash distrorejuve.sh --dist-upgrade
```

| Variable | Default and effect |
| --- | --- |
| `DISTROREJUVE_LOG_DIR` | `/root/distrorejuveinfo/runs`; parent directory for private run logs. |
| `MANIFEST_MAIL_METRICS` | `true`; set to `false` to skip bounded mail size/count probes. |
| `MIN_FREE_DISK_MIB` | `5120`; minimum available MiB on each checked filesystem. Use a positive integer. |
| `SKIP_DISK_SPACE_CHECK` | `false`; set to `true` to bypass disk-space checks after review. |
| `ALLOW_CROSSGRADE_BLOCKERS` | `false`; permit starting despite predicted package blockers during a crossgrade. Final native 64-bit verification remains required. |
| `PURGE_INCOMPATIBLE_PACKAGES` | `false`; set to `true` to back up and purge known config-only upgrade blockers. Reinstall manually afterward. |
| `PREFER_PACKAGED_USRMERGE_FILES` | `false`; set to `true` after review to back up an unowned `/usr` merge conflict and keep the packaged file. |
| `REMOVE_OBSOLETE_CROSSGRADE_PACKAGES` | `true`; remove verified obsolete compiler, library and transitional packages after backup during a crossgrade. Set to `false` to require manual removal. |
| `IGNOREKERNEL` | Unset; bypass the old-kernel precondition. |
| `IGNOREX11` | Unset; bypass the X11 precondition when `REMOVEX11` is unset. |
| `IGNOREBACKPORTS` | Unset; permit active backports during preflight. |
| `IGNOREOTHERREPOS` | Unset; bypass current-release repository checks. Does not bypass release-transition vendor checks. |
| `IGNORECRUFT` | Unset; bypass the old-package precondition for crossgrades. |
| `IGNORE_DOVECOT_ERROR` | Unset; override the Dovecot 2.4 configuration guard after manual review. |
| `REMOVEX11` | Unset; enable X11 package removal during preflight, including `--check`. |
| `ENABLE_UBUNTU_CROSSGRADE` | Unset; permit the experimental Ubuntu crossgrade path. |
| `DAYS_UPGRADE_ONGOING` | `7`; days to look back for the pre-upgrade comparison baseline. |
| `UCF_FORCE_CONFFOLD` | Unset; retain the caller's explicit ucf keep-old-configuration policy. |

`SKIP_DISK_SPACE_CHECK`, `ALLOW_CROSSGRADE_BLOCKERS`, `PURGE_INCOMPATIBLE_PACKAGES`, `PREFER_PACKAGED_USRMERGE_FILES`, `REMOVE_OBSOLETE_CROSSGRADE_PACKAGES` and `MANIFEST_MAIL_METRICS` accept only `true` or `false`.
For the `IGNORE*` variables, `REMOVEX11` and `ENABLE_UBUNTU_CROSSGRADE`, any nonempty value enables
the control, including `false` or `0`. Use `unset` to disable one of these controls.

Written by Peter Bryant at http://launchtimevps.com.
