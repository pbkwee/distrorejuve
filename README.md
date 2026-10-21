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

### Download failures on very old systems

Old `wget`/OpenSSL versions, such as those on Ubuntu 6.06, can fail with
`SSL23_GET_SERVER_HELLO:unknown protocol` or `Unable to establish SSL connection`.
These clients cannot negotiate modern TLS. `--no-check-certificate` does not fix
that protocol failure, and GitHub redirects plain HTTP downloads to HTTPS.

Download on a newer computer, then copy the file to the old server over SSH.
Replace `OLD_SERVER` with the server's address. Run these commands on the newer computer:

```sh
curl --fail --location --output distrorejuve.sh \
  https://raw.githubusercontent.com/pbkwee/distrorejuve/master/distrorejuve.sh &&
scp -O distrorejuve.sh root@OLD_SERVER:/root/distrorejuve.sh
```

`-O` selects the legacy SCP transfer protocol for old SSH servers. If an older SCP
client does not recognize `-O`, omit it. If SSH also reports a negotiation failure,
add the required option to this SCP command:

- If the host-key error offers `ssh-rsa`, add `-oHostKeyAlgorithms=+ssh-rsa`.
- If the key-exchange error offers `diffie-hellman-group14-sha1`, add `-oKexAlgorithms=+diffie-hellman-group14-sha1`.
  Use `-oKexAlgorithms=+diffie-hellman-group1-sha1` only if that is the available method.
- If an existing RSA login key needs SHA-1 signatures, add `-oPubkeyAcceptedAlgorithms=+ssh-rsa`.

To try the legacy RSA methods and both SHA-1 key exchanges in one command:

```sh
scp -O \
  -oHostKeyAlgorithms=+ssh-rsa \
  -oPubkeyAcceptedAlgorithms=+ssh-rsa \
  -oKexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 \
  distrorejuve.sh root@OLD_SERVER:/root/distrorejuve.sh
```

The `+` adds these methods after the modern defaults. Host-key verification still applies.

Keep these legacy settings on the individual command. See the
[OpenSSH legacy connection guide](https://www.openssh.org/legacy.html).
After copying, inspect `/root/distrorejuve.sh` on the old server and run `bash /root/distrorejuve.sh --check`.

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
| `--support-report [RUN_DIRECTORY]` | Print a minimal report for a public bug report. Review it before posting. |
| `--upgrade-report` | Collect a read-only developer handover with package, repository, configuration and application facts. Add `--no-dns` to skip DNS checks. |
| `--manifest` / `--manifest-json` | Report applications, service state, websites, mail storage and migration hints as text or JSON (dpkg or RPM). Add `--no-dns` to skip DNS checks. |
| `--show-changes` | Report differences from the pre-upgrade configuration and system state. |
| `--show-cruft` | List packages left over from older releases or architectures. |
| `--remove-cruft` | Remove those leftover packages. |
| `--remove-deprecated-packages` | Remove packages left over from older releases. |
| `--pause` / `--resume` | Pause or resume a running upgrade at its next pause check. |

Run `bash distrorejuve.sh --usage` for all options, including older release shortcuts.
Upgrade commands keep private detailed logs in `/root/distrorejuveinfo/runs` and show concise progress.
Add `--verbose` to display command output, or `--trace` to retain a separate Bash trace.

## Migration inventory

Capture the manifest before planning an upgrade or reinstall:

```sh
sudo bash distrorejuve.sh --manifest --no-dns
sudo bash distrorejuve.sh --manifest-json --no-dns > manifest.json
```

The manifest supports Debian/Ubuntu package databases and RPM-based systems such as
CentOS, RHEL, Rocky and AlmaLinux. It preserves distribution package versions,
including RPM epochs/releases and architecture. PHP CLI, FPM, Apache module and
extension packages are listed separately. Common RPM Apache, Remi and SCL PHP
configuration paths are included. Runtime associations are inferred from package
ownership and configuration; they do not establish which code a live process has loaded.

Migration hints include local program and service paths, cron files and custom timer
paths, selected local user IDs/groups/homes/shells, and configured mount targets and
filesystem types. Cron and timer files whose contents match their installed package
are omitted; customer edits, unowned files and unknown ownership remain visible.
Nonexecutable periodic cron jobs also remain visible because removing execute
permission can disable a package job. Other permission/owner changes are not checked.
Unverifiable files, including symlinks and files over 1 MiB, remain for manual review.

Collection reads conventional paths to depth 2, examines at most 200 file paths per
directory and limits each filesystem scan to five seconds. File metadata is capped
at 1 MiB; user and mount records are capped at 200 each. Warnings describe failures
and limits. Command bodies, environment contents, password fields, mount devices
and mount options are omitted. Literal proxy destinations contain only the authority;
credentials, paths, query strings and fragments are discarded. Named or dynamic
upstreams may still require manual resolution.

Keep the output private. It is a planning inventory: websites, database contents,
mail accounts/aliases, backups, certificate validity, remote mounts and application
compatibility still need separate checks. Custom includes, containers and uncommon
layouts can be missed. RPM support here applies to `--manifest` and `--manifest-json`;
`--upgrade-report` and Debian-specific upgrade/crossgrade checks retain their APT/dpkg scope.

## Environment variables

Set variables when invoking the script, for example:

```sh
sudo env MIN_FREE_DISK_MIB=6144 bash distrorejuve.sh --dist-upgrade
```

| Variable | Default and effect |
| --- | --- |
| `DISTROREJUVE_LOG_DIR` | `/root/distrorejuveinfo/runs`; parent directory for private run logs. |
| `MANIFEST_MAIL_METRICS` | `true`; set to `false` to skip mail size scans and spool counts. |
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

## Reporting problems

Failed upgrades save a minimal support report beside the private detailed log. Review that report before
[opening an issue](https://github.com/pbkwee/distrorejuve/issues/new). Do not post private logs or configuration.
See [reporting problems](docs/reporting-problems.md) for the command and included fields.

Written by Peter Bryant at http://launchtimevps.com.
