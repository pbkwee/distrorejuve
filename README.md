# distrorejuve

![distrorejuve. Move your Linux server forward. Linux release upgrades and migration checks.](assets/branding/readme-banner.png)

distrorejuve is a Bash utility for upgrading Debian and Ubuntu systems. It can perform
release upgrades, update packages, check upgrade preconditions and report configuration changes.
It also updates RPM packages using DNF/YUM, repairs selected CentOS archive sources,
and includes experimental 32-bit to 64-bit Debian/Ubuntu crossgrades.

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
sudo bash distrorejuve.sh --check-upgrade
```

To upgrade to the latest Debian stable release or Ubuntu LTS:

```sh
sudo bash distrorejuve.sh --to-latest
```

If downloading fails with `unknown protocol` or `Unable to establish SSL connection`,
see [download and SSH tips](docs/reporting-problems.md#download-errors-on-old-servers).

## Main options

| Option | Purpose |
| --- | --- |
| `--check-upgrade` (or no argument) | Read-only review of the current distro, intended newer release and known upgrade blockers. RPM major-release upgrades require a reviewed migration procedure. |
| `--upgrade` | Update native APT or DNF/YUM packages. End-of-life CentOS requires an explicit repository/migration choice below. |
| `--dist-update` | Perform a full package upgrade on the current release. |
| `--to-latest` | Upgrade through successive releases to Debian stable or the latest Ubuntu LTS. |
| `--to-debian-release VERSION` | Upgrade Debian to a specific release. |
| `--to-next-ubuntu` | Upgrade Ubuntu to its next release, or next LTS when starting from an LTS. |
| `--crossgrade` | Add to a release upgrade to permit i386 → amd64 conversion at the last native i386 release, then continue. Requires a running x86_64 kernel. |
| `--to-64bit` | Attempt an experimental crossgrade from 32-bit to 64-bit. |
| `--support-report [RUN_DIRECTORY]` | Print a minimal report for a public bug report. Review it before posting. |
| `--upgrade-report` | Collect a read-only developer handover with package, repository, configuration and application facts. |
| `--manifest` / `--manifest-json` | Report applications, service state, websites, mail storage and migration hints as text or JSON (dpkg or RPM). |
| `--show-changes` | Report differences from the pre-upgrade configuration and system state. |
| `--list-leftover-packages` | List packages left over from older releases or architectures. |
| `--remove-leftover-packages` | Remove those leftover packages. |
| `--remove-deprecated-packages` | Remove packages left over from older releases. |
| `--pause` / `--resume` | Pause or resume a running upgrade at its next pause check. |

Run `bash distrorejuve.sh --help` for all options.
Upgrade commands keep private detailed logs in `/root/distrorejuveinfo/runs` and show concise progress.
Add `--verbose` to display command output, or `--trace` to retain a separate Bash trace.

## RPM updates and CentOS recovery

On AlmaLinux, Rocky Linux and RHEL, `--upgrade` uses the installed native repositories
and prefers DNF over YUM. RHEL needs suitable subscription repositories. Active
CentOS Stream releases also keep their native repositories. `--dist-update` uses
this same RPM update path once. RPM major-release upgrades are separate work;
`--to-latest` does not perform an ELevate migration.

An end-of-life CentOS system stops before source/package changes until you set
`DR_RPM_MIGRATION_TARGET`. The choices are:

| Choice | Behaviour |
| --- | --- |
| `alma` | Convert eligible CentOS systems to the same-major AlmaLinux release using your reviewed vendor script. |
| `rocky` | Convert eligible CentOS systems to the same-major Rocky Linux release using the matching reviewed vendor script. |
| `centos-vault` | Restore recognized official CentOS sources to their final archived release, then install remaining historical updates. |

There is no AlmaLinux or Rocky Linux 7 repository equivalent. For CentOS 7 and
older systems, an Alma/Rocky choice stops with migration guidance; it never mixes
EL7 and EL8 packages. Use a reviewed [ELevate procedure](https://wiki.almalinux.org/elevate/)
or rebuild on a supported release. AlmaLinux also hosts an EL7 archive for ELevate;
those remain CentOS 7 packages, not AlmaLinux 7.

For historical package recovery only:

```sh
sudo env DR_RPM_MIGRATION_TARGET=centos-vault bash distrorejuve.sh --upgrade
```

Archive recovery is limited to recognized CentOS releases and architectures.
Old TLS clients or YUM versions may still require manual recovery. The script does
not bypass TLS/signature checks, import arbitrary signing keys, rebuild the RPM
database automatically, or bootstrap old YUM from hard-coded HTTP packages.

Before conversion, back up the VM and arrange console access and downtime.
Download and review the appropriate [AlmaLinux migration tool](https://wiki.almalinux.org/documentation/migration-guide.html)
or [Rocky migration tool](https://github.com/rocky-linux/rocky-tools/tree/main/migrate2rocky),
then save the script under `/root`. See [migration script setup](docs/environment-variables.md#rpm-migration-script-setup) for file requirements.

For example, after reviewing `/root/almalinux-deploy.sh`:

```sh
sudo env DR_RPM_MIGRATION_TARGET=alma \
  DR_RPM_MIGRATION_SCRIPT=/root/almalinux-deploy.sh \
  bash distrorejuve.sh --upgrade
```

The script first updates the existing release, runs the selected vendor conversion,
checks the resulting distro and major version, then updates from the new native
repositories. Stream-to-Alma conversion passes the vendor's `--downgrade` option:
some packages may be replaced with older stable EL versions. Migration tools vary
by source release; provide the script matching the source distribution and major version.

Repository repair preserves enabled choices, signing keys and third-party sources.
It stages the changed files, checks repository metadata and saves originals before
replacement. Custom `reposdir`/includes, linked files and ambiguous official source
layouts require manual review. Inaccessible enabled repositories and remaining
update candidates cause failure; exclusions, version locks and PHP module streams
are not silently removed or switched.

Private logs contain the RPM evidence directory, package inventories and available
before/after manifests. Repository backups and the copied vendor script are retained
there. A failed/interrupted conversion leaves
`/root/distrorejuveinfo/rpm-migration.pending`; finish vendor recovery and verify the
result before removing that marker and retrying. No automatic rollback or reboot
occurs. A successful transaction still requires checks of PHP-FPM/Apache, affected
processes and the applications. Rebooting into the new kernel must be arranged
separately where required. [CentOS Vault](https://vault.centos.org/) is a frozen archive.

## Migration inventory

Capture the manifest before planning an upgrade or reinstall:

```sh
bash distrorejuve.sh --manifest
bash distrorejuve.sh --manifest-json > manifest.json
```

The manifest can run as a non-privileged user. See [manifest privileges](docs/manifest.md)
for the differences in service checks, listener details, mail measurements and file access.

Upgrade/removal commands, pause/resume, `--show-changes` (which writes a snapshot)
and `--list-leftover-packages` (which can install a helper) require root outside reduced mode.
`--check-upgrade` works in reduced mode. It ignores repair and skip overrides, reports blockers, and never changes packages or configuration.
`--upgrade-report` also permits reduced collection, within its existing APT/dpkg scope.

DNS checks report whether website domains resolve to this server.

The manifest supports Debian/Ubuntu package databases and RPM-based systems such as
CentOS, RHEL, Rocky and AlmaLinux. It preserves distribution package versions,
including RPM epochs/releases and architecture. PHP CLI, FPM, Apache module and
extension packages are listed separately. Common RPM Apache, Remi and SCL PHP
configuration paths are included. Runtime associations are inferred from package
ownership and configuration; they do not establish which code a live process has loaded.

Mail-storage discovery covers these standard layouts:

| Hosting panel/layout | Mail storage |
| --- | --- |
| Plesk | `/var/qmail/mailnames` and the configured `PLESK_MAILNAMES_D` |
| ISPConfig and CWP | `/var/vmail` |
| CyberPanel | `/home/vmail` |
| aaPanel | `/www/vmail` |
| KeyHelp and other Postfix virtual-mail layouts | `/var/mail`, including `/var/mail/vhosts` |
| Froxlor | `/var/customers/mail` |
| cPanel, HestiaCP and VestaCP | `/home/USER/mail` when the panel installation is present |
| DirectAdmin | `/home/USER/imap` when installed, plus account `Maildir` directories |
| Virtualmin/Webmin | Account `Maildir`/`.Maildir`, legacy `mail` when Virtualmin is present, nested `homes/USER` mailboxes and subserver layouts under `domains/DOMAIN` |
| InterWorx | `/home/USER/var/DOMAIN/mail` when installed |
| Conventional local delivery | `/var/mail`, `/var/spool/mail`, `/root/Maildir` and `/root/.Maildir` |

Account discovery also checks numbered home partitions such as `/home2` and `/home10`.
Literal paths from common Postfix, Dovecot (including `/etc/dovecot.conf` and KeyHelp
fragments), Courier and Plesk configuration are reported too. These follow layouts
such as [DirectAdmin mail storage](https://docs.directadmin.com/other-hosting-services/webmail/),
[InterWorx account storage](https://appendix.interworx.com/current-7/getting_started/introduction_to_interworx/siteworx_101/introduction_to_siteworx.html)
and [KeyHelp storage paths](https://kb.keyhelp.de/print-119.html).

Mail-storage collection never reads message contents or changes mail. Sizes use
bounded metadata scans: at most eight mail stores, three seconds per size probe,
and 20 account mail directories.
Empty conventional roots are omitted and aliases to the same directory are deduplicated.
Both the literal path and resolved symlink target must be recognised narrow mail
locations before measuring. Custom paths can therefore be reported with unknown
size; missing results and incomplete coverage are not evidence of empty mailboxes.

Potential compromise indicators appear as `security_indicator` records in text and JSON.
The process check flags shell redirection or `tee` targeting sudoers, Base64 decoding
piped to a shell, kernel-thread-style names with a nonzero UID or userspace memory,
and executable or interpreter-script paths under `/tmp`, `/var/tmp` or `/dev/shm`.
It also flags download-tool commands piped to a shell, mining protocol URLs and
correlated mining algorithm, pool and user options. Authorized maintenance and
mining can match; endpoints, credentials and command bodies are omitted.
Dot-prefixed listener names also get a review record.
The kernel executable-link check also catches temporary binaries hidden behind altered
process names, executables in hidden system binary/library directories, and deleted
executables in home, application-state or temporary directories. It reports
counts and sample PIDs without executable pathnames; ordinary deleted system binaries
are omitted because package updates commonly replace them. The probe is limited to
five seconds and 20000 links; permissions or process exits can leave gaps.
See the [Linux executable-link documentation](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html).
Groups of at least 20 Webmin workers sharing a parent and UID get a concurrency
review hint. This does not establish unauthorized sessions or exploitation.

Website files and scheduled jobs are checked for possible signs of compromise.
Website sampling includes WordPress plugin directories within the shared file and
time limits. Scheduled checks also flag execution from hidden directories under
home, application-state and system binary/library paths, and downloads piped to a shell.
Checks are read-only, and reports omit file contents and raw commands.

Findings need review because legitimate activity can trigger them and some problems
may be missed. Warnings indicate incomplete coverage. A report without findings
does not establish a clean server. These observations are excluded from before/after
configuration comparisons.

Migration hints include local program and service paths, cron files and custom timer
paths, selected local user IDs/groups/homes/shells, and configured mount targets and
filesystem types. Service, cron and timer files whose contents match their installed
package are omitted, including routine systemd links to unchanged vendor units.
Package backup files (`.dpkg-*`, `.ucf-*`, `.rpmnew`, `.rpmsave`, `.rpmorig`, `~`),
cron placeholders and SysV dependency metadata are omitted. Routine boot/console,
legacy OS logging and file-indexing scripts are also omitted unless package checks
confirm local content changes. These filters affect migration hints only; security
indicator scans still examine their existing paths.
Other customer edits, unowned files and unknown ownership remain visible, including
stopped or disabled application services and custom jobs that may need migration.
Nonexecutable periodic cron jobs remain visible because removing execute permission
can disable a package job. Other permission/owner changes are not checked.
Unverifiable files, other symlinks and files over 1 MiB remain for manual review.
Ownership-query failures produce one summary warning with a count; affected paths
retain `ownership=unknown`.

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
sudo env DR_MIN_FREE_DISK_MIB=6144 bash distrorejuve.sh --to-latest
```

| Variable | Default and effect |
| --- | --- |
| `DR_UNPRIVILEGED` | Automatically enabled for non-root users; `true` forces reduced collection and blocks commands requiring root. `false` never grants privileges. CLI equivalent: `--unprivileged`. |
| `DR_LOG_DIRECTORY` | `/root/distrorejuveinfo/runs`; parent directory for private run logs. |
| `DR_MANIFEST_DNS` | `true`; set to `false` to skip DNS lookups in manifests and upgrade reports. |
| `DR_MANIFEST_MAIL_METRICS` | `true`; set to `false` to skip mail size scans and spool counts. |
| `DR_MIN_FREE_DISK_MIB` | `5120`; minimum available MiB on each checked filesystem. Use a positive integer. |
| `DR_SKIP_DISK_SPACE_CHECK` | `false`; set to `true` to bypass disk-space checks after review. |
| `DR_ALLOW_CROSSGRADE_BLOCKERS` | `false`; permit starting despite predicted package blockers during a crossgrade. Final native 64-bit verification remains required. |
| `DR_PURGE_INCOMPATIBLE_PACKAGES` | `false`; set to `true` to back up and purge known config-only upgrade blockers. Reinstall manually afterward. |
| `DR_PREFER_PACKAGED_USRMERGE_FILES` | `false`; set to `true` after review to back up an unowned `/usr` merge conflict and keep the packaged file. |
| `DR_REMOVE_OBSOLETE_CROSSGRADE_PACKAGES` | `true`; remove verified obsolete compiler, library and transitional packages after backup during a crossgrade. Set to `false` to require manual removal. |
| `DR_SKIP_KERNEL_CHECK` | `false`; bypass the old-kernel precondition. |
| `DR_SKIP_X11_CHECK` | `false`; bypass the X11 precondition when `DR_REMOVE_X11_PACKAGES` is `false`. |
| `DR_ALLOW_BACKPORTS` | `false`; permit active backports during preflight. |
| `DR_SKIP_CURRENT_RELEASE_REPOSITORY_CHECK` | `false`; bypass current-release repository checks. Does not bypass release-transition vendor checks. |
| `DR_SKIP_OLD_PACKAGE_CHECK` | `false`; bypass the old-package precondition for crossgrades. |
| `DR_SKIP_DOVECOT_MIGRATION_CHECK` | `false`; override the Dovecot 2.4 configuration guard after manual review. |
| `DR_REMOVE_X11_PACKAGES` | `false`; enable X11 package removal during upgrade preflight. `--check-upgrade` never removes packages. |
| `DR_ENABLE_UBUNTU_CROSSGRADE` | `false`; permit the experimental Ubuntu crossgrade path. |
| `DR_PANEL_UPGRADE` | Unset; select `plesk` or `cpanel` for a supported single-release vendor OS upgrade. |
| `DR_PLESK_UPGRADE_TOOL` | Unset; absolute path of the reviewed Plesk executable for the selected transition. See [download instructions](docs/hosting-panels.md#prepare-the-vendor-tool). |
| `DR_RPM_MIGRATION_TARGET` | Unset; required for end-of-life CentOS: `alma`, `rocky` or `centos-vault`. |
| `DR_RPM_MIGRATION_SCRIPT` | Absolute path to the reviewed vendor script; required for an Alma/Rocky conversion. |
| `DR_ALLOW_UNAUTHENTICATED_ARCHIVES` | `false`; explicit official APT archive exception. Never affects RPM signature checks. |
| `DR_ACTION` | Unset; override the action selected from command-line arguments. Prefer a command-line action. |
| `DR_CONFIGURATION_HISTORY_DAYS` | `7`; days to look back for the pre-upgrade comparison baseline. |
| `UCF_FORCE_CONFFOLD` | Unset; retain the caller's explicit ucf keep-old-configuration policy. |

Boolean settings accept `true` or `false`. Unset or empty settings use their documented defaults.
Use the `DR_` names; older environment names are not supported.
See [environment settings](docs/environment-variables.md) for validation and migration script setup.
Standard tool settings such as `UCF_FORCE_CONFFOLD`, `APT_CONFIG` and `NO_COLOR` retain their names.

Hosting-panel servers use a separate vendor upgrade procedure.
See [hosting-panel upgrades](docs/hosting-panels.md) for supported Plesk/cPanel paths and
manual upgrade or migration guidance for other detected panels.

## Reporting problems

Failed upgrades save a minimal support report beside the private detailed log. Review that report before
[opening an issue](https://github.com/pbkwee/distrorejuve/issues/new). Do not post private logs or configuration.
See [reporting problems](docs/reporting-problems.md#reporting-upgrade-problems) for the command and included fields.

Developed by the team at [RimuHosting](https://rimuhosting.com/). We've hosted Linux virtual machines
since 2003 and use this script internally to upgrade older servers.

We can also help you upgrade an old server and migrate it to our modern hardware and VM hosting
platform. [Contact us](https://rimuhosting.com/contact.jsp) to discuss your server, or read about our
[distro upgrade service](https://blog.rimuhosting.com/2021/07/12/distro-upgrade-as-a-service/).

## Branding

See the [branding guide](docs/branding.md) for the editable SVG logo, PNG exports
and README banner.
