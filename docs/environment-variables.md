# Environment settings

Use the `DR_` names listed below. Older environment names are not supported.

Settings are checked once before logging or system work. Boolean settings accept
only `true` or `false`. Unset or empty settings use the documented defaults.
`DR_MIN_FREE_DISK_MIB` defaults to `2048` MiB; it and
`DR_CONFIGURATION_HISTORY_DAYS` must be positive integers. The disk floor is not a
transaction peak estimate; raise it after reviewing downloads and installed growth.

`DR_UNPRIVILEGED` defaults to `true` for a non-root effective user and `false` for root.
`--unprivileged` forces it to `true`. Setting it to `false` cannot override a non-root
identity. The script never tries sudo; request elevation explicitly when needed.
See [migration inventory](inventory.md) for reduced coverage.

An explicit `--support-report` remains available even when an inherited upgrade
setting is invalid.

`DR_RUN_DIRECTORY` identifies the logging child's current run. Use `DR_LOG_DIRECTORY`
to choose the log location.

External tool settings keep their names, including `PATH`, `HOME`, locale and Bash
variables, `DEBIAN_FRONTEND`, `APT_CONFIG`, `APT_LISTCHANGES_FRONTEND`, `DPKG_*`,
`UCF_*`, `SYSTEMD_*` and `NO_COLOR`.

## RPM migration script setup

Set `DR_RPM_MIGRATION_SCRIPT` to the absolute path of the vendor script you downloaded
and reviewed. Use the script for your source distribution and major release.

The file and its parent directories must be owned by root and must not be writable
by group or other users. Neither the file nor its parent directories can be symbolic
links. Store the file under `/root`; distrorejuve checks these requirements before conversion.

## Hosting-panel upgrades

`DR_PANEL_UPGRADE` accepts `plesk` or `cpanel`. An unset or empty value does not enable those vendor tools.
Virtualmin, ISPConfig and standalone Webmin use the normal distro path without this setting.
Other detected hosting panels stop with their vendor upgrade or migration URL; this setting does not bypass that stop.
`DR_PLESK_UPGRADE_TOOL` must be an absolute path to the reviewed, executable vendor tool.
See [hosting-panel upgrades](hosting-panels.md) for supported transitions, vendor checks and automatic reboots.

## Available settings

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
| `DR_MIN_FREE_DISK_MIB` | `2048`; minimum available MiB on each checked filesystem. Use a positive integer. |
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
| `DR_PLESK_UPGRADE_TOOL` | Unset; absolute path of the reviewed Plesk executable for the selected transition. See [download instructions](hosting-panels.md#prepare-the-vendor-tool). |
| `DR_RPM_MIGRATION_TARGET` | Unset; required for end-of-life CentOS: `alma`, `rocky` or `centos-vault`. |
| `DR_RPM_MIGRATION_SCRIPT` | Absolute path to the reviewed vendor script; required for an Alma/Rocky conversion. |
| `DR_ALLOW_UNAUTHENTICATED_ARCHIVES` | `false`; explicit official APT archive exception. Never affects RPM signature checks. |
| `DR_ACTION` | Unset; override the action selected from command-line arguments. Prefer a command-line action. |
| `DR_CONFIGURATION_HISTORY_DAYS` | `7`; days to look back for the pre-upgrade comparison baseline. |
| `UCF_FORCE_CONFFOLD` | Unset; retain the caller's explicit ucf keep-old-configuration policy. |

Boolean settings accept `true` or `false`. Unset or empty settings use their documented defaults.
Use the `DR_` names; older environment names are not supported.
Standard tool settings such as `UCF_FORCE_CONFFOLD`, `APT_CONFIG` and `NO_COLOR` retain their names.

Virtualmin, ISPConfig and standalone Webmin use normal distro upgrade checks.
Other detected hosting panels use a separate vendor upgrade procedure.
See [hosting-panel upgrades](hosting-panels.md) for supported Plesk/cPanel paths and
manual upgrade or migration guidance for other detected panels.
