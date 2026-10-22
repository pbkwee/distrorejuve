# Environment settings

Use the `DR_` names listed in the [README](../README.md#environment-variables).
Older environment names are not supported.

Settings are checked once before logging or system work. Boolean settings accept
only `true` or `false`. Unset or empty settings use the documented defaults.
`DR_MIN_FREE_DISK_MIB` and `DR_CONFIGURATION_HISTORY_DAYS` must be positive integers.

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

`DR_PANEL_UPGRADE` accepts `plesk` or `cpanel`. An unset or empty value does not enable panel automation.
`DR_PLESK_UPGRADE_TOOL` must be an absolute path to the reviewed, executable vendor tool.
See [hosting-panel upgrades](hosting-panels.md) for supported transitions, vendor checks and automatic reboots.
