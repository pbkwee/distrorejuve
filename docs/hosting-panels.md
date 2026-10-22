# Hosting-panel upgrades

Plesk, cPanel and Virtualmin manage hosting configuration and packages.
Distrorejuve detects these panels before generic package, repository, cleanup or crossgrade work.
Standalone Webmin does not select this restriction.
Use `--manifest`, `--upgrade-report` and `--show-changes` to collect and review information.
The manifest includes the detected panel and version. An unreadable version is reported as unknown.

Set `DR_PANEL_UPGRADE=plesk` or `DR_PANEL_UPGRADE=cpanel` to select a supported vendor OS upgrade.
The setting is not a bypass for failed checks. Automatic Virtualmin upgrades are not implemented.
Generic `--upgrade`, `--dist-update`, cleanup and crossgrade commands remain blocked on panel hosts.
Use the panel's own tools for those package updates.

## Supported transitions

Each invocation supports one adjacent release transition on native amd64 with an x86_64 kernel.
The host must run systemd and must not be a container.

| Panel | Source → target | Required panel version |
| --- | --- | --- |
| Plesk | Debian 11 → 12 | 18.0.57 or later |
| Plesk | Debian 12 → 13 | 18.0.74 or later |
| Plesk | Ubuntu 20.04 → 22.04 | 18.0.44 or later |
| Plesk | Ubuntu 22.04 → 24.04 | 18.0.62 or later |
| Plesk | Ubuntu 24.04 → 26.04 | 18.0.81 or later |
| cPanel | Ubuntu 20.04 → 22.04 | Current updates of cPanel 118 |
| cPanel | Ubuntu 22.04 → 24.04 | Current updates of cPanel 134 |

These integrations follow the vendor procedures checked on 2026-10-23.
The installed vendor tool must also accept the upgrade.
Older Plesk transitions, RPM transitions and panel crossgrades are not automated here.
Use [Plesk's procedure](https://support.plesk.com/hc/en-us/articles/12377714344983-How-to-perform-dist-upgrade-procedure-on-Linux-server-with-Plesk)
or [cPanel ELevate](https://cpanel.github.io/elevate/getting-started/) for current requirements.
Virtualmin treats major OS upgrades as a separate administrator-managed task; see its
[system-upgrade guidance](https://www.virtualmin.com/docs/faq/#system-upgrade).

Multi-release requests stop before the first transition. A future transition can need a different panel version and tool.
Those checks cannot be completed on the original OS.
For example, use `--to-debian-release 12` for Plesk on Debian 11, verify the vendor's completed upgrade,
then prepare the next transition. `--to-latest` is accepted only when the script's latest target is one supported hop away.
It does not silently stop at an earlier panel-supported release.

## Prepare the vendor tool

Run upgrade commands as root. Update the panel on its current OS as required by the vendor. Make a complete recoverable backup and arrange console access.
The configuration/manifest baseline saved by distrorejuve is not a full backup.
Plesk's documented resource requirements include 5 GB free space and 2 GB RAM.
A passing minimum-version or disk check does not establish that every vendor prerequisite is met.
The vendor checks do not prove application compatibility.

For Plesk, download and review the executable linked in the vendor procedure for the exact transition.
Keep it under a root-owned directory such as `/root/panel-upgrade`.
Set `DR_PLESK_UPGRADE_TOOL` to its absolute path.
The executable and all parent directories must be root-owned and not writable by group or other users.
Symlinks in this path are rejected. Make the downloaded executable runnable by root.

Example after preparing Plesk's `debian12to13` tool:

```sh
chmod 700 /root/panel-upgrade/debian12to13
DR_PANEL_UPGRADE=plesk \
DR_PLESK_UPGRADE_TOOL=/root/panel-upgrade/debian12to13 \
  bash distrorejuve.sh --to-debian-release 13
```

For cPanel, install and review the current ELevate tool using its vendor instructions.
Distrorejuve uses `/usr/local/cpanel/scripts/elevate-cpanel`; `/scripts` is the usual cPanel alias.
The same ownership and write-permission requirements apply to the installed tool.

```sh
DR_PANEL_UPGRADE=cpanel bash distrorejuve.sh --to-next-ubuntu
```

Distrorejuve does not download or self-update these tools automatically.
An unsupported path, missing tool, insufficient panel version or failed prerequisite check stops the upgrade.
Clear any `ELEVATE_BASE_URL` override before using the cPanel integration.
Provider instructions in `/var/cpanel/elevate-noc-recommendations` require manual review through the vendor procedure.

## Execution and recovery

Plesk uses `--version` to check the tool's transition and `--precheck` to test prerequisites.
cPanel uses ELevate's `--check`.
These checks can write private vendor logs. The cPanel check can also refresh APT indexes,
clear the package cache and archive state from an already completed vendor upgrade.
They do not start the OS/package upgrade.

After checks pass, distrorejuve saves its existing configuration/manifest baseline and starts the vendor procedure.
Plesk runs its tool normally. cPanel runs `elevate-cpanel --start --non-interactive`.
The vendor tool controls package/configuration changes, recovery and automatic reboots.
Distrorejuve does not impose its generic conffile defaults, migrate PHP separately or run generic cleanup afterward.

The console reports a **vendor handoff**, not a verified completed OS upgrade.
ELevate can keep the command attached to its log until a reboot.
Use `--verbose` to see vendor output in the terminal, or monitor the vendor log from another session.
Use Plesk's `TOOL --monitor`, or cPanel's `elevate-cpanel --status` and `--log`, as documented by the vendor.

An unfinished Plesk resume service, resume file, conversion marker or lock stops a new invocation.
An existing cPanel state file must report exactly `success` before another transition is considered.
The vendor prerequisite check still runs after that status check.
Distrorejuve does not automatically select `--resume`, `--continue`, `--clean` or blocker-bypass options.
Follow the vendor recovery procedure after an interruption; do not start a competing upgrade.

After vendor completion and the required reboots, review panel notifications, services and the saved manifest/configuration changes.
Use the panel's validation tools and check hosted applications separately.
A vendor success status alone does not prove that every website, mailbox or extension works.
