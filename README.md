# distrorejuve

![distrorejuve. Move your Linux server forward. Linux release upgrades and migration checks.](assets/branding/readme-banner.png)

distrorejuve helps bring older Linux servers up to date. It checks the system,
guides distribution upgrades and reports what changed along the way.

It supports Debian and Ubuntu release upgrades, package updates on RPM-based
systems, and inventories for upgrade or migration planning. Experimental tools
also help move older 32-bit Debian/Ubuntu installations to 64-bit.

## How it works

Start with a read-only assessment. Review the findings, arrange a backup and
recovery access, then choose the upgrade that suits the server. The script
checks prerequisites and keeps detailed logs while it works. Application and
reboot checks complete the job.

Hosting panels and unusual configurations may need a separate upgrade procedure.
An inventory helps identify them before making changes.

## Getting started

Download the script and check the server:

```sh
wget -O distrorejuve.sh https://raw.githubusercontent.com/pbkwee/distrorejuve/master/distrorejuve.sh
sudo bash distrorejuve.sh --check-upgrade
```

Run `bash distrorejuve.sh --help` to see the available actions.
Take a full backup before running an upgrade.

## AI-assisted assessment and migration

You can use these tools wherever your server is hosted. Follow the
[step-by-step guide](docs/ai-assisted-migration.md) to supply a private manifest
or arrange SSH access, review a recommendation, and choose an in-place upgrade,
an upgraded copy or a fresh-server migration. Agents can use the
[server-upgrade skill](.agents/skills/server-upgrade/SKILL.md).
For a new RimuHosting destination, see [account and API setup](docs/rimuhosting.md).

## Documentation

- [Usage](docs/usage.md): upgrade actions, reports and logs.
- [Upgrade checks](docs/upgrade-review.md): prerequisites and checks needing operator review.
- [Inventory](docs/inventory.md): collected information, privacy and coverage, including [non-root visibility](docs/manifest.md).
- [Hosting panels](docs/hosting-panels.md) and [RPM upgrades](docs/rpm-upgrades.md).
- [Environment settings](docs/environment-variables.md).
- [Troubleshooting and reporting problems](docs/reporting-problems.md).
- [Branding](docs/branding.md): logos, colours and artwork.

Developed by the team at [RimuHosting](https://rimuhosting.com/), where we use it
to help maintain Linux virtual machines. We also offer
[server upgrade and migration assistance](https://blog.rimuhosting.com/2021/07/12/distro-upgrade-as-a-service/).
