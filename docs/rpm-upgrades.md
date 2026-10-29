# RPM updates and CentOS recovery

On AlmaLinux, Rocky Linux and RHEL, `--upgrade` uses the installed native repositories
and prefers DNF over YUM. RHEL needs suitable subscription repositories. Active
CentOS Stream releases also keep their native repositories. `--dist-update` uses
this same RPM update path once. RPM major-release upgrades are separate work;
`--to-latest` does not perform an ELevate migration.

Before package updates, enabled native repository IDs must cover the distro's
base and update packages. EL 8+ requires BaseOS and AppStream; older CentOS needs
base and updates, while Fedora needs fedora and updates. RHEL and Oracle use
recognized native subscription/channel pairs. EL delivers security fixes through
these repositories rather than a separate Debian-style security repository.
Missing or custom repository IDs stop for review; no subscription channel or
optional repository is enabled automatically. Signature/TLS checks remain required.
The same gate runs after vendor conversion, and its recovery marker is retained
until the target repositories pass validation and refresh successfully.

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
then save the script under `/root`. See [migration script setup](environment-variables.md#rpm-migration-script-setup) for file requirements.

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
