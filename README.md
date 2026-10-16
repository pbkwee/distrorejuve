# distrorejuve

## Summary
distrorejuve is a utility that helps with upgrading distros. It works on a number of different distros (Ubuntu, 
Debian, Centos). It uses apt, yum and repository corrections as appropriate. It can dist upgrade between 
multiple versions for Ubuntu and Debian.  It can convert (some) distros from 32bit to 64 bit (a cross grade).

If you are using the script to make changes, please take a full backup first.

Example usage to download the latest version of the script, then dist upgrade to latest Debian or Ubuntu disto. 

```bash
wget -O distrorejuve.sh --no-check-certificate https://raw.githubusercontent.com/pbkwee/distrorejuve/master/distrorejuve.sh

sudo nohup bash -x distrorejuve.sh --dist-upgrade 2>&1 | tee -a distrorejuve.log | egrep -v '^\+'
````

## Use Cases
- Enable lts archive for Debian squeeze servers and old-releases for Ubuntu
- Dist upgrade Ubuntu distros to the next LTS version.  Then from LTS version to LTS version.
- On completion provides information on config changes (modified config files, changed ports, changed packages, changed running processes)
- Install missing Debian keys
- Handles a few common Apache config issues after a distro upgrade.
- Designed to run unattended without lots of prompting.
- Burgeoning support to cross grade 32 bit distros to 64 bit
- Show/remove cruft to permit tidy up of packages installed from non-current (old) repositories

### Arguments
  
Run with…
* `--check` (or no argument) makes no changes.  Reports information like disk space free, kernel, distro version, config files modified from package defaults.
* `--dist-upgrade` run an upgrade, followed by dist-upgrading ubuntu distros to the latest lts or debian distros to latest debian.
*  `--upgrade` to run a yum upgrade or apt-get upgrade (fixing up repos, etc where we can).  no distro version change.
* `--dist-update` to update packages on the current distro version (no distro version change).
* `--show-changes` to report the differences pre/post upgrading (packages installed, config files, ports, etc).
* `--show-cruft` to see packages that do not belong to the current distro.  e.g. leftover packages from older distros.  And to see 32 bit packages installed on 64 bit distros.
* `--remove-cruft` to remove old packages and 32 bit applications on 64 bit distros.
* `--remove-deprecated-packages` to remove old packages
* `--to-64bit` to convert a 32 bit distro to 64 bit.  
     _NEW_ as at 2018-03/not so bullet-proof.  Only tested so far with Debian not Ubuntu.
* `--to-wheezy` to get from squeeze to wheezy
* `--to-jessie` to get from an older distro to jessie
* `--to-latest-debian` to get from squeeze or lenny or wheezy or jessie or stretch or buster to trixie 13
* `--to-debian-release [6-13]` to get from your current version to the specified version
* `--to-latest-lts` to get from an ubuntu distro to the most recent ubuntu lts version
* `--to-next-ubuntu` to get from an ubuntu distro to the next ubuntu version.  If the current ubuntu is an LTS version then this skips to the next LTS version.
* `--pause` to pause a distro rejuve running process (`touch ~/distrorejuve.pause`).  Triggers 30s sleeps at key points in the script.
* `--resume` to resume a paused distro rejuve running process (`rm -f ~/distrorejuve.pause`)

Use with `--source` if you just wish to have the distrorejuve functions available to you for testing

## Debian, Ubuntu and APT sources

Release and vendor tables were checked on **16 October 2026**. Debian upgrades stop at 13 (`trixie`).
Ubuntu LTS upgrades stop at 26.04 (`resolute`); interim upgrades include 26.10 (`stonking`).
Releases remain in chronological order. Debian upgrades proceed one major release at a time.
Ubuntu LTS releases move to the next LTS; interim releases move to the next release.

Support status and archive location are separate tables. An unsupported release can still be on a live mirror.
Ubuntu trusty/xenial/bionic/focal are outside standard support and need applicable Pro/legacy coverage.
These releases stay on normal mirrors; this script does not inspect a support subscription.
Debian bullseye is outside community LTS support and now has archived base and security repositories.
Ubuntu plucky and questing are outside support but are still on live mirrors at the audit date.

Sources: [Debian releases](https://www.debian.org/releases/),
[Bullseye LTS end](https://www.debian.org/News/2026/20260831),
[Ubuntu release cycle](https://ubuntu.com/about/release-cycle),
[Ubuntu 26.10](https://documentation.ubuntu.com/release-notes/26.10/),
[Debian archive](https://archive.debian.org/debian/dists/),
[Debian security archive](https://archive.debian.org/debian-security/dists/),
[Ubuntu archive](https://archive.ubuntu.com/ubuntu/dists/),
[Ubuntu old releases](https://old-releases.ubuntu.com/ubuntu/dists/).

The shared `apt_sources_*` functions handle `/etc/apt/sources.list` and valid `.list` and `.sources` files
in `/etc/apt/sources.list.d/`. Backup files, nested directories, comments and disabled entries are ignored.
Checks examine every active URI/suite pair, including deb822 stanzas with several URIs or suites.
Known mirror hosts and paths are recognized explicitly. Custom mirrors need manual review.

Rewrites retain source types, components, architecture filters, signing keys and other options.
Deb822 stanzas split when their suites need different archive locations or availability.
Malformed active sources stop the operation. Changed symlink sources require manual handling.
Files are staged before activation; originals are retained under `/root/distrorejuveinfo/apt-sources/change.*`.
An activation failure restores files already replaced. The backup tree retains each file's absolute path.
Do not run concurrent source editors or upgrade processes.

Debian archive conversion preserves the separate security archive and historical `/updates` suites.
Unavailable old `-updates` pockets are disabled; archived buster/bullseye updates remain enabled.
Historical backports use the appropriate archive path. Upgrades retire backports and proposed-update pockets.
Missing binary security/update pockets inherit the base source's options and components.
Partial existing security coverage requires manual review of components and architecture filters.
The squeeze transition includes squeeze-lts. Bookworm and later gain `non-free-firmware` when `non-free` was enabled.
Ubuntu archive conversion uses `old-releases.ubuntu.com`; upgrades retain ports mirrors where needed.

See [APT source formats](https://manpages.debian.org/trixie/apt/sources.list.5.en.html) and
[Debian upgrade guidance](https://www.debian.org/releases/trixie/release-notes/upgrading.en.html).

### Third-party repositories

`apt_repo_<provider>_support FAMILY CODENAME` returns 0 for documented target availability,
1 for an unsupported target, and 2 when vendor/version review is required.
Use `debian` or `ubuntu` and a codename such as `bookworm`, not a numeric release.
The functions are available through `source ./distrorejuve.sh --source`.

| Provider | Documented targets at the audit date |
| --- | --- |
| Sury PHP / Ondřej PHP PPA | Debian bookworm/trixie; Ubuntu jammy/noble/resolute |
| Virtualmin | Debian bookworm/trixie; Ubuntu noble/resolute; other targets need review |
| PostgreSQL PGDG / Docker | Debian bookworm/trixie; Ubuntu jammy/noble/resolute/stonking |
| cPanel | Ubuntu noble; Debian unsupported; other targets need review |
| Webmin / Plesk / MariaDB / MongoDB / other PPAs | Installed product/version or individual repository review required |

Recognizing a repository does not certify an installed application's upgrade path.
Release upgrades stop while any third-party source is active, even when the target has packages.
Review the vendor migration procedure and disable the source before continuing; the script leaves vendor sources unchanged.
Plesk and cPanel installations require their vendor upgrade tools/procedures even if their sources are disabled.
`IGNOREOTHERREPOS` retains its current-release update use; it cannot bypass target-release vendor checks.
Webmin's historical `sarge` and current `stable` suites do not count as Debian release mixing.

Provider sources: [Sury policy](https://github.com/oerdnj/deb.sury.org/wiki/Frequently-Asked-Questions),
[Virtualmin support](https://www.virtualmin.com/docs/os-support/), [Webmin repository migration](https://webmin.com/download/),
[Plesk upgrade procedure](https://support.plesk.com/hc/en-us/articles/12377714344983-How-to-perform-dist-upgrade-procedure-on-Linux-server-with-Plesk),
[cPanel requirements](https://docs.cpanel.net/installation-guide/system-requirements-ubuntu/),
[PGDG Debian](https://www.postgresql.org/download/linux/debian/), [PGDG Ubuntu](https://www.postgresql.org/download/linux/ubuntu/),
[Docker Debian](https://docs.docker.com/engine/install/debian/), [Docker Ubuntu](https://docs.docker.com/engine/install/ubuntu/),
[MariaDB repository support](https://mariadb.com/docs/server/server-management/install-and-upgrade-mariadb/installing-mariadb/binary-packages/mariadb-package-repository-setup-and-usage/),
[MongoDB platform requirements](https://www.mongodb.com/docs/manual/administration/production-notes/).

Fail2ban and Dovecot checks protect transitions with incompatible configuration formats.
Dovecot 2.4 migration checks apply to Debian trixie and the Ubuntu questing/resolute boundary.
Review the migration before using `IGNORE_DOVECOT_ERROR=Y`.
Native i386/mipsel/mips64el cannot upgrade to Debian trixie; Ubuntu i386 cannot upgrade past bionic.
Other 32-bit architectures are not rejected solely for being 32-bit.

### Local verification

Run `bash -n distrorejuve.sh repolines.sh`, compare ShellCheck findings, and run:

```sh
python3 tests/test-tidy.py
python3 tests/test-apt-sources.py
python3 tests/test-releases.py
```

Tests use isolated files and mocked package/service operations. One fixture uses native APT `--print-uris`
to validate rewritten deb822 files without downloading anything. These checks do not establish live-upgrade success.

## Notes

Written by Peter Bryant at http://launchtimevps.com

Latest version (or thereabouts) will be available at https://github.com/pbkwee/distrorejuve
