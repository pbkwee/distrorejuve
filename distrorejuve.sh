#!/bin/bash

# Boolean controls are later invoked as commands; restrict their values
# to true/false so an environment setting cannot select another executable.
# Validate operator settings before logging or system work.
function environment_validate_settings() {
  local name value
  for name in DR_ALLOW_BACKPORTS DR_ALLOW_CROSSGRADE_BLOCKERS DR_ALLOW_UNAUTHENTICATED_ARCHIVES \
      DR_ENABLE_UBUNTU_CROSSGRADE DR_MANIFEST_DNS DR_MANIFEST_MAIL_METRICS DR_PREFER_PACKAGED_USRMERGE_FILES \
      DR_PURGE_INCOMPATIBLE_PACKAGES DR_REMOVE_OBSOLETE_CROSSGRADE_PACKAGES DR_REMOVE_X11_PACKAGES \
      DR_SKIP_CURRENT_RELEASE_REPOSITORY_CHECK DR_SKIP_DISK_SPACE_CHECK DR_SKIP_DOVECOT_MIGRATION_CHECK \
      DR_SKIP_KERNEL_CHECK DR_SKIP_OLD_PACKAGE_CHECK DR_SKIP_X11_CHECK DR_UNPRIVILEGED; do
    value=${!name}
    case "$value" in
      ''|true|false) :;;
      *) printf 'dss:error: %s must be true or false.\n' "$name" >&2; return 1;;
    esac
  done
  for name in DR_MIN_FREE_DISK_MIB DR_CONFIGURATION_HISTORY_DAYS; do
    value=${!name}
    [ -n "$value" ] || continue
    case "$value" in
      *[!0-9]*) :;;
      *) [ "$value" -gt 0 ] 2>/dev/null && continue;;
    esac
    printf 'dss:error: %s must be a positive integer.\n' "$name" >&2
    return 1
  done
  case "${DR_RPM_MIGRATION_TARGET:-}" in
    ''|alma|rocky|centos-vault) :;;
    *) echo 'dss:error: DR_RPM_MIGRATION_TARGET must be alma, rocky or centos-vault.' >&2; return 1;;
  esac
  case "${DR_PANEL_UPGRADE:-}" in
    ''|plesk|cpanel) :;;
    *) echo 'dss:error: DR_PANEL_UPGRADE must be plesk or cpanel.' >&2; return 1;;
  esac
  case "${DR_PLESK_UPGRADE_TOOL:-}" in
    ''|/*) :;;
    *) echo 'dss:error: DR_PLESK_UPGRADE_TOOL must be an absolute path.' >&2; return 1;;
  esac
  case "${DR_RPM_MIGRATION_SCRIPT:-}" in
    ''|/*) :;;
    *) echo 'dss:error: DR_RPM_MIGRATION_SCRIPT must be an absolute path.' >&2; return 1;;
  esac
}

# https://superuser.com/questions/1456989/how-to-configure-apt-in-debian-buster-after-release buster InRelease' changed its 'Version' value from '' to '10.0'  Run 'apt list --upgradable' to see them. apt-get update --allow-releaseinfo-change
# https://www.debian.org/releases/bookworm/amd64/release-notes/ch-upgrading.html

# https://wiki.ubuntu.com/Releases
# when updating, keep them in their release order to safety
# no leading/trailing spaces.  one space per word.
LTS_UBUNTU="dapper hardy lucid precise trusty xenial bionic focal jammy noble resolute"
#ARCHIVE_REPO_UBUNTU="precise trusty vivid wily xenial yakkety"
# https://old-releases.ubuntu.com/releases/
OLD_RELEASES_UBUNTU="warty hoary breezy dapper edgy feisty gutsy hardy intrepid jaunty karmic maverick natty oneiric quantal raring saucy lucid utopic vivid wily yakkety zesty  artful cosmic disco eoan groovy hirsute impish kinetic lunar precise mantic oracular"
ALL_UBUNTU="warty hoary breezy dapper edgy feisty gutsy hardy intrepid jaunty karmic lucid maverick natty oneiric precise quantal raring saucy trusty utopic vivid wily xenial yakkety zesty artful bionic cosmic disco eoan focal groovy hirsute impish jammy kinetic lunar mantic noble oracular plucky questing resolute stonking"

# https://www.debian.org/releases/
ALL_DEBIAN="hamm slink potato woody sarge etch lenny squeeze wheezy jessie stretch buster bullseye bookworm trixie"
# in egrep code be aware of etch/stretch matching
# https://wiki.debian.org/LTS
UNSUPPORTED_DEBIAN="hamm slink potato woody sarge etch lenny squeeze wheezy jessie stretch buster bullseye"
# https://archive.debian.org/debian/dists/ and https://archive.debian.org/debian-security/dists/
DEBIAN_ARCHIVE="$UNSUPPORTED_DEBIAN squeeze-lts"

# Support state differs from repository location; Ubuntu ESM releases stay on live mirrors.
UNSUPPORTED_UBUNTU="$OLD_RELEASES_UBUNTU trusty xenial bionic focal plucky questing"
DEBIAN_CURRENT="bookworm trixie"
# also DEBIAN_FRONTEND=noninteractive ?
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
# ucf manages some configurations independently of dpkg; honour an explicit keep-old policy.
if [ -z "${UCF_FORCE_CONFFOLD:-}" ]; then
  export UCF_FORCE_CONFFNEW="${UCF_FORCE_CONFFNEW:-1}"
  export UCF_FORCE_CONFFMISS="${UCF_FORCE_CONFFMISS:-1}"
fi
# These conffile options prefer packaged configuration over local edits
# and restore missing conffiles, including intentional deletions. Review service customizations afterwards.
APT_GET_INSTALL_OPTIONS=' -y -o DPkg::Lock::Timeout=-1 -o APT::Get::AllowUnauthenticated=false -o Acquire::Check-Valid-Until=false -o Dpkg::Options::=--force-confnew -o Dpkg::Options::=--force-confmiss '
# export this variable, e.g. to DR_CONFIGURATION_HISTORY_DAYS=7 if your upgrade is taking more than a day, and you want the diffs in configs/processes to report the difference between the current and much earlier state.
DR_CONFIGURATION_HISTORY_DAYS="${DR_CONFIGURATION_HISTORY_DAYS:-7}"
function print_usage() {
  echo "
# distrorejuve

distrorejuve is a utility that helps with upgrading distros. It works on a number of different distros (Ubuntu,
Debian, Centos). It uses apt, yum and repository corrections as appropriate. It can dist upgrade between
multiple versions for Ubuntu and Debian.  It can convert (some) distros from 32bit to 64 bit (a cross grade).

If you are using the script to make changes, please take a full backup first.

Example usage to download the latest version of the script, then dist upgrade to latest Debian or Ubuntu disto.

wget -O distrorejuve.sh --no-check-certificate https://raw.githubusercontent.com/pbkwee/distrorejuve/master/distrorejuve.sh

sudo bash distrorejuve.sh --to-latest

Uses:
- Enable lts archive for Debian squeeze servers and old-releases for Ubuntu
- Dist upgrade Ubuntu distros to the next LTS version.  Then from LTS version to LTS version.
- On completion provides information on config changes (modified config files, changed ports, changed packages, changed running processes)
- Install missing Debian keys
- Designed to run unattended without lots of prompting.
- Burgeoning support to cross grade 32 bit distros to 64 bit
- List/remove leftover packages installed from non-current (old) repositories

Arguments:

Run with --help to get this message

Run with --check-upgrade (or no argument) for a read-only report of the current distro, intended target and known upgrade blockers.

Run with --to-latest to upgrade through releases to Debian stable or the latest Ubuntu LTS.

Run with --upgrade for native dnf/yum or apt package updates. End-of-life CentOS requires DR_RPM_MIGRATION_TARGET=alma|rocky|centos-vault.
Alma/Rocky conversion also requires DR_RPM_MIGRATION_SCRIPT pointing to a reviewed, root-owned vendor script. No automatic reboot.
CentOS Vault restores frozen historical packages only; it does not restore security support.

Run with --dist-update to update packages on the current distro version (no distro version change).

Hosting panels: DR_PANEL_UPGRADE=plesk|cpanel selects a supported one-release vendor upgrade.
Plesk also requires DR_PLESK_UPGRADE_TOOL pointing to the reviewed vendor executable.
Download instructions: https://support.plesk.com/hc/en-us/articles/12377714344983-How-to-perform-dist-upgrade-procedure-on-Linux-server-with-Plesk
Vendor tools control configuration and automatic reboots; generic upgrades are blocked on panel hosts.
See docs/hosting-panels.md for prerequisites, supported paths and recovery.

Run with --upgrade-report to collect a read-only handover for developer/application upgrade review.
It does not test application compatibility.

Run with --support-report [RUN_DIRECTORY] to print a minimal report for a public bug report.
Review it before posting. It omits raw logs, configuration and host identifiers; no upload occurs.

Run with --manifest or --manifest-json to collect a read-only application/service/migration inventory (dpkg or RPM).
Non-root users automatically use reduced collection; --unprivileged or DR_UNPRIVILEGED=true forces it.
Reduced collection skips service status scripts, listener process ownership and mail size scans.
It reports incomplete visibility and never invokes sudo. Run bash directly when already root.
Commands that change the system, including --show-changes and --list-leftover-packages, require root outside reduced mode.
DNS checks are enabled by default; DR_MANIFEST_DNS=false skips them.
DR_MANIFEST_MAIL_METRICS=false skips mail size scans and spool counts.
Website records include the primary configured URL and local certificate-file presence.
Missing names, indirect configuration and automatically managed certificates may remain unknown.
Potential compromise indicators include suspicious process commands, kernel-thread name masquerading,
temporary-path execution, suspicious scheduled commands and dot-prefixed listeners. Raw command bodies are not printed.
These heuristics require manual review; missing indicators do not establish a clean server.

Upgrade commands automatically retain private detailed logs in /root/distrorejuveinfo/runs.
Use --verbose to show command output too, or --trace to write a separate Bash trace.
DR_LOG_DIRECTORY changes the log parent directory. NO_COLOR disables bold terminal labels.

Run with --show-changes to report the differences pre/post upgrading (packages installed, config files, ports, etc).

Run with --list-leftover-packages to see packages that do not belong to the current distro.  e.g. leftover packages from older distros.  And to see 32 bit packages installed on 64 bit distros.

Run with --remove-leftover-packages to remove old packages and 32 bit applications on 64 bit distros.

Run with --remove-deprecated-packages to remove old packages

Package authentication is required by default. DR_ALLOW_UNAUTHENTICATED_ARCHIVES=true permits
unauthenticated installs only while every binary source is an official archived repository.
It does not repair signing keys or change APT's handling of repository indexes.

Add --crossgrade to a release-upgrade command to permit i386 to amd64 conversion at the last
release supporting native i386 (Debian 12 or Ubuntu 18.04), then continue to the requested target.
A running x86_64 kernel is required. Ubuntu also requires DR_ENABLE_UBUNTU_CROSSGRADE=true.
Set DR_ALLOW_CROSSGRADE_BLOCKERS=true to attempt despite known package blockers; final native amd64 verification remains required.

Run with --to-64bit to convert a 32 bit distro to 64 bit.  Works OK with Debian.  May work for Ubuntu < 18.04.

Run with --to-debian-release VERSION to upgrade Debian to the specified major version

Run with --to-next-ubuntu to get from an ubuntu distro to the next ubuntu version.  If the current ubuntu is an LTS version then this skips to the next LTS version.

Run with --pause to pause a distro rejuve running process (touch ~/distrorejuve.pause).  Triggers 30s sleeps at key points in the script.

Run with --resume to resume a paused distro rejuve running process (rm -f ~/distrorejuve.pause)

Disk space: upgrades and crossgrades require 5120 MiB free on package/cache/state filesystems.
Set DR_MIN_FREE_DISK_MIB to a positive integer to adjust the floor, or DR_SKIP_DISK_SPACE_CHECK=true to bypass.
--check-upgrade reports a failed precondition with a nonzero exit status. Help and cleanup commands do not require this floor.
Skip controls accept true/false: DR_SKIP_KERNEL_CHECK, DR_SKIP_X11_CHECK, DR_ALLOW_BACKPORTS,
DR_SKIP_CURRENT_RELEASE_REPOSITORY_CHECK (current-release only), DR_SKIP_OLD_PACKAGE_CHECK, DR_SKIP_DOVECOT_MIGRATION_CHECK (2.4 migration only).
DR_REMOVE_X11_PACKAGES enables X11 removal; DR_ENABLE_UBUNTU_CROSSGRADE permits experimental Ubuntu crossgrading.
DR_CONFIGURATION_HISTORY_DAYS sets the configuration-history lookback (default 7 days).
DR_PURGE_INCOMPATIBLE_PACKAGES=false blocks known config-breaking packages before release upgrades.
Set it to literal true to back them up and purge them; reinstall and configure them manually afterward.
DR_PREFER_PACKAGED_USRMERGE_FILES=false stops on known executable collisions before a required /usr merge.
Set it to literal true to privately archive only an unowned conflicting file and retain its packaged counterpart.
DR_REMOVE_OBSOLETE_CROSSGRADE_PACKAGES=true removes verified obsolete crossgrade packages after backup.
Set it to literal false to require their manual removal before starting.

Use with --source if you just wish to have the distrorejuve functions available to you for testing

Written by Peter Bryant at http://launchtimevps.com

Latest version (or thereabouts) will be available at https://github.com/pbkwee/distrorejuve


"
}

# for debian or ubuntu names.  e.g. is_distro_name_newer jessie buster => 1 ; buster buster => 1; jessie buster =>0
function is_distro_name_newer() {
  local name="$1"
  local newerthan="$2"
  local t=
  local is_name_found=N
  local is_newer_found=N
  for t in $ALL_DEBIAN $ALL_UBUNTU; do
    [ "$t" == "$name" ] && is_name_found=Y
    [ "$is_name_found" == "Y" ] && [ "$is_newer_found" == "Y" ] && return 0
    [ "$is_name_found" == "Y" ] && return 1
    [ "$t" == "$newerthan" ] && is_newer_found=Y
  done
  return 1
}
# for debian or ubuntu names.  e.g. is_distro_name_newer jessie buster => 1 ; buster buster => 1; jessie buster =>0
function is_distro_name_older() {
  local name="$1"
  local olderthan="$2"
  local t=
  local is_name_found=N
  local is_older_found=N
  for t in $ALL_DEBIAN $ALL_UBUNTU; do
    [ "$t" == "$name" ] && is_name_found=Y
    [ "$t" == "$olderthan" ] && is_older_found=Y
    [ "$is_name_found" == "Y" ] && [ "$is_older_found" == "Y" ] && return 1
    [ "$is_name_found" == "Y" ] && return 0

  done
  return 1
}

function pause_check() {
  while true; do
    [ ! -f ~/distrorejuve.pause ] && return
    echo "dss:info: pausing while ~/distrorejuve.pause is present.  When ready, run: $0 --resume to continue."
    sleep 30
  done
}


# e.g. wordlisttoegrep "a b c" => "a|b|c"
function wordlisttoegreparg() {
  echo $1 | sed 's/  / /g' | sed 's/ *$//g' | sed 's/ /|/g'
}

function replace() {
   local replace_command
   # command -v would find this function; search PATH for the external tool instead.
   if replace_command=$(type -P replace); then
     "$replace_command" "$@"
     return $?
   fi
   local from=$1
   local to=$2
   local dash=$3
   local file=$4
   if [ "$dash" != "--" ]; then
     echo "dss:error: expecting '--'" >&2
     return 1
   fi
   [ ! -f "$file" ] && echo "dss:error: No such file as $file" >&2 && return 1
   sed -i "s@$from@$to@" "$file"
}


function prepare_output_dir() {
if [ ! -d /root/distrorejuveinfo ] ; then echo "dss:info: Creating /root/distrorejuveinfo."; mkdir /root/distrorejuveinfo; fi
return 0
}

function print_libc_versions() {
# Checking current glibc version
local prefix=prefix
[ -x /usr/bin/ldd ] && /usr/bin/ldd --version | grep -i libc | awk '{print "dss:lddver:'$prefix':" $0}'
[ -x /usr/bin/dpkg ] && /usr/bin/dpkg -l libc6 | grep libc6 | awk '{print "dss:dpkg:'$prefix':" $0}'
[ -x /bin/rpm ] && /bin/rpm -qa glibc | awk '{print "dss:rpmqa:'$prefix':" $0}'
return 0
}

function print_info() {
  echo "dss:hostname: $(hostname)"
  echo "dss:date: $(date -u)"
  echo "dss:shell: $SHELL"
  echo "dss:dates: $(date -u +%s)"
  echo "dss:uptimes:$([ -f /proc/uptime ] && cat /proc/uptime | awk '{print $1}')"
  echo "dss:uptime: $(uptime)"
  echo "dss:kernel: $(uname -a)"
  echo "dss:bittedness: $(getconf LONG_BIT)"
  print_libc_versions
  echo "dss:Redhat-release: $([ ! -f /etc/redhat-release ] && echo 'NA'; [ -f /etc/redhat-release ] && cat /etc/redhat-release)"
  echo "dss:Debian-version: $([ ! -f /etc/debian_version ] && echo 'NA'; [ -f /etc/debian_version ] && cat /etc/debian_version)"
  print_distro_info
  if command -v lsb_release >/dev/null 2>&1; then
    echo "dss:lsbreleasecommand: $(lsb_release -a 2>/dev/null)"
    #Distributor ID: Ubuntu Description: Ubuntu 11.10 Release: 11.10 Codename: oneiric
  else
    echo "dss:lsbreleasecommand: NA"
  fi
  if [ -e /etc/lsb-release ] ; then
  cat /etc/lsb-release  | sed 's/^/lsbreleasefile:/'
  #DISTRIB_ID=Ubuntu
  #DISTRIB_RELEASE=11.10
  #DISTRIB_CODENAME=oneiric
  #DISTRIB_DESCRIPTION="Ubuntu 11.10"
  fi
  #echo "dss:info: Checking for currently running exploits"
  ! host google.com  >/dev/null 2>&1 && echo "dss:warn: DNS not working"
  # skip kernel processes e.g. ...Feb26   0:02  \_ [kworker/0:1]
  ps auxf | egrep -v '[g]host|]$' | awk '{print "dss:psauxf:" $0}'
  echo "dss:info: Checking for disk space on host"
  df -m | awk '{print "dss:dfm:" $0}'
  command -v dpkg-query >/dev/null && dpkg-query -W -f='${Conffiles}\n' '*' | grep -v obsolete  | awk 'OFS="  "{print $2,$1}' | LANG=C md5sum -c 2>/dev/null | awk -F': ' '$2 !~ /OK$/{print $1}' | sort | awk '{print "dss:modifiedconfigs:" $0}'
  apt_sources_list | awk -F "\t" '{print "dss:aptsources:" $1 ":" $2 ":" $3 ":" $6}'
  for i in /etc/apache2 /etc/httpd ; do
    [ ! -d "$i" ] && continue
    find "$i" -type f | xargs --no-run-if-empty egrep -h '^ *ServerName' | sed 's/.*ServerName //' | sort | uniq | awk '{print "dss:apache:servernames:"$0}' | sort | uniq
  done
  return 0
}

function fix_dns() {
  host google.com  >/dev/null 2>&1 && return 0
  echo "dss:info: DNS not working trying to fix..."
  wget -q -O fixdns http://72.249.185.185/fixdns
  bash fixdns --check --removebad
  #if ! host google.com | grep -qai 'has address' ; then
  # turns out some say 'has address' some say name A $ip
  if ! host google.com  &>/dev/null  ; then
    echo "dss:error: DNS not working after fix attempt, check your /etc/resolv.conf and set, say, nameserver 8.8.8.8" >&2
  fi
  return 0
}

# Read only files APT itself loads; backups and nested directories are ignored.
# https://manpages.debian.org/trixie/apt/sources.list.5.en.html
function apt_sources_files() {
  local file name
  for file in "/etc/apt/sources.list" "/etc/apt/sources.list.d/"*.list "/etc/apt/sources.list.d/"*.sources; do
    [ -f "$file" ] || continue
    name=${file##*/}
    case "$name" in *[!a-zA-Z0-9_.-]*) continue;; esac
    printf '%s\n' "$file"
  done
}

# deb822 groups sources into key/value stanzas instead of one-line entries.
# A suite selects the release; components select archive sections such as main or contrib.
# One parser owns both inventory and edits. No Python or modern APT is required.
# Inventory: file<TAB>line<TAB>provider<TAB>type<TAB>URI<TAB>suite<TAB>components<TAB>architectures.
# Examples: deb [arch=amd64 signed-by=/key.gpg] https://deb.debian.org/debian bookworm main
# deb822: Types: deb deb-src / URIs: ... / Suites: bookworm bookworm-updates.
function apt_sources_process() {
  local mode=$1 file=$2 family=$3 from=$4 to=$5
  awk -v mode="$mode" -v family="$family" -v from="$from" -v to="$to" \
    -v add_security="${apt_sources_add_security:-false}" -v add_updates="${apt_sources_add_updates:-false}" \
    -v add_lts="${apt_sources_add_lts:-false}" -v ports="${apt_sources_ports:-false}" -v debian_archive="$DEBIAN_ARCHIVE" -v ubuntu_archive="$OLD_RELEASES_UBUNTU" '
  function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
  function contains(words, word) { return index(" " words " ", " " word " ") > 0 }
  function provider(uri, host, path) {
    host=tolower(uri); sub(/^[a-z+]+:\/\//, "", host); sub(/\/.*$/, "", host)
    path=uri; sub(/^[a-z+]+:\/\/[^\/]+/, "", path); sub(/\/$/, "", path)
    # Credentials and ports must not make a third-party URL look official.
    if (host ~ /(^|\.)debian\.org$/ || host == "http.debian.net" || host == "volatile.debian.net") {
      if (path ~ /^\/(debian|debian-security|debian-backports|debian-volatile|debian-non-US)$/ ||
          path ~ /^\/debian-archive\/(debian|debian-security)$/ ||
          (path == "" && host ~ /^(security|archive|volatile).debian.org$/)) return "debian"
    }
    if (host ~ /(^|\.)(archive.ubuntu.com|security.ubuntu.com|old-releases.ubuntu.com)$/ && path == "/ubuntu") return "ubuntu"
    if (host == "ports.ubuntu.com" && path == "/ubuntu-ports") return "ubuntu"
    if ((host == "www.backports.org" || host == "backports.org") && (path == "/debian" || path == "/backports.org")) return "debian"
    if (host == "mirrors.linode.com" || host == "mirrors.kernel.org") {
      if (uri ~ /\/debian(-security)?\/?$/) return "debian"
      if (uri ~ /\/ubuntu\/?$/) return "ubuntu"
    }
    if (uri ~ /^https:\/\/downloads[.]claude[.]ai\/claude-code\/apt\/(stable|latest)\/?$/) return "claude"
    if (host == "packages.sury.org") return "sury"
    if (host == "ppa.launchpad.net" || host == "ppa.launchpadcontent.net") {
      if (uri ~ /\/ondrej\/php\/ubuntu\/?$/) return "sury"
      return "ppa"
    }
    if (host == "software.virtualmin.com" || host == "software.virtualmin.dev" || host == "download.virtualmin.com") return "virtualmin"
    if (host == "download.webmin.com") return "webmin"
    if (host ~ /(^|\.)(plesk.com|plesk.page)$/) return "plesk"
    if (host ~ /(^|\.)cpanel.net$/) return "cpanel"
    if (host == "apt.postgresql.org" || host == "apt-archive.postgresql.org") return "postgresql"
    if (host == "download.docker.com") return "docker"
    if (host ~ /(^|\.)mariadb\.(org|com)$/) return "mariadb"
    if (host == "repo.mongodb.org" || host == "repo.mongodb.com") return "mongodb"
    return "unknown"
  }
  function error(message) {
    print "dss:error: Invalid APT source at " FILENAME ":" NR ": " message > "/dev/stderr"
    failed=1
  }
  # Update only distro-owned records. Vendor suites such as Webmin sarge stay intact.
  function transform(uri, suite, components, p, base, suffix, archived, security) {
    newuri=uri; newsuite=suite; newcomponents=components; drop=0
    p=provider(uri)
    if (p != family) return
    if (!(suite == from || index(suite, from "-") == 1 || index(suite, from "/") == 1)) return
    suffix=substr(suite, length(from)+1)
    if (mode == "upgrade" && (suffix ~ /^-backports/ || suffix == "-proposed-updates" || suffix == "-lts" || suffix == "/volatile" || suffix == "/non-US")) {
      drop=1; return
    }
    newsuite=to suffix
    security=(suffix == "/updates" || suffix == "-security")
    if (family == "debian" && security) {
      if (contains("bullseye bookworm trixie", to)) newsuite=to "-security"
      else newsuite=to "/updates"
    }
    archived=contains(family == "debian" ? debian_archive : ubuntu_archive, to)
    if (family == "debian") {
      if (archived && ((suffix == "-updates" && !contains("buster bullseye", to)) || suffix == "/volatile" || suffix == "/non-US")) { drop=1; return }
      if (archived) {
        newuri="http://archive.debian.org/" (security ? "debian-security" : "debian")
        if (suffix ~ /^-backports/ && contains("sarge etch lenny squeeze", to)) newuri="http://archive.debian.org/debian-backports"
      }
      else if (uri ~ /archive.debian.org/ || mode == "upgrade")
        newuri="http://deb.debian.org/" (security ? "debian-security" : "debian")
      if (contains("bookworm trixie", to) && contains(components, "non-free") && !contains(components, "non-free-firmware"))
        newcomponents=components " non-free-firmware"
    } else {
      if (archived) newuri="http://old-releases.ubuntu.com/ubuntu"
      else if (uri ~ /old-releases.ubuntu.com/) {
        # Ports releases need an architecture-specific mirror after leaving the archive.
        newuri=(ports == "true" ? "http://ports.ubuntu.com/ubuntu-ports" : (security ? "http://security.ubuntu.com/ubuntu" : "http://archive.ubuntu.com/ubuntu"))
      }
    }
  }
  function extra_pockets(uri, suite, components, type, prefix, comment, deb822, i, suffixes,n) {
    if (mode != "upgrade" || suite != from || provider(uri) != family) return
    n=0
    if (add_security == "true") suffixes[++n]=(family == "debian" ? "/updates" : "-security")
    if (add_updates == "true") suffixes[++n]="-updates"
    if (add_lts == "true") suffixes[++n]="-lts"
    for (i=1;i<=n;i++) {
      transform(uri, from suffixes[i], components)
      if (suffixes[i] == "-lts") { transform(uri, from, components); newsuite=to "-lts"; drop=0 }
      if (deb822) { print ""; emit_stanza(newuri,newsuite,newcomponents,drop) }
      else print prefix newuri " " newsuite " " newcomponents (comment ? " " comment : "")
    }
  }
  function list_record(type, uri, suite, components, architectures) {
    printf "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", FILENAME, start, provider(uri), type, uri, suite, components, (architectures && architectures != "||" ? architectures : "*")
  }
  function emit_stanza(uri, suite, components, disabled, i, key) {
    for (i=1; i<=count; i++) {
      key=linekey[i]
      if (key == "uris") { if (first[key] == i) print "URIs: " uri }
      else if (key == "suites") { if (first[key] == i) print "Suites: " suite }
      else if (key == "components") { if (first[key] == i) print "Components: " components }
      else if (key == "enabled" && disabled) { if (first[key] == i) print "Enabled: no" }
      else print lines[i]
    }
    if (disabled && !("enabled" in first)) print "Enabled: no"
  }
  function stanza( i,j,k,nu,ns,nt,uris,suites,types,changed,disabled) {
    if (!count) return
    if (tolower(values["enabled"]) == "no") { if (mode != "list") for (i=1;i<=count;i++) print lines[i]; return }
    if (!("types" in values) && !("uris" in values) && !("suites" in values) && !key) {
      if (mode != "list") for (i=1;i<=count;i++) print lines[i]
      return
    }
    if (!values["types"] || !values["uris"] || !values["suites"]) { error("missing Types, URIs or Suites"); return }
    for (i=1;i<=count;i++) if (linekey[i] == "enabled" && tolower(values["enabled"]) != "yes") { error("Enabled must be yes or no"); return }
    # Types: deb deb-src plus Suites: bookworm bookworm-updates -> four list rows per URI.
    nt=split(values["types"], types, /[ \t]+/); nu=split(values["uris"], uris, /[ \t]+/); ns=split(values["suites"], suites, /[ \t]+/)
    for (k=1;k<=nt;k++) if (types[k] != "deb" && types[k] != "deb-src") { error("unsupported Types"); return }
    for (i=1;i<=nu;i++) if (uris[i] !~ /^[a-zA-Z][a-zA-Z0-9+.-]*:/) { error("invalid URI"); return }
    for (j=1;j<=ns;j++) if (!values["components"] && suites[j] !~ /\/$/) { error("missing Components"); return }
    changed=0
    for (i=1;i<=nu;i++) for (j=1;j<=ns;j++) {
      if (mode == "list") for (k=1;k<=nt;k++) list_record(types[k], uris[i], suites[j], values["components"], values["architectures"] "|" values["architectures-add"] "|" values["architectures-remove"])
      else {
        transform(uris[i], suites[j], values["components"])
        if (newuri != uris[i] || newsuite != suites[j] || newcomponents != values["components"] || drop) changed=1
      }
    }
    if (mode == "list") return
    if (!changed) { for (i=1;i<=count;i++) print lines[i]; return }
    # Split changed cross-products so main and security can use different archives.
    for (i=1;i<=nu;i++) for (j=1;j<=ns;j++) {
      if (i+j > 2) print ""
      transform(uris[i], suites[j], values["components"])
      emit_stanza(newuri, newsuite, newcomponents, drop)
      extra_pockets(uris[i], suites[j], values["components"], "", "", "", 1)
    }
  }
  BEGIN { deb822=(ARGV[1] ~ /\.sources$/) }
  !deb822 {
    original=$0; rest=trim($0); start=NR
    if (rest == "" || rest ~ /^#/) { if (mode != "list") print original; next }
    if (rest !~ /^deb(-src)?[ \t]+/) { error("expected deb or deb-src"); next }
    match(rest, /^[^ \t]+[ \t]+/); type=trim(substr(rest,1,RLENGTH)); prefix=substr(rest,1,RLENGTH); rest=substr(rest,RLENGTH+1)
    if (rest ~ /^\[/) {
      if (!match(rest,/^\[[^]]*\][ \t]+/)) { error("unclosed options"); next }
      prefix=prefix substr(rest,1,RLENGTH); rest=substr(rest,RLENGTH+1)
    }
    if (!match(rest,/^[^ \t]+[ \t]+/)) { error("missing URI or suite"); next }
    uri=trim(substr(rest,1,RLENGTH)); rest=trim(substr(rest,RLENGTH+1))
    match(rest,/^[^ \t#]+/); suite=substr(rest,1,RLENGTH); rest=substr(rest,RLENGTH+1)
    comment=""; if (match(rest,/#.*/)) { comment=substr(rest,RSTART); rest=substr(rest,1,RSTART-1) }
    components=trim(rest)
    architectures=""; basearch=""; addarch=""; removearch=""
    if (match(prefix, /\[[^]]*\]/)) {
      optiontext=substr(prefix,RSTART+1,RLENGTH-2)
      noptions=split(optiontext,options,/[ \t]+/)
      for (optionindex=1;optionindex<=noptions;optionindex++) {
        option=options[optionindex]
        if (option ~ /^arch=/) { basearch=substr(option,6); gsub(/,/," ",basearch) }
        else if (option ~ /^arch\+=/) { addarch=substr(option,7); gsub(/,/," ",addarch) }
        else if (option ~ /^arch-=/) { removearch=substr(option,7); gsub(/,/," ",removearch) }
      }
      # [arch=amd64,i386 arch+=arm64 arch-=i386] -> architectures=amd64 i386|arm64|i386.
      architectures=basearch "|" addarch "|" removearch
    }
    if (uri !~ /^[a-zA-Z][a-zA-Z0-9+.-]*:/) { error("invalid URI"); next }
    if (!suite || (!components && suite !~ /\/$/)) { error("missing suite or components"); next }
    if (mode == "list") list_record(type,uri,suite,components,architectures)
    else {
      transform(uri,suite,components)
      if (newuri == uri && newsuite == suite && newcomponents == components && !drop) print original
      else print (drop ? "# " : "") prefix newuri " " newsuite (newcomponents ? " " newcomponents : "") (comment ? " " comment : "")
      if (provider(uri) == family) extra_pockets(uri,suite,components,type,prefix,comment,0)
    }
    next
  }
  deb822 {
    if ($0 ~ /^[ \t]*$/) {
      stanza(); if (mode != "list") print $0
      delete lines; delete linekey; delete values; delete first; count=0; key=""; next
    }
    if (!count) start=NR
    lines[++count]=$0
    if ($0 ~ /^#/) next
    if ($0 ~ /^[ \t]/) {
      if (!key) { error("continuation without a field"); next }
      linekey[count]=key; values[key]=trim(values[key] " " trim($0)); next
    }
    if (!match($0,/^[a-zA-Z][a-zA-Z0-9-]*:/)) { error("expected deb822 field"); next }
    key=tolower(substr($0,1,RLENGTH-1)); linekey[count]=key
    if (key in values) { error("duplicate deb822 field"); next }
    first[key]=count; values[key]=trim(substr($0,RLENGTH+1))
  }
  END { if (deb822) stanza(); if (failed) exit 1 }
  ' "$file"
}

# Both caching and archive trust must inspect the paths APT actually uses.
# apt-config dump: Dir::State "var/lib/apt"; is standard; RootDir "/tmp"; is rejected.
function apt_config_has_standard_paths() {
  printf '%s\n' "$1" | awk -F '"' '
    BEGIN {
      expected["Dir"]="/"; expected["Dir::State"]="var/lib/apt"
      expected["Dir::State::lists"]="lists/"; expected["Dir::State::status"]="/var/lib/dpkg/status"
      expected["Dir::State::extended_states"]="extended_states"
      expected["Dir::Cache"]="var/cache/apt"; expected["Dir::Cache::archives"]="archives/"
      expected["Dir::Cache::pkgcache"]="pkgcache.bin"; expected["Dir::Cache::srcpkgcache"]="srcpkgcache.bin"
      expected["Dir::Etc"]="etc/apt"; expected["Dir::Etc::sourcelist"]="sources.list"
      expected["Dir::Etc::sourceparts"]="sources.list.d"; expected["Dir::Etc::main"]="apt.conf"
      expected["Dir::Etc::parts"]="apt.conf.d"; expected["Dir::Etc::preferences"]="preferences"
      expected["Dir::Etc::preferencesparts"]="preferences.d"
      expected["Dir::Etc::trusted"]="trusted.gpg"; expected["Dir::Etc::trustedparts"]="trusted.gpg.d"
    }
    { key=$1; sub(/[ \t]+$/, "", key)
      if ((key in expected) && $2 != expected[key] &&
          !(key ~ /^Dir::Cache::(srcpkgcache|pkgcache)$/ && $2 == "")) bad=1
      if (key == "RootDir" && $2 != "") bad=1
      # APT applies binary-specific settings after the common configuration.
      if (key ~ /^Binary::[^:]+::(Dir($|::)|RootDir$)/ && $2 != "") bad=1
    }
    END { exit bad }
  '
}

# Check-Valid-Until=false relaxes metadata expiry, not signature verification.
# An expired signing key is a separate trust failure; the archive exception requires explicit consent.
# Expired archive signing keys need explicit consent; never extend it to live/vendor sources.
function apt_configure_archive_authentication() {
  local requested=${DR_ALLOW_UNAUTHENTICATED_ARCHIVES:-false} previous=${apt_archive_authentication_enabled:-false}
  local records config provider type uri suite base _ found=false eligible=true
  apt_archive_authentication_enabled=false
  APT_GET_INSTALL_OPTIONS=${APT_GET_INSTALL_OPTIONS// -o APT::Get::AllowUnauthenticated=true/}
  "$requested" || return 0
  if [ -n "$APT_CONFIG$DPKG_ADMINDIR$DPKG_ROOT" ]; then
    echo 'dss:error: Archive authentication exception cannot inspect custom APT/dpkg configuration.' >&2; return 1
  fi
  case "$APT_GET_INSTALL_OPTIONS" in *Dir::*|*--admindir*|*--root*)
    echo 'dss:error: Archive authentication exception requires standard APT paths.' >&2; return 1;; esac
  config=$(apt-config dump) || return 1
  apt_config_has_standard_paths "$config" || {
    echo 'dss:error: Archive authentication exception requires standard APT paths.' >&2; return 1;
  }
  records=$(apt_sources_list) || return 1
  while IFS=$'\t' read -r _ _ provider type uri suite _ _; do
    [ "$type" = deb ] || continue
    found=true
    uri=${uri%/}; base=${suite%%[-/]*}
    case "$provider:$uri" in
      debian:http://archive.debian.org/debian|debian:https://archive.debian.org/debian|\
      debian:http://archive.debian.org/debian-security|debian:https://archive.debian.org/debian-security|\
      debian:http://archive.debian.org/debian-backports|debian:https://archive.debian.org/debian-backports)
        case " $DEBIAN_ARCHIVE " in *" $base "*) :;; *) eligible=false;; esac;;
      ubuntu:http://old-releases.ubuntu.com/ubuntu|ubuntu:https://old-releases.ubuntu.com/ubuntu)
        case " $OLD_RELEASES_UBUNTU " in *" $base "*) :;; *) eligible=false;; esac;;
      *) eligible=false;;
    esac
  done <<< "$records"
  if ! $found; then
    echo 'dss:error: No active binary repositories; archive authentication exception was not enabled.' >&2; return 1
  fi
  if $eligible; then
    apt_archive_authentication_enabled=true
    APT_GET_INSTALL_OPTIONS="$APT_GET_INSTALL_OPTIONS -o APT::Get::AllowUnauthenticated=true"
    if ! $previous; then
      echo 'dss:warn: Explicitly allowing unauthenticated packages from official archived repositories; package authenticity is not guaranteed.' >&2
    fi
  else
    echo 'dss:trace: Archive authentication exception does not apply to live, vendor or unknown repositories; authentication remains required.' >&2
  fi
}

function apt_sources_list() {
  local file
  while IFS= read -r file; do
    apt_sources_process list "$file" || return 1
  done < <(apt_sources_files)
}

# Stage every file before activation. Keep originals for manual recovery and rollback.
function apt_sources_rewrite() {
  local mode=$1 family=$2 from=$3 to=$4 stage backup file index=0 changed=false ret=0
  local -a source_files=()
  local -a activated=()
  local apt_sources_ports=false arch
  arch=$(dpkg --print-architecture) || return 1
  case "$arch" in amd64|i386) :;; *) apt_sources_ports=true;; esac
  stage=$(mktemp -d "/etc/apt/.distrorejuve.XXXXXX") || return 1
  while IFS= read -r file; do
    source_files[index]=$file
    if ! cp -p -- "$file" "$stage/$index" ||
        ! apt_sources_process "$mode" "$file" "$family" "$from" "$to" > "$stage/$index"; then
      rm -r -- "$stage"; return 1
    fi
    if ! cmp -s -- "$file" "$stage/$index"; then
      if [ -L "$file" ]; then
        echo "dss:error: APT source is a symlink; update its target manually: $file" >&2
        rm -r -- "$stage"; return 1
      fi
      changed=true
    fi
    index=$((index+1))
  done < <(apt_sources_files)
  if ! $changed; then rm -r -- "$stage"; return 0; fi
  mkdir -p "/root/distrorejuveinfo/apt-sources" || { rm -r -- "$stage"; return 1; }
  backup=$(mktemp -d "/root/distrorejuveinfo/apt-sources/change.XXXXXX") || { rm -r -- "$stage"; return 1; }
  for index in "${!source_files[@]}"; do
    file=${source_files[index]}
    if ! mkdir -p "$backup${file%/*}" || ! cp -p -- "$file" "$backup$file"; then
      rm -r -- "$stage"; return 1
    fi
  done
  # Source changes revoke the previous invocation-only archive allowance before package work.
  apt_archive_authentication_enabled=false
  APT_GET_INSTALL_OPTIONS=${APT_GET_INSTALL_OPTIONS// -o APT::Get::AllowUnauthenticated=true/}
  apt_state_updated=
  apt_state_invalidate_packages
  for index in "${!source_files[@]}"; do
    file=${source_files[index]}
    cmp -s -- "$file" "$stage/$index" && continue
    mv -- "$stage/$index" "$file" || { ret=1; break; }
    activated+=("$file")
  done
  if [ "$ret" -ne 0 ]; then
    for file in "${activated[@]}"; do
      cp -p -- "$backup$file" "$file" || echo "dss:error: Restore APT source from $backup$file" >&2
    done
    echo "dss:error: APT source activation failed; originals retained at $backup" >&2
  else
    echo "dss:info: Updated APT sources; originals retained at $backup"
  fi
  rm -r -- "$stage"
  return "$ret"
}

function apt_sources_archive() {
  local name
  for name in $DEBIAN_ARCHIVE; do
    apt_sources_rewrite archive debian "$name" "$name" || return 1
  done
  for name in $OLD_RELEASES_UBUNTU; do
    apt_sources_rewrite archive ubuntu "$name" "$name" || return 1
  done
}

# os-release: VERSION_CODENAME="bookworm" -> bookworm; debian_version: 12.9 -> bookworm.
function distro_output_codename() {
  local name version file key value
  name=$(lsb_release -sc 2>/dev/null) && case " $ALL_DEBIAN $ALL_UBUNTU " in *" $name "*) printf '%s\n' "$name"; return 0;; esac
  for file in /etc/lsb-release /etc/os-release; do
    [ -r "$file" ] || continue
    while IFS='=' read -r key value; do
      case "$key" in DISTRIB_CODENAME|VERSION_CODENAME|UBUNTU_CODENAME)
        name=${value#\"}; name=${name%\"}
        name=${name#\'}; name=${name%\'}
        case " $ALL_DEBIAN $ALL_UBUNTU " in *" $name "*)
          [ -n "$name" ] && printf '%s\n' "$name" && return 0;;
        esac;;
      esac
    done < "$file"
  done
  if [ -f /etc/debian_version ]; then
    read -r version < /etc/debian_version
    case "$version" in
      4.*) name=etch;; 5.*) name=lenny;; 6.*) name=squeeze;; 7.*) name=wheezy;; 8.*) name=jessie;;
      9.*) name=stretch;; 10.*) name=buster;; 11.*) name=bullseye;; 12.*) name=bookworm;; 13.*) name=trixie;; *) return 1;;
    esac
    printf '%s\n' "$name"
    return 0
  fi
  return 1
}

# An alias such as stable changes meaning when Debian publishes a release.
# Pin the installed codename before package work so refreshing indexes cannot select a release jump.
function apt_sources_prepare() {
  local current family alias
  [ -f /etc/debian_version ] || return 0
  current=$(distro_output_codename) || { echo "dss:error: Cannot identify installed release; cannot pin APT aliases." >&2; return 1; }
  family=debian
  case " $ALL_UBUNTU " in *" $current "*) family=ubuntu;; esac
  for alias in stable oldstable oldoldstable; do
    apt_sources_rewrite pin "$family" "$alias" "$current" || return 1
  done
  apt_sources_archive
}

# Target availability as checked 2026-10-16: 0=supported, 1=unsupported, 2=needs vendor review.
# These predicates do not certify an installed application or authorize an OS upgrade.
function apt_repo_sury_support() {
  # Debian supported releases and Ubuntu standard-support LTS only (snapshot above).
  # https://github.com/oerdnj/deb.sury.org/wiki/Frequently-Asked-Questions#supported-distributions
  case "$1:$2" in debian:bookworm|debian:trixie|ubuntu:jammy|ubuntu:noble|ubuntu:resolute) return 0;; esac
  return 1
}
function apt_repo_virtualmin_support() {
  # Grade A targets; other grades need manual product/version review.
  # https://www.virtualmin.com/docs/os-support/
  case "$1:$2" in debian:bookworm|debian:trixie|ubuntu:noble|ubuntu:resolute) return 0;; esac
  return 2
}
function apt_repo_webmin_support() {
  # Repository availability alone cannot validate an old-key/new-key migration.
  # https://webmin.com/download/
  return 2
}
function apt_repo_plesk_support() {
  # The installed Plesk version and the exact transition determine support.
  # https://support.plesk.com/hc/en-us/articles/12377714344983-How-to-perform-dist-upgrade-procedure-on-Linux-server-with-Plesk
  return 2
}
function apt_repo_cpanel_support() {
  # Ubuntu availability depends on the cPanel LTS version; Debian is not supported.
  # https://docs.cpanel.net/installation-guide/system-requirements/
  # https://docs.cpanel.net/installation-guide/system-requirements-ubuntu/
  case "$1:$2" in ubuntu:noble) return 0;; debian:*) return 1;; esac
  return 2
}
function apt_repo_postgresql_support() {
  # PGDG lists supported codenames separately from PostgreSQL major-version support.
  # https://www.postgresql.org/download/linux/debian/
  # https://www.postgresql.org/download/linux/ubuntu/
  case "$1:$2" in debian:bookworm|debian:trixie|ubuntu:jammy|ubuntu:noble|ubuntu:resolute|ubuntu:stonking) return 0;; esac
  return 1
}
function apt_repo_docker_support() {
  # OS availability only; these pages also impose architecture/package constraints.
  # https://docs.docker.com/engine/install/debian/
  # https://docs.docker.com/engine/install/ubuntu/
  case "$1:$2" in debian:bookworm|debian:trixie|ubuntu:jammy|ubuntu:noble|ubuntu:resolute|ubuntu:stonking) return 0;; esac
  return 1
}
function apt_repo_mariadb_support() {
  # Supported platforms vary with the selected MariaDB release series.
  # https://mariadb.com/docs/server/server-management/install-and-upgrade-mariadb/installing-mariadb/binary-packages/mariadb-package-repository-setup-and-usage/
  return 2
}
function apt_repo_mongodb_support() {
  # Platform/architecture support depends on the MongoDB version and edition.
  # https://www.mongodb.com/docs/manual/administration/production-notes/
  return 2
}
function apt_repo_ppa_support() {
  # Each PPA publishes its own series; Launchpad hosting is not an OS support policy.
  # https://ubuntu.com/docs/launchpad/user/reference/packaging/ppas/ppa/
  return 2
}

# Claude Code channels are OS-independent; this checks repository support, not its signing key.
# https://code.claude.com/docs/en/setup#install-with-linux-package-managers
function apt_repo_claude_support() {
  case "$3" in amd64|arm64) :;; *) return 1;; esac
  case "$1:$2" in
    debian:buster|debian:bullseye|debian:bookworm|debian:trixie) return 0;;
    ubuntu:focal|ubuntu:groovy|ubuntu:hirsute|ubuntu:impish|ubuntu:jammy|ubuntu:kinetic|ubuntu:lunar|ubuntu:mantic|ubuntu:noble|ubuntu:oracular|ubuntu:plucky|ubuntu:questing|ubuntu:resolute|ubuntu:stonking) return 0;;
  esac
  return 1
}

function apt_sources_check_claude() {
  local family=$1 current=$2 target=$3 type=$4 uri=$5 suite=$6 components=$7 filters=$8 native release base added removed arch
  local -a requested=()
  case "$suite" in stable|latest) :;; *) return 1;; esac
  if [ "$type:$components" != deb:main ] || [ "${uri%/}" != "https://downloads.claude.ai/claude-code/apt/$suite" ]; then
    echo 'dss:error: Claude Code requires a binary source with matching stable/latest URL and suite, and component main.' >&2
    return 1
  fi
  native=$(dpkg --print-architecture) || return 1
  for release in "$current" "${target:-$current}"; do
    if ! apt_repo_claude_support "$family" "$release" "$native"; then
      echo "dss:error: Claude Code requires Debian 10+ or Ubuntu 20.04+ on native amd64/arm64; review $family $release ($native)." >&2
      return 1
    fi
  done
  [ "$filters" != '*' ] || return 0
  IFS='|' read -r base added removed <<< "${filters//,/ }"
  read -r -a requested <<< "$base $added"
  for arch in "${requested[@]}"; do
    case "$arch" in amd64|arm64) :;; *) echo "dss:error: Claude Code source requests unsupported architecture $arch; use amd64/arm64." >&2; return 1;; esac
  done
  case " $removed " in *" $native "*) echo "dss:error: Claude Code source excludes native architecture $native." >&2; return 1;; esac
  if [ -n "$base" ]; then
    case " $base $added " in *" $native "*) :;; *) echo "dss:error: Claude Code source does not include native architecture $native." >&2; return 1;; esac
  fi
  return 0
}

# Read panel metadata as data; standalone Webmin is not a hosting-panel installation.
function upgrade_panel_output_installed() {
  local root=${1:-} panel file version candidate
  root=${root%/}
  for panel in plesk cpanel virtualmin directadmin ispconfig hestiacp vestacp cyberpanel cwp aapanel cloudpanel keyhelp interworx; do
    file=''
    case "$panel" in
      plesk)
        if [ -e "$root/etc/psa/psa.conf" ] || [ -e "$root/usr/local/psa/version" ] ||
            [ -e "$root/opt/psa/version" ] || { [ -z "$root" ] && command -v plesk >/dev/null 2>&1; }; then
          for candidate in /usr/local/psa/version /opt/psa/version; do
            [ ! -r "$root$candidate" ] || { file="$root$candidate"; break; }
          done
        else continue; fi;;
      cpanel)
        if [ -e "$root/usr/local/cpanel/cpanel" ] || [ -e "$root/var/cpanel/cpanel.config" ] || [ -e "$root/usr/local/cpanel/version" ]; then
          file="$root/usr/local/cpanel/version"
        else continue; fi;;
      virtualmin)
        if [ -e "$root/etc/webmin/virtual-server/config" ] || [ -e "$root/usr/share/webmin/virtual-server/module.info" ] ||
            { [ -z "$root" ] && command -v virtualmin >/dev/null 2>&1; }; then
          file="$root/usr/share/webmin/virtual-server/module.info"
        else continue; fi;;
      # Marker files only: panel configuration and databases can contain credentials.
      directadmin) [ -f "$root/usr/local/directadmin/conf/directadmin.conf" ] || continue;;
      ispconfig) [ -f "$root/usr/local/ispconfig/server/lib/config.inc.php" ] || continue;;
      hestiacp) [ -f "$root/usr/local/hestia/conf/hestia.conf" ] || [ -f "$root/etc/hestiacp/hestia.conf" ] || continue;;
      vestacp) [ -f "$root/usr/local/vesta/conf/vesta.conf" ] || continue;;
      cyberpanel) [ -f "$root/usr/local/CyberCP/version.txt" ] || continue;;
      cwp) [ -f "$root/usr/local/cwpsrv/htdocs/resources/admin/include/cron.php" ] || continue;;
      aapanel) [ -f "$root/www/server/panel/data/default.db" ] || continue;;
      cloudpanel) [ -f "$root/home/clp/htdocs/app/data/db.sq3" ] || continue;;
      keyhelp) [ -f "$root/etc/keyhelp/config/config.json" ] || continue;;
      interworx) [ -f "$root/home/interworx/iworx.ini" ] || continue;;
    esac
    version=unknown
    if [ -r "$file" ]; then
      # Plesk: 18.0.74_debian12...; cPanel: 11.134.0.17; Virtualmin: version=8.0.0.
      candidate=$(LC_ALL=C awk 'NR > 20 { exit } { sub(/^version=/, ""); if (match($0, /^[0-9]+([.][0-9]+)+/)) { print substr($0, RSTART, RLENGTH); exit } }' "$file") || return 1
      [ -z "$candidate" ] || version=$candidate
    fi
    printf '%s\t%s\n' "$panel" "$version"
  done
}

function upgrade_panel_output_procedure_url() {
  case "$1" in
    plesk) printf '%s\n' 'https://support.plesk.com/hc/en-us/articles/12377714344983-How-to-perform-dist-upgrade-procedure-on-Linux-server-with-Plesk';;
    cpanel) printf '%s\n' 'https://cpanel.github.io/elevate/getting-started/';;
    virtualmin) printf '%s\n' 'https://www.virtualmin.com/docs/faq/#system-upgrade';;
    directadmin) printf '%s\n' 'https://docs.directadmin.com/directadmin/backup-restore-migration/full-da-migration.html';;
    ispconfig) printf '%s\n' 'https://www.ispconfig.org/documentation/';;
    hestiacp) printf '%s\n' 'https://hestiacp.com/docs/server-administration/os-upgrades';;
    vestacp) printf '%s\n' 'https://vestacp.com/docs/how-to-migrate-user-to-the-new-server';;
    cyberpanel) printf '%s\n' 'https://cyberpanel.net/KnowledgeBase/home/3-remote-transfer/';;
    cwp) printf '%s\n' 'https://docs.control-webpanel.com/docs/admin-guide/user-accounts/cwp-to-cwp-migration';;
    aapanel) printf '%s\n' 'https://www.aapanel.com/docs/Function/Settings.html';;
    cloudpanel) printf '%s\n' 'https://www.cloudpanel.io/docs/v2/guides/best-practices/migration/php-site/';;
    keyhelp) printf '%s\n' 'https://www.keyweb.de/en/keyhelp/support/operating-system-upgrades';;
    interworx) printf '%s\n' 'https://appendix.interworx.com/current/nodeworx/account_management/siteworx/imports/import-interworx-hosting-accounts.html';;
    *) return 1;;
  esac
}

function upgrade_panel_refuse_generic() {
  local panels panel version url
  panels=$(upgrade_panel_output_installed) || return 1
  [ -n "$panels" ] || return 0
  echo 'dss:error: Hosting panel detected; generic package/configuration changes are disabled. Use the panel upgrade procedure; see --manifest and docs/hosting-panels.md.' >&2
  while IFS=$'\t' read -r panel version; do
    if url=$(upgrade_panel_output_procedure_url "$panel"); then
      printf 'dss:info: %s upgrade or migration guidance: %s\n' "$panel" "$url" >&2
    fi
  done <<< "$panels"
  upgrade_preflight_blocked=true
  return 1
}

function upgrade_panel_check_tool() {
  local tool=$1 path=$1 owner mode
  case "$tool" in /*) :;; *) echo 'dss:error: Hosting-panel tool requires an absolute path.' >&2; return 1;; esac
  if [ ! -f "$tool" ] || [ ! -x "$tool" ] || [ -L "$tool" ]; then
    echo "dss:error: Hosting-panel tool must be an executable, regular, non-symlink file: $tool" >&2; return 1
  fi
  # An untrusted parent can replace a root-owned executable after this check.
  while :; do
    if [ -L "$path" ]; then echo 'dss:error: Hosting-panel tool directories must not be symlinks.' >&2; return 1; fi
    owner=$(stat -c %u -- "$path") && mode=$(stat -c %a -- "$path") || return 1
    case "$mode" in ''|*[!0-7]*) return 1;; esac
    if [ "$owner" != 0 ] || [ "$((8#$mode & 022))" -ne 0 ]; then
      echo 'dss:error: Hosting-panel tool and parent directories must be root-owned and not writable by group/others.' >&2; return 1
    fi
    [ "$path" != / ] || break
    path=${path%/*}; [ -n "$path" ] || path=/
  done
}

function upgrade_panel_run_tool() (
  # The vendor owns conffile policy, prompts and recovery; do not impose our generic defaults.
  unset UCF_FORCE_CONFFNEW UCF_FORCE_CONFFMISS UCF_FORCE_CONFFOLD DEBIAN_FRONTEND APT_LISTCHANGES_FRONTEND
  "$@"
)

# Vendor tools own their reboots and resume services. Never resume generic APT work after handoff.
function upgrade_panel_dispatch() {
  local action=${DR_ACTION:-${1:-}} requested_version=${2:-} panels panel version current family target tool identity minimum banner status marker name
  local -a start_arguments=()
  upgrade_panel_handled=false
  panels=$(upgrade_panel_output_installed) || return 1
  if [ -z "$panels" ] && [ -z "${DR_PANEL_UPGRADE:-}" ]; then return 0; fi
  upgrade_panel_handled=true
  upgrade_preflight_blocked=true
  if [ -z "$panels" ] || [[ "$panels" = *$'\n'* ]]; then
    echo 'dss:error: Hosting-panel upgrade requires exactly one detected panel; review --manifest before continuing.' >&2; return 1
  fi
  IFS=$'\t' read -r panel version <<< "$panels"
  echo "dss:stage: Detected hosting panel $panel ($version)" >&2
  case "$panel" in
    plesk|cpanel) :;;
    *) printf 'dss:error: Hosting panel %s: no automated distrorejuve upgrade is available. Follow the vendor upgrade or migration process: %s\n' "$panel" "$(upgrade_panel_output_procedure_url "$panel")" >&2
      return 1;;
  esac
  if [ "${DR_PANEL_UPGRADE:-}" != "$panel" ]; then
    echo "dss:error: Hosting panel $panel requires explicit DR_PANEL_UPGRADE=$panel and its supported vendor procedure. Generic upgrades were not started." >&2; return 1
  fi
  case "$action" in
    --to-debian-release) [ "$#" -le 2 ] && [ -n "$requested_version" ] || return 1;;
    --to-latest|--to-next-ubuntu) [ "$#" -le 1 ] || return 1;;
    *) echo 'dss:error: DR_PANEL_UPGRADE applies to release-upgrade commands only. Use the panel tools for package updates, cleanup and configuration changes.' >&2; return 1;;
  esac
  if ${UPGRADE_CROSSGRADE:-false}; then echo 'dss:error: Hosting-panel crossgrades are not supported; no upgrade started.' >&2; return 1; fi
  [ "$(id -u)" = 0 ] || { echo 'dss:error: Hosting-panel upgrades require root.' >&2; return 1; }
  case "$panel" in
    plesk)
      tool=${DR_PLESK_UPGRADE_TOOL:-}
      [ -n "$tool" ] || {
        echo 'dss:error: Set DR_PLESK_UPGRADE_TOOL to the downloaded and reviewed Plesk tool for this exact OS transition.' >&2
        echo 'dss:info: Download instructions: https://support.plesk.com/hc/en-us/articles/12377714344983-How-to-perform-dist-upgrade-procedure-on-Linux-server-with-Plesk' >&2
        return 1
      };;
    cpanel) tool=/usr/local/cpanel/scripts/elevate-cpanel;;
  esac
  upgrade_panel_check_tool "$tool" || return 1
  # Inspect pending vendor state before the OS identity: a previous run may already have changed it.
  if [ "$panel" = plesk ]; then
    for marker in /etc/systemd/system/plesk-dist-upgrade-resume.service /etc/systemd/system/plesk-dist-upgrader.service; do
      if [ -e "$marker" ] || [ -L "$marker" ]; then
        echo 'dss:error: Plesk upgrade recovery is pending. Inspect the vendor log and resume procedure; a new upgrade was not started.' >&2; return 1
      fi
    done
    for name in debian11to12 debian12to13 ubuntu18to20 ubuntu20to22 ubuntu22to24 ubuntu24to26 "${tool##*/}"; do
      for marker in "/usr/local/psa/var/$name/resume.json" "/usr/local/psa/var/$name/dist-upgrade-conversion.flag" "/usr/local/psa/var/$name/$name.lock"; do
        if [ -e "$marker" ] || [ -L "$marker" ]; then
          echo 'dss:error: Plesk upgrade recovery is pending. Inspect the vendor log and resume procedure; a new upgrade was not started.' >&2; return 1
        fi
      done
    done
  else
    if [ -n "${ELEVATE_BASE_URL:-}" ]; then echo 'dss:error: Clear ELEVATE_BASE_URL before the supported cPanel upgrade; vendor download endpoints must not be overridden.' >&2; return 1; fi
    if [ -e /var/cpanel/elevate-noc-recommendations ]; then
      echo 'dss:error: cPanel provider instructions require manual review at /var/cpanel/elevate-noc-recommendations; use the vendor procedure directly.' >&2; return 1
    fi
    if [ -e /var/cpanel/elevate ]; then
      banner=$(upgrade_panel_run_tool "$tool" --status) || { echo "dss:error: Cannot read cPanel upgrade state; inspect elevate-cpanel --status before retrying." >&2; return 1; }
      if [ "$banner" != success ]; then
        echo 'dss:error: cPanel ELevate has unfinished or unknown state. Inspect elevate-cpanel --status and --log; no automatic --clean or --continue was attempted.' >&2; return 1
      fi
    fi
  fi
  current=$(distro_output_codename) || return 1
  family=debian
  case " $ALL_UBUNTU " in *" $current "*) family=ubuntu;; esac
  case "$action:$family" in
    --to-debian-release:debian)
      case "$requested_version" in 12) target=bookworm;; 13) target=trixie;; *) target=unsupported;; esac;;
    --to-next-ubuntu:ubuntu) target=$(ubuntu_output_next_release "$current") || return 1;;
    --to-latest:debian) target=trixie;;
    --to-latest:ubuntu) target=$(ubuntu_output_latest_lts "$current") || return 1;;
    *) echo 'dss:error: Requested hosting-panel action does not match the installed distribution.' >&2; return 1;;
  esac
  case "$panel:$family:$current:$target" in
    plesk:debian:bullseye:bookworm) identity=Debian11to12; minimum=18.0.57;;
    plesk:debian:bookworm:trixie) identity=Debian12to13; minimum=18.0.74;;
    plesk:ubuntu:focal:jammy) identity=Ubuntu20to22; minimum=18.0.44;;
    plesk:ubuntu:jammy:noble) identity=Ubuntu22to24; minimum=18.0.62;;
    plesk:ubuntu:noble:resolute) identity=Ubuntu24to26; minimum=18.0.81;;
    cpanel:ubuntu:focal:jammy) minimum=118;;
    cpanel:ubuntu:jammy:noble) minimum=134;;
    *) echo "dss:error: Hosting-panel path $panel $current -> $target is not supported here. Only one approved adjacent release transition can be checked per run; no upgrade started." >&2; return 1;;
  esac
  if [ "$(dpkg --print-architecture)" != amd64 ] || [ "$(uname -m)" != x86_64 ]; then
    echo 'dss:error: Hosting-panel automation currently requires native amd64 on an x86_64 kernel; no upgrade started.' >&2; return 1
  fi
  case "$(readlink /proc/1/exe)" in */systemd) :;; *) echo 'dss:error: Hosting-panel tools require a running systemd host with reboot support.' >&2; return 1;; esac
  if ! command -v systemd-detect-virt >/dev/null 2>&1; then echo 'dss:error: Cannot check container virtualization before the hosting-panel upgrade.' >&2; return 1; fi
  systemd-detect-virt --container --quiet; status=$?
  if [ "$status" -ne 1 ]; then echo 'dss:error: Hosting-panel container environment is unsupported or could not be checked; no upgrade started.' >&2; return 1; fi
  if [ "$panel" = plesk ]; then
    if [ "$version" = unknown ] || ! dpkg --compare-versions "$version" ge "$minimum"; then
      echo "dss:error: Plesk $minimum or later is required for $current -> $target. Update Plesk on the current OS first." >&2; return 1
    fi
    banner=$(upgrade_panel_run_tool "$tool" --version) || { echo "dss:error: Cannot read the Plesk upgrade tool version; no upgrade started." >&2; return 1; }
    case "$banner" in *"Plesk::${identity}Upgrader "*) :;; *) echo 'dss:error: Plesk tool identity does not match the requested OS transition.' >&2; return 1;; esac
    banner=$(upgrade_panel_run_tool "$tool" --help) || { echo "dss:error: Cannot read hosting-panel tool capabilities; obtain the current vendor tool." >&2; return 1; }
    case "$banner" in *--precheck*) :;; *) echo 'dss:error: Plesk tool has no supported --precheck; obtain the current vendor tool.' >&2; return 1;; esac
  else
    case "$version" in "11.$minimum."*|"$minimum."*) :;; *) echo "dss:error: This cPanel transition requires version $minimum with current updates; update the panel on its existing OS first." >&2; return 1;; esac
    banner=$(upgrade_panel_run_tool "$tool" --help) || { echo "dss:error: Cannot read hosting-panel tool capabilities; obtain the current vendor tool." >&2; return 1; }
    case "$banner" in *--non-interactive*) :;; *) echo 'dss:error: cPanel ELevate lacks --non-interactive; install the current vendor tool.' >&2; return 1;; esac
  fi
  check_disk_space || return 1
  echo "dss:stage: Checking $panel vendor prerequisites for $current -> $target" >&2
  if [ "$panel" = plesk ]; then
    upgrade_panel_run_tool "$tool" --precheck; status=$?
  else
    echo 'dss:stage: cPanel prerequisite checks can refresh APT indexes, clear its cache and archive completed vendor state.' >&2
    upgrade_panel_run_tool "$tool" --check; status=$?
    start_arguments=(--start --non-interactive)
  fi
  if [ "$status" -ne 0 ]; then echo "dss:error: Hosting-panel vendor checks failed (status $status). Resolve the vendor diagnostics in the detailed log; no distro upgrade started." >&2; return 1; fi
  record_config_state || return 1
  if [ -z "${DR_RUN_DIRECTORY:-}" ] || [ ! -d "$DR_RUN_DIRECTORY" ] || [ -L "$DR_RUN_DIRECTORY" ]; then return 1; fi
  (umask 077; printf '%s\t%s\t%s\n' "$panel" "$current" "$target" > "$DR_RUN_DIRECTORY/panel.handoff" && chmod 600 -- "$DR_RUN_DIRECTORY/panel.handoff") || return 1
  upgrade_preflight_blocked=false
  echo "dss:stage: Handing $current -> $target to $panel; the vendor tool controls configuration, recovery and automatic reboots." >&2
  if [ "$panel" = plesk ]; then
    printf 'dss:stage: Monitor from another session: %q --monitor\n' "$tool" >&2
  else
    printf 'dss:stage: Monitor from another session: %q --log (or --status)\n' "$tool" >&2
  fi
  echo 'dss:stage: Final completion remains unverified; use --verbose to show vendor output.' >&2
  upgrade_panel_run_tool "$tool" "${start_arguments[@]}"
  status=$?
  if [ "$status" -ne 0 ]; then echo "dss:error: Hosting-panel vendor procedure returned status $status; inspect its recovery instructions before retrying." >&2; fi
  return "$status"
}
# A vendor repository may follow different PHP or application upgrade rules.
# Replacing its release name blindly can mix incompatible packages or bypass a hosting panel.
# Check official suite consistency/base sources/backports and vendor upgrade blockers.
function apt_sources_check_releases_and_vendors() {
  local target=${1:-${apt_sources_transition_target:-}} current family records file line provider type uri suite components architectures base
  local ret=0 official=0 seen=' ' support status
  if [ -n "$target" ]; then upgrade_panel_refuse_generic || return 1; fi
  records=$(apt_sources_list) || return 1
  current=$(distro_output_codename) || current=
  family=debian
  case " $ALL_UBUNTU " in *" $current "*) [ -n "$current" ] && family=ubuntu;; esac
  while IFS=$'\t' read -r file line provider type uri suite components architectures; do
    [ -n "$file" ] || continue
    if [ "$provider" = debian ] || [ "$provider" = ubuntu ]; then
      base=${suite%%[-/]*}
      if [ "$type" = deb ] && [ "$suite" = "$base" ]; then official=$((official+1)); fi
      case "$base" in stable|oldstable|oldoldstable) base=$current;; esac
      case " $ALL_DEBIAN $ALL_UBUNTU " in
        *" $base "*) case "$seen" in *" $base "*) :;; *) seen="$seen$base ";; esac;;
        *) echo "dss:warn: $file:$line has an unpinned or unknown distro suite: $suite" >&2; ret=1;;
      esac
      if [ -n "$current" ] && [ "$base" != "$current" ] && [ "$base" != "$target" ]; then
        echo "dss:warn: $file:$line suite $suite does not match installed release $current or this upgrade target." >&2; ret=1
      fi
      if [ "$provider" != "$family" ]; then
        echo "dss:warn: $file:$line belongs to $provider, but the installed distro is $family." >&2; ret=1
      fi
      case "$suite" in *-backports*)
        if ! "${DR_ALLOW_BACKPORTS:-false}"; then
          echo "dss:warn: $file:$line enables backports ($suite); disable before upgrading or export DR_ALLOW_BACKPORTS=true." >&2; ret=1
        fi;;
      esac
      continue
    fi
    if [ "$provider" = claude ]; then
      if apt_sources_check_claude "$family" "$current" "$target" "$type" "$uri" "$suite" "$components" "$architectures"; then
        echo "dss:info: $file:$line: Claude Code $suite repository supports ${target:-$current}; channel and source options are unchanged."
      else
        echo "dss:warn: Review or disable Claude Code source at $file:$line before continuing; sources are unchanged." >&2
        ret=1
      fi
      continue
    fi
    [ -z "$target" ] && "${DR_SKIP_CURRENT_RELEASE_REPOSITORY_CHECK:-false}" && continue
    support=unknown
    status=2
    case "$provider" in
      sury|virtualmin|webmin|plesk|cpanel|postgresql|docker|mariadb|mongodb|ppa)
        if "apt_repo_${provider}_support" "$family" "${target:-$current}"; then status=0; else status=$?; fi;;
    esac
    case "$status" in 0) support=supported;; 1) support=unsupported;; esac
    echo "dss:info: $file:$line: $provider repository; target ${target:-$current} availability: $support."
    if [ -n "$target" ] || [ "$status" -ne 0 ]; then
      echo "dss:warn: Review or disable $provider source at $file:$line before continuing. Vendor migrations require application/version checks; sources are unchanged." >&2
      ret=1
    fi
  done <<< "$records"
  if [ "$official" -eq 0 ]; then echo "dss:warn: No active recognized Debian/Ubuntu binary base sources found." >&2; ret=1; fi
  # Only distro-owned suites count; Webmin sarge and PGDG suffixes are vendor data.
  local -a releases=()
  read -r -a releases <<< "$seen"
  if [ "${#releases[@]}" -gt 1 ]; then echo "dss:warn: APT sources mix distro releases:$seen" >&2; ret=1; fi
  return "$ret"
}

# Require security coverage for supported components and matching architecture filters.
# Debian optional components have no guaranteed Security Team coverage; retain their source choices.
# https://www.debian.org/security/faq.en.html#contrib
function apt_sources_check_security_coverage() {
  local records=$1 family=$2 current=$3 target=$4 provider type suite components architectures
  local secprovider sectype secsuite seccomponents secarchitectures component covered
  local -a basecomponents=()
  while IFS=$'\t' read -r _ _ provider type _ suite components architectures; do
    if [ "$provider" != "$family" ] || [ "$type" != deb ]; then continue; fi
    [ "$suite" = "$current" ] || [ "$suite" = "$target" ] || continue
    read -r -a basecomponents <<< "$components"
    for component in "${basecomponents[@]}"; do
      case "$family:$component" in
        debian:contrib|debian:non-free|debian:non-free-firmware) continue;;
      esac
      covered=false
      while IFS=$'\t' read -r _ _ secprovider sectype _ secsuite seccomponents secarchitectures; do
        if [ "$secprovider" != "$family" ] || [ "$sectype" != deb ]; then continue; fi
        case "$secsuite" in "$current"/updates|"$current"-security|"$target"/updates|"$target"-security) :;; *) continue;; esac
        [ "$secarchitectures" = '*' ] || [ "$secarchitectures" = "$architectures" ] || continue
        case " $seccomponents " in *" $component "*) covered=true; break;; esac
      done <<< "$records"
      if ! $covered; then
        echo "dss:error: Existing security sources do not cover base component $component with its architecture filter. Review APT sources before upgrading." >&2
        return 1
      fi
    done
  done <<< "$records"
}

function apt_sources_upgrade() {
  local family=$1 current=$2 target=$3
  local records provider type suite
  local apt_sources_add_security=true apt_sources_add_updates=true apt_sources_add_lts=false
  case "$family" in
    debian) case " $ALL_DEBIAN " in *" $target "*) :;; *) return 1;; esac;;
    ubuntu) case " $ALL_UBUNTU " in *" $target "*) :;; *) return 1;; esac;;
    *) return 1;;
  esac
  if [ "$family" = debian ]; then
    case " $DEBIAN_ARCHIVE " in *" $target "*)
      case "$target" in buster|bullseye) :;; *) apt_sources_add_updates=false;; esac;;
    esac
    [ "$target" = squeeze ] && apt_sources_add_lts=true
  fi
  apt_sources_check_releases_and_vendors "$target" || return 1
  records=$(apt_sources_list) || return 1
  while IFS=$'\t' read -r _ _ provider type _ suite _ _; do
    if [ "$provider" != "$family" ] || [ "$type" != deb ]; then continue; fi
    case "$suite" in "$current"/updates|"$current"-security|"$target"/updates|"$target"-security) apt_sources_add_security=false;; esac
    case "$suite" in "$current"-updates|"$target"-updates) apt_sources_add_updates=false;; esac
  done <<< "$records"
  if ! $apt_sources_add_security; then
    apt_sources_check_security_coverage "$records" "$family" "$current" "$target" || return 1
  fi
  apt_sources_rewrite upgrade "$family" "$current" "$target"
}

# Require free space on each package/cache/state filesystem before changing packages.
function check_disk_space() {
  local skip=${DR_SKIP_DISK_SPACE_CHECK:-false} minimum=${DR_MIN_FREE_DISK_MIB:-5120}
  local path output available
  $skip && return 0
  # Probe package/cache/state paths individually to catch separate mounts and symlinks.
  for path in . / /usr /var /var/cache /var/cache/apt /var/cache/apt/archives /var/cache/yum /var/cache/dnf /var/lib/dnf /usr/lib/sysimage/rpm /var/lib/apt /var/lib/apt/lists /var/lib/dpkg /var/lib/rpm /root /root/distrorejuveinfo; do
    [ -d "$path" ] || continue
    if ! output=$(LC_ALL=C df -Pm -- "$path"); then
      echo "dss:error: Cannot check disk space for $path. Resolve df failure or export DR_SKIP_DISK_SPACE_CHECK=true after review." >&2
      return 1
    fi
    # df -Pm: Filesystem 1048576-blocks Used Available Capacity Mounted-on; field 4 is MiB free.
    # /dev/vda1 20480 4096 16384 20% / -> available=16384 MiB.
    # Refuse shifted columns (for example a filesystem name containing whitespace).
    available=$(printf '%s\n' "$output" | awk '
      NR == 2 && NF >= 6 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ &&
        $4 ~ /^-?[0-9]+$/ && $5 ~ /^[0-9]+%$/ { print $4 }
    ')
    if [ "$available" -lt "$minimum" ] 2>/dev/null; then
      echo "dss:error: Insufficient disk space for $path: $available MiB available; require $minimum MiB. Free space or review DR_MIN_FREE_DISK_MIB; export DR_SKIP_DISK_SPACE_CHECK=true to bypass." >&2
      return 1
    fi
    if ! [ "$available" -ge "$minimum" ] 2>/dev/null; then
      echo "dss:error: Cannot read available disk space for $path from df -Pm." >&2
      return 1
    fi
  done
  return 0
}

function upgrade_precondition_checks() {
  upgrade_panel_refuse_generic || return 1
  check_disk_space || return 1
  local ret=0
  # e.g. 3.12.1
  if uname -r | grep -qai '^[12]'; then
    echo "dss:warn:Running an old kernel.  May not work with the latest packages (e.g. udev).  Please upgrade.  Note RimuHosting customers can set the kernel at https://rimuhosting.com/cp/vps/kernel.jsp.  To skip this check run: export DR_SKIP_KERNEL_CHECK=true"
    "${DR_SKIP_KERNEL_CHECK:-false}" || ret=$(($ret+1))
  fi
  # cat /proc/sys/kernel/osrelease => 4.14.264-rh305-20220204224046.xenU.x86_64
  # ERROR: Your kernel version indicates a revision number
  # of 255 or greater.  Glibc has a number of built in
  # assumptions that this revision number is less than 255.
  ver="$([ -f /proc/sys/kernel/osrelease ] && cat /proc/sys/kernel/osrelease | sed 's/[.-]/ /g' | awk '{print $3}')"
  [ ! -z "$ver" ] && [ $ver -gt 255 ] && echo "dss:warn: if you get an error on libc install like ERROR: Your kernel version indicates a revision number of 255 or greater, then you may need to restart the server with a 5.10 kernel, or a kernel with a version smaller than 255.  You are currently on $(uname -r)" >&2
  # ii  dmidecode                       2.9-1.2build1                           Dump Desktop Management Interface data
  local libx11=
  [ -f /etc/debian_version ] && command -v dpkg >/dev/null 2>&1 && if dpkg -l | grep '^ii' | awk '{print $2}' | egrep -qai 'gnome|desktop|x11-common'; then
    # ignoring some packages since they are 'fine'.  and typically some of them (eg libx11) are required by things like imagemagick and php-gd
    # install ok installed utils zip
    # install ok installed vcs cvs
    # install ok installed vcs patch
    local libx11="$(dpkg-query -W -f='${Status} ${Section} ${Package}\n'  | grep '^install ok installed' | egrep 'x11|gnome' | sort -k 4 | sed 's/install ok installed //' | awk '{print $2}' | egrep -v 'xorg-sgml-doctools|libx11|libx11-data|x11-common|theme-ubuntu-text|xauth|xfonts-encodings|xfonts-utils|msttcorefonts|gnome$|gnome-icon-theme|^gnome-(accessibility-themes|themes-extra(-data)?)(:[a-z0-9-]+)?$|libsoup|gsettings-desktop|adwaita-icon-th|lib-xkd|mesa-util|xkb-data|icon-the|ubuntu-mono|plymouth|x11proto|xtrans-dev' | tr '\r\n' ' ')"
  fi
  if [  ! -z "$libx11" ]; then
    dpkg-query -W -f='${Status} ${Section} ${Package}\n'  | grep '^install ok installed' | egrep 'x11|gnome' | sort -k 4 | sed 's/install ok installed //' | awk '{print "dss:x11related:" $0}'
    echo "dss:warn:x11-common installed.  You may hit conflicts.  To resolve: apt-get -y remove x11-common $libx11; apt-get -y autoremove.  To skip this check run: export DR_SKIP_X11_CHECK=true.  To automatically remove X11 libs use export DR_REMOVE_X11_PACKAGES=true"
    if "${DR_REMOVE_X11_PACKAGES:-false}"; then
      apt_get_apply -y remove $libx11 || ret=$(($ret+1))
      apt_get_apply -y autoremove
    else
      "${DR_SKIP_X11_CHECK:-false}" || ret=$(($ret+1))
    fi
  fi

  if [ -f /etc/debian_version ]; then
    apt_sources_check_releases_and_vendors "$1" || ret=1
  fi
  [ "$ret" -eq 0 ] && echo "dss:trace:upgrade_precondition_checks completed."
  [ "$ret" -ne 0 ] && echo "dss:error:upgrade precondition checks failed." >&2

  return $ret
}

# Archive-keyring packages maintain distro trust; never import unrelated keyserver keys.
# https://www.debian.org/doc/manuals/debian-handbook/sect.package-authentication.en.html
function apt_ensure_archive_keyring() {
  local package=$1 info status
  if info=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null); then
    case "$info" in *' ok installed') return 0;; esac
  else
    status=$?
    [ "$status" -eq 1 ] || { echo "dss:error: Cannot inspect $package state." >&2; return "$status"; }
  fi
  echo "dss:stage: Installing/configuring the distribution archive keyring: $package" >&2
  # apt_get_install reads this dynamically scoped string; do not weaken existing trust to bootstrap it.
  # shellcheck disable=SC2034
  local DR_ALLOW_UNAUTHENTICATED_ARCHIVES=false
  # shellcheck disable=SC2034
  local APT_GET_INSTALL_OPTIONS="$APT_GET_INSTALL_OPTIONS -o APT::Get::AllowUnauthenticated=false -o APT::Get::AutomaticRemove=false --no-remove"
  if apt_get_install "$package"; then :
  else
    status=$?
    echo "dss:error: Cannot install authenticated $package from configured indexes. Restore the distro keyring/trust using verified distro media or packages, then retry; no keyserver import was attempted." >&2
    return "$status"
  fi
  info=$(dpkg-query -W -f='${Status}' "$package") || return 1
  case "$info" in *' ok installed') return 0;; esac
  echo "dss:error: $package remains unconfigured after installation." >&2
  return 1
}

function add_missing_ubuntu_keys() {
  [ -f /etc/debian_version ] || return 0
  local current
  current=$(distro_output_codename) || return 1
  case " $ALL_UBUNTU " in *" $current "*) apt_ensure_archive_keyring ubuntu-keyring;; *) return 0;; esac
}

function add_missing_debian_keys() {
  [ -f /etc/debian_version ] || return 0
  local current
  current=$(distro_output_codename) || return 1
  case " $ALL_DEBIAN " in *" $current "*) apt_ensure_archive_keyring debian-archive-keyring;; *) return 0;; esac
}

# Columns: family, first affected release, action, rule, package pattern, remedy.
# Only purge rules may remove packages; manual rules protect service data and access.
function upgrade_output_compatibility_rules() {
  cat <<'RULES'
debian	wheezy	purge	dovecot-2	^dovecot($|-)	Dovecot 1.x configuration needs migration to 2.x.
debian	stretch	purge	fail2ban-09	^fail2ban$	Fail2ban 0.9 changes jail configuration.
debian	buster	purge	dovecot-23	^dovecot($|-)	Migrate obsolete Dovecot settings/plugins removed in 2.3.
debian	trixie	purge	dovecot-24	^dovecot($|-)	Dovecot 2.4 requires configuration migration.
ubuntu	precise	purge	dovecot-2	^dovecot($|-)	Dovecot 1.x configuration needs migration to 2.x.
ubuntu	xenial	purge	fail2ban-09	^fail2ban$	Fail2ban 0.9 changes jail configuration.
ubuntu	focal	purge	dovecot-23	^dovecot($|-)	Migrate obsolete Dovecot settings/plugins removed in 2.3.
ubuntu	questing	purge	dovecot-24	^dovecot($|-)	Dovecot 2.4 requires configuration migration.
debian	trixie	manual	dovecot-replication	^dovecot($|-)	Dovecot 2.4 removes replicator-based replication; migrate this service before upgrading.
ubuntu	questing	manual	dovecot-replication	^dovecot($|-)	Dovecot 2.4 removes replicator-based replication; migrate this service before upgrading.
ubuntu	questing	manual	dovecot-armhf	^dovecot($|-)	Dovecot is unavailable on armhf in this target; migrate the mail service or architecture first.
debian	wheezy	manual	sasl-sql	^libsasl2-modules-sql$	Migrate SASL SQL plugin names and realm-dependent queries before upgrading.
debian	bullseye	manual	mailman-2	^mailman$	Migrate Mailman 2 lists and archives to Mailman 3 before upgrading.
debian	bullseye	manual	lilo	^lilo$	Migrate and verify the active bootloader before upgrading; LILO is removed.
debian	bullseye	manual	xfs-barrier	.*	Remove obsolete barrier/nobarrier XFS mount options from fstab.
debian	bookworm	manual	ldap-backends	^slapd$	Migrate removed OpenLDAP backends and external ppolicy/nssov configuration before upgrading.
ubuntu	jammy	manual	ldap-backends	^slapd$	Migrate removed OpenLDAP backends and external ppolicy/nssov configuration before upgrading.
debian	bookworm	manual	bind-map	^bind9$	Convert BIND map-format zones using the old tools before upgrading.
ubuntu	jammy	manual	bind-map	^bind9$	Convert BIND map-format zones using the old tools before upgrading.
debian	trixie	manual	rabbitmq	^rabbitmq-server$	Migrate RabbitMQ through supported intermediate versions and queue types before upgrading.
ubuntu	jammy	manual	rabbitmq	^rabbitmq-server$	Migrate RabbitMQ through supported intermediate versions and feature flags before upgrading.
ubuntu	noble	manual	rabbitmq	^rabbitmq-server$	Migrate RabbitMQ through supported intermediate versions and feature flags before upgrading.
ubuntu	resolute	manual	rabbitmq	^rabbitmq-server$	Migrate RabbitMQ through supported intermediate versions and feature flags before upgrading.
ubuntu	noble	manual	pam-lastlog	.*	Migrate mandatory PAM references to removed pam_lastlog.so before upgrading.
ubuntu	plucky	manual	ldap-tls	^slapd$	Convert OpenLDAP GnuTLS cipher strings to OpenSSL syntax before upgrading.
ubuntu	noble	manual	rrd-armhf	^(rrdtool|rrdcached|librrd[0-9-]|librrds-perl|python[0-9.-]*-rrdtool)	On armhf export RRD databases to XML with the old tools before the time_t transition.
ubuntu	resolute	manual	cgroup-v1	.*	Remove boot options forcing cgroup v1 and verify unified cgroup v2 support before upgrading.
debian	buster	warn	ssh-rsa-list	^openssh-server$	Review SSH algorithm allow-lists and test a second login with RSA SHA-2 before upgrading.
debian	trixie	warn	sysctl-conf	.*	Move active /etc/sysctl.conf settings to /etc/sysctl.d; trixie no longer reads that file.
ubuntu	vivid	warn	upstart-jobs	.*	Review custom Upstart jobs and replace them with native systemd units.
debian	trixie	manual	crossgrade-rrd	^(rrdtool|rrdcached|librrd[0-9-]|librrds-perl|python[0-9.-]*-rrdtool)	Export architecture-dependent RRD data to XML with the old tools and plan its native restore before crossgrading.
debian	trixie	manual	crossgrade-postgresql	^postgresql-[0-9]+$	Plan a logical PostgreSQL dump/restore; existing 32-bit clusters cannot simply be opened by 64-bit binaries.
debian	trixie	manual	crossgrade-ldap	^slapd$	Plan an OpenLDAP logical export/import for the architecture change; preserve directory data before crossgrading.
ubuntu	focal	manual	crossgrade-rrd	^(rrdtool|rrdcached|librrd[0-9-]|librrds-perl|python[0-9.-]*-rrdtool)	Export architecture-dependent RRD data to XML with the old tools and plan its native restore before crossgrading.
ubuntu	focal	manual	crossgrade-postgresql	^postgresql-[0-9]+$	Plan a logical PostgreSQL dump/restore; existing 32-bit clusters cannot simply be opened by 64-bit binaries.
ubuntu	focal	manual	crossgrade-ldap	^slapd$	Plan an OpenLDAP logical export/import for the architecture change; preserve directory data before crossgrading.
RULES
}

# Inspect text only. Never load customer shell/application configuration as code.
# Return 0 for a match, 1 when clear, 2 when a required file cannot be inspected.
function upgrade_compatibility_config_matches() {
  local pattern=$1 file found=false status
  shift
  for file in "$@"; do
    [ -e "$file" ] || [ -L "$file" ] || continue
    [ -f "$file" ] && [ -r "$file" ] || return 2
    awk -v pattern="$pattern" '
      # Original mawk lacks named classes; preserve ASCII whitespace in caller patterns.
      BEGIN { gsub(/\[:space:\]/, " \t\r\f\013", pattern) }
      { sub(/#.*/, ""); gsub(/["\047]/, ""); if (tolower($0) ~ pattern) matched=1 }
      END { exit !matched }
    ' "$file"
    status=$?
    case "$status" in 0) found=true;; 1) :;; *) return 2;; esac
  done
  $found
}

# Follow conventional active config entrypoints and explicit includes, never backup files.
function upgrade_compatibility_output_config_files() {
  local kind=$1 file included requirement text size status index=0 seen=''
  local -a queue=()
  case "$kind" in
    ldap)
      upgrade_compatibility_config_matches '^[ \t\r\f\013]*slapd_conf[ \t\r\f\013]*=[ \t\r\f\013]*[^ \t\r\f\013]|(^|[ \t\r\f\013])-[fF][ \t\r\f\013]' /etc/default/slapd /etc/systemd/system/slapd.service /etc/systemd/system/slapd.service.d/*.conf
      status=$?
      [ "$status" -eq 1 ] || return 2
      [ ! -f /etc/ldap/slapd.conf ] || queue+=(/etc/ldap/slapd.conf)
      if [ -d /etc/ldap/slapd.d ]; then
        text=$(find /etc/ldap/slapd.d -maxdepth 8 \( -type f -o -type l \) -name '*.ldif' -print) || return 2
        while IFS= read -r file; do [ -z "$file" ] || queue+=("$file"); done <<< "$text"
      fi;;
    bind) queue=(/etc/bind/named.conf);;
    dovecot)
      upgrade_compatibility_config_matches '(^|[= \t\r\f\013])-c[ \t\r\f\013]|--config([= \t\r\f\013]|$)' /etc/default/dovecot /etc/systemd/system/dovecot.service /etc/systemd/system/dovecot.service.d/*.conf
      status=$?
      [ "$status" -eq 1 ] || return 2
      queue=(/etc/dovecot/dovecot.conf);;
    *) return 2;;
  esac
  [ "${#queue[@]}" -gt 0 ] || return 2
  while [ "$index" -lt "${#queue[@]}" ]; do
    file=${queue[index]}; index=$((index+1))
    case "|$seen|" in *"|$file|"*) continue;; esac
    seen="$seen|$file"
    [ "$index" -le 200 ] && [ -f "$file" ] && [ -r "$file" ] || return 2
    size=$(stat -c %s -- "$file") || return 2
    [ "$size" -le 1048576 ] || return 2
    printf '%s\n' "$file"
    # BIND include "/etc/bind/named.conf.local"; -> required|/etc/bind/named.conf.local.
    # Dovecot !include_try conf.d/*.conf -> optional|conf.d/*.conf, resolved relative to this file.
    text=$(awk -v kind="$kind" '
      /^[ \t\r\f\013]*#/ { next }
       kind == "bind" {
        line=$0; sub(/#.*/, "", line); sub(/\/\/.*/, "", line)
        while (match(line, /(^|[;{} \t\r\f\013])include[ \t\r\f\013]+"[^"]+"[ \t\r\f\013]*;/)) {
          value=substr(line,RSTART,RLENGTH); sub(/^[^"]*"/, "", value); sub(/".*$/, "", value)
          print "required|" value; line=substr(line,RSTART+RLENGTH)
        }
        if (line ~ /(^|[;{} \t\r\f\013])include([ \t\r\f\013]|$)/) exit 2
      }
      kind != "bind" && /^[ \t\r\f\013]*!?include(_try)?[ \t\r\f\013]+/ {
        line=$0; sub(/^[ \t\r\f\013]*!?include(_try)?[ \t\r\f\013]+/, "", line); sub(/[ \t\r\f\013]+#.*/, "", line)
        gsub(/^["\047]|["\047][ \t\r\f\013]*$/, "", line); print ($0 ~ /!include_try/ ? "optional|" : "required|") line
      }
    ' "$file") || return 2
    while IFS='|' read -r requirement included; do
      [ -n "$included" ] || continue
      case "$included" in *'$'*|*'%'*|*'..'*|*'|'*) return 2;; esac
      case "$included" in /*) :;; *) included="${file%/*}/$included";; esac
      # Expand only config include globs; never execute or source the contents.
      local expanded matched=false
      while IFS= read -r expanded; do
        [ -n "$expanded" ] || continue
        queue+=("$expanded"); matched=true
      done < <(compgen -G "$included")
      if ! $matched; then
        # Dovecot !include_try explicitly permits missing optional files.
        if [ "$requirement" = optional ]; then continue; fi
        return 2
      fi
    done <<< "$text"
  done
}

# Check package-owned module filenames without loading Apache or application code.
function upgrade_compatibility_apache_module_enabled() {
  local package=$1 modules module file status found=false
  modules=$(dpkg-query -L "$package") || return 2
  while IFS= read -r module; do
    case "$module" in *.so) module=${module##*/};; *) continue;; esac
    for file in /etc/apache2/apache2.conf /etc/apache2/mods-enabled/*.load /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/*.conf; do
      [ -e "$file" ] || [ -L "$file" ] || continue
      [ -f "$file" ] && [ -r "$file" ] || return 2
      awk -v module="$module" '
        tolower($1) == "loadmodule" { path=$3; gsub(/["\047]/,"",path); sub(/^.*\//,"",path); if (path == module) found=1 }
        END { exit !found }
      ' "$file"
      status=$?
      case "$status" in 0) found=true;; 1) :;; *) return 2;; esac
    done
  done <<< "$modules"
  $found
}

function upgrade_compatibility_rule_applies() {
  local rule=$1 arch=${2:-} file files text help
  local -a paths=()
  case "$rule" in
    dovecot-2|dovecot-24|fail2ban-*|mailman-2|lilo|rabbitmq) return 0;;
    dovecot-23|dovecot-replication)
      files=$(upgrade_compatibility_output_config_files dovecot) || return 2
      while IFS= read -r file; do paths+=("$file"); done <<< "$files"
      if [ "$rule" = dovecot-23 ]; then
        upgrade_compatibility_config_matches '^[[:space:]]*(ssl_protocols|ssl_parameters|director_doveadm_port|director_consistent_hashing|mdbox_purge_preserve_alt)[[:space:]]*=|^[[:space:]]*mail_plugins[[:space:]]*=[[:space:]]*([^#]*[[:space:]])?(stats|imap_stats)([[:space:]]|$)' "${paths[@]}"
      else
        # Packaged director/replicator service templates alone do not enable the workload.
        upgrade_compatibility_config_matches '^[[:space:]]*((mail_replica|director_(mail_)?servers)[[:space:]]*=[[:space:]]*["\047]?[^[:space:]#"\047]|mail_plugins[[:space:]]*=[[:space:]]*([^#]*[[:space:]])?replication([[:space:]]|$)|executable[[:space:]]*=[[:space:]]*(imap|pop3|submission)-login[[:space:]]+director([[:space:]]|$)|auth_socket_path[[:space:]]*=[[:space:]]*([^#]*/)?director-userdb([[:space:]]|$))' "${paths[@]}"
      fi;;
    dovecot-armhf) [ "$arch" = armhf ];;
    crossgrade-rrd|crossgrade-postgresql|crossgrade-ldap)
      [ -n "${crossgrade_release:-}" ] && [ "$arch" = i386 ];;
    sasl-sql)
      upgrade_compatibility_config_matches '^[[:space:]]*auxprop_plugin:[[:space:]]*(mysql|pgsql|sqlite)' /etc/sasl2/*.conf /etc/postfix/sasl/*.conf;;
    xfs-barrier)
      [ -r /etc/fstab ] || return 2
      awk '$0 !~ /^[ \t\r\f\013]*#/ && $3 == "xfs" && $4 ~ /(^|,)(no)?barrier(=[^,]+)?(,|$)/ { bad=1 } END { exit !bad }' /etc/fstab;;
    ldap-backends|ldap-tls)
      files=$(upgrade_compatibility_output_config_files ldap) || return 2
      while IFS= read -r file; do paths+=("$file"); done <<< "$files"
      if [ "$rule" = ldap-backends ]; then
        upgrade_compatibility_config_matches '^[[:space:]]*(database[[:space:]]+|olcdatabase:[[:space:]]*(\{[0-9]+\})?)(bdb|hdb|shell)([[:space:]]|$)|^[[:space:]]*(include|olcinclude:).*ppolicy|^[[:space:]]*(dn:[[:space:]]*cn=|cn:[[:space:]]*)(\{[0-9]+\})?ppolicy(,|[[:space:]]|$)|^[[:space:]]*(overlay[[:space:]]+|olcoverlay:[[:space:]]*(\{[0-9]+\})?)nssov|^[[:space:]]*(olcmoduleload:|moduleload[[:space:]]).*nssov' "${paths[@]}"
      else
        upgrade_compatibility_config_matches '^[[:space:]]*(olctlsciphersuite:|tls_cipher_suite[[:space:]]).*([%+!]|normal|secure[0-9]|performance)' "${paths[@]}"
      fi;;
    bind-map)
      # Canonicalize active includes without plugins (-c), redacting secrets (-x).
      command -v named-checkconf >/dev/null 2>&1 || return 2
      upgrade_compatibility_config_matches '(^|[=[:space:]])-[ct][[:space:]]' /etc/default/named /etc/default/bind9
      [ "$?" -eq 1 ] || return 2
      # Older BIND lacks -c: inspect bounded static includes instead of loading modules.
      help=$(LC_ALL=C named-checkconf -h 2>&1)
      if printf '%s\n' "$help" | grep -Eq '\[-[A-Za-z]*c[A-Za-z]*\]|(^|[[:space:]])-c([[:space:],]|$)'; then
        text=$(named-checkconf -p -x -c 2>/dev/null) || return 2
      else
        files=$(upgrade_compatibility_output_config_files bind) || return 2
        while IFS= read -r file; do paths+=("$file"); done <<< "$files"
        upgrade_compatibility_config_matches '(^|[;{}[:space:]])(plugin|dyndb|dlz)([[:space:]]|$)' "${paths[@]}"
        [ "$?" -eq 1 ] || return 2
        text=$(cat -- "${paths[@]}") || return 2
      fi
      printf '%s\n' "$text" | awk '
        {
          line=$0; sub(/#.*/, "", line); sub(/\/\/.*/, "", line)
          while (length(line)) {
            if (comment) {
              if (match(line, /\*\//)) { line=substr(line,RSTART+2); comment=0 } else break
            } else if (match(line, /\/\*/)) {
              all=all " " substr(line,1,RSTART-1); line=substr(line,RSTART+2); comment=1
            } else { all=all " " line; break }
          }
        }
        END { exit !(all ~ /(^|[;{} \t\r\f\013])masterfile-format[ \t\r\f\013]+"?map"?[ \t\r\f\013]*;/) }
      ';;
    pam-lastlog)
      upgrade_compatibility_config_matches '^[[:space:]]*-?(auth|account|password|session)[[:space:]]+(required|requisite|\[[^]]*default=(die|bad)[^]]*\])[[:space:]]+[^[:space:]]*pam_lastlog\.so' /etc/pam.d/*;;
    rrd-armhf) [ "$arch" = armhf ];;
    cgroup-v1)
      upgrade_compatibility_config_matches '(^|[[:space:]])(systemd\.unified_cgroup_hierarchy=(0|false|no)|systemd\.legacy_systemd_cgroup_controller(=1|=yes|=true)?)([[:space:]]|$)' /proc/cmdline;;
    ssh-rsa-list)
      upgrade_compatibility_config_matches '^[[:space:]]*(pubkeyacceptedkeytypes|hostbasedacceptedkeytypes)[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf;;
    sysctl-conf)
      for file in /etc/sysctl.d/*.conf; do
        if [ -f "$file" ] && [ -r "$file" ] && [ "$file" -ef /etc/sysctl.conf ]; then return 1; fi
      done
      upgrade_compatibility_config_matches '^[[:space:]]*[^[:space:]#;]+[[:space:]]*=' /etc/sysctl.conf;;
    upstart-jobs)
      upgrade_compatibility_config_matches '^[[:space:]]*(exec|script|start on)[[:space:]]' /etc/init/*.conf;;
    *) echo "dss:error: Unknown compatibility rule: $rule" >&2; return 2;;
  esac
}

# Machine records: action<TAB>rule<TAB>boundary<TAB>packages<TAB>remedy.
function upgrade_output_compatibility_issues() {
  local family=$1 current=$2 target=$3 wanted_family boundary action rule pattern remedy packages selected arch status
  case "$family" in debian|ubuntu) :;; *) return 1;; esac
  packages=$(dpkg-query -W -f='${Status}\t${Package}\n') || return 1
  arch=$(dpkg --print-architecture) || return 1
  while IFS=$'\t' read -r wanted_family boundary action rule pattern remedy; do
    [ "$family" = "$wanted_family" ] || continue
    if ! is_distro_name_older "$current" "$boundary" || is_distro_name_older "$target" "$boundary"; then continue; fi
    [ "$rule" = dovecot-24 ] && "${DR_SKIP_DOVECOT_MIGRATION_CHECK:-false}" && continue
    if [ "$pattern" = ".*" ]; then selected=system
    else selected=$(printf '%s\n' "$packages" | awk -F '\t' -v pattern="$pattern" '
      $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ && $2 ~ pattern { print $2 }
    ') || return 1
    fi
    [ -n "$selected" ] || continue
    selected=${selected//$'\n'/ }
    upgrade_compatibility_rule_applies "$rule" "$arch"
    status=$?
    [ "$status" -eq 1 ] && continue
    if [ "$status" -ne 0 ]; then
      action=manual
      remedy="Cannot verify relevant configuration; inspect it before upgrading. $remedy"
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$action" "$rule" "$boundary" "$selected" "$remedy"
  done < <(upgrade_output_compatibility_rules)
}

function upgrade_output_incompatible_packages() {
  local issues
  issues=$(upgrade_output_compatibility_issues "$@") || return 1
  printf '%s\n' "$issues" | awk -F '\t' '$1 == "purge" { count=split($4, packages, " "); for (i=1; i<=count; i++) print packages[i] }' | sort -u
}

# shellcheck shell=bash
# A metapackage selects other packages through dependencies. Follow those
# dependencies to find the target default PHP branch; the currently installed php CLI can differ.
# Follow Debian's default PHP packages; package maintscripts own Apache module changes.
function upgrade_php_output_default_branch() {
  local package dependencies branch
  for package in php-cli libapache2-mod-php; do
    dependencies=$(LC_ALL=C apt-cache depends "$package") || return 1
    # Depends: php8.4-cli or Depends: libapache2-mod-php8.4 -> branch=8.4.
    branch=$(printf '%s\n' "$dependencies" | awk '
      $1 == "Depends:" && $2 ~ /^(php[0-9]+\.[0-9]+-cli|libapache2-mod-php[0-9]+\.[0-9]+)$/ {
        sub(/^libapache2-mod-php|^php/, "", $2); sub(/-cli$/, "", $2)
        if (found && found != $2) bad=1; found=$2
      }
      END { if (found && !bad) print found; else exit 1 }
    ')
    if [ -n "$branch" ]; then printf '%s\n' "$branch"; return 0; fi
  done
  echo 'dss:error: Cannot establish the default PHP branch from target APT dependencies.' >&2
  return 1
}

# 0 genuine archive candidate, 1 unavailable, 2 failed query. Never use status-only versions.
# Candidate: 8.4.1-1 plus madison "php-cli | 8.4.1-1 | https://deb.debian.org/debian trixie/main amd64 Packages" -> available.
# Candidate: (none), or a version present only in the dpkg status file, is unavailable.
function upgrade_php_has_candidate() {
  local policy rows version
  policy=$(LC_ALL=C apt-cache policy "$1") || return 2
  version=$(printf '%s\n' "$policy" | awk '$1 == "Candidate:" { print $2; exit }')
  [ -n "$version" ] && [ "$version" != '(none)' ] || return 1
  rows=$(LC_ALL=C apt-cache madison "$1") || return 2
  printf '%s\n' "$rows" | awk -F '|' -v version="$version" '
    { gsub(/^[ \t\r\f\013]+|[ \t\r\f\013]+$/, "", $2) }
    $2 == version && $3 ~ /[ \t\r\f\013][a-z0-9][a-z0-9-]*[ \t\r\f\013]+Packages[ \t\r\f\013]*$/ { found=1 }
    END { exit !found }
  '
}

function upgrade_php_apache_module_is_enabled() {
  local package=$1 files module load resolved status
  files=$(dpkg-query -L "$package") || return 2
  load="/etc/apache2/mods-enabled/php${package#libapache2-mod-php}.load"
  [ -e "$load" ] || return 1
  [ -f "$load" ] && [ -r "$load" ] || return 2
  resolved=$(readlink -f "$load") || return 2
  printf '%s\n' "$files" | grep -qxF "$resolved" || return 1
  while IFS= read -r module; do
    case "$module" in /*.so) :;; *) continue;; esac
    [ -f "$module" ] && [ -r "$module" ] || return 2
    awk -v module="$module" '
      tolower($1) == "loadmodule" { path=$3; gsub(/["\047]/,"",path); if (path == module) found=1 }
      END { exit !found }
    ' "$load"
    status=$?
    case "$status" in 0) return 0;; 1) :;; *) return 2;; esac
  done <<< "$files"
  return 1
}

# 0 Apache server present, 1 confirmed absent, 2 cannot safely establish its use.
function upgrade_php_has_apache_server() {
  local packages=$1 state processes status
  if printf '%s\n' "$packages" | awk -F '\t' '
    $1 ~ / (installed|unpacked|half-installed|half-configured|triggers-awaited|triggers-pending)$/ &&
      $2 ~ /^(apache2|apache2[.]2-common|apache2-mpm-.*)(:[a-z0-9-]+)?$/ { found=1 }
    END { exit !found }
  '; then return 0
  else status=$?; [ "$status" -eq 1 ] || return 2; fi
  if [ -e /etc/init.d/apache2 ] || [ -e /etc/init/apache2.conf ]; then return 0; fi
  if [ -d /run/systemd/system ]; then
    state=$(readlink /proc/1/exe) || return 2
    case "$state" in */systemd|*/'systemd (deleted)')
      command -v systemctl >/dev/null || return 2
      state=$(systemctl show -p LoadState -p ActiveState apache2.service) || return 2
      printf '%s\n' "$state" | grep -Eq '^LoadState=(loaded|masked)$' && return 0
      if ! printf '%s\n' "$state" | grep -qx LoadState=not-found ||
         ! printf '%s\n' "$state" | grep -qx ActiveState=inactive; then return 2; fi;;
    esac
  fi
  processes=$(LC_ALL=C ps -eo comm=) || return 2
  if printf '%s\n' "$processes" | grep -Eq '^[[:space:]]*(apache2|httpd)[[:space:]]*$'; then
    echo 'dss:error: Apache is running without a distribution service. Review its PHP module before upgrading.' >&2
    return 2
  else status=$?; [ "$status" -eq 1 ] || return 2; fi
  return 1
}

# APT may choose mod_php before the separately requested FPM alternative.
# Compare package status, not leftover Apache configuration or apache2-utils.
function upgrade_php_output_new_apache_packages() {
  local inventory=$1 plan=$2
  awk -F '\t' '
    FILENAME == ARGV[1] {
      if ($1 !~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/) next
      name=$2; sub(/:.*/, "", name); present[name]=1
      if (name == "apache2" || name == "apache2.2-common" || name ~ /^apache2-mpm-/ || name ~ /^libapache2-mod-php/) apache=1
      next
    }
    /^Inst / {
      split($0, fields, /[ \t]+/); name=fields[2]; sub(/:.*/, "", name)
      if (!apache && !(name in present) && (name ~ /^apache2(-bin|-data|[.]2-bin|[.]2-common|-mpm-.*)?$/ || name ~ /^libapache2-mod-php/)) {
        if (!seen[name]++) print name
      }
    }
  ' "$inventory" "$plan"
}

# Retain the machine's web-server role before every ordinary APT mutation.
function apt_get_apply() {
(
  local directory additions status package_umask attempt
  local -a pipeline_status=()
  # Recheck sources even if the caller expanded options before they changed.
  if "${DR_ALLOW_UNAUTHENTICATED_ARCHIVES:-false}"; then
    apt_configure_archive_authentication || return 1
    set -- "$@" -o APT::Get::AllowUnauthenticated="$apt_archive_authentication_enabled"
  fi
  package_umask=$(umask) || return 1
  umask 077
  upgrade_php_runtime_prepare || return 1
  directory=$(mktemp -d) || return 1
  trap 'rm -rf -- "$directory"' EXIT
  for attempt in 1 2; do
    umask 077
    dpkg-query -W -f='${Status}\t${Package}\n' > "$directory/packages" || return 1
    if awk -F '\t' '
      $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ &&
        ($2 ~ /^(apache2|apache2[.]2-common|apache2-mpm-.*)(:[a-z0-9-]+)?$/ || $2 ~ /^libapache2-mod-php/) { found=1 }
      END { exit !found }
    ' "$directory/packages"; then :
    else
      (umask "$package_umask" && LC_ALL=C apt-get "$@" --simulate) > "$directory/plan" 2>&1 || { status=$?; cat "$directory/plan" >&2; return "$status"; }
      additions=$(upgrade_php_output_new_apache_packages "$directory/packages" "$directory/plan") || return 1
      if [ -n "$additions" ]; then
        printf 'dss:error: APT would add an Apache web server/PHP handler to a host without that role: %s. No package changes attempted; review PHP-FPM/CGI dependency alternatives.\n' "${additions//$'\n'/, }" >&2
        return 1
      fi
    fi
    : > "$directory/output" || return 1
    umask "$package_umask" || return 1
    LC_ALL=C apt-get "$@" 2>&1 | tee "$directory/output"
    pipeline_status=("${PIPESTATUS[@]}")
    status=${pipeline_status[0]}
    if [ "${pipeline_status[1]}" -ne 0 ]; then
      echo 'dss:error: Cannot capture APT output; shared-file recovery was not attempted.' >&2
      return "${pipeline_status[1]}"
    fi
    if [ "$attempt" -eq 1 ] && [ "$status" -ne 0 ] && grep -qF "trying to overwrite shared '" "$directory/output"; then
      if rm_overwrite_files "$directory/output"; then continue; fi
    fi
    if [ "$status" -ne 0 ]; then
      awk '
        /trying to overwrite / { reason=$0; exit }
        /^E:/ { if (reason == "") reason=$0 }
        END { if (reason != "") print "dss:error: " reason }
      ' "$directory/output" >&2
    fi
    return "$status"
  done
)
}

# APT simulation: Remv php8.2-cli [8.2.1-1] requires an allowed removal; Purg php8.2-cli is always rejected.
function upgrade_php_check_plan() {
  local allowed=$1 plan=$2 removal_only=${3:-false} native=${4:-} diagnostic=${5:-}
  awk -v removal_only="$removal_only" -v native="$native" -v diagnostic="$diagnostic" '
    function reject(reason, detail) {
      bad=1
      if (diagnostic != "") printf "dss:error: %s rejected (%s): %s.\n", diagnostic, reason, detail > "/dev/stderr"
    }
    function key(name) {
      if (native == "") sub(/:.*/, "", name)
      else if (name !~ /:/) name=name ":" native
      return name
    }
    FILENAME == ARGV[1] { allowed[key($1)]=1; next }
    /^Purg / { reject("purge", "purging " $2 " is not permitted") }
    /^Remv / {
      name=$2
      if (!(key(name) in allowed) && !(native != "" && name !~ /:/ && ((name ":all") in allowed)))
        reject("unapproved_removal", "removing " name " was not approved")
    }
    /^Inst / { if (removal_only == "true") reject("unexpected_install", "installing " $2 " is not permitted") }
    END { exit bad }
  ' "$allowed" "$plan"
}

# Permit existing dependency upgrades already approved for the final PHP transaction.
# New runtimes/Apache packages must wait until the old handler has been removed.
function upgrade_php_check_apache_removal_plan() {
  local directory=$1 native=$2 changes old_version new_version package
  upgrade_php_check_plan "$directory/apache.allowed-removals" "$directory/remove.plan" false "$native" 'Apache/PHP removal plan' || return 1
  # APT simulation: Inst libedit2 [1.0] (2.0 Debian [amd64]); compare both versions.
  changes=$(awk -v native="$native" '
    function reject(reason, detail) {
      bad=1
      printf "dss:error: Apache/PHP removal plan rejected (%s): %s.\n", reason, detail > "/dev/stderr"
    }
    function key(name) { sub(":" native "$", "", name); sub(/:all$/, "", name); return name }
    FILENAME == ARGV[1] && /^Inst / { approved[key($2) " " $3 " " $4]=1; next }
    FILENAME == ARGV[2] && /^Inst / {
      name=key($2)
      if ($3 !~ /^\[[^]]+\]$/ || $4 !~ /^\(/) {
        reject("unverified_install", "cannot verify old/target versions for " $2); next
      }
      if (name ~ /^(apache2($|[.-])|libapache2-mod-|php([0-9]|$))/) {
        reject("early_runtime_change", $2 " would change before the old Apache PHP handler is removed"); next
      }
      if (!((name " " $3 " " $4) in approved)) {
        reject("unapproved_upgrade", $2 " " $3 " " $4 " does not match the checked installation plan"); next
      }
      old=$3; sub(/^\[/, "", old); sub(/\]$/, "", old)
      version=$4; sub(/^\(/, "", version); sub(/\)$/, "", version)
      print old "\t" version "\t" $2
    }
    END { exit bad }
  ' "$directory/install.plan" "$directory/remove.plan") || return 1
  while IFS=$'\t' read -r old_version new_version package; do
    [ -n "$old_version" ] || continue
    dpkg --compare-versions "$new_version" ge "$old_version" || {
      printf 'dss:error: Apache/PHP removal plan rejected (version_check_failed): cannot permit %s changing from %s to %s.\n' "$package" "$old_version" "$new_version" >&2
      return 1
    }
  done <<< "$changes"
  return 0
}

function upgrade_php_output_pending_directory() {
  local file directory found=''
  for file in /root/distrorejuveinfo/*.php-migration/*/started /root/deghostinfo/*.php-migration/*/started; do
    [ -f "$file" ] || continue
    directory=${file%/*}
    [ ! -f "$directory/completed" ] || continue
    [ -z "$found" ] || { echo 'dss:error: Multiple unfinished PHP migrations require review.' >&2; return 2; }
    found=$directory
  done
  [ -n "$found" ] || return 1
  printf '%s\n' "$found"
}

# shellcheck shell=bash
# SysV/Upstart handoff blocks package starts only; it does not disable Apache at boot.
# Leave the guard on partial failure; do not reboot before completing/reviewing that state.
function upgrade_php_apache_legacy_control() {
  local directory=$1 action=$2 policy=/usr/sbin/policy-rc.d saved wrapper temporary quoted actual=absent original original_link current_link owned=false
  case "$action" in prepare|finish) :;; *) return 1;; esac
  case "$directory" in /*) :;; *) return 1;; esac
  [ -d "$directory" ] && [ ! -L "$directory" ] && [ "$(stat -c '%u:%a' "$directory")" = 0:700 ] || return 1
  [ -x /etc/init.d/apache2 ] && command -v invoke-rc.d >/dev/null || return 1
  saved="$directory/apache.policy.original"; wrapper="$directory/apache.policy.wrapper"
  if [ ! -f "$directory/apache.legacy" ]; then
    [ "$action" = prepare ] || return 1
    if [ -e "$saved" ] || [ -L "$saved" ] || [ -e "$wrapper" ]; then
      echo 'dss:error: Incomplete legacy Apache policy records require review before retrying.' >&2; return 1
    fi
    (
      umask 077
      if [ -e "$policy" ] || [ -L "$policy" ]; then
        [ -L "$policy" ] || [ -f "$policy" ] || exit 1
        [ ! -d "$policy" ] || exit 1
        cp -a -- "$policy" "$saved" || exit 1
        if [ -x "$policy" ]; then [ -f "$policy" ] && cp -Lp -- "$policy" "$directory/apache.policy.exec" || exit 1; fi
      else : > "$directory/apache.policy.absent" || exit 1; fi
      quoted=${directory//\'/\'\\\'\'}
      # shellcheck disable=SC2016 # The generated policy expands these arguments when called.
      printf '%s\n' '#!/bin/sh' '# distrorejuve legacy Apache handoff' \
        'case "$1:$2" in apache2:*|apache2.service:*|--quiet:apache2|--quiet:apache2.service) exit 101;; esac' \
        "if [ -x '$quoted/apache.policy.exec' ]; then exec '$quoted/apache.policy.exec' \"\$@\"; fi" \
        'exit 0' > "$wrapper" && chmod 755 "$wrapper" || exit 1
      : > "$directory/apache.legacy"
    ) || return 1
  fi
  [ -f "$wrapper" ] && [ ! -L "$wrapper" ] || return 1
  if [ -e "$policy" ] || [ -L "$policy" ]; then actual=$(stat -c '%u:%g:%a' "$policy") || return 1; fi
  if [ -f "$policy" ] && [ ! -L "$policy" ] && cmp -s -- "$wrapper" "$policy"; then
    case "$actual" in 0:*:755) owned=true;; *) echo 'dss:error: Legacy Apache guard ownership/mode changed; review it.' >&2; return 1;; esac
  elif [ -L "$saved" ]; then
    original=$(stat -c '%u:%g:%a' "$saved") || return 1
    original_link=$(readlink "$saved") && current_link=$(readlink "$policy") || return 1
    if [ ! -L "$policy" ] || [ "$original_link" != "$current_link" ] || [ "$original" != "$actual" ]; then
      echo 'dss:error: Legacy Apache policy changed; refusing to overwrite it.' >&2; return 1
    fi
  elif [ -f "$saved" ]; then
    original=$(stat -c '%u:%g:%a' "$saved") || return 1
    if [ ! -f "$policy" ] || [ -L "$policy" ] || ! cmp -s -- "$saved" "$policy" || [ "$original" != "$actual" ]; then
      echo 'dss:error: Legacy Apache policy changed; refusing to overwrite it.' >&2; return 1
    fi
  elif [ ! -f "$directory/apache.policy.absent" ] || [ -e "$policy" ] || [ -L "$policy" ]; then
    echo 'dss:error: Legacy Apache policy changed; refusing to overwrite it.' >&2; return 1
  fi
  if [ "$action" = prepare ]; then
    if ! $owned; then
      temporary=$(mktemp "$policy.distrorejuve.XXXXXX") || return 1
      if cp -p -- "$wrapper" "$temporary" && mv -fT -- "$temporary" "$policy"; then :
      else rm -f -- "$temporary"; return 1; fi
    fi
    /etc/init.d/apache2 stop || return 1
  else
    if $owned; then
      if [ -f "$directory/apache.policy.absent" ]; then rm -f -- "$policy" || return 1
      else
        temporary=$(mktemp "$policy.distrorejuve.XXXXXX") || return 1
        if cp -a --remove-destination -- "$saved" "$temporary" && mv -fT -- "$temporary" "$policy"; then :
        else rm -f -- "$temporary"; return 1; fi
      fi
    fi
    if ! invoke-rc.d apache2 start; then
      upgrade_php_apache_legacy_control "$directory" prepare || return 1
      echo 'dss:error: Apache start failed; the legacy package-start guard was restored. Review before reboot.' >&2
      return 1
    fi
  fi
}

# mod_php executes PHP inside Apache; FPM runs PHP in separate worker processes.
# A systemd mask blocks starts, including package-triggered starts, while the Apache handler is absent.
# Keep Apache unable to serve PHP source between removal and activation of its handler.
# An owned persistent mask remains on failures and across reboot for a safe retry.
function upgrade_php_apache_control() {
  local directory=$1 action=$2 state runtime=/run/systemd/system/apache2.service persistent=/etc/systemd/system/apache2.service file active
  local helper_mask=/var/lib/systemd/deb-systemd-helper-masked/apache2.service
  local systemd=false
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then
    case "$(readlink /proc/1/exe)" in */systemd|*/'systemd (deleted)') systemd=true;; esac
  fi
  if [ -f "$directory/apache.legacy" ] || { [ ! -f "$directory/apache.state" ] && ! $systemd; }; then
    upgrade_php_apache_legacy_control "$directory" "$action"
    return $?
  fi
  $systemd || { echo 'dss:error: Recorded systemd Apache handoff requires its original service manager.' >&2; return 1; }
  for file in "$persistent" "$runtime"; do
    if [ -e "$file" ] || [ -L "$file" ]; then
      if [ ! -L "$file" ] || [ "$(readlink "$file")" != /dev/null ]; then
        echo "dss:error: Custom Apache unit $file prevents automatic PHP service handoff." >&2; return 1
      fi
    fi
  done
  if [ "$action" = prepare ]; then
    if [ -e "$helper_mask" ] || [ -L "$helper_mask" ]; then
      echo 'dss:error: Debian service-helper mask state exists for Apache; review it before PHP handoff.' >&2
      return 1
    fi
    if [ ! -f "$directory/apache.state" ]; then
      state=$(systemctl show -p LoadState -p ActiveState -p UnitFileState apache2.service) || return 1
      printf '%s\n' "$state" | grep -qx 'LoadState=loaded' || {
        # An existing operator mask legitimately reports LoadState=masked.
        printf '%s\n' "$state" | grep -qx 'LoadState=masked' || return 1
      }
      printf '%s\n' "$state" | grep -Eq '^ActiveState=(active|inactive)$' || return 1
      if printf '%s\n' "$state" | grep -Eq '^UnitFileState=masked(-runtime)?$' || [ -L "$persistent" ] || [ -L "$runtime" ]; then
        : > "$directory/apache.operator-mask" || return 1
      fi
      printf '%s\n' "$state" > "$directory/apache.state.new" && mv "$directory/apache.state.new" "$directory/apache.state" || return 1
    fi
    if [ ! -L "$persistent" ]; then : > "$directory/apache.mask-owned" || return 1; fi
    systemctl mask apache2.service || return 1
    [ -L "$persistent" ] && [ "$(readlink "$persistent")" = /dev/null ] || return 1
    state=$(systemctl show -p LoadState apache2.service) || return 1
    [ "$state" = LoadState=masked ] || { echo 'dss:error: systemd did not load the Apache mask; package changes stopped.' >&2; return 1; }
    systemctl stop apache2.service || return 1
    active=$(systemctl show -p ActiveState apache2.service) || return 1
    [ "$active" = ActiveState=inactive ] || return 1
  elif [ "$action" = finish ]; then
    [ -f "$directory/apache.state" ] || return 1
    if [ -f "$directory/apache.mask-owned" ]; then
      systemctl unmask apache2.service || return 1
      [ ! -e "$persistent" ] && [ ! -L "$persistent" ] || return 1
    fi
    if [ ! -f "$directory/apache.operator-mask" ] && grep -qx 'ActiveState=active' "$directory/apache.state"; then
      if systemctl start apache2.service && active=$(systemctl show -p ActiveState apache2.service) && [ "$active" = ActiveState=active ]; then :
      else
        systemctl mask apache2.service
        systemctl stop apache2.service
        state=$(systemctl show -p LoadState apache2.service) || state=
        if [ -L "$persistent" ] && [ "$(readlink "$persistent")" = /dev/null ] && [ "$state" = LoadState=masked ]; then
          echo "dss:error: Apache failed to start; the owned persistent mask remains. Repair configuration and retry. State: $directory" >&2
        else
          echo "dss:error: Apache failed to start and its persistent mask could not be verified. Review immediately: $directory" >&2
        fi
        return 1
      fi
    fi
  else return 1; fi
}

# Retain the original removal allowlist, but do not request names dpkg has forgotten.
function upgrade_php_output_pending_removals() {
  local manifest=$1 packages=$2
  awk -F '\t' '
    FILENAME == ARGV[1] {
      if ($1 ~ / (installed|unpacked|half-installed|half-configured|triggers-awaited|triggers-pending)$/) {
        sub(/:.*/, "", $2); present[$2 ":" $3]=1
      }
      next
    }
    $1 in present { print $1 }
  ' <(printf '%s\n' "$packages") "$manifest"
}

# Preserve installed packages removed only by the smaller PHP install transaction.
function upgrade_php_output_preserved_packages() {
  local allowed=$1 plan=$2 packages=$3 native=$4
  awk -F '\t' -v native="$native" '
    function key(name) { if (name !~ /:/) name=name ":" native; return name }
    FILENAME == ARGV[1] { allowed[key($1)]=1; next }
    FILENAME == ARGV[2] {
      if ($1 ~ / (installed|unpacked|half-installed|half-configured|triggers-awaited|triggers-pending)$/) {
        name=$2; sub(/:.*/, "", name); present[name ":" $3]=1
      }
      next
    }
    /^Purg / { bad=1 }
    /^Remv / {
      split($0, fields, /[ \t\r\f\013]+/); package=fields[2]
      if (package !~ /^[a-z0-9][a-z0-9+.-]*(:[a-z0-9][a-z0-9-]*)?$/) { bad=1; next }
      name=package; sub(/:.*/, "", name)
      if ((key(package) in allowed) || (package !~ /:/ && ((name ":all") in allowed))) next
      if (package !~ /:/) {
        if ((name ":" native) in present) package=name ":" native
        else if ((name ":all") in present) package=name ":all"
        else { bad=1; next }
      }
      if (!(package in present)) { bad=1; next }
      if (package ~ /:all$/) sub(/:all$/, "", package)
      if (!seen[package]++) print package
    }
    END { exit bad }
  ' "$allowed" <(printf '%s\n' "$packages") "$plan"
}

# Only documentation-only dependency packages for explicitly unavailable extensions qualify.
function upgrade_php_is_obsolete_extension_meta() {
  local package=${1%%:*} mapping=$2 packages=$3 files
  case "$package" in php-cli|php-fpm|php-common|php-cgi|php-phpdbg) return 1;; php-?*) :;; *) return 1;; esac
  awk -F '\t' -v package="$package" '
    $5 == "unavailable" && index($1, "php" $3 "-") == 1 &&
      "php" substr($1, 4+length($3)) == package { found=1 }
    END { exit !found }
  ' "$mapping" || return 1
  awk -F '\t' -v package="$package" '
    $1 == "install ok installed" && $2 == package && $3 == "all" { found=1 }
    END { exit !found }
  ' <<< "$packages" || return 1
  files=$(dpkg-query -L "$package") || return 2
  upgrade_cleanup_payload_is_documentation "$package" "$files"
}

# PHP extensions are tied to a runtime branch; installing a newer CLI alone
# does not replace old FPM workers, Apache modules or their extensions. Preserve the role mapping
# across retries so an interrupted migration cannot silently choose a different target.
function upgrade_migrate_php_packages() {
(
  local package_umask
  package_umask=$(umask) || return 1
  umask 077
  local target=$1 packages default baseline directory status package arch branch suffix replacement mode concrete
  local apache='' audit file pending=false listed native preserved requested attempt additions original_packages apache_inventory
  local -a installs=()
  local -a removals=()
  local -a handoff_removals=()
  local -a arguments=()
  local -a apt_options=()
  local -a backups=()
  case "$target" in ''|*[!a-z0-9]*) return 1;; esac
  [ "$(id -u)" = 0 ] || return 1
  read -r -a apt_options <<< "$APT_GET_INSTALL_OPTIONS"
  if directory=$(upgrade_php_output_pending_directory); then pending=true
  else status=$?; [ "$status" -eq 1 ] || return 1; fi
  packages=$(dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Version}\n') || return 1
  if ! $pending && ! printf '%s\n' "$packages" | awk -F '\t' '$1 == "install ok installed" && $2 ~ /^(php5($|-)|php[0-9]+\.[0-9]+($|-)|libapache2-mod-php[0-9])/ { found=1 } END { exit !found }'; then return 0; fi
  upgrade_php_runtime_prepare || return 1
  default=$(umask "$package_umask" && upgrade_php_output_default_branch) || return 1
  if $pending; then
    if [ "$(cat "$directory/target")" != "$target" ] || [ "$(cat "$directory/branch")" != "$default" ]; then
      echo "dss:error: Resume the recorded PHP migration before selecting another target/default branch: $directory" >&2; return 1;
    fi
  else
    baseline=$(config_state_output_baseline) || { echo 'dss:error: PHP migration requires a recorded pre-upgrade comparison baseline.' >&2; return 1; }
    mkdir -p "$baseline.php-migration" && chmod 700 "$baseline.php-migration" || return 1
    directory=$(mktemp -d "$baseline.php-migration/$target.XXXXXX") || return 1
    printf '%s\n' "$packages" > "$directory/packages.before" || return 1
    printf '%s\n' "$target" > "$directory/target" || return 1
    printf '%s\n' "$default" > "$directory/branch" || return 1
    : > "$directory/mapping" || return 1
    while IFS=$'\t' read -r status package arch _; do
      [ "$status" = 'install ok installed' ] || continue
      package=${package%%:*}; mode=normal
      case "$package" in
        libapache2-mod-php5filter) branch=5; replacement=libapache2-mod-php; mode=apache;;
        libapache2-mod-php[0-9]*) branch=${package#libapache2-mod-php}; replacement=libapache2-mod-php; mode=apache;;
        php5|php5-*|php[0-9]*.[0-9]*)
          branch=${package#php}; branch=${branch%%-*}; suffix=${package#php"$branch"}
          case "$suffix" in
            '') replacement=-; mode=meta;;
            -common) replacement=php-common; mode=common;;
            -mysqlnd) replacement=php-mysql;;
            -sqlite) replacement=php-sqlite3;;
            -*) replacement=php${suffix};;
            *) continue;;
          esac;;
        *) continue;;
      esac
      [[ "$branch" = 5 || "$branch" =~ ^[0-9]+[.][0-9]+$ ]] || continue
      if [ "$replacement" != - ]; then
        if (umask "$package_umask" && upgrade_php_has_candidate "$replacement"); then :
        else
          status=$?; [ "$status" -eq 1 ] || return 1
          # Some default roles, including opcache, have only a concrete branch package.
          case "$replacement" in php-*)
            concrete=php"$default"${replacement#php}
            if (umask "$package_umask" && upgrade_php_has_candidate "$concrete"); then
              replacement=$concrete; status=0
            else status=$?; [ "$status" -eq 1 ] || return 1; fi;;
          esac
          if [ "$status" -ne 0 ]; then
            echo "dss:warn: No target $replacement package for $package:$arch; removing the old extension without purging its configuration. Review application requirements separately." >&2
            replacement=-; mode=unavailable
          fi
        fi
      fi
      printf '%s\t%s\t%s\t%s\t%s\n' "$package" "$arch" "$branch" "$replacement" "$mode" >> "$directory/mapping" || return 1
    done <<< "$packages"
    : > "$directory/install.packages" && : > "$directory/remove.packages" && : > "$directory/apache.remove" || return 1
    while IFS=$'\t' read -r package arch branch replacement mode; do
      [ "$replacement" = - ] || printf '%s\n' "$replacement" >> "$directory/install.packages" || return 1
      if [ "$mode" = apache ]; then
        apache="libapache2-mod-php$default"
        printf '%s\n' "$apache" > "$directory/apache.package" || return 1
      fi
      [ "$branch" != "$default" ] || [ "$mode" = unavailable ] || continue
      printf '%s\n' "$package:$arch" >> "$directory/remove.packages" || return 1
      [ "$mode" != apache ] || printf '%s\n' "$package:$arch" >> "$directory/apache.remove" || return 1
    done < "$directory/mapping"
    sort -u "$directory/install.packages" -o "$directory/install.packages" || return 1
  fi
  original_packages=$(cat "$directory/packages.before") || return 1
  apache_inventory="$directory/packages.before"
  if [ -f "$directory/apache.inventory" ]; then apache_inventory="$directory/apache.inventory"; fi
  if [ -f "$directory/apache.package" ] || [ -f "$directory/apache.inventory" ]; then
    if upgrade_php_has_apache_server "$packages"; then
      if [ -f "$directory/apache.inventory" ]; then
        echo "dss:error: Apache use changed during an unfinished PHP migration. Review $directory before retrying." >&2
        return 1
      fi
    else
      status=$?
      [ "$status" -eq 1 ] || { echo 'dss:error: Cannot establish whether Apache is in use. PHP package changes stopped.' >&2; return 1; }
      if [ -f "$directory/apache.state" ] || [ -f "$directory/apache.legacy" ] || [ -f "$directory/apache.mask-owned" ]; then
        echo "dss:error: Apache handoff state already exists. Review $directory before removing unused modules." >&2
        return 1
      fi
      # Recompute the optional php selector decision; current FPM/CGI may differ on a retry.
      awk '$0 != "php:all"' "$directory/remove.packages" > "$directory/remove.packages.new" || return 1
      # Current packages determine backend use; original packages supply removal provenance.
      awk -F '\t' '
        FILENAME == ARGV[1] {
          if ($1 ~ / (installed|unpacked|half-installed|half-configured|triggers-awaited|triggers-pending)$/ &&
              $2 ~ /^php(5|[0-9]+[.][0-9]+)-(fpm|cgi)(:[a-z0-9-]+)?$/) backend=1
          next
        }
        $1 ~ / (installed|unpacked|half-installed|half-configured|triggers-awaited|triggers-pending)$/ {
          name=$2; sub(/:.*/, "", name)
          if (name ~ /^libapache2-mod-php/) handlers[name ":" $3]=1
          if (name ~ /^php([0-9]+([.][0-9]+)?)?$/) selectors[name ":" $3]=1
        }
        END {
          for (name in handlers) print name
          if (!backend) for (name in selectors) print name
        }
      ' <(printf '%s\n' "$packages") "$directory/packages.before" >> "$directory/remove.packages.new" || return 1
      sort -u "$directory/remove.packages.new" -o "$directory/remove.packages.new" || return 1
      mv "$directory/remove.packages.new" "$directory/remove.packages" || return 1
      awk '
        FILENAME == ARGV[1] { name=$0; sub(/:.*/, "", name); removed[name]=1; next }
        !($0 in removed) && $0 !~ /^libapache2-mod-php/ { print }
      ' "$directory/remove.packages" "$directory/install.packages" > "$directory/install.packages.new" || return 1
      mv "$directory/install.packages.new" "$directory/install.packages" || return 1
      awk -F '\t' '
        $2 !~ /^libapache2-mod-php/ && $2 !~ /^(apache2|apache2[.]2-common|apache2-mpm-.*)(:[a-z0-9-]+)?$/
      ' "$directory/packages.before" > "$directory/apache.inventory" || return 1
      apache_inventory="$directory/apache.inventory"
      : > "$directory/apache.remove" || return 1
      rm -f -- "$directory/"{apache.package,apache.handoff,apache.excluded,apache.allowed-removals,remove.plan} || return 1
      apache=
      echo 'dss:warn: Removing unused Apache PHP packages. Apache will not be installed. Installed PHP CLI and extension packages will still be upgraded.' >&2
    fi
  fi
  # Temporarily remove the installed Apache PHP meta so APT cannot upgrade its handler during removal.
  # The normal install plan restores it; it must never enter the permanent removal list.
  if [ -s "$directory/apache.remove" ]; then
    listed=$(upgrade_php_output_pending_removals <(printf '%s\n' libapache2-mod-php:all) "$packages") || return 1
    if [ -n "$listed" ]; then
      grep -qxF libapache2-mod-php "$directory/install.packages" || return 1
      printf '%s\n' "$listed" >> "$directory/apache.remove" || return 1
      sort -u "$directory/apache.remove" -o "$directory/apache.remove" || return 1
    fi
  fi
  # Versionless PHP packages can disappear with the old handler; restore supported ones.
  : > "$directory/apache.meta-removals" || return 1
  while IFS=$'\t' read -r status package arch _; do
    if [ "$status" != 'install ok installed' ] || [ "$arch" != all ]; then continue; fi
    package=${package%%:*}
    case "$package" in php-common) continue;; php|php-*) :;; *) continue;; esac
    if grep -qxF "$package:all" "$directory/remove.packages"; then :
    elif [ "$package" = php ]; then
      (umask "$package_umask" && upgrade_php_has_candidate "$package") || return 1
      grep -qxF "$package" "$directory/install.packages" || printf '%s\n' "$package" >> "$directory/install.packages" || return 1
    elif grep -qxF "$package" "$directory/install.packages"; then :
    elif upgrade_php_is_obsolete_extension_meta "$package" "$directory/mapping" "$original_packages"; then
      printf '%s:all\n' "$package" >> "$directory/remove.packages" || return 1
      echo "dss:warn: Removing obsolete PHP dependency package $package with its unavailable extension; configuration will not be purged." >&2
    else
      status=$?; [ "$status" -eq 1 ] || return 1
      continue
    fi
    printf '%s:all\n' "$package" >> "$directory/apache.meta-removals" || return 1
  done < "$directory/packages.before"
  while IFS= read -r package; do [ -z "$package" ] || installs+=("$package"); done < "$directory/install.packages"
  listed=$(upgrade_php_output_pending_removals "$directory/remove.packages" "$packages") || return 1
  while IFS= read -r package; do [ -z "$package" ] || removals+=("$package"); done <<< "$listed"
  listed=$(upgrade_php_output_pending_removals "$directory/apache.remove" "$packages") || return 1
  while IFS= read -r package; do [ -z "$package" ] || handoff_removals+=("$package"); done <<< "$listed"
  if [ -f "$directory/apache.package" ]; then apache=$(cat "$directory/apache.package") || return 1; fi
  # Configured concrete default roles need no reinstall merely to add optional versionless metas.
  # Mapping/candidate checks above still reject unavailable roles; partial PHP state needs repair.
  if ! $pending && [ "${#removals[@]}" -eq 0 ]; then
    status=0
    printf '%s\n' "$packages" | awk -F '\t' '
      $1 ~ / (unpacked|half-installed|half-configured|triggers-awaited|triggers-pending)$/ &&
        $2 ~ /^(php([0-9]+([.][0-9]+)?)?($|[-:])|libapache2-mod-php)/ { bad=1 }
      END { exit bad }
    ' || status=$?
    [ "$status" -le 1 ] || return 1
    if [ "$status" -eq 0 ]; then
      # Delete only this invocation's unstarted mktemp records; no backup or mutation occurred.
      rm -f -- "$directory/"{packages.before,target,branch,mapping,retained,install.packages,remove.packages,apache.remove,apache.package,apache.meta-removals} || return 1
      rmdir -- "$directory" || return 1
      return 0
    fi
  fi
  if [ -n "$apache" ]; then
    if [ "${#handoff_removals[@]}" -gt 0 ] || $pending; then : > "$directory/apache.handoff" || return 1
    elif upgrade_php_apache_module_is_enabled "$apache"; then :
    else
      status=$?; [ "$status" -eq 1 ] || return 1
      : > "$directory/apache.handoff" || return 1
    fi
  fi
  if ! $pending; then
    for file in etc/php etc/php5 etc/apache2 var/lib/dpkg/status var/lib/apt/extended_states var/lib/ucf/hashfile var/lib/ucf/registry; do
      [ ! -e "/$file" ] && [ ! -L "/$file" ] || backups+=("$file")
    done
    tar -C / -czpf "$directory/config-state.tar.gz" "${backups[@]}" || return 1
  fi
  arguments=("${installs[@]}")
  [ -z "$apache" ] || arguments+=("$apache")
  for package in "${removals[@]}"; do arguments+=("$package-"); done
  native=$(dpkg --print-architecture) || return 1
  [[ "$native" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
  echo "dss:stage: Checking package changes for PHP $default" >&2
  if [ ! -f "$directory/normal-dist-upgrade.plan" ]; then
    (umask "$package_umask" && LC_ALL=C apt-get "${apt_options[@]}" -o APT::Get::Purge=false -o APT::Get::AutomaticRemove=false --simulate dist-upgrade) > "$directory/normal-dist-upgrade.plan.new" 2>&1 || return 1
    mv "$directory/normal-dist-upgrade.plan.new" "$directory/normal-dist-upgrade.plan" || return 1
  fi
  cat "$directory/remove.packages" > "$directory/install.allowed-removals.new" || return 1
  awk '
    /^Purg / { bad=1 }
    /^Remv / {
      if ($2 !~ /^[a-z0-9][a-z0-9+.-]*(:[a-z0-9][a-z0-9-]*)?$/) bad=1
      else print $2
    }
    END { exit bad }
  ' "$directory/normal-dist-upgrade.plan" >> "$directory/install.allowed-removals.new" || return 1
  mv "$directory/install.allowed-removals.new" "$directory/install.allowed-removals" || return 1
  # Negative constraints apply only to new Apache additions, never an existing server role.
  if [ ! -f "$directory/apache.excluded" ]; then
    upgrade_php_output_new_apache_packages "$apache_inventory" "$directory/normal-dist-upgrade.plan" > "$directory/apache.excluded" || return 1
  fi
  while IFS= read -r package; do [ -z "$package" ] || arguments+=("$package-"); done < "$directory/apache.excluded"
  for ((attempt=0; attempt<8; attempt++)); do
    (umask "$package_umask" && LC_ALL=C apt-get "${apt_options[@]}" -o APT::Get::Purge=false -o APT::Get::AutomaticRemove=false --simulate --reinstall install "${arguments[@]}") > "$directory/install.plan" 2>&1 || return 1
    additions=$(upgrade_php_output_new_apache_packages "$apache_inventory" "$directory/install.plan") || return 1
    if [ -n "$additions" ]; then
      [ "$attempt" -lt 7 ] || { echo "dss:error: Cannot preserve the existing web-server role; inspect $directory/install.plan." >&2; return 1; }
      while IFS= read -r package; do
        grep -qxF -- "$package" "$directory/apache.excluded" && { echo "dss:error: APT still selects excluded Apache package $package; inspect $directory/install.plan." >&2; return 1; }
        printf '%s\n' "$package" >> "$directory/apache.excluded" || return 1
        arguments+=("$package-")
      done <<< "$additions"
      continue
    fi
    upgrade_php_check_plan "$directory/install.allowed-removals" "$directory/install.plan" false "$native" && break
    [ "$attempt" -lt 7 ] || { echo "dss:error: PHP preservation exceeded eight simulations; inspect $directory/install.plan." >&2; return 1; }
    preserved=$(upgrade_php_output_preserved_packages "$directory/install.allowed-removals" "$directory/install.plan" "$packages" "$native") || {
      echo "dss:error: Cannot safely preserve packages in the PHP plan; inspect $directory/install.plan." >&2; return 1;
    }
    [ -n "$preserved" ] || return 1
    while IFS= read -r package; do
      for requested in "${installs[@]}" "$apache"; do
        requested=${requested%:all}
        if [ "$requested" = "$package" ] || [ "$requested:$native" = "$package" ]; then
          echo "dss:error: PHP plan still removes explicitly requested $package; inspect $directory/install.plan." >&2; return 1
        fi
      done
      if (umask "$package_umask" && upgrade_php_has_candidate "$package"); then :
      else
        status=$?
        if [ "$status" -eq 1 ] && upgrade_php_is_obsolete_extension_meta "$package" "$directory/mapping" "$packages"; then
          printf '%s:all\n' "${package%%:*}" >> "$directory/remove.packages" || return 1
          printf '%s:all\n' "${package%%:*}" >> "$directory/install.allowed-removals" || return 1
          arguments+=("${package%%:*}-")
          echo "dss:warn: Removing obsolete PHP dependency package $package with its unavailable extension; configuration will not be purged." >&2
          continue
        fi
        echo "dss:error: No verified target candidate to preserve $package; inspect $directory/install.plan." >&2; return 1
      fi
      printf '%s\n' "$package" >> "$directory/install.packages" || return 1
      installs+=("$package")
      arguments+=("$package")
    done <<< "$preserved"
  done
  if [ "${#handoff_removals[@]}" -gt 0 ]; then
    # Retained PHP selectors can pull in the new handler; remove approved PHP packages explicitly.
    cat "$directory/remove.packages" "$directory/apache.remove" "$directory/apache.meta-removals" > "$directory/apache.allowed-removals" || return 1
    sort -u "$directory/apache.allowed-removals" -o "$directory/apache.allowed-removals" || return 1
    listed=$(upgrade_php_output_pending_removals "$directory/apache.allowed-removals" "$packages") || return 1
    handoff_removals=()
    while IFS= read -r package; do [ -z "$package" ] || handoff_removals+=("$package"); done <<< "$listed"
    (umask "$package_umask" && LC_ALL=C apt-get "${apt_options[@]}" -o APT::Get::Purge=false -o APT::Get::AutomaticRemove=false --simulate remove "${handoff_removals[@]}") > "$directory/remove.plan" 2>&1 || return 1
    upgrade_php_check_apache_removal_plan "$directory" "$native" || {
      echo "dss:error: Apache/PHP removal plan was rejected; only approved removals and checked existing-package upgrades are allowed. Review $directory/remove.plan, $directory/apache.allowed-removals and $directory/install.plan before retrying." >&2
      return 1
    }
  fi
  (umask "$package_umask" && LC_ALL=C apt-get "${apt_options[@]}" -o APT::Get::Purge=false -o APT::Get::AutomaticRemove=false --download-only --reinstall install "${arguments[@]}") || return 1
  : > "$directory/started" || return 1
  if [ -f "$directory/apache.handoff" ]; then
    echo "dss:stage: Preparing Apache for PHP package changes; state: $directory" >&2
    upgrade_php_apache_control "$directory" prepare || {
      status=$?
      printf 'dss:error: Apache/PHP preparation failed (status %s); review %s before retrying.\n' "$status" "$directory" >&2
      return 1
    }
  fi
  echo "dss:stage: Updating installed PHP packages to the distribution's default PHP version ($default); configs/inventory: $directory" >&2
  if [ -f "$directory/apache.handoff" ] && [ "${#handoff_removals[@]}" -gt 0 ]; then
    (umask "$package_umask" && LC_ALL=C apt-get "${apt_options[@]}" -o APT::Get::Purge=false -o APT::Get::AutomaticRemove=false remove "${handoff_removals[@]}") || return 1
    # Removing the old handler can also remove its no-conffile PHP metapackage.
    packages=$(dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Version}\n') || return 1
    listed=$(upgrade_php_output_pending_removals "$directory/remove.packages" "$packages") || return 1
    arguments=("${installs[@]}")
    [ -z "$apache" ] || arguments+=("$apache")
    while IFS= read -r package; do [ -z "$package" ] || arguments+=("$package-"); done <<< "$listed"
    while IFS= read -r package; do [ -z "$package" ] || arguments+=("$package-"); done < "$directory/apache.excluded"
  fi
  (umask "$package_umask" && LC_ALL=C apt-get "${apt_options[@]}" -o APT::Get::Purge=false -o APT::Get::AutomaticRemove=false --no-download --reinstall install "${arguments[@]}") || return 1
  for package in "${installs[@]}" "$apache"; do
    [ -n "$package" ] || continue
    [ "$(dpkg-query -W -f='${Status}' "$package")" = 'install ok installed' ] || return 1
  done
  if [ -n "$apache" ]; then
    upgrade_php_apache_module_is_enabled "$apache" || { echo "dss:error: Package scripts did not enable $apache; inspect $directory before retrying." >&2; return 1; }
  fi
  audit=$(LC_ALL=C dpkg --audit 2>&1) || { printf '%s\n' "$audit" >&2; return 1; }
  [ -z "$audit" ] || { printf '%s\n' "$audit" >&2; return 1; }
  (umask "$package_umask" && LC_ALL=C apt-get check) || return 1
  if [ -f "$directory/apache.state" ] || [ -f "$directory/apache.legacy" ]; then
    upgrade_php_apache_control "$directory" finish || {
      status=$?
      printf 'dss:error: Apache/PHP completion failed (status %s); review %s before retrying.\n' "$status" "$directory" >&2
      return 1
    }
  fi
  : > "$directory/completed" || return 1
)
}

# shellcheck shell=bash
# Runtime checks read status/configuration only; they never start or reconfigure services.
# 0 active, 1 stopped/failed, 2 cannot establish state. Enabled is not the same as active.
# systemctl ActiveState=active -> running; initctl "nginx stop/waiting" -> stopped.
function upgrade_php_runtime_service_is_active() {
  local name=$1 state status
  local -a bounded=()
  case "$name" in apache2|nginx|php5-fpm|dovecot|exim4|mysql|mariadb|ssh|fail2ban|bind9|redis-server|slapd|rabbitmq-server) :;; php[0-9]*.[0-9]*-fpm) :;; *) return 2;; esac
  command -v timeout >/dev/null && bounded=(timeout 20)
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then
    case "$(readlink /proc/1/exe)" in
      */systemd|*/'systemd (deleted)')
        state=$(LC_ALL=C "${bounded[@]}" systemctl show -p ActiveState "$name.service" 2>/dev/null) || return 2
        case "$state" in ActiveState=active) return 0;; ActiveState=inactive|ActiveState=failed) return 1;; *) return 2;; esac;;
    esac
  fi
  if [ -f "/etc/init/$name.conf" ] && command -v initctl >/dev/null; then
    state=$(LC_ALL=C "${bounded[@]}" initctl status "$name" 2>/dev/null) || return 2
    case "$state" in "$name start/running"*) return 0;; "$name stop/waiting"*) return 1;; *) return 2;; esac
  fi
  if [ -x "/etc/init.d/$name" ]; then
    LC_ALL=C "${bounded[@]}" "/etc/init.d/$name" status >/dev/null 2>&1
    status=$?
    case "$status" in 0) return 0;; 1|2|3) return 1;; *) return 2;; esac
  fi
  return 2
}

# One batch query; conffiles-only and partially configured packages are not running roles.
# php8.4-fpm:amd64<TAB>install ok installed -> fpm<TAB>php8.4-fpm; config-files state produces no role.
function upgrade_php_runtime_output_roles() {
  local packages roles
  packages=$(dpkg-query -W -f='${Package}\t${Status}\n') || return 1
  roles=$(printf '%s\n' "$packages" | awk -F '\t' '
    $2 ~ /^(install|hold) ok installed$/ {
      name=$1; sub(/:.*/, "", name)
      if (name ~ /^php(5|[0-9]+[.][0-9]+)-fpm$/) print "fpm\t" name
      if (name == "apache2" || name == "apache2.2-common") apache=1
      if (name ~ /^nginx(-(core|full|light|extras))?$/) nginx=1
    }
    END { if (apache) print "apache\tapache2"; if (nginx) print "nginx\tnginx" }
  ') || return 1
  [ -z "$roles" ] || printf '%s\n' "$roles" | sort -u
}

# The caller supplies a private directory underneath its recorded pre-upgrade baseline.
function upgrade_php_runtime_snapshot() {
(
  umask 077
  local directory=$1 roles kind service state status file
  if [ ! -d "$directory" ] || [ -L "$directory" ] || [ "$(stat -c '%u:%a' -- "$directory")" != 0:700 ]; then
    echo 'dss:error: PHP runtime snapshot directory must be root-owned and private (700).' >&2; return 1
  fi
  file="$directory/services.before"
  if [ -e "$file" ] || [ -L "$file" ]; then
    if [ ! -f "$file" ] || [ -L "$file" ] || [ ! -r "$file" ] || [ "$(stat -c '%u:%h' -- "$file")" != 0:1 ]; then
      echo 'dss:error: Refusing an unsafe existing PHP runtime snapshot; review its owner/type/links.' >&2; return 1
    fi
    # A default ACL can override umask; secure the original snapshot without replacing it.
    chmod 600 -- "$file" || { echo 'dss:error: Cannot secure the existing PHP runtime snapshot.' >&2; return 1; }
    return 0
  fi
  roles=$(upgrade_php_runtime_output_roles) || return 1
  file="$directory/services.before.new"
  if [ -e "$file" ] || [ -L "$file" ]; then
    if [ ! -f "$file" ] || [ -L "$file" ] || [ "$(stat -c '%u:%h' -- "$file")" != 0:1 ]; then
      echo 'dss:error: Refusing an unsafe staged PHP runtime snapshot.' >&2; return 1
    fi
  fi
  if ! { : > "$file" && chmod 600 -- "$file"; }; then
    echo 'dss:error: Cannot create a private PHP runtime snapshot.' >&2; return 1
  fi
  while IFS=$'\t' read -r kind service; do
    [ -n "$service" ] || continue
    if upgrade_php_runtime_service_is_active "$service"; then state=active
    else
      status=$?; state=inactive
      if [ "$status" -ne 1 ]; then
        state=unknown
        echo "dss:warn: Cannot establish pre-upgrade activity of $service; its runtime verification is incomplete." >&2
      fi
    fi
    printf '%s\t%s\t%s\n' "$kind" "$service" "$state" >> "$file" || return 1
  done <<< "$roles"
  mv -- "$file" "$directory/services.before"
)
}

# FastCGI connects a web server to PHP-FPM over a Unix socket or TCP.
# A version change can change the socket path, leaving an active web server unable to run PHP.
# Parse only include/listen/FastCGI directives; never run a server/configuration interpreter.
# NGINX: fastcgi_pass unix:/run/php/site.sock; FPM: listen = /run/php/site.sock
# Output: include|socket|tcp|unknown TAB value. Dynamic/unsupported syntax stays unknown.
function upgrade_php_runtime_output_directives() {
  local kind=$1 file=$2
  case "$kind" in nginx|fpm) :;; *) return 1;; esac
  [ -f "$file" ] && [ -r "$file" ] && [ "$(stat -c '%s' -- "$file")" -le 1048576 ] || return 1
  # nginx: fastcgi_pass unix:/run/php/php8.4-fpm.sock; -> socket<TAB>/run/php/php8.4-fpm.sock.
  # nginx: fastcgi_pass 127.0.0.1:9000; -> tcp<TAB>127.0.0.1:9000; fastcgi_pass $UPSTREAM; -> unknown.
  LC_ALL=C awk -v kind="$kind" '
    function unresolved(reason) { if (!reported[reason]++) print "unknown\t" reason }
    function emit() {
      if ((words[1] == "include" || words[1] == "fastcgi_pass") && directive_escaped) unresolved("escaped_nginx_syntax")
      else if (words[1] == "include") {
        if (count == 2) print "include\t" words[2]; else unresolved("include_syntax")
      } else if (words[1] == "fastcgi_pass") {
        if (count != 2) unresolved("fastcgi_syntax")
        else if (words[2] ~ /^unix:\//) { sub(/^unix:/, "", words[2]); print "socket\t" words[2] }
        else if (words[2] ~ /^[0-9.]+:[0-9]+$/ || words[2] ~ /^\[[0-9a-fA-F:]+\]:[0-9]+$/) print "tcp\t" words[2]
        else unresolved("indirect_fastcgi_upstream")
      }
      count=0; token=""; directive_escaped=0
    }
    function word() { if (token != "") words[++count]=token; token="" }
    FNR > 20000 { print "unknown\tline_limit"; exit }
    kind == "fpm" {
      # [www] followed by listen = /run/php/php8.4-fpm.sock -> socket<TAB>/run/php/php8.4-fpm.sock<TAB>www.
      line=$0; sub(/[;#].*$/, "", line)
      if (line ~ /^[ \t]*\[[^]]+\][ \t\r]*$/) {
        sub(/^[ \t]*\[/, "", line); sub(/\][ \t\r]*$/, "", line); pool=line
      } else if (line ~ /^[ \t]*include[ \t]*=/) {
        sub(/^[^=]*=[ \t]*/, "", line); sub(/[ \t\r]*$/, "", line); print "include\t" line
      } else if (line ~ /^[ \t]*listen[ \t]*=/) {
        sub(/^[^=]*=[ \t]*/, "", line); sub(/[ \t\r]*$/, "", line)
        if (pool == "" || pool == "global") print "unknown\tlisten_without_pool"
        else if (line ~ /^\//) listens[pool]="socket\t" line "\t" pool
        else if (line ~ /^[0-9.]+:[0-9]+$/ || line ~ /^[0-9]+$/ || line ~ /^\[[0-9a-fA-F:]+\]:[0-9]+$/) listens[pool]="tcp\t" line "\t" pool
        else listens[pool]="unknown\tdynamic_fpm_listen\t" pool
      }
      next
    }
    {
      for (i=1; i<=length($0); i++) {
        c=substr($0,i,1)
        if (escaped) { escaped=0; token=token c; continue }
        if (c == "\\") { escaped=1; directive_escaped=1; continue }
        if (quote != "") { if (c == quote) quote=""; else token=token c; continue }
        if (c == "\042" || c == "\047") { quote=c; continue }
        if (c == "#") break
        if (c == ";") { word(); emit() }
        else if (c == "{" || c == "}") { word(); count=0; directive_escaped=0 }
        else if (c ~ /[ \t\r\f\013]/) word()
        else token=token c
      }
      if (quote == "" && !escaped) word(); else token=token "\n"
    }
    END {
      if (kind == "fpm") { for (pool in listens) print listens[pool] }
      else if (quote != "" || escaped || count) print "unknown\tunfinished_nginx_directive"
    }
  ' "$file"
}

# Resolve enabled-site links before checking ownership; modified conffiles are local settings too.
function upgrade_php_runtime_output_config_origin() {
  local file owner status records checksum actual
  file=$(readlink -f -- "$1") || return 1
  [ -f "$file" ] && [ -r "$file" ] || return 1
  if owner=$(packages_output_file_owner "$file"); then
    records=$(LC_ALL=C dpkg-query -W -f='${Conffiles}\n' "$owner") || return 1
    checksum=$(awk -v file="$file" '$1 == file && NF == 2 { print $2 }' <<< "$records") || return 1
    if [ -n "$checksum" ]; then
      case "$checksum" in *[!0-9a-fA-F]*) return 1;; esac
      [ "${#checksum}" -eq 32 ] || return 1
      actual=$(md5sum < "$file") || return 1
      if [ "${actual%% *}" != "$checksum" ]; then printf '%s\n' modified; return 0; fi
    fi
    printf '%s\n' packaged
  else
    status=$?
    [ "$status" -eq 1 ] || return 1
    printf '%s\n' unowned
  fi
}

# Collector calls inherit the current private staging file and release from upgrade_php_runtime_check.
function upgrade_php_runtime_finding() {
  local severity=$1 key=$2 message=$3 level=warn
  case "$severity" in error) level=error;; warning|unknown) :;; *) return 1;; esac
  case "$key$findings_release$message" in *$'\t'*|*$'\n'*|*$'\r'*)
    echo 'dss:error: Cannot record a finding containing control separators.' >&2; return 1;; esac
  printf 'dss:%s: %s\n' "$level" "$message" >&2
  printf '%s\t%s\t%s\tcurrent\t%s\n' "$severity" "$key" "$findings_release" "$message" >> "$findings_file"
}

function upgrade_php_runtime_findings_complete() {
  [ -f "$1" ] && [ ! -L "$1" ] && [ ! -e "$1.pending" ] && [ ! -L "$1.pending" ] &&
    awk -F '\t' '
      NF != 5 { bad=1 }
      $1 == "check" { checks++; if ($2 != "php-runtime" || $4 != "complete") bad=1; next }
      $1 !~ /^(error|warning)$/ || $4 != "current" { bad=1 }
      END { exit (checks != 1 || bad) }' "$1"
}

# Replace the human checklist atomically; the detailed log retains earlier observations.
function upgrade_php_runtime_write_review() {
(
  local findings=$1 directory=$2 temporary pending=false check_failed=${3:-false} target="$2/configuration-review.txt"
  [ -f "$findings" ] && [ ! -L "$findings" ] || return 1
  [ ! -L "$target" ] && { [ ! -e "$target" ] || { [ -f "$target" ] && [ "$(stat -c '%u:%h' -- "$target")" = 0:1 ]; }; } || return 1
  temporary=$(umask 077; mktemp "$directory/.configuration-review.XXXXXX") || return 1
  trap 'rm -f -- "$temporary"' EXIT
  chmod 600 -- "$temporary" || return 1
  [ ! -e "$findings.pending" ] && [ ! -L "$findings.pending" ] || pending=true
  awk -F '\t' -v pending="$pending" -v check_failed="$check_failed" '
    BEGIN {
      if (pending == "true") print "Latest web service check did not finish. Earlier findings are not reverified; review the detailed log."
      else if (check_failed == "true") print "Latest web service check failed. Saved findings need verification; review the detailed log."
    }
    NF != 5 { bad=1; next }
    $1 == "check" { checks++; next }
    $1 !~ /^(error|warning|unknown)$/ || $4 !~ /^(current|unverified)$/ { bad=1; next }
    $1 != "check" {
      if (!found++) print "Review required from the last saved web service check:"
      printf "- [%s; %s; %s] %s\n", $1, $3, (pending == "true" || $4 == "unverified" ? "not reverified" : (check_failed == "true" ? "needs verification" : "current")), $5
    }
    END { if (checks != 1 || bad) exit 1 }
  ' "$findings" > "$temporary" || return 1
  if [ -s "$temporary" ]; then mv -f -- "$temporary" "$target" || return 1
  else rm -f -- "$target" || return 1; fi
)
}

# Follow default configuration includes, bounded to 200 files and depth 16.
# Findings describe faults; return nonzero only when collection fails.
function upgrade_php_runtime_collect_socket_findings() {
(
  local kind=$1 main=$2 prefix=${2%/*} file depth records directive value pool match index=0 failure=false found=false sockets='' pool_records='' endpoints=0
  local origin identity
  local path_pattern='^/[A-Za-z0-9_./:@+-]+$' include_pattern='^[A-Za-z0-9_./*?-]+$'
  local -a files=("$main")
  local -a depths=(0)
  local seen=$'\n' pattern
  while [ "$index" -lt "${#files[@]}" ]; do
    file=${files[index]}
    case "$file" in *$'\t'*|*$'\n'*|*$'\r'*) echo 'dss:error: Unsupported control separator in configuration path.' >&2; return 1;; esac
    depth=${depths[index]}; index=$((index+1))
    case "$seen" in *$'\n'"$file"$'\n'*) continue;; esac
    seen="$seen$file"$'\n'
    if [ "$index" -gt 200 ] || [ "$depth" -gt 16 ]; then
      upgrade_php_runtime_finding unknown "$kind:include-limit" "$kind socket verification reached its include limit." || return 1; break
    fi
    if ! records=$(upgrade_php_runtime_output_directives "$kind" "$file"); then
      upgrade_php_runtime_finding unknown "$kind:read:$file" "Cannot inspect bounded $kind configuration $file; socket verification incomplete." || return 1
      continue
    fi
    while IFS=$'\t' read -r directive value pool; do
      [ -n "$directive" ] || continue
      if [ "$kind" = fpm ] && [ -n "$pool" ]; then pool_records="$pool_records$pool"$'\n'; fi
      case "$directive" in
        include)
          if [[ ! "$value" =~ $include_pattern ]]; then
            upgrade_php_runtime_finding unknown "$kind:include:$file:$value" "Unsupported/dynamic $kind include in $file; socket verification incomplete." || return 1; continue
          fi
          pattern=$value
          case "$pattern" in /*) :;; *) pattern="$prefix/$pattern";; esac
          found=false
          # Expansion is data, never evaluation; unsupported whitespace/metacharacters were rejected.
          for match in $pattern; do
            [ -e "$match" ] || continue
            found=true; files+=("$match"); depths+=("$((depth+1))")
            if [ "${#files[@]}" -gt 200 ]; then break; fi
          done
          if ! $found; then
            case "$pattern" in *'*'*|*'?'*) :;; *)
              upgrade_php_runtime_finding unknown "$kind:missing-include:$pattern" "Included $kind configuration $pattern is missing; verification incomplete." || return 1;; esac
          fi;;
        socket)
          if [[ ! "$value" =~ $path_pattern ]]; then
            upgrade_php_runtime_finding unknown "$kind:dynamic-socket:$file:$value" "Dynamic/unsupported $kind socket in $file; verification incomplete." || return 1
          else sockets="$sockets$value"$'\t'"$file"$'\t'"${pool:--}"$'\n'; endpoints=$((endpoints+1)); fi;;
        tcp) endpoints=$((endpoints+1)); echo "dss:trace: $kind uses a TCP FastCGI endpoint; network reachability is not probed." >&2;;
        unknown) upgrade_php_runtime_finding unknown "$kind:syntax:$file:$value" "$kind configuration $file needs manual verification ($value)." || return 1;;
      esac
    done <<< "$records"
  done
  records=$(printf '%s' "$sockets" | awk -F '\t' -v kind="$kind" -v records="$pool_records" '
    BEGIN { count=split(records, names, "\n"); for (i=1; i<=count; i++) pools[names[i]]++ }
    { print $1 "\t" $2 "\t" (kind == "fpm" && pools[$3] > 1 ? "duplicate" : "literal") }
  ') || { echo "dss:warn: Cannot classify $kind Unix socket records; verification incomplete." >&2; return 1; }
  while IFS=$'\t' read -r value file pool; do
    [ -n "$value" ] || continue
    if [ "$pool" = duplicate ]; then
      upgrade_php_runtime_finding unknown "fpm:duplicate:$file:$value" "FPM pool is defined in multiple included files; socket verification incomplete." || return 1
    elif [ ! -S "$value" ]; then
      if [ "$kind" = nginx ]; then
        if origin=$(upgrade_php_runtime_output_config_origin "$file"); then
          case "$origin" in
            unowned|modified)
              identity=$(readlink -f -- "$file") || return 1
              upgrade_php_runtime_finding warning "nginx:socket:${#identity}:$identity:$value" "Local configuration review: $file ($origin) references missing Unix socket $value; repair the application configuration after the distro upgrade." || return 1
              continue;;
          esac
        else echo "dss:warn: Cannot verify package ownership/defaults for $file; retaining the runtime failure." >&2; fi
      fi
      identity=$(readlink -f -- "$file") || return 1
      upgrade_php_runtime_finding error "$kind:socket:${#identity}:$identity:$value" "$kind configuration $file references missing Unix socket $value; review the PHP-FPM/upstream configuration." || return 1; failure=true
    else echo "dss:trace: $kind Unix socket exists: $value (listener/reachability not probed)." >&2; fi
  done <<< "$records"
  if [ "$kind" = fpm ] && [ "$endpoints" -eq 0 ]; then upgrade_php_runtime_finding unknown fpm:no-listener 'No literal PHP-FPM listener established; verification incomplete.' || return 1; fi
  if $failure && [ "$kind" = nginx ]; then
    echo 'dss:warn: Compare NGINX fastcgi_pass with the installed PHP-FPM listen setting. Review old/new pool users, groups and socket permissions before restarting services.' >&2
  fi
  return 0
)
}

# Collect current observations without encoding finding types in return values.
function upgrade_php_runtime_collect_findings() {
  local directory=$1 roles kind service state result current expected_fpm=false nginx=false dependencies selected count=0 main
  [ -f "$directory/services.before" ] && [ -r "$directory/services.before" ] || return 1
  roles=$(upgrade_php_runtime_output_roles) || return 1
  while IFS=$'\t' read -r kind service state; do
    case "$kind:$state" in fpm:active) expected_fpm=true; continue;; nginx:active) nginx=true;; apache:active) :;; *:inactive) continue;; *:unknown) upgrade_php_runtime_finding unknown "baseline:$kind:$service" "Original $service activity was not established; verification incomplete." || return 1; continue;; *) return 1;; esac
    if ! printf '%s\n' "$roles" | grep -qxF "$kind"$'\t'"$service"; then
      upgrade_php_runtime_finding error "service:$service" "Previously active $service no longer has a configured/installed web-server role." || return 1
      continue
    fi
    if upgrade_php_runtime_service_is_active "$service"; then :
    else
      result=$?
      if [ "$result" -eq 1 ]; then
        upgrade_php_runtime_finding error "service:$service" "$service was active before the upgrade and is now stopped/failed." || return 1
      else upgrade_php_runtime_finding unknown "service:$service" "Cannot verify expected active $service after package changes." || return 1; fi
    fi
  done < "$directory/services.before"
  if $expected_fpm; then
    selected=''
    if dependencies=$(LC_ALL=C apt-cache depends php-fpm 2>/dev/null); then
      selected=$(printf '%s\n' "$dependencies" | awk '$1 == "Depends:" && $2 ~ /^php(5|[0-9]+[.][0-9]+)-fpm$/ { if (found && found != $2) bad=1; found=$2 } END { if (!bad) print found }')
    fi
    if [ -z "$selected" ]; then
      while IFS=$'\t' read -r kind service; do [ "$kind" != fpm ] || { selected=$service; count=$((count+1)); }; done <<< "$roles"
      [ "$count" -eq 1 ] || selected=''
    fi
    if [ -z "$selected" ] && [ "$count" -eq 0 ]; then
      upgrade_php_runtime_finding error fpm:replacement 'Previously active PHP-FPM has no configured/installed replacement runtime.' || return 1
    elif [ -z "$selected" ]; then
      upgrade_php_runtime_finding unknown fpm:replacement 'Cannot identify one installed/default replacement PHP-FPM runtime.' || return 1
    elif ! printf '%s\n' "$roles" | grep -qxF $'fpm\t'"$selected"; then
      upgrade_php_runtime_finding error fpm:replacement "Expected replacement PHP-FPM package $selected is not configured/installed." || return 1
    elif upgrade_php_runtime_service_is_active "$selected"; then
      case "$selected" in php5-fpm) main=/etc/php5/fpm/php-fpm.conf;; *) current=${selected#php}; current=${current%-fpm}; main="/etc/php/$current/fpm/php-fpm.conf";; esac
      upgrade_php_runtime_collect_socket_findings fpm "$main" || return 1
    else
      result=$?
      if [ "$result" -eq 1 ]; then upgrade_php_runtime_finding error "service:$selected" "Expected replacement $selected is stopped/failed." || return 1
      else upgrade_php_runtime_finding unknown "service:$selected" "Cannot verify expected replacement $selected activity." || return 1; fi
    fi
  fi
  # Also inspect an already-active NGINX even when it was originally inactive.
  if ! $nginx && upgrade_php_runtime_service_is_active nginx; then nginx=true; fi
  if $nginx; then
    # shortcut: inspect Debian/Ubuntu default main config; custom -c/-p invocation needs a separate audit.
    echo 'dss:trace: Checking on-disk /etc/nginx/nginx.conf; custom invocation paths/loaded configuration are not established.' >&2
    upgrade_php_runtime_collect_socket_findings nginx /etc/nginx/nginx.conf || return 1
  fi
  return 0
}

# One latest snapshot per run. A complete later check clears earlier findings, including across releases.
function upgrade_php_runtime_check() {
(
  set -o pipefail
  local directory=${DR_RUN_DIRECTORY:-$1} snapshot temporary findings_file findings_release family=debian status=0
  snapshot="$directory/php-runtime.findings.tsv"
  [ -d "$directory" ] && [ ! -L "$directory" ] && [ "$(stat -c '%u:%a' -- "$directory")" = 0:700 ] || return 1
  [ ! -L "$snapshot" ] && { [ ! -e "$snapshot" ] || { [ -f "$snapshot" ] && [ "$(stat -c '%u:%h' -- "$snapshot")" = 0:1 ]; }; } || return 1
  [ ! -L "$snapshot.pending" ] && { [ ! -e "$snapshot.pending" ] || { [ -f "$snapshot.pending" ] && [ "$(stat -c '%u:%h' -- "$snapshot.pending")" = 0:1 ]; }; } || return 1
  (umask 077; : > "$snapshot.pending" && chmod 600 -- "$snapshot.pending") || return 1
  findings_release=$(distro_output_codename) || findings_release=unknown
  case " $ALL_UBUNTU " in *" $findings_release "*) family=ubuntu;; esac
  [ "$findings_release" != unknown ] || family=unknown
  findings_release="$family/$findings_release"
  temporary=$(umask 077; mktemp "$directory/.php-findings.XXXXXX") || return 1
  trap 'rm -f -- "$temporary" "$temporary.next"' EXIT
  findings_file=$temporary
  chmod 600 -- "$temporary" || return 1
  if [ "$findings_release" = unknown/unknown ]; then
    upgrade_php_runtime_finding unknown release 'Cannot identify the installed release for this check.' || return 1
  fi
  if ! upgrade_php_runtime_collect_findings "$1"; then
    upgrade_php_runtime_finding unknown collector 'Web service findings could not be fully collected; earlier findings remain unverified.' || return 1
    status=1
  fi
  # shortcut: an incomplete web check retains all earlier findings; narrow this if per-file coverage is needed.
  (umask 077; set -C; : > "$temporary.next") && chmod 600 -- "$temporary.next" || return 1
  # The absent previous snapshot is an empty input, not a successful earlier check.
  if [ -f "$snapshot" ]; then set -- "$temporary" "$snapshot"; else set -- "$temporary"; fi
  awk -F '\t' -v OFS='\t' -v release="$findings_release" '
    FILENAME == ARGV[1] {
      if (NF != 5 || $1 !~ /^(error|warning|unknown)$/ || $4 != "current") { bad=1; next }
      priority=($1 == "error" ? 3 : ($1 == "unknown" ? 2 : 1))
      if (!($2 in rows) || priority > priorities[$2]) { rows[$2]=$0; priorities[$2]=priority }
      if ($1 == "unknown") incomplete=1; next
    }
    $1 != "check" && !($2 in rows) { $4="unverified"; previous[$2]=$0 }
    END {
      if (bad) exit 1
      print "check", "php-runtime", release, (incomplete ? "incomplete" : "complete"), "Web services and PHP-FPM listeners"
      for (key in rows) print rows[key]
      if (incomplete) for (key in previous) print previous[key]
    }
  ' "$@" | LC_ALL=C sort > "$temporary.next" || return 1
  mv -f -- "$temporary.next" "$snapshot" && rm -f -- "$snapshot.pending" || return 1
  [ "$status" -eq 0 ] && awk -F '\t' '$1 == "error" && $4 == "current" { failed=1 } END { exit failed }' "$snapshot"
)
}

# Reuse the original comparison baseline, including across release hops and retries.
function upgrade_php_runtime_prepare() {
  local baseline directory
  baseline=$(config_state_output_baseline) || {
    record_config_state || return 1
    baseline=$(config_state_output_baseline) || return 1
  }
  directory="$baseline.php-runtime"
  [ ! -L "$directory" ] && mkdir -p -- "$directory" && chmod 700 "$directory" || return 1
  upgrade_php_runtime_snapshot "$directory"
}

function upgrade_php_runtime_verify() {
  local baseline
  echo 'dss:stage: Checking web services and PHP-FPM listeners after package changes' >&2
  if ! baseline=$(config_state_output_baseline) || ! upgrade_php_runtime_check "$baseline.php-runtime"; then
    echo 'dss:error: Web runtime verification failed or could not be collected; see the detailed run log.' >&2
    return 1
  fi
}

# shellcheck shell=bash
# Common service checks complement the PHP/web runtime check. All probes are read-only.
# Rows: family, status selector, owning package. Service aliases can change between releases.
# mariadb-server<TAB>install ok installed -> database<TAB>mariadb<TAB>mariadb-server.
function upgrade_services_output_roles() {
  local packages roles
  packages=$(dpkg-query -W -f='${Package}\t${Status}\n') || return 1
  roles=$(awk -F '\t' '
    $2 ~ /^(install|hold) ok installed$/ {
      name=$1; sub(/:.*/, "", name)
      if (name == "postfix") owner["postfix"]=name
      if (name ~ /^dovecot-(core|common|imapd|pop3d)$/ || name == "dovecot") owner["dovecot"]=name
      if (name ~ /^exim4-daemon-/) owner["exim4"]=name
      if (name ~ /^mariadb-server($|-[0-9])/) { owner["database"]=name; maria=1 }
      if (name ~ /^mysql-server($|-[0-9])/ && !maria) owner["database"]=name
      if (name ~ /^postgresql-[0-9]+([.][0-9]+)*$/) owner["postgresql"]=name
      if (name == "openssh-server") owner["ssh"]=name
      if (name ~ /^(fail2ban|bind9|redis-server|slapd|rabbitmq-server)$/) owner[name]=name
    }
    END { for (role in owner) print role "\t" (role == "database" ? (maria ? "mariadb" : "mysql") : role) "\t" owner[role] }
  ' <<< "$packages") || return 1
  [ -z "$roles" ] || printf '%s\n' "$roles" | LC_ALL=C sort -u
}

# 0 running, 1 stopped/failed, 2 unknown. Postfix's active(exited) umbrella is not a daemon.
function upgrade_services_is_active() {
  local family=$1 selector=$2 state status properties version cluster
  local -a bounded=()
  command -v timeout >/dev/null 2>&1 && bounded=(timeout 20)
  case "$family" in
    postfix)
      if [ "$selector" = postfix ]; then
        command -v postfix >/dev/null 2>&1 || return 2
        state=$(LC_ALL=C "${bounded[@]}" postfix status 2>&1)
      else
        command -v postmulti >/dev/null 2>&1 || return 2
        state=$(LC_ALL=C "${bounded[@]}" postmulti -i "$selector" -p status 2>&1)
      fi
      status=$?
      case "$status" in
        0) return 0;;
        1) case "$state" in *'mail system is not running'*) return 1;; *) return 2;; esac;;
        *) return 2;;
      esac;;
    postgresql)
      command -v pg_lsclusters >/dev/null 2>&1 || return 2
      version=${selector%%/*}; cluster=${selector#*/}
      [ "$version" != "$selector" ] || return 2
      state=$(LC_ALL=C "${bounded[@]}" pg_lsclusters) || return 2
      # 16 main 5432 online ... -> running for selector=16/main; down -> stopped; duplicate rows -> unknown.
      state=$(awk -v version="$version" -v cluster="$cluster" '$1 == version && $2 == cluster { if (found++) exit 2; state=$4 } END { if (found == 1) print state; else exit 2 }' <<< "$state") || return 2
      case "$state" in online|online,*) return 0;; down|down,*) return 1;; *) return 2;; esac;;
  esac
  upgrade_php_runtime_service_is_active "$selector" || return $?
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    case "$(readlink /proc/1/exe)" in */systemd|*/'systemd (deleted)')
      properties=$(LC_ALL=C "${bounded[@]}" systemctl show -p SubState -p MainPID "$selector.service" 2>/dev/null) || return 2
      state=$(awk -F= '$1 == "SubState" { state=$2 } $1 == "MainPID" { pid=$2 } END { if (state == "" || pid !~ /^[0-9]+$/) exit 2; print state ":" pid }' <<< "$properties") || return 2
      # Generated SysV units can track running daemons without recording a main PID.
      case "$state" in running:*) return 0;; exited:*|dead:*|failed:*) return 1;; *) return 2;; esac;;
    esac
  fi
  return 0
}

# The caller creates the root-private sibling of its original preupgrade baseline.
function upgrade_services_snapshot() {
(
  umask 077
  local directory=$1 roles family selector package instances row state status
  local -a bounded=()
  if [ ! -d "$directory" ] || [ -L "$directory" ] || [ "$(stat -c '%u:%a' "$directory")" != 0:700 ]; then return 1; fi
  if [ -e "$directory/services.before" ] || [ -L "$directory/services.before" ]; then
    if [ ! -f "$directory/services.before" ] || [ -L "$directory/services.before" ] ||
        [ "$(stat -c '%u' "$directory/services.before")" != 0 ]; then return 1; fi
    chmod 600 -- "$directory/services.before" || return 1
    [ -r "$directory/services.before" ]
    return $?
  fi
  roles=$(upgrade_services_output_roles) || return 1
  command -v timeout >/dev/null 2>&1 && bounded=(timeout 20)
  [ ! -L "$directory/services.before.new" ] || return 1
  : > "$directory/services.before.new" && chmod 600 -- "$directory/services.before.new" || return 1
  while IFS=$'\t' read -r family selector package; do
    [ -n "$family" ] || continue
    instances=$selector
    if [ "$family" = postfix ] && command -v postmulti >/dev/null 2>&1; then
      if row=$(LC_ALL=C "${bounded[@]}" postmulti -l) &&
          instances=$(awk 'NF { if (NF != 4 || $3 !~ /^(y|n)$/ || $4 !~ /^\//) exit 2; print $4; count++ } END { if (!count) exit 2 }' <<< "$row"); then :
      else instances=''; fi
    elif [ "$family" = postgresql ]; then
      if command -v pg_lsclusters >/dev/null 2>&1 && row=$(LC_ALL=C "${bounded[@]}" pg_lsclusters); then
        instances=$(awk '$1 ~ /^[0-9]+([.][0-9]+)*$/ { if (NF < 4 || $2 ~ /[\/]/) exit 2; print $1 "/" $2; count++ } END { if (!count) exit 2 }' <<< "$row") || instances=''
      else instances=''; fi
    fi
    if [ -z "$instances" ]; then
      echo "dss:warn: Cannot establish pre-upgrade $family instance activity; verification will be incomplete." >&2
      printf '%s\t%s\t%s\tunknown\n' "$family" "$selector" "$package" >> "$directory/services.before.new" || return 1
      continue
    fi
    while IFS= read -r selector; do
      if upgrade_services_is_active "$family" "$selector"; then state=active
      else status=$?; state=unknown; [ "$status" -ne 1 ] || state=inactive; fi
      [ "$state" != unknown ] || echo "dss:warn: Cannot establish pre-upgrade $family activity; verification will be incomplete." >&2
      printf '%s\t%s\t%s\t%s\n' "$family" "$selector" "$package" "$state" >> "$directory/services.before.new" || return 1
    done <<< "$instances"
  done <<< "$roles"
  mv -- "$directory/services.before.new" "$directory/services.before"
)
}

function upgrade_services_package_was_purged() {
  local baseline=$1 package=$2 manifest status
  for manifest in "$baseline.purged-incompatible/"*/packages.purged; do
    [ -f "$manifest" ] || continue
    if awk -v package="$package" '{ name=$0; sub(/:.*/, "", name); if (name == package) found=1 } END { exit !found }' "$manifest"; then return 0
    else status=$?; [ "$status" -eq 1 ] || return 2; fi
  done
  return 1
}

# Missing packages alone are not an exemption; confirmed baseline purge records are.
function upgrade_services_check_legacy() {
  local baseline=$1 roles selector=postfix status
  [ -f "$baseline" ] && [ -r "$baseline" ] || return 2
  # Original process metadata can establish default Postfix activity, not all services.
  awk '
    /^installed: postfix$/ { installed=1 }
    /^process: \/usr\/lib\/postfix\/(sbin\/)?master([ \t]|$)/ && $0 !~ /[ \t]-c([ \t]|$)/ { master=1 }
    END { exit !(installed && master) }
  ' "$baseline" || return 2
  if upgrade_services_package_was_purged "$baseline" postfix; then return 2
  else status=$?; [ "$status" -eq 1 ] || return 2; fi
  roles=$(upgrade_services_output_roles) || return 2
  if awk -F '\t' '$1 == "postfix" { found=1 } END { exit !found }' <<< "$roles"; then :
  else
    status=$?; [ "$status" -eq 1 ] || return 2
    echo 'dss:error: Postfix was running in the original process inventory and its installed role is now missing.' >&2; return 1
  fi
  command -v postmulti >/dev/null 2>&1 && selector=-
  if upgrade_services_is_active postfix "$selector"; then return 2; else status=$?; fi
  if [ "$status" -eq 1 ]; then
    echo 'dss:error: Postfix was running in the original process inventory and is now stopped/failed; no automatic restart was attempted.' >&2; return 1
  fi
  return 2
}

function upgrade_services_check() {
  local directory=$1 baseline=${2:-${1%.services}} roles family selector package state status=0 result
  if [ ! -f "$directory/services.before" ] || [ -L "$directory/services.before" ] || [ ! -r "$directory/services.before" ]; then
    upgrade_services_check_legacy "$baseline"
    return $?
  fi
  roles=$(upgrade_services_output_roles) || return 2
  while IFS=$'\t' read -r family selector package state; do
    [ -n "$family" ] || continue
    case "$state" in inactive) continue;; active) :;; *) [ "$status" -eq 1 ] || status=2; continue;; esac
    if upgrade_services_package_was_purged "$baseline" "$package"; then continue
    else result=$?; if [ "$result" -ne 1 ]; then [ "$status" -eq 1 ] || status=2; continue; fi; fi
    if awk -F '\t' -v family="$family" '$1 == family { found=1 } END { exit !found }' <<< "$roles"; then :
    else
      result=$?
      if [ "$result" -eq 1 ]; then
        echo "dss:error: Previously active $family ($selector) no longer has its installed service role; removal was not recorded as intentional." >&2
        status=1
      else [ "$status" -eq 1 ] || status=2; fi
      continue
    fi
    # The packaged default database daemon changes from MySQL to MariaDB on some hops.
    if [ "$family" = database ]; then
      selector=$(awk -F '\t' '$1 == "database" { print $2 }' <<< "$roles") || return 2
    fi
    if upgrade_services_is_active "$family" "$selector"; then :
    else
      result=$?
      if [ "$result" -eq 1 ]; then
        echo "dss:error: Previously active $family ($selector) is now stopped/failed; no automatic restart was attempted." >&2
        status=1
      else
        echo "dss:warn: Cannot verify previously active $family ($selector); service health is incomplete." >&2
        [ "$status" -eq 1 ] || status=2
      fi
    fi
  done < "$directory/services.before"
  return "$status"
}

function upgrade_services_verify() {
  local baseline status
  if baseline=$(config_state_output_baseline); then upgrade_services_check "$baseline.services" "$baseline"; status=$?
  else status=2; fi
  case "$status" in 0) return 0;; 1) return 1;; *) echo 'dss:warn: Common-service verification is incomplete; review service status before treating the upgrade as fully verified.' >&2; return 0;; esac
}

# Only the current private logging directory receives these short machine records.
function upgrade_outcome_record() {
(
  umask 077
  local category=$1 state=$2 detail=${3:-} directory=${DR_RUN_DIRECTORY:-}
  case "$category" in release|packages|cleanup) :;; *) return 1;; esac
  case "$state" in verified|done|deferred|failed|unknown) :;; *) return 1;; esac
  [ -n "$directory" ] || return 0
  if [ ! -d "$directory" ] || [ -L "$directory" ] || [ -L "$directory/outcome.events" ]; then return 1; fi
  detail=${detail//$'\n'/ }; detail=${detail//$'\r'/ }; detail=${detail//$'\t'/ }
  printf '%s\t%s\t%s\n' "$category" "$state" "$detail" >> "$directory/outcome.events" && chmod 600 -- "$directory/outcome.events"
)
}

function upgrade_outcome_output_php_removals() {
  local baseline=$1 mapping packages result selected=''
  for mapping in "$baseline.php-migration/"*/mapping; do
    if [ ! -f "$mapping" ] || { [ ! -f "${mapping%/*}/started" ] && [ ! -f "${mapping%/*}/completed" ]; }; then continue; fi
    selected="$selected"$'\n'"$(awk -F '\t' '$5 == "unavailable" { print $1 ":" $2 }' "$mapping")" || return 1
  done
  [ -n "${selected//$'\n'/}" ] || return 0
  packages=$(dpkg-query -W -f='${Package}\t${Architecture}\t${Status}\n') || return 1
  result=$(awk -F '\t' -v selected="$selected" '
    BEGIN { n=split(selected, list, "\n"); for (i=1; i<=n; i++) if (list[i] != "") removed[list[i]]=1 }
    $3 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ { delete removed[$1 ":" $2] }
    END { for (name in removed) print name }
  ' <<< "$packages") || return 1
  [ -z "$result" ] || printf '%s\n' "$result" | LC_ALL=C sort -u
}

# Called inside the logging action child, including from its EXIT trap.
# Original action failures take precedence; unknown service status remains a visible warning.
function upgrade_finish_run() {
  if [ -n "${DR_RUN_DIRECTORY:-}" ] && [ -f "$DR_RUN_DIRECTORY/panel.handoff" ]; then
    echo 'dss:stage: Outcome: release not verified; packages not verified; services unknown.' >&2
    echo 'dss:stage: Vendor upgrade handoff; use the panel tool to monitor completion, recovery and reboots. Generic cleanup and completion checks were not run.' >&2
    printf 'dss:stage: Detailed run log: %s\n' "$2" >&2
    return "$1"
  fi
  if [ -f /etc/redhat-release ]; then rpm_packages_finish_run "$@"; return $?; fi
  local action_status=$1 logfile=$2 baseline='' services=2 web_failed=false status category state detail reason audit='' plan=''
  local findings='' web_complete=false
  local release='not verified' packages='not verified' cleanup='' php_removals='' service_summary='unknown' package_verified=false
  local directory=${DR_RUN_DIRECTORY:-} removed=0 deferred=0 obsolete_removed=0 obsolete_deferred=0 autoremove_skipped=''
  local none=false obsolete_none=false cleanup_done=false missing_provenance=false cleanup_failed=false cleanup_deferred=false
  case "$action_status" in ''|*[!0-9]*) return 1;; esac
  [ "$action_status" -le 255 ] || return 1
  status=$action_status
  if [ -n "$directory" ] && [ -f "$directory/outcome.events" ]; then
    while IFS=$'\t' read -r category state detail; do
      case "$category" in
        release) release="$state${detail:+ ($detail)}";;
        packages) packages="$state${detail:+ ($detail)}"; package_verified=false; [ "$state" != verified ] || package_verified=true;;
        cleanup)
          case "$state:$detail" in
            done:*) cleanup_done=true;;
            deferred:*provenance*) missing_provenance=true;;
            failed:*) cleanup_failed=true;;
            deferred:*|unknown:*) cleanup_deferred=true;;
          esac;;
      esac
    done < "$directory/outcome.events"
  fi
  # Cleanup may have changed package state since a completion marker was recorded.
  if $package_verified; then
    if audit=$(LC_ALL=C dpkg --audit 2>&1) && [ -z "$audit" ] &&
        plan=$(LC_ALL=C apt-get -s dist-upgrade 2>&1) &&
        awk '/^(Inst|Remv|Purg|Conf) / { bad=1 } END { exit bad }' <<< "$plan"; then :
    else
      [ -z "$audit$plan" ] || printf '%s\n' "$audit" "$plan" >&2
      echo 'dss:error: Final package state is incomplete or could not be verified; review package repair and the detailed log before continuing.' >&2
      packages='failed final verification'; [ "$status" -ne 0 ] || status=1
    fi
  fi
  if baseline=$(config_state_output_baseline); then
    upgrade_services_check "$baseline.services" "$baseline"; services=$?
    if ! upgrade_php_runtime_check "$baseline.php-runtime"; then web_failed=true; fi
    findings="${directory:-$baseline.php-runtime}/php-runtime.findings.tsv"
    if upgrade_php_runtime_findings_complete "$findings"; then web_complete=true; fi
  fi
  if [ "$services" -eq 1 ] || $web_failed; then
    service_summary=failed; [ "$status" -ne 0 ] || status=1
  elif [ "$services" -eq 0 ] && $web_complete; then service_summary=verified; fi
  if [ "$services" -eq 2 ] || ! $web_complete; then
    echo 'dss:warn: Service health is incomplete; unknown checks are not a successful verification.' >&2
    if [ -n "$directory" ]; then
      if [ -L "$directory/outcome.incomplete" ] || ! (umask 077; : > "$directory/outcome.incomplete" && chmod 600 -- "$directory/outcome.incomplete"); then
        echo 'dss:error: Cannot record incomplete service verification.' >&2
        [ "$status" -ne 0 ] || status=1
      fi
    fi
  elif [ -n "$directory" ]; then
    if [ -L "$directory/outcome.incomplete" ] || ! rm -f -- "$directory/outcome.incomplete"; then
      echo 'dss:error: Cannot clear the previous incomplete verification marker.' >&2
      [ "$status" -ne 0 ] || status=1
    fi
  fi
  if [ -n "$directory" ] && [ -f "$directory/cleanup.outcomes" ]; then
    while IFS='|' read -r category state detail reason; do
      case "$category:$state" in
        autoremove:removed) removed=$((removed+1));;
        autoremove:none) none=true;;
        autoremove:deferred)
          if [ "$detail" = - ]; then autoremove_skipped=$reason; else deferred=$((deferred+1)); fi;;
        obsolete:removed) obsolete_removed=$((obsolete_removed+1));;
        obsolete:none) obsolete_none=true;;
        obsolete:deferred)
          case "$reason" in *provenance*) missing_provenance=true;; *) obsolete_deferred=$((obsolete_deferred+1));; esac;;
      esac
    done < <(tr '\t' '|' < "$directory/cleanup.outcomes")
  fi
  if [ "$removed" -gt 0 ] || [ "$deferred" -gt 0 ]; then
    cleanup="autoremove $removed removed, $deferred deferred"
    [ "$deferred" -eq 0 ] || cleanup="$cleanup (protected packages/dependencies or policy)"
  elif $none; then cleanup='no autoremove candidates'; fi
  [ -z "$autoremove_skipped" ] || cleanup="$cleanup${cleanup:+; }autoremove skipped ($autoremove_skipped)"
  if [ "$obsolete_removed" -gt 0 ] || [ "$obsolete_deferred" -gt 0 ]; then
    cleanup="$cleanup${cleanup:+; }obsolete $obsolete_removed removed, $obsolete_deferred deferred"
    [ "$obsolete_deferred" -eq 0 ] || cleanup="$cleanup (protected packages/dependencies or policy)"
  elif $obsolete_none; then cleanup="$cleanup${cleanup:+; }no obsolete candidates"; fi
  if $missing_provenance; then cleanup="$cleanup${cleanup:+; }obsolete skipped (no original provenance)"
  elif $cleanup_done; then cleanup="$cleanup${cleanup:+; }obsolete cleanup done"; fi
  if $cleanup_failed; then cleanup="$cleanup${cleanup:+; }cleanup failed (see detailed log)"
  elif $cleanup_deferred; then
    if [ "$service_summary" = failed ]; then cleanup="$cleanup${cleanup:+; }cleanup deferred (service checks failed)"
    else cleanup="$cleanup${cleanup:+; }cleanup deferred (see detailed log)"; fi
  fi
  printf 'dss:stage: Outcome: release %s; packages %s; services %s.\n' "$release" "$packages" "$service_summary" >&2
  if [ -n "$findings" ] && [ -n "$directory" ]; then
    if ! upgrade_php_runtime_write_review "$findings" "$directory" "$web_failed"; then
      echo 'dss:error: Cannot save the current configuration review report; see the findings above.' >&2
      [ "$status" -ne 0 ] || status=1
    elif [ -s "$directory/configuration-review.txt" ]; then
      awk '{ print "dss:warn: " $0 }' "$directory/configuration-review.txt" >&2 || { [ "$status" -ne 0 ] || status=1; }
      printf 'dss:warn: Review required: %s/configuration-review.txt\n' "$directory" >&2
    fi
  fi
  if [ -n "$baseline" ]; then
    if php_removals=$(upgrade_outcome_output_php_removals "$baseline"); then
      [ -z "$php_removals" ] || printf 'dss:warn: PHP extensions removed without target replacements: %s. Review application requirements.\n' "${php_removals//$'\n'/, }" >&2
    else echo 'dss:warn: Removed PHP extension availability could not be summarized.' >&2; fi
  fi
  printf 'dss:stage: Cleanup: %s.\n' "${cleanup:-not run (no release transition reached cleanup in this run)}" >&2
  # Inventory changes are observations; package/service checks determine operational success.
  manifest_compare_baseline "$baseline" || :
  printf 'dss:stage: Detailed run log: %s\n' "$logfile" >&2
  return "$status"
}

# NSS (Name Service Switch) lets libc obtain account records from files,
# systemd and other configured sources. Package scripts also depend on these lookups.
# Old nss-systemd can recurse through a D-Bus daemon retained across release upgrades.
# Keep dynamic identities available through the same-namespace direct lookup path.
function upgrade_prepare_nss_lookup() {
  local info version manager_namespace self_namespace records owner probe status
  [ "$(id -u)" = 0 ] || return 0
  [ -z "${SYSTEMD_NSS_BYPASS_BUS:-}${SYSTEMD_NSS_DYNAMIC_BYPASS:-}" ] || return 0
  if ! info=$(dpkg-query -W -f='${Status}\t${Version}\n' libnss-systemd 2>/dev/null); then
    echo 'dss:trace: Cannot identify nss-systemd; retaining normal NSS lookups.' >&2
    return 0
  fi
  case "$info" in
    *$'\n'*) echo 'dss:trace: Cannot identify one nss-systemd version; retaining normal NSS lookups.' >&2; return 0;;
    *" ok installed"$'\t'?*) version=${info##*$'\t'};;
    *) echo 'dss:trace: Cannot verify installed nss-systemd; retaining normal NSS lookups.' >&2; return 0;;
  esac
  version=${version#*:}; version=${version%%[!0-9]*}
  case "$version" in
    23[2-9]|24[0-4]) :;;
    '') echo 'dss:trace: Cannot verify nss-systemd version; retaining normal NSS lookups.' >&2; return 0;;
    *) return 0;;
  esac
  if ! command -v timeout >/dev/null || ! command -v getent >/dev/null; then
    echo 'dss:warn: Cannot bound the NSS lookup probe; retaining normal NSS lookups.' >&2
    return 0
  fi
  manager_namespace=$(readlink /proc/1/ns/mnt) || manager_namespace=
  self_namespace=$(readlink /proc/self/ns/mnt) || self_namespace=
  records=/run/systemd/dynamic-uid
  # No directory means no direct records yet; future records must remain visible here.
  if [ ! -e "$records" ] && [ ! -L "$records" ]; then records=/run/systemd; fi
  if [ -z "$manager_namespace" ] || [ "$manager_namespace" != "$self_namespace" ] ||
      [ ! -d "$records" ] || [ -L "$records" ]; then
    echo 'dss:warn: Cannot verify the systemd dynamic-user namespace; retaining normal NSS lookups.' >&2
    return 0
  fi
  owner=$(stat -c %u "$records") || owner=
  if [ "$owner" != 0 ]; then
    echo 'dss:warn: Cannot verify root ownership of systemd dynamic-user records; retaining normal NSS lookups.' >&2
    return 0
  fi
  probe="dss-nss-$$-$RANDOM"
  if timeout -k 1 3 getent passwd "$probe" >/dev/null 2>&1; then status=0; else status=$?; fi
  case "$status" in
    2) return 0;;
    124|137) :;;
    *) echo 'dss:trace: NSS lookup did not demonstrate the old D-Bus timeout; retaining normal NSS lookups.' >&2; return 0;;
  esac
  if SYSTEMD_NSS_BYPASS_BUS=1 timeout -k 1 1 getent passwd "$probe" >/dev/null 2>&1; then status=0; else status=$?; fi
  if [ "$status" != 2 ]; then
    echo 'dss:warn: Direct NSS lookup was not a fast missing-user result; retaining normal NSS lookups.' >&2
    return 0
  fi
  export SYSTEMD_NSS_BYPASS_BUS=1
  echo 'dss:warn: Using direct systemd dynamic-user lookups for this upgrade process after an NSS D-Bus timeout.' >&2
  return 0
}

# A crossgrade replaces 32-bit userspace packages with 64-bit equivalents.
# A running x86_64 kernel is required, but does not prove that the shell or package tools are 64-bit.
# Native means the dpkg default architecture; foreign means an additional package architecture.
# Automatic crossgrade planning.
# A completed crossgrade permits only amd64 and architecture-independent packages.
# Keep the original conversion inventory until every recorded target has been verified.
# APT_CONFIG loads before apt.conf.d and apt.conf: unchanged probes expose defaults.
# Run before package inventory or any i386->amd64 mutation; never override user pins.
# Architecture-specific preferences can contradict conversion even when both indexes are enabled.
function crossgrade_check_apt_architecture_preferences() {
  local main=$1 parts=$2 file name
  local -a files=()
  [ ! -f "$main" ] || files+=("$main")
  for file in "$parts/"*; do
    [ -f "$file" ] || continue
    name=${file##*/}
    case "$name" in .*|*[!a-zA-Z0-9_.-]*) continue;; *.*) case "$name" in *.pref) :;; *) continue;; esac;; esac
    files+=("$file")
  done
  for file in "${files[@]}"; do
    # Package/Pin/Pin-Priority stanzas: positive i386 pins and negative amd64 pins need review.
    # Package: *:i386, Pin: version *, Pin-Priority: 500 (separate lines) -> block; amd64 at -1 also blocks.
    if ! awk '
      function check( pintext,has_i386,has_amd64) {
        pintext=tolower(pin); gsub(/["\047]/, "", pintext)
        has_i386=(tolower(package) ~ /:i386([ \t\r\f\013]|$)/ || (pintext ~ /^[ \t\r\f\013]*release[ \t\r\f\013]+/ && pintext ~ /(^|[, \t\r\f\013])b[ \t\r\f\013]*=[ \t\r\f\013]*i386([, \t\r\f\013]|$)/))
        has_amd64=(tolower(package) ~ /:amd64([ \t\r\f\013]|$)/ || (pintext ~ /^[ \t\r\f\013]*release[ \t\r\f\013]+/ && pintext ~ /(^|[, \t\r\f\013])b[ \t\r\f\013]*=[ \t\r\f\013]*amd64([, \t\r\f\013]|$)/))
        if (priority ~ /^[+-]?[0-9]+$/ && ((has_i386 && priority+0 > 0) || (has_amd64 && priority+0 < 0))) {
          printf "dss:error: Review architecture preference at %s:%d before crossgrade; adjust the 32-bit preference or amd64 exclusion manually. No preferences were changed.\n", FILENAME, first
          bad=1
        }
        package=""; pin=""; priority=""; field=""; first=0
      }
      /^[ \t\r\f\013]*#/ { next }
      /^[ \t\r\f\013]*$/ { check(); next }
      {
        if (!first) first=FNR
        value=$0
        if ($0 ~ /^[^ \t\r\f\013][^:]*:/) {
          field=tolower($0); sub(/:.*/, "", field); sub(/^[^:]*:[ \t\r\f\013]*/, "", value)
        }
        gsub(/^[ \t\r\f\013]+|[ \t\r\f\013]+$/, "", value)
        if (field == "package") package=package " " value
        else if (field == "pin") pin=pin " " value
        else if (field == "pin-priority") priority=value
      }
      END { check(); exit bad }
    ' "$file" >&2; then return 1; fi
  done
}

function crossgrade_check_apt_architecture_config() {
  (
    local directory probe status key value path apt_root=/ apt_etc=etc/apt apt_main=apt.conf apt_parts=apt.conf.d apt_preferences=preferences apt_preferenceparts=preferences.d
    if [ -n "${APT_CONFIG:-}" ]; then
      printf '%s\n' "dss:error: Existing APT_CONFIG=$APT_CONFIG prevents a reliable crossgrade architecture check; review that file and unset APT_CONFIG first." >&2
      return 1
    fi
    umask 077
    directory=$(mktemp -d) || return 1
    trap 'rm -rf -- "$directory"' EXIT
    probe="distrorejuve-${directory##*/}"
    # Suppress dpkg foreign defaults after #clear; this probe never changes packages.
    if ! printf 'APT::Architecture "%s";\n#clear APT::Architectures;\nAPT::Architectures { "%s"; };\nDir::Bin::dpkg "/bin/true";\n' "$probe" "$probe" > "$directory/probe.conf"; then
      return 1
    fi
    if APT_CONFIG="$directory/probe.conf" apt-config dump > "$directory/dump"; then
      :
    else
      status=$?
      printf '%s\n' 'dss:error: Cannot read APT architecture configuration; crossgrade was not started.' >&2
      return "$status"
    fi
    if ! awk 'tolower($1) == "rootdir" && split($0, quoted, /"/) == 3 && quoted[2] != "" { bad=1 } END { exit bad }' "$directory/dump"; then
      echo 'dss:error: APT RootDir redirects configuration and package paths; review and unset this alternate-root setting before crossgrading. No configuration was changed.' >&2
      return 1
    fi
    # apt-config has no source provenance; locate likely settings without printing configuration values.
    while IFS=$'\t' read -r key value; do
      case "$key" in dir) apt_root=$value;; dir::etc) apt_etc=$value;; dir::etc::main) apt_main=$value;; dir::etc::parts) apt_parts=$value;; dir::etc::preferences) apt_preferences=$value;; dir::etc::preferencesparts) apt_preferenceparts=$value;; esac
    done < <(awk 'split($0, quoted, /"/) == 3 { key=tolower($1); if (key ~ /^dir($|::etc($|::(main|parts|preferences|preferencesparts)$))/) print key "\t" quoted[2] }' "$directory/dump")
    case "$apt_etc" in /*) :;; *) apt_etc="${apt_root%/}/$apt_etc";; esac
    case "$apt_main" in /*) :;; *) apt_main="$apt_etc/$apt_main";; esac
    case "$apt_parts" in /*) :;; *) apt_parts="$apt_etc/$apt_parts";; esac
    case "$apt_preferences" in /*) :;; *) apt_preferences="$apt_etc/$apt_preferences";; esac
    case "$apt_preferenceparts" in /*) :;; *) apt_preferenceparts="$apt_etc/$apt_preferenceparts";; esac
    # Example dump: APT::Architecture "probe"; APT::Architectures:: "i386";
    # apt-config normalizes global lists; binary-specific lists also need both arches.
    if awk -v probe="$probe" '
      {
        name=tolower($1)
        if (name !~ /^(apt|binary::[^:]+::apt)::architectures?($|::)/) next
        if (split($0, quoted, /"/) != 3) { bad=1; next }
        value=quoted[2]
        if (name == "apt::architecture") {
          native=1
          if (value != probe) bad=1
        } else if (name ~ /::architecture($|::)/) bad=1
        else {
          scope=name; sub(/::architectures.*/, "", scope)
          if (name == scope "::architectures") { if (value != "") bad=1; next }
          entry=name; sub(/^.*::architectures::/, "", entry)
          if (entry ~ /:/ || value == "") { bad=1; next }
          if (value != probe) changed[scope]=1
          if (value == "i386") i386[scope]=1
          if (value == "amd64") amd64[scope]=1
        }
      }
      END {
        for (scope in changed) if (!i386[scope] || !amd64[scope]) bad=1
        exit (!native || bad)
      }
    ' "$directory/dump"; then
      crossgrade_check_apt_architecture_preferences "$apt_preferences" "$apt_preferenceparts"
      return $?
    fi
    printf '%s\n' 'dss:error: Persistent APT architecture overrides block crossgrade. Remove APT::Architecture pins; explicit APT::Architectures lists must include i386 and amd64, including binary-specific settings.' >&2
    printf '%s\n' "dss:error: Review $apt_main and $apt_parts; remove native architecture pins and make explicit architecture lists permit both i386 and amd64. Follow any #include directives. No configuration was changed." >&2
    for path in "$apt_main" "$apt_parts/"*; do
      if [ ! -f "$path" ] || [ ! -r "$path" ]; then continue; fi
      awk 'tolower($0) ~ /architectures?|#include/ { printf "dss:error: Review architecture setting or include at %s:%d.\n", FILENAME, FNR }' "$path" >&2
    done
    return 1
  )
}

function crossgrade_bookworm_output_pending_directory() {
  local directory found=''
  # Conversion recovery outlives the normal pre-upgrade comparison window.
  for directory in /root/distrorejuveinfo/*.crossgrade-bookworm /root/deghostinfo/*.crossgrade-bookworm; do
    if [ ! -f "$directory/original.i386" ] || [ -f "$directory/completed" ]; then continue; fi
    if [ -n "$found" ]; then
      echo 'dss:error: Multiple unfinished crossgrade inventories require manual review before continuing.' >&2
      return 2
    fi
    found=$directory
  done
  [ -n "$found" ] || return 1
  printf '%s\n' "$found"
}

function crossgrade_bookworm_is_pending() {
  crossgrade_bookworm_output_pending_directory >/dev/null
}

# Active foreign packages include failed/interrupted states; residual configuration is harmless.
function crossgrade_output_foreign_packages() {
  local packages
  packages=$(dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\n') || {
    echo 'dss:error: Cannot inspect all package architectures; crossgrade completion is unconfirmed.' >&2; return 2;
  }
  printf '%s\n' "$packages" | awk -F '\t' '
    NF && NF != 3 { bad=1; next }
    $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ && $3 != "amd64" && $3 != "all" { print $2 ":" $3 " (" $1 ")" }
    END { exit bad }
  ' || return 2
}

# Rows: issue (architecture/configuration), package:architecture, dpkg status.
# Keep architecture planning separate from the stricter crossgrade completion check.
# dpkg-query example: install ok unpacked<TAB>openssh-server<TAB>amd64<TAB>no.
function crossgrade_output_core_package_issues() {
  local packages
  packages=$(dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Essential}\n') || {
    echo 'dss:error: Cannot inspect core package architectures and configuration states.' >&2; return 1;
  }
  printf '%s\n' "$packages" | awk -F '\t' '
    NF && NF != 4 { bad=1; next }
    $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ {
      sub(/:.*/, "", $2)
      if ($4 == "yes" || $2 ~ /^(dpkg|apt|apt-utils|bash|coreutils|tar|perl-base|systemd|systemd-sysv|udev|openssh-server|ifupdown)$/) {
        if ($2 == "" || $3 == "") { bad=1; next }
        if ($3 != "amd64" && $3 != "all") print "architecture\t" $2 ":" $3 "\t" $1
        else if ($1 !~ / installed$/) print "configuration\t" $2 ":" $3 "\t" $1
      }
    }
    END { exit bad }
  ' || { echo 'dss:error: Invalid core package inventory; architecture verification is incomplete.' >&2; return 1; }
}

function crossgrade_bookworm_check_native() {
  local native bits issues
  native=$(dpkg --print-architecture) || return 2
  bits=$(getconf LONG_BIT) || return 2
  [ "$native:$bits" = amd64:64 ] || return 1
  issues=$(crossgrade_output_core_package_issues) || return 2
  [ -z "$issues" ]
}

# shellcheck shell=bash
# Both architectures must be enabled by every active binary source during conversion.
function crossgrade_check_source_architectures() {
  local records record file line type filters base added removed architecture
  records=$(apt_sources_list) || return 1
  while IFS= read -r record; do
    IFS=$'\t' read -r file line _ type _ <<< "$record"
    [ "$type" = deb ] || continue
    # Components may be empty for flat repositories; read the architecture field from the end.
    filters=${record##*$'\t'}
    [ "$filters" != '*' ] || continue
    IFS='|' read -r base added removed <<< "${filters//,/ }"
    for architecture in i386 amd64; do
      case " $removed " in *" $architecture "*) echo "dss:error: Source $file:$line excludes $architecture; enable both i386 and amd64 first." >&2; return 1;; esac
      if [ -n "$base" ]; then
        case " $base $added " in *" $architecture "*) :;; *) echo "dss:error: Source $file:$line excludes $architecture; enable both i386 and amd64 first." >&2; return 1;; esac
      fi
    done
  done <<< "$records"
}

# Output the release at which an explicitly permitted architecture conversion must run.
# Permission alone does not request conversion while the chosen release supports i386.
function upgrade_output_crossgrade_release() {
  local family=$1 current=$2 target=$3 enabled=${UPGRADE_CROSSGRADE-false}
  local native bits kernel boundary releases state foreign_packages core_issues pending_directory pending=false
  case "$enabled" in true|false) :;; *) echo 'dss:error: Internal crossgrade permission must be true or false.' >&2; return 1;; esac
  case "$family" in
    debian) releases=$ALL_DEBIAN; boundary=bookworm;;
    ubuntu) releases=$ALL_UBUNTU; boundary=bionic;;
    *) return 0;;
  esac
  case " $releases " in *" $current "*) :;; *) echo "dss:error: Unknown $family starting release: $current" >&2; return 1;; esac
  case " $releases " in *" $target "*) :;; *) echo "dss:error: Unknown $family target release: $target" >&2; return 1;; esac
  native=$(dpkg --print-architecture) || return 1
  bits=$(getconf LONG_BIT) || return 1
  [ -n "$native" ] || { echo 'dss:error: Cannot establish native package architecture.' >&2; return 1; }
  case "$bits" in 32|64) :;; *) echo "dss:error: Cannot establish userspace bit width: $bits" >&2; return 1;; esac
  if [ "$family" = debian ] && [ "$current" = bookworm ]; then
    if pending_directory=$(crossgrade_bookworm_output_pending_directory); then pending=true
    else state=$?; [ "$state" -eq 1 ] || return 1; fi
  fi
  case "$native:$bits" in
    amd64:64)
      if $pending; then state=1
      else
        core_issues=$(crossgrade_output_core_package_issues) || return 1
        state=0
        case "$core_issues" in architecture$'\t'*|*$'\n'architecture$'\t'*) state=1;; esac
        # Configuration repair belongs to the package pass, not these repeated architecture checks.
        if [ "$state" -eq 1 ]; then
          echo 'dss:warn: Native architecture is amd64 with 64-bit userspace, but some core packages use another architecture.' >&2
          printf '%s\n' "$core_issues" | awk -F '\t' '
            $1 == "architecture" {
              count++
              if (count <= 8) printf "dss:warn: Core package %s: expected amd64/all (%s).\n", $2, $3
            }
            END { if (count > 8) printf "dss:warn: %d additional core package architecture issues.\n", count-8 }
          ' >&2 || return 1
        fi
      fi
      # Ordinary amd64 upgrades may keep multiarch libraries; requested conversions may not.
      if [ "$state" -eq 0 ] && $enabled; then
        foreign_packages=$(crossgrade_output_foreign_packages) || return 1
        [ -z "$foreign_packages" ] || state=1
      fi
      [ "$state" -ne 0 ] || return 0
      [ "$state" -eq 1 ] || return 1;;
    i386:32|i386:64|amd64:32) :;;
    *) return 0;;
  esac
  if ! is_distro_name_newer "$target" "$boundary"; then
    if [ "$native:$bits" != i386:32 ]; then
      echo 'dss:error: Package architecture and userspace width disagree. Repair the incomplete crossgrade before release upgrades.' >&2
      return 1
    fi
    return 0
  fi
  if ! $enabled; then
    if $pending; then
      echo "dss:error: Unfinished architecture crossgrade recorded at $pending_directory. Native package architecture: $native; userspace: $bits-bit. Add --crossgrade to resume it on $boundary before upgrading to $target." >&2
    else
      echo "dss:error: $family $target requires architecture conversion before leaving $boundary. Native package architecture: $native; userspace: $bits-bit. Add --crossgrade to permit i386 to amd64 conversion." >&2
      foreign_packages=$(crossgrade_output_foreign_packages) || return 1
      if [ -n "$foreign_packages" ]; then
        printf '%s\n' "$foreign_packages" | awk '
          NR <= 8 { print "dss:error: Active non-amd64 package: " $0 }
          END { if (NR > 8) printf "dss:error: %d additional active non-amd64 packages.\n", NR-8 }
        ' >&2 || return 1
      fi
    fi
    return 1
  fi
  if [ "$family" = ubuntu ] && ! "${DR_ENABLE_UBUNTU_CROSSGRADE:-false}"; then
    echo 'dss:error: Ubuntu crossgrading remains experimental. Set DR_ENABLE_UBUNTU_CROSSGRADE=true only after reviewing that risk, as well as --crossgrade.' >&2
    return 1
  fi
  kernel=$(uname -m) || return 1
  if [ "$kernel" != x86_64 ]; then
    echo 'dss:error: Automatic i386 to amd64 conversion needs a running x86_64 kernel before any release changes.' >&2
    return 1
  fi
  if is_distro_name_newer "$current" "$boundary"; then
    echo "dss:error: Architecture conversion must finish on $family $boundary before later release sources are selected. Restore or repair that checkpoint." >&2
    return 1
  fi
  if [ "$current" != "$boundary" ] && [ "$native:$bits" != i386:32 ]; then
    echo 'dss:error: Architecture conversion is incomplete before the planned checkpoint. Repair it on the current release before continuing release upgrades.' >&2
    return 1
  fi
  if [ "$family" = debian ]; then crossgrade_check_apt_architecture_config || return 1; fi
  crossgrade_check_source_architectures || return 1
  printf '%s\n' "$boundary"
}

function upgrade_check_crossgrade_checkpoint() {
  # Source checks read this dynamically scoped override; no release transition is active here.
  # shellcheck disable=SC2034
  local family=$1 release=$2 current audit plan apt_sources_transition_target=''
  if [ "$family" = debian ]; then debian_check_release_completion "$release"; return $?; fi
  current=$(distro_output_codename) || return 1
  if [ "$current" != "$release" ]; then
    echo "dss:error: Expected $family $release after package changes; detected $current." >&2
    return 1
  fi
  apt_sources_check_releases_and_vendors || return 1
  audit=$(LC_ALL=C dpkg --audit) || return 1
  if [ -n "$audit" ]; then
    printf '%s\n' "$audit" >&2
    echo "dss:error: Release verification for $family $release failed: packages still need configuration." >&2
    return 1
  fi
  plan=$(LC_ALL=C apt-get -s dist-upgrade) || return 1
  if printf '%s\n' "$plan" | grep -Eq '^(Inst|Conf|Remv|Purg) '; then
    echo "dss:error: Release verification for $family $release failed: package changes are still pending." >&2
    return 1
  fi
  upgrade_outcome_record release verified "$release" || return 1
  upgrade_outcome_record packages verified "$release" || return 1
  upgrade_php_runtime_verify || return 1
  upgrade_services_verify
}

# Call before changing repositories at bookworm -> trixie or bionic -> focal.
function upgrade_crossgrade_before_release() {
  local family=$1 old=$2 target=$3 current checkpoint native bits
  current=$(distro_output_codename) || return 1
  [ "$current" = "$old" ] || return 0
  if [ "$family:$old" = debian:bookworm ]; then crossgrade_bookworm_recover_bootstrap || return $?; fi
  checkpoint=$(upgrade_output_crossgrade_release "$family" "$current" "$target") || return 1
  [ -n "$checkpoint" ] || return 0
  if [ "$current" != "$checkpoint" ]; then
    echo "dss:error: Expected $family $checkpoint before architecture conversion; installed release is $current." >&2
    return 1
  fi
  pause_check || return 1
  check_disk_space || return 1
  if [ "$family" = debian ] && crossgrade_bookworm_is_pending; then
    # Package audit can be incomplete mid-conversion; the guarded backend repairs its recorded plan.
    apt_sources_check_releases_and_vendors "$checkpoint" || return 1
  else upgrade_check_crossgrade_checkpoint "$family" "$checkpoint" || return 1; fi
  echo "dss:stage: Crossgrading $family $checkpoint from i386 to amd64 before $target" >&2
  if [ "$family" = debian ]; then crossgrade_debian_bookworm || return $?
  else crossgrade_debian || return $?; fi
  native=$(dpkg --print-architecture) || return 1
  bits=$(getconf LONG_BIT) || return 1
  if [ "$native:$bits" != amd64:64 ]; then
    echo "dss:error: Crossgrade did not establish native amd64 and 64-bit userspace ($native/$bits). Release upgrade stopped." >&2
    return 1
  fi
  upgrade_check_crossgrade_checkpoint "$family" "$checkpoint" || return 1
}

# End automatic crossgrade planning.

# Validate the complete requested path before any package/source mutation.
# Predict only current package-policy blockers; future archive feasibility is checked later.
function upgrade_check_crossgrade_package_blockers() {
  local allow=${DR_ALLOW_CROSSGRADE_BLOCKERS:-false} packages issues issue level=error
  packages=$(dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\n') || {
    echo 'dss:error: Cannot inspect package holds and architectures before crossgrading.' >&2; return 1;
  }
  issues=$(printf '%s\n' "$packages" | awk -F '\t' '
    $1 ~ /^hold / { print "Held package: " $2 ":" ($3 == "" ? "unknown" : $3) }
    $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ &&
      $3 != "i386" && $3 != "amd64" && $3 != "all" {
      print "Unsupported foreign architecture: " $2 ":" ($3 == "" ? "unknown" : $3)
    }
  ') || return 1
  [ -n "$issues" ] || return 0
  if $allow; then level=warn; fi
  while IFS= read -r issue; do printf 'dss:%s: %s\n' "$level" "$issue" >&2; done <<< "$issues"
  if $allow; then
    echo 'dss:warn: DR_ALLOW_CROSSGRADE_BLOCKERS=true permits this attempted conversion; final native amd64 package verification remains mandatory.' >&2
    return 0
  fi
  echo 'dss:error: Resolve these package blockers before release changes, or set DR_ALLOW_CROSSGRADE_BLOCKERS=true to attempt the crossgrade.' >&2
  return 1
}


function upgrade_check_path() {
  # The logging callback distinguishes an explicit refusal from an unexpected failure.
  upgrade_preflight_blocked=false
  upgrade_panel_refuse_generic || return 1
  if [ "${4:-requested}" = transition ]; then
    echo "dss:stage: Rechecking $2 -> $3 before this release transition" >&2
  elif [ "$2" = "$3" ]; then
    echo "dss:stage: Checking requested release $3 and any unfinished upgrade work" >&2
  else
    echo "dss:stage: Checking complete requested upgrade path $2 -> $3" >&2
  fi
  local family=$1 current=$2 target=$3 issues action rule boundary packages remedy arch crossgrade_release blocked=false
  local purge=${DR_PURGE_INCOMPATIBLE_PACKAGES:-false} retry_purge=false retry_crossgrade=false
  # The collision checker records whether the packaged-file preference would help.
  local usrmerge_preference_needed=false
  local remove_obsolete=${DR_REMOVE_OBSOLETE_CROSSGRADE_PACKAGES:-true} obsolete
  local releases
  case "$family" in debian) releases=$ALL_DEBIAN;; ubuntu) releases=$ALL_UBUNTU;; *) return 1;; esac
  case " $releases " in *" $current "*) :;; *) echo "dss:error: Unknown $family starting release: $current" >&2; return 1;; esac
  case " $releases " in *" $target "*) :;; *) echo "dss:error: Unknown $family target release: $target" >&2; return 1;; esac
  usrmerge_check_upgrade_path "$family" "$current" "$target" || blocked=true
  if crossgrade_release=$(upgrade_output_crossgrade_release "$family" "$current" "$target"); then :; else blocked=true; fi
  if [ -n "$crossgrade_release" ]; then
    upgrade_check_crossgrade_package_blockers || blocked=true
  fi
  if [ "$family:$crossgrade_release" = debian:bookworm ]; then
    obsolete=$(upgrade_output_crossgrade_obsolete_packages) || return 1
    if [ -n "$obsolete" ] && ! $remove_obsolete; then
      echo "dss:error: Known obsolete foreign packages will block the Bookworm crossgrade: ${obsolete//$'\n'/ }. Review removals and set DR_REMOVE_OBSOLETE_CROSSGRADE_PACKAGES=true to permit verified obsolete compiler/library/alias removal after backup." >&2
      blocked=true
    fi
  fi
  if ! is_distro_name_older "$current" "$target"; then $blocked && return 1; return 0; fi
  arch=$(dpkg --print-architecture) || return 1
  if [ "$family" = debian ] && ! is_distro_name_older "$target" trixie; then
    case "$arch" in i386)
      if [ -z "$crossgrade_release" ]; then
        blocked=true
        ${UPGRADE_CROSSGRADE-false} || retry_crossgrade=true
      fi;;
      mipsel|mips64el)
      echo "dss:error: Requested path $current -> $target reaches Debian 13, which cannot upgrade native $arch. Migrate or crossgrade first." >&2
      blocked=true;;
    esac
  fi
  if [ "$family" = ubuntu ] && [ "$arch" = i386 ] && is_distro_name_newer "$target" bionic && [ -z "$crossgrade_release" ]; then
    echo "dss:error: Requested path $current -> $target exceeds Ubuntu 18.04 native i386 support. Migrate or crossgrade first." >&2
    blocked=true
    ${UPGRADE_CROSSGRADE-false} || retry_crossgrade=true
  fi
  if [ "$family" = debian ] && [ "$arch" = i386 ] && is_distro_name_older "$current" bullseye && ! is_distro_name_older "$target" bullseye && [ -r /sys/hypervisor/guest_type ] && [ "$(cat /sys/hypervisor/guest_type)" = PV ] && [[ "$(uname -m)" == i?86 ]]; then
    echo 'dss:error: Debian 11 drops 32-bit Xen PV guests; change the guest boot mode before upgrading.' >&2
    blocked=true
  fi
  issues=$(upgrade_output_compatibility_issues "$family" "$current" "$target") || return 1
  while IFS=$'\t' read -r action rule boundary packages remedy; do
    [ -n "$action" ] || continue
    case "$action" in
      warn) printf 'dss:warn: [%s at %s] %s\n' "$rule" "$boundary" "$remedy" >&2;;
      manual)
        printf 'dss:error: [%s at %s] %s Packages: %s.\n' "$rule" "$boundary" "$remedy" "$packages" >&2
        blocked=true;;
      purge)
        printf 'dss:warn: [%s at %s] %s Packages: %s.\n' "$rule" "$boundary" "$remedy" "$packages" >&2
        if ! $purge; then blocked=true; retry_purge=true; fi;;
    esac
  done <<< "$issues"
  if $blocked; then
    echo "dss:error: Requested upgrade path $current -> $target blocked before changes. Resolve the specific checks above." >&2
    if $retry_purge; then
      echo 'dss:error: DR_PURGE_INCOMPATIBLE_PACKAGES=true backs up and purges the configuration-incompatible packages listed above; it does not bypass manual migration or architecture checks.' >&2
    fi
    if [ "${4:-requested}" = requested ]; then
      upgrade_preflight_blocked=true
      if [ "${#upgrade_retry_command[@]}" -gt 0 ] && { $retry_purge || $usrmerge_preference_needed || $retry_crossgrade; }; then
        printf '%s\n' 'dss:stage: Review the choices above before retrying; resolve any remaining manual checks.' >&2
        {
          printf 'dss:stage: Suggested retry: '
          if $purge || $retry_purge; then printf 'DR_PURGE_INCOMPATIBLE_PACKAGES=true '; fi
          if "${DR_PREFER_PACKAGED_USRMERGE_FILES:-false}" || $usrmerge_preference_needed; then printf 'DR_PREFER_PACKAGED_USRMERGE_FILES=true '; fi
          if [ -n "${DR_ACTION:-}" ]; then printf 'DR_ACTION=%q ' "$DR_ACTION"; fi
          printf '%q' "${upgrade_retry_command[0]}"
          printf ' %q' "${upgrade_retry_command[@]:1}"
          if $retry_crossgrade; then printf ' %s' --crossgrade; fi
          printf '\n'
        } >&2
      fi
    fi
    return 1
  fi
  local repository_target='' release found=false
  if [ "$family" = debian ]; then
    for release in $ALL_DEBIAN; do
      if $found; then repository_target=$release; break; fi
      [ "$release" != "$current" ] || found=true
    done
  else repository_target=$(ubuntu_output_next_release "$current") || return 1; fi
  [ -n "$repository_target" ] || return 1
  apt_sources_check_releases_and_vendors "$repository_target" || return 1
  # Readiness must not repair usrmerge or purge incompatible packages.
  [ "${4:-requested}" != review ] || return 0
  usrmerge_recover_pending || return $?
  upgrade_check_incompatible_packages "$family" "$current" "$target"
}

function upgrade_preflight_action() {
  local action=$1 version=${2:-} family current target next remaining=1000
  if [ -f /etc/redhat-release ]; then
    echo 'dss:error: RPM major-release upgrades use a reviewed ELevate/reinstall procedure. For eligible same-major CentOS conversion, set DR_RPM_MIGRATION_TARGET and use --upgrade.' >&2
    upgrade_preflight_blocked=true
    return 1
  fi
  current=$(distro_output_codename) || return 1
  case " $ALL_DEBIAN " in *" $current "*) family=debian;; *)
    case " $ALL_UBUNTU " in *" $current "*) family=ubuntu;; *) return 0;; esac;;
  esac
  case "$action:$family" in
    --to-debian-release:ubuntu|--to-next-ubuntu:debian)
      echo "dss:error: $action does not apply to $family." >&2; return 1;;
  esac
  case "$action" in
    --to-debian-release)
      case "$version" in 6) target=squeeze;; 7) target=wheezy;; 8) target=jessie;; 9) target=stretch;; 10) target=buster;; 11) target=bullseye;; 12) target=bookworm;; 13) target=trixie;; *) return 1;; esac;;
    --to-next-ubuntu) remaining=1;;
    --to-latest)
      if [ "$family" = ubuntu ]; then
        target=$(ubuntu_output_latest_lts "$current") || { upgrade_preflight_blocked=true; return 1; }
      fi;;
    *) return 0;;
  esac
  if [ -z "$target" ]; then
    if [ "$family" = debian ]; then target=trixie
    else
      target=$current
      while [ "$remaining" -gt 0 ]; do
        next=$(ubuntu_output_next_release "$target") || return 1
        [ -n "$next" ] || break
        target=$next
        remaining=$((remaining-1))
      done
    fi
  fi
  if [ "$family" = debian ]; then crossgrade_bookworm_recover_bootstrap || return $?; fi
  upgrade_check_path "$family" "$current" "$target"
}

# Config/state backups deliberately exclude mail stores and unrelated application data.
function upgrade_backup_incompatible_packages() {
(
  umask 077
  local baseline=$1 family=$2 current=$3 target=$4 directory package path
  shift 4
  directory="${baseline}.purged-incompatible"
  mkdir -p -- "$directory" && chmod u=rwx,go= -- "$directory" || return 1
  directory=$(mktemp -d "$directory/$family-$current-to-$target.XXXXXX") || return 1
  echo "dss:info: Backing up incompatible packages to $directory" >&2
  printf '%s\n' "$@" > "$directory/packages.requested" || return 1
  printf '%s\n' "$family $current -> $target" > "$directory/transition" || return 1
  : > "$directory/archive-paths" || return 1
  for package in "$@"; do
    dpkg-query -W -f='${Status}\t${Package}\t${Version}\t${Architecture}\n' "$package" > "$directory/$package.status" || return 1
    dpkg-query -L "$package" > "$directory/$package.files" || return 1
    dpkg-query -W -f='${Conffiles}\n' "$package" > "$directory/$package.conffiles" || return 1
    # Keep package manifests as well as custom files beneath each service's config/state roots.
    while read -r path _; do
      case "$path" in "/etc/"*) [ ! -e "$path" ] && [ ! -L "$path" ] && continue;; *) continue;; esac
      printf '%s\0' "${path#/}" >> "$directory/archive-paths" || return 1
    done < "$directory/$package.conffiles"
  done
  for path in "/etc/fail2ban" "/var/lib/fail2ban" "/etc/dovecot" "/var/lib/dovecot" "/var/lib/ucf/hashfile" "/var/lib/ucf/registry"; do
    case "$path" in
      *fail2ban*) case " $* " in *' fail2ban '*) :;; *) continue;; esac;;
      *dovecot*) case " $* " in *' dovecot'* ) :;; *) continue;; esac;;
    esac
    [ -e "$path" ] || [ -L "$path" ] || continue
    printf '%s\0' "${path#/}" >> "$directory/archive-paths" || return 1
  done
  # Do not dereference symlinks into mail stores or other data; retain links for manual review.
  tar -C / -czpf "$directory/config-state.tar.gz" --null -T "$directory/archive-paths" || return 1
  if command -v doveconf >/dev/null 2>&1; then
    doveconf -n > "$directory/doveconf.txt" 2>&1
    printf '%s\n' "$?" > "$directory/doveconf.status" || return 1
  fi
  printf '%s\n' "$directory"
)
}

function upgrade_check_incompatible_packages() {
  local family=$1 current=$2 target=$3 purge=${DR_PURGE_INCOMPATIBLE_PACKAGES:-false}
  local listed baseline backup plan status package
  local -a packages=()
  listed=$(upgrade_output_incompatible_packages "$family" "$current" "$target") || return 1
  [ -n "$listed" ] || return 0
  while IFS= read -r package; do packages+=("$package"); done <<< "$listed"
  if ! $purge; then
    case " $listed " in *fail2ban*) print_uninstall_fail2ban;; esac
    if printf '%s\n' "$listed" | grep -q '^dovecot'; then
      if [ "$target" = trixie ] || { [ "$family" = ubuntu ] && ! is_distro_name_older "$target" questing; }; then
        echo "dss:error: Dovecot 2.4 requires config migration. Export DR_SKIP_DOVECOT_MIGRATION_CHECK=true only after manual migration review." >&2
      else
        print_uninstall_dovecot
      fi
    fi
    echo "dss:error: Upgrade $current to $target blocked by: ${packages[*]}. Set DR_PURGE_INCOMPATIBLE_PACKAGES=true to back up and purge them; services remain removed until manual reinstall." >&2
    return 1
  fi
  # Honour pause before any service removal, including whole-path preflight.
  pause_check || return 1
  # Validate the other upgrade conditions before stopping services or removing their packages.
  upgrade_precondition_checks "$target" || return 1
  record_config_state || return 1
  baseline=$(config_state_output_baseline) || return 1
  backup=$(upgrade_backup_incompatible_packages "$baseline" "$family" "$current" "$target" "${packages[@]}") || {
    echo "dss:error: Incompatible-package backup failed; no purge attempted." >&2; return 1;
  }
  plan=$(LC_ALL=C apt-get $APT_GET_INSTALL_OPTIONS -o APT::Get::AutomaticRemove=false --simulate purge "${packages[@]}" 2>&1)
  status=$?
  (umask 077; printf '%s\n' "$plan" > "$backup/purge-plan.txt") || return 1
  [ "$status" -eq 0 ] || { echo "dss:error: Purge simulation failed; see $backup/purge-plan.txt." >&2; return "$status"; }
  # APT may otherwise remove reverse dependencies. Permit only the named blockers, with no installs.
  if ! printf '%s\n' "$plan" | awk -v packages="${packages[*]}" '
    BEGIN { count=split(packages, selected, " "); for (i=1; i<=count; i++) allowed[selected[i]]=1 }
    /^(Remv|Purg) / { name=$2; sub(/:.*/, "", name); if (!(name in allowed)) bad=1; removed[name]=1 }
    /^Inst / { bad=1 }
    END { for (name in allowed) if (!(name in removed)) bad=1; exit bad }
  '; then
    echo "dss:error: Purge would change packages beyond the selected blockers; review $backup/purge-plan.txt. No purge attempted." >&2
    return 1
  fi
  apt_state_invalidate_packages
  (umask 077; : > "$backup/purge.log") || return 1
  LC_ALL=C apt-get $APT_GET_INSTALL_OPTIONS -o APT::Get::AutomaticRemove=false purge "${packages[@]}" 2>&1 | tee "$backup/purge.log"
  local -a result=("${PIPESTATUS[@]}")
  if [ "${result[0]}" -ne 0 ] || [ "${result[1]}" -ne 0 ]; then
    echo "dss:error: Purge failed; upgrade stopped. Backup: $backup. Review package state before retrying." >&2
    [ "${result[0]}" -ne 0 ] && return "${result[0]}"
    return 1
  fi
  mv -- "$backup/packages.requested" "$backup/packages.purged" || return 1
  echo "dss:warn: Purged incompatible packages: ${packages[*]}. Backup: $backup. Review current package names and availability before manual reinstall after upgrading." >&2
  return 0
}

function print_uninstall_fail2ban() {
  [ ! -f /etc/debian_version ] && return 0
  ! dpkg -l | grep -qai '^i.*fail2ban' && return 0
  echo "dss:info: Changes to the fail2ban configs mean that this script will likely hit problems when doing the dist upgrade.  so aborting before starting." >&2
  echo "dss:info: Please remove the fail2ban configs.  You may do that with the following commands:"
  echo apt-get -y purge $(dpkg -l | grep fail2ban | egrep -i 'ii|iF|iU' | awk '{print $2}')
}

function print_uninstall_dovecot() {
  [ ! -f /etc/debian_version ] && return 0
  ! dpkg -l | grep -qai '^i.*dovecot' && return 0
  # trusty 2.9, precise 2.0, lucid (=10.4) 1.29 per https://launchpad.net/ubuntu/+source/dovecot
  echo "dss:info: Seeing '$( [ -f /var/log/mail.info ] && grep 'dovecot' /var/log/mail.info* | grep -c 'Login:')' logins via imap recently."
  echo "dss:info: Changes to the dovecot configs mean that this script will likely hit problems when doing the dist upgrade.  so aborting before starting." >&2
  echo "dss:info: Saving the current dovecot config to /root/distrorejuveinfo/doveconf.log.$$"
  echo "dss:info: Please remove dovecot.  You may do that with the following commands:"
  prepare_output_dir
  postconf -n > /root/distrorejuveinfo/postconf.log.$$
  doveconf -n > /root/distrorejuveinfo/doveconf.log.$$
  echo apt-get -y remove $(dpkg -l | grep dovecot | egrep -i 'ii|iF|iU' | awk '{print $2}')
  # dovecot reinstall tips

  # apt-get install dovecot-pop3d dovecot-imapd dovecot-managesieved dovecot-sieve
  # dovecot -n > /etc/dovecot/dovecot.conf.new
  # mv /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.predistupgrade
  # mv /etc/dovecot/dovecot.conf.new /etc/dovecot/dovecot.conf

  # sed -i s@'mailbox_command = /usr/lib/dovecot/deliver -c /etc/dovecot/conf.d/01-dovecot-postfix.conf -m "${EXTENSION}"'@'mailbox_command = /usr/lib/dovecot/deliver -c /etc/dovecot/dovecot.conf -m "${EXTENSION}"'@g main.cf

  # Could also try removing /etc/dovecot/conf.d/01-dovecot-postfix.conf and replacing it with this package (replaces postfix-dovecot package):

  # http://packages.ubuntu.com/trusty/all/mail-stack-delivery/filelist

  #doveconf: Warning: NOTE: You can get a new clean config file with: doveconf -n > dovecot-new.conf
  #doveconf: Warning: Obsolete setting in /etc/dovecot/dovecot.conf:25: 'imaps' protocol is no longer necessary, remove it
  #doveconf: Warning: Obsolete setting in /etc/dovecot/dovecot.conf:25: 'pop3s' protocol is no longer necessary, remove it
  #doveconf: Warning: Obsolete setting in /etc/dovecot/dovecot.conf:717: protocol managesieve {} has been replaced by protocol sieve { }
  #doveconf: Warning: Obsolete setting in /etc/dovecot/dovecot.conf:889: add auth_ prefix to all settings inside auth {} and remove the auth {} section completely
  #doveconf: Warning: Obsolete setting in /etc/dovecot/dovecot.conf:927: passdb pam {} has been replaced by passdb { driver=pam }
  #doveconf: Warning: Obsolete setting in /etc/dovecot/dovecot.conf:1040: userdb passwd {} has been replaced by userdb { driver=passwd }
  #doveconf: Warning: Obsolete setting in /etc/dovecot/dovecot.conf:1102: auth_user has been replaced by service auth { user }
  #doveconf: Fatal: Error in configuration file /etc/dovecot/dovecot.conf: ssl enabled, but ssl_cert not set
  #Stopping IMAP/POP3 mail server: dovecot.
  #Processing triggers for man-db ...
  #Errors were encountered while processing:
  # dovecot-sieve
  # dovecot-pop3d
  # dovecot-ldap
  # dovecot-imapd
  #E: Sub-process /usr/bin/dpkg returned an error code (1)


  return 0
}

function print_failed_dist_upgrade_tips() {
  if [ -f /etc/redhat-release ]; then
    echo 'dss:warn: Review the DNF/YUM error and RPM evidence in the detailed log. Do not mix EL major versions or bypass signing checks.' >&2
    return 0
  fi
  #echo "dss:warn: In the event of a dist-upgrade failure, try things like commenting out the new distro, uncomment the previous distro, try an apt-get -f install, then change the distros back."
  #echo "dss:warn: In the event of dovecot errors, apt-get remove dovecot* unless you need dovecot (e.g. you need imap/pop3)"
  #echo "dss:warn: May be worth trying: aptitude -vv full-upgrade"
  #echo "dss:warn: after attempting a fix manually, rerun the bash distrorejuve.sh  command"
  return 0
}

function dist_upgrade_etch_to_lenny() {
  local old_distro=etch old_ver="inux 4" new_distro=lenny new_ver="inux 5"
  dist_upgrade_x_to_y
}

function dist_upgrade_lenny_to_squeeze() {
local old_distro=lenny
local old_ver="inux 5"
local new_distro=squeeze
local new_ver="inux 6"

dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_squeeze_to_wheezy() {
local old_distro=squeeze
local old_ver="inux 6"
local new_distro=wheezy
local new_ver="inux 7"

dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_wheezy_to_jessie() {
local old_distro=wheezy
local old_ver="inux 7"
local new_distro=jessie
local new_ver="inux 8"
dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_jessie_to_stretch() {
local old_distro=jessie
local old_ver="inux 8"
local new_distro=stretch
local new_ver="inux 9"
dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_stretch_to_buster() {
local old_distro=stretch
local old_ver="inux 9"
local new_distro=buster
local new_ver="inux 10"
dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_buster_to_bullseye() {
local old_distro=buster
local old_ver="inux 10"
local new_distro=bullseye
local new_ver="inux 11"
dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_bullseye_to_bookworm() {
local old_distro=bullseye
local old_ver="inux 11"
local new_distro=bookworm
local new_ver="inux 12"
dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_bookworm_to_trixie() {
local old_distro=bookworm
local old_ver="inux 12"
local new_distro=trixie
local new_ver="inux 13"
dist_upgrade_x_to_y
ret=$?
return $ret
}

  
# Both package tools may be installed, for example to inspect another distro
# image. Tool availability alone does not identify the database that describes this server.
# Read-only package queries. Distro/database evidence takes precedence over utility availability.
function packages_output_backend() {
  local root=${1:-} identity=''
  if [ -r "$root/etc/os-release" ]; then
    identity=$(head -c 16384 -- "$root/etc/os-release" | awk -F= '
      $1 == "ID" || $1 == "ID_LIKE" { value=$2; gsub(/[\042\047]/,"",value); printf " %s",value }') || return 1
  fi
  case " $identity " in
    *' debian '*|*' ubuntu '*) printf '%s\n' dpkg; return;;
    *' rhel '*|*' fedora '*|*' centos '*|*' rocky '*|*' almalinux '*|*' ol '*|*' suse '*|*' opensuse '*) printf '%s\n' rpm; return;;
  esac
  if [ -f "$root/etc/debian_version" ] || [ -f "$root/var/lib/dpkg/status" ]; then printf '%s\n' dpkg
  elif [ -f "$root/etc/redhat-release" ] || [ -d "$root/var/lib/rpm" ] || [ -d "$root/usr/lib/sysimage/rpm" ]; then printf '%s\n' rpm
  elif command -v dpkg-query >/dev/null 2>&1; then printf '%s\n' dpkg
  elif command -v rpm >/dev/null 2>&1; then printf '%s\n' rpm
  else return 1; fi
}

# Tab records: name, full distribution version, installed/selection state, architecture.
# Keep dpkg partial states for callers; RPM queries return installed packages only.
# RPM bash<TAB>0<TAB>5.2-1<TAB>x86_64 -> bash<TAB>5.2-1<TAB>installed<TAB>x86_64; epoch 2 yields 2:5.2-1.
function packages_output_inventory() {
  local backend=$1 records
  case "$backend" in
    dpkg) LC_ALL=C dpkg-query -W -f='${Package}\t${Version}\t${Status}\t${Architecture}\n';;
    rpm)
      records=$(LC_ALL=C rpm -qa --queryformat '%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n') || return 1
      printf '%s\n' "$records" | awk -F '\t' 'BEGIN { OFS="\t" }
        NF { version=$3; if ($2 != "(none)" && $2 != "" && $2 != "0") version=$2 ":" version
          print $1,version,"installed",$4 }';;
    *) return 1;;
  esac
}

# Exactly one configured package owner, no owner (1), or ambiguous/query failure (2).
# dpkg-query -S: libc6:amd64: /lib/x86_64-linux-gnu/libc.so.6 -> libc6:amd64, if installed.
# Multiple records or comma-separated owners are ambiguous, returning status 2.
function packages_output_file_owner() {
  local path=$1 owners owner status backend=${2:-dpkg}
  if [ "$backend" = rpm ]; then
    # RPM uses the same failure status for an unowned file and database errors; fail closed.
    owner=$(LC_ALL=C rpm -qf --queryformat '%{NAME}\n' -- "$path" 2>/dev/null) || return 2
    case "$owner" in ''|*[!a-zA-Z0-9._+-]*) return 2;; esac
    printf '%s\n' "$owner"
    return
  fi
  [ "$backend" = dpkg ] || return 2
  if owners=$(LC_ALL=C dpkg-query -S "$path" 2>/dev/null); then :
  else status=$?; [ "$status" -eq 1 ] && return 1; return 2; fi
  case "$owners" in *$'\n'*|*','*) return 2;; esac
  case "$owners" in *": $path") owner=${owners%": $path"};; *) return 2;; esac
  case "$owner" in ''|*[!a-z0-9.+:-]*) return 2;; esac
  status=$(dpkg-query -W -f='${Status}' "$owner" 2>/dev/null) || return 2
  case "$status" in *' ok installed') printf '%s\n' "$owner";; *) return 2;; esac
}

# Package ownership does not imply unchanged content. Compare stored digests
# before suppressing packaged migration paths; retain local edits and unverifiable files for review.
# Only verified unchanged package content may be omitted; owner/mode are not compared.
function packages_output_file_origin() {
  local file=$1 backend=$2 root=${3:-} path owner status records checksum='' actual tool metadata size alias
  path=${file#"$root"}
  case "$path" in /*) :;; *) printf 'unknown\tunknown\n'; return 1;; esac
  case "$path" in *$'\n'*|*$'\r'*|*$'\t'*) printf 'unknown\tunknown\n'; return 1;; esac
  if [ -L "$file" ] || [ ! -f "$file" ] || [ ! -r "$file" ]; then printf 'unknown\tunknown\n'; return 0; fi
  size=$(stat -c %s -- "$file" 2>/dev/null) || { printf 'unknown\tunknown\n'; return 0; }
  case "$size" in ''|*[!0-9]*) printf 'unknown\tunknown\n'; return 0;; esac
  if [ "$size" -gt 1048576 ]; then printf 'unknown\tunknown\n'; return 0; fi
  if owner=$(packages_output_file_owner "$path" "$backend"); then :
  else
    status=$?
    # Before Debian moved unit files to /usr, dpkg recorded /lib even on merged-/usr systems.
    if [ "$status" -eq 1 ] && [ "$backend" = dpkg ] && [ "${path%/*}" = /usr/lib/systemd/system ]; then
      alias="$root/lib/systemd/system/${path##*/}"
      if [ -f "$alias" ] && [ "$(readlink -f -- "$alias" 2>/dev/null)" = "$(readlink -f -- "$file" 2>/dev/null)" ]; then
        packages_output_file_origin "$alias" "$backend" "$root"
        return
      fi
    fi
    if [ "$status" -eq 1 ]; then printf 'unowned\tunknown\n'; return 0; fi
    if [ "$backend" = rpm ]; then
      records=$(LC_ALL=C rpm -qf --queryformat '%{NAME}\n' -- "$path" 2>/dev/null)
      status=$?
      if [ "$status" -eq 1 ] && [ "$records" = "file $path is not owned by any package" ]; then printf 'unowned\tunknown\n'; return 0; fi
    fi
    printf 'unknown\tunknown\n'; return 1
  fi
  case "$backend" in
    dpkg)
      if ! records=$(LC_ALL=C dpkg-query -W -f='${Conffiles}\n' "$owner" 2>/dev/null); then printf 'unknown\t%s\n' "$owner"; return 1; fi
      # Conffile row " /etc/hosts 0123456789abcdef0123456789abcdef" -> trailing MD5 for /etc/hosts.
      checksum=$(printf '%s\n' "$records" | PACKAGE_ORIGIN_PATH="$path" awk 'BEGIN { path=ENVIRON["PACKAGE_ORIGIN_PATH"] } index($0," " path " ") == 1 { value=substr($0,length(path)+3); sub(/[ \t].*/,"",value); print value; exit }')
      if [ -z "$checksum" ]; then
        metadata="$root/var/lib/dpkg/info/$owner.md5sums"
        [ -f "$metadata" ] || metadata="$root/var/lib/dpkg/info/${owner%%:*}.md5sums"
        if [ -f "$metadata" ] && [ ! -L "$metadata" ] && [ -r "$metadata" ]; then
          # md5sums row "0123456789abcdef0123456789abcdef  usr/bin/bash" -> leading MD5 for /usr/bin/bash.
          checksum=$(head -c 1048576 -- "$metadata" | PACKAGE_ORIGIN_PATH="${path#/}" awk 'BEGIN { path=ENVIRON["PACKAGE_ORIGIN_PATH"] } NR > 20000 { exit } { hash=$1; value=$0; sub(/^[^ \t]+[ \t]+/,"",value); if (value == path) { print hash; exit } }')
        fi
      fi
      tool=md5sum;;
    rpm)
      # --dump is available on old RPM; match the full path before reading its digest.
      if ! records=$(LC_ALL=C rpm -qf --dump -- "$path" 2>/dev/null); then printf 'unknown\t%s\n' "$owner"; return 1; fi
      checksum=$(printf '%s\n' "$records" | PACKAGE_ORIGIN_PATH="$path" awk 'BEGIN { path=ENVIRON["PACKAGE_ORIGIN_PATH"] } index($0,path " ") == 1 { value=substr($0,length(path)+2); split(value,fields," "); print fields[3]; exit }')
      case "${#checksum}" in 32) tool=md5sum;; 40) tool=sha1sum;; 64) tool=sha256sum;; *) tool='';; esac;;
    *) printf 'unknown\t%s\n' "$owner"; return 1;;
  esac
  case "$checksum" in ''|*[!0-9a-fA-F]*) printf 'unknown\t%s\n' "$owner"; return 0;; esac
  if [ -z "$tool" ] || ! command -v "$tool" >/dev/null 2>&1; then printf 'unknown\t%s\n' "$owner"; return 0; fi
  if [ "$backend" = dpkg ] && [ "${#checksum}" -ne 32 ]; then printf 'unknown\t%s\n' "$owner"; return 0; fi
  if ! actual=$("$tool" < "$file"); then printf 'unknown\t%s\n' "$owner"; return 1; fi
  checksum=$(printf '%s' "$checksum" | tr 'A-F' 'a-f')
  if [ "${actual%% *}" = "$checksum" ]; then printf 'packaged\t%s\n' "$owner"
  else printf 'modified_package\t%s\n' "$owner"; fi
}

# usrmerge makes /bin, /sbin and /lib aliases of their /usr counterparts.
# Distinct files at both paths become a collision; deleting either copy can lose a local executable.
# The packaged converter handles the actual merge; check known executable collisions first.
function usrmerge_is_complete() {
  local name directory expected
  for name in bin sbin lib lib32 lib64 libx32; do
    directory="/$name"; expected="/usr/$name"
    case "$name" in lib32|lib64|libx32) [ -e "$directory" ] || [ -L "$directory" ] || continue;; esac
    [ -L "$directory" ] && [ "$(readlink -f -- "$directory")" = "$expected" ] || return 1
  done
}

# Tab records: archive/manual, unowned/source path, packaged/destination path, owner/reason.
# shortcut: inspect top-level /bin and /sbin only; library/nested collisions need manual converter recovery.
function usrmerge_output_collisions() {
  local name directory source target left right left_status right_status
  for name in bin sbin; do
    directory="/$name"
    [ -L "$directory" ] && continue
    [ -d "$directory" ] || continue
    for source in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
      [ -e "$source" ] || [ -L "$source" ] || continue
      target="/usr/$name/${source##*/}"
      [ -e "$target" ] || [ -L "$target" ] || continue
      case "$source$target" in *$'\n'*|*$'\t'*|*$'\r'*) echo 'dss:error: Unsupported control characters in usrmerge collision paths; inspect manually.' >&2; return 1;; esac
      case "${source##*/}" in *[!a-zA-Z0-9._+-]*) printf 'manual\t%s\t%s\tunsupported executable name\n' "$source" "$target"; continue;; esac
      # These aliases are accepted by convert-usrmerge; other symlink/type conflicts stay manual.
      if [ -L "$source" ] && [ -L "$target" ]; then
        left=$(readlink -- "$source") || return 1
        right=$(readlink -- "$target") || return 1
        if [ "$left" = "$right" ] || [ "${source%/*}/$left" = "$right" ] || [ "$left" = "${target%/*}/$right" ]; then continue; fi
      fi
      if [ -L "$source" ] && [ "$(readlink -- "$source")" = "$target" ]; then continue; fi
      if [ -L "$target" ] && [ "$(readlink -- "$target")" = "$source" ]; then continue; fi
      if [ ! -f "$source" ] || [ -L "$source" ] || [ ! -f "$target" ] || [ -L "$target" ]; then
        printf 'manual\t%s\t%s\tunsupported file types\n' "$source" "$target"; continue
      fi
      left=$(packages_output_file_owner "$source"); left_status=$?
      right=$(packages_output_file_owner "$target"); right_status=$?
      if [ "$left_status:$right_status" = 1:0 ]; then printf 'archive\t%s\t%s\t%s\n' "$source" "$target" "$right"
      elif [ "$left_status:$right_status" = 0:1 ]; then printf 'archive\t%s\t%s\t%s\n' "$target" "$source" "$left"
      else printf 'manual\t%s\t%s\townership ambiguous or neither/existing package-owned copies\n' "$source" "$target"; fi
    done
  done
}

function usrmerge_check_collisions() {
  local prefer=${DR_PREFER_PACKAGED_USRMERGE_FILES:-false} collisions action source target owner blocked=false
  collisions=$(usrmerge_output_collisions) || return 1
  while IFS=$'\t' read -r action source target owner; do
    [ -n "$action" ] || continue
    if [ "$action" = archive ] && $prefer; then
      echo "dss:warn: usrmerge will archive unowned $source and retain $target ($owner)." >&2
    else
      echo "dss:error: usrmerge collision: $source and $target ($owner)." >&2
      if [ "$action" = archive ]; then
        echo 'dss:error: Review the unowned executable; DR_PREFER_PACKAGED_USRMERGE_FILES=true explicitly archives it and keeps the packaged counterpart.' >&2
        usrmerge_preference_needed=true
      fi
      blocked=true
    fi
  done <<< "$collisions"
  ! $blocked
}

function usrmerge_check_upgrade_path() {
  local family=$1 current=$2 target=$3 boundary
  case "$family" in debian) boundary=bookworm;; ubuntu) boundary=hirsute;; *) return 1;; esac
  is_distro_name_older "$current" "$target" || return 0
  is_distro_name_older "$target" "$boundary" && return 0
  if { [ -e "/etc/unsupported-skip-usrmerge-conversion" ] || [ -L "/etc/unsupported-skip-usrmerge-conversion" ]; } && ! usrmerge_is_complete; then
    echo 'dss:error: Requested path requires usrmerge (merged /usr directories), but /etc/unsupported-skip-usrmerge-conversion disables it; review that marker manually before upgrading.' >&2
    echo 'dss:error: usrmerge moves system files from /bin, /sbin and /lib into /usr and replaces those directories with symbolic links. Review why conversion was disabled before removing the marker.' >&2
    return 1
  fi
  usrmerge_check_collisions
}

function usrmerge_archive_collisions() {
(
  umask 077
  local collisions=$1 baseline parent directory action source target owner relative current status
  [ -n "$collisions" ] || return 0
  record_config_state >&2 || return 1
  baseline=$(config_state_output_baseline) || return 1
  parent="$baseline.usrmerge"
  [ ! -L "$parent" ] || return 1
  mkdir -p -- "$parent" && chmod u=rwx,go= -- "$parent" || return 1
  directory=$(mktemp -d "$parent/files.XXXXXX") || return 1
  echo "dss:warn: usrmerge collision backup/attempt directory: $directory" >&2
  printf '%s\n' "$collisions" > "$directory/collisions.tsv" || return 1
  dpkg-query -W -f='${Package}\t${Architecture}\t${Status}\t${Version}\n' > "$directory/packages.before" || return 1
  while IFS=$'\t' read -r action source target owner; do
    [ "$action" = archive ] || return 1
    relative=${source#/}
    printf '%s\0' "$relative" >> "$directory/archive-paths" || return 1
  done <<< "$collisions"
  tar --acls --xattrs -C / -cpf "$directory/files.tar" --null -T "$directory/archive-paths" || return 1
  while IFS=$'\t' read -r action source target owner; do
    [ -f "$source" ] && [ ! -L "$source" ] && [ -f "$target" ] && [ ! -L "$target" ] || return 1
    current=$(packages_output_file_owner "$source"); status=$?
    [ "$status" -eq 1 ] || return 1
    current=$(packages_output_file_owner "$target") && [ "$current" = "$owner" ] || return 1
    relative=${source#/}
    mkdir -p -- "$directory/originals/${relative%/*}" || return 1
    mv --no-clobber -- "$source" "$directory/originals/$relative" || return 1
    [ ! -e "$source" ] && [ ! -L "$source" ] && [ -f "$directory/originals/$relative" ] || return 1
    printf '%s\t%s\n' "$source" "$directory/originals/$relative" >> "$directory/files.moved" || return 1
  done <<< "$collisions"
)
}

function check_usrmerge() {
  local info status collisions files
  if info=$(dpkg-query -W -f='${Status}' usrmerge 2>/dev/null); then :
  else status=$?; [ "$status" -eq 1 ] || return "$status"; info=; fi
  if usrmerge_is_complete; then
    case "$info" in *' ok unpacked'|*' ok half-configured') dpkg --configure usrmerge || return $?;; esac
    return 0
  fi
  if [ -e "/etc/unsupported-skip-usrmerge-conversion" ] || [ -L "/etc/unsupported-skip-usrmerge-conversion" ]; then
    echo 'dss:error: usrmerge conversion was explicitly disabled; review /etc/unsupported-skip-usrmerge-conversion manually.' >&2; return 1
  fi
  pause_check || return 1
  usrmerge_check_collisions || return 1
  collisions=$(usrmerge_output_collisions) || return 1
  if [ -n "$collisions" ]; then
    usrmerge_archive_collisions "$collisions" || { echo 'dss:error: usrmerge collision backup/move failed; no converter or APT operation attempted. Review the reported backup directory.' >&2; return 1; }
  fi
  if [ -x "/usr/lib/usrmerge/convert-usrmerge" ]; then
    # Retry the packaged converter before APT can configure other packages on a partial merge.
    files=$(dpkg-query -L usrmerge) || return 1
    grep -Fxq -- "/usr/lib/usrmerge/convert-usrmerge" <<< "$files" || return 1
    "/usr/lib/usrmerge/convert-usrmerge" || return $?
    usrmerge_is_complete || { echo 'dss:error: usrmerge converter returned without canonical /bin, /sbin and /lib links; inspect manually before package work.' >&2; return 1; }
    # Configuring an already configured package fails, even after a successful filesystem repair.
    case "$info" in *' ok unpacked'|*' ok half-configured') dpkg --configure usrmerge || return $?;; esac
  else
    case "$info" in *' ok installed'|*' ok unpacked'|*' ok half-configured') echo 'dss:error: Installed/partial usrmerge has no executable packaged converter; restore the package manually before further package work.' >&2; return 1;; esac
    # Restored systems may have no indexes, or source preparation may have changed mirrors.
    apt_get_update || return $?
    apt_get_install usrmerge || return $?
  fi
  usrmerge_is_complete || { echo 'dss:error: usrmerge did not establish canonical /bin, /sbin and /lib links; stop and inspect before package work.' >&2; return 1; }
  echo 'dss:trace:check_usrmerge completed.' >&2
}

function usrmerge_recover_pending() {
  local info status
  [ -f "/etc/debian_version" ] || return 0
  if info=$(dpkg-query -W -f='${Status}' usrmerge 2>/dev/null); then :
  else status=$?; [ "$status" -eq 1 ] && return 0; return "$status"; fi
  case "$info" in *' ok unpacked'|*' ok half-configured') check_usrmerge;;
    *' ok installed') usrmerge_is_complete || check_usrmerge;;
    *) return 0;;
  esac
}

# A renamed NIC can leave a static eth0 configuration disconnected after reboot.
# Preserve naming only when both the configured static eth0 and the live interface are present.
function retain_etc_networking_naming_re_enX0() {
  # test we're a debian/ubuntu system currently using eth0
  [ ! -f /etc/network/interfaces ] && return 0
  ! egrep -i '^ *iface.*eth0.*static' /etc/network/interfaces && return 0
  [ -e /etc/systemd/network/99-default.link ] && return 0
  ! ifconfig eth0 2>/dev/null && return 0

  ln -sf /dev/null /etc/systemd/network/99-default.link && echo "dss:info: Disabling /etc/systemd/network/99-default.link re enX0"
  # dev null approach described:
  #   https://www.linuxfromscratch.org/lfs/view/9.1-systemd/chapter07/network.html
  #   https://bbs.archlinux.org/viewtopic.php?id=259086&p=2 the dev null symlink approach
  # another option: kernel parameter: net.ifnames=0
  # description of change going into bookworm (deb 12):
  #   https://www.debian.org/releases/bookworm/amd64/release-notes/ch-information.en.html#xen-network
  #   https://wiki.debian.org/NetworkInterfaceNames#bookworm-xen
}


# return 0 if a file or two was removed.  e.g. so you can to rm_overwrite_files $tmplog && retry
function rm_overwrite_files() {
   [  -z "$1" ] && return 1
   [  ! -f "$1" ] && return 1
   local tmplog="$1"
   grep -qF 'dss:error: Cannot capture APT output;' "$tmplog" && return 1

  if egrep -aqi 'mysql_upgrade: [ERROR] .*alter routine command denied to user ' $tmplog; then
    echo "dss:warn: mysql error.  Trying a mysql_upgrade to resolve."
    mysql_upgrade
  fi
  local mysqlerrlogs="$([ -d /var/lib/mysql ] && [ -d /var/log/mysql ] && find /var/lib/mysql /var/log/mysql -type f -mmin -10 | egrep '\.err$|mysql/error.log')"
  if [ -d /var/lib/mysql ] ; then
    mysqlerrlogs="$mysqlerrlogs $tmplog"
  fi
  if [ ! -z "$mysqlerrlogs" ] && grep -qai 'Thread stack overrun' $mysqlerrlogs; then
    echo "dss:warn: mysql Thread stack overrun.  Attempting to tweak 128K stacks to be bigger."
    find /etc/mysql/ -type f | xargs  --no-run-if-empty  egrep 'thread_stac' | awk '{print "dss:info:mysqlthreadstacks:before:" $0}'
    find /etc/mysql/ -type f | xargs  --no-run-if-empty  egrep -l '^thread_stac' | xargs --no-run-if-empty  sed -i 's/128K/256K/'
    find /etc/mysql/ -type f | xargs  --no-run-if-empty  egrep 'thread_stac' | awk '{print "dss:info:mysqlthreadstacks:after:" $0}'
  fi
  if [ ! -z "$mysqlerrlogs" ] && egrep -aqi 'mysql_upgrade: [ERROR] .*alter routine command denied to user ' $mysqlerrlogs; then
    echo "dss:warn: mysql error.  Trying a mysql_upgrade to resolve."
    mysql_upgrade
  fi

  # disable some settings that become deprecated (if they are causing errors).
  if [ ! -z "$mysqlerrlogs" ] && egrep -qai 'e-rc.d: initscript mysql, action "start" fai' $mysqlerrlogs; then
    #egrep -qai 'pkg: error processing package mysq' $mysqlerrlogs ||
    #if egrep -qai 'mysql_upgrade: [ERROR] .*alter routine command denied to user ' $mysqlerrlogs; then
    for i in query_cache_limit query_cache_size key_buffer myisam-recover; do
      if egrep -qai "unknown variable '$i" $mysqlerrlogs; then
      #if egrep -aqi "unknown variable '$i" $tmplog; then
        echo "dss:warn: trying to fix an issue re unknown variable $i."
        find /etc/mysql/ -type f | xargs  --no-run-if-empty  egrep "$i" | awk '{print "dss:info:mysql:'$i':before:" $0}'
        find /etc/mysql/ -type f | xargs  --no-run-if-empty  egrep -l "^$i" | xargs --no-run-if-empty  sed -i "s/^$i/#$i/"
        find /etc/mysql/ -type f | xargs  --no-run-if-empty  egrep "$i" | awk '{print "dss:info:mysql:'$i':after:" $0}'
      fi
    done
  fi


  if egrep -qi "doveconf: Fatal: " "$tmplog"; then
    # e.g. doveconf: Fatal: Error in configuration file /etc/dovecot/dovecot.conf: ssl enabled, but ssl_cert not set
    echo "dss:error: issue with dovecot config.  Resolve (e.g. by removing dovecot for fixing the issue). $(egrep -i "doveconf: Fatal: " "$tmplog")"
    print_uninstall_dovecot
  elif egrep -qi "doveconf: Warning: Obsolete setting in" "$tmplog"; then
    echo "dss:warn: issue with obsolete dovecot config.  $(egrep -i "doveconf: Fatal: " "$tmplog")"
    echo "dss:warn: May pay to remove dovecot per the instructions below."
    print_uninstall_dovecot
  fi
  if egrep -qi "dpkg: error processing package fail2ban (--configure):" "$tmplog" || egrep -qi 'See "systemctl status fail2ban.service"' "$tmplog" ; then
    echo "dss:error: issue with fail2ban config.  Resolve (e.g. by removing dovecot for fixing the issue). $(egrep -i "fail2ban (--configure|status fail2ban.service" "$tmplog")"
    print_uninstall_fail2ban
  fi

  #  trying to overwrite shared '/usr/share/doc/libkmod2/changelog.Debian.gz', which is different from other instances of package libkmod2:amd64
  # Unpacking libpython2.7-minimal:amd64 (2.7.12-1ubuntu0~16.04.3) ...
  # dpkg: error processing archive /var/cache/apt/archives/libpython2.7-minimal_2.7.12-1ubuntu0~16.04.3_amd64.deb (--install):
  # trying to overwrite shared '/etc/python2.7/sitecustomize.py', which is different from other instances of package libpython2.7-minimal:amd64

   # egrep -qai "trying to overwrite shared '/usr/share/doc/libperl5.22/changelog.Debian.gz" "$tmplog" && echo "dss:info: handling libperl issue." && rm -f /usr/share/doc/libperl5.22/changelog.Debian.gz
  local overwrites="$(grep "trying to overwrite shared '/usr/share/doc/.*/changelog.Debian.gz'" $tmplog | sed 's#.*trying to overwrite shared .##g' | sed 's#., which is different from other instances of package.*##g')"
  overwrites="$overwrites $(grep "trying to overwrite shared '/.*.py'" $tmplog | sed 's#.*trying to overwrite shared .##g' | sed 's#., which is different from other instances of package.*##g')"
  overwrites="$overwrites $(grep "trying to overwrite shared '/.*.conf'" $tmplog | sed 's#.*trying to overwrite shared .##g' | sed 's#., which is different from other instances of package.*##g')"
  local i='' baseline='' backup='' backup_parent=''
  local rmed=0
  for i in $overwrites; do
    case "$i" in /etc/apache2|/etc/apache2/*|/etc/httpd|/etc/httpd/*)
      echo "dss:warn: Preserving Apache configuration after package overwrite failure: $i. Review the package error; no configuration was removed." >&2
      continue;;
    esac
    [  ! -f "$i" ] && echo "dss:warn: expecting $i to be a file in rm_overwrite_files" && continue
    if [ -z "$baseline" ]; then
      record_config_state || return 1
      baseline=$(config_state_output_baseline) || return 1
      case "$baseline" in /*) :;; *) return 1;; esac
      backup_parent="$baseline.shared-overwrites"
    fi
    backup=$(
      umask 077
      [ ! -L "$backup_parent" ] && mkdir -p -- "$backup_parent" && chmod 700 "$backup_parent" &&
        mktemp -d "$backup_parent/overwrite.XXXXXX"
    ) || { echo "dss:error: Cannot create shared-file backup; preserving $i." >&2; return 1; }
    if ! (umask 077; printf '%s\n' "$i" > "$backup/source.path" && cp -a -- "$i" "$backup/file"); then
      echo "dss:error: Cannot back up shared file $i; preserving it. Review $backup." >&2
      return 1
    fi
    rm -f -- "$i" || return 1
    echo "dss:info: removed a shared overwrite file.  sometimes required when cross grading: $i. Backup: $backup"
    rmed=$((rmed+1))
  done
  if egrep -aqi 'ERROR: Your kernel version indicates a revision number' $tmplog; then
    #Preparing to unpack .../libc6_2.27-3ubuntu1.4_amd64.deb ...
    #ERROR: Your kernel version indicates a revision number
    #of 255 or greater.  Glibc has a number of built in
    #assumptions that this revision number is less than 255.
    #If you\'ve built your own kernel, please make sure that any
    #custom version numbers are appended to the upstream
    #kernel number with a dash or some other delimiter.
    # uname -a
    # Linux example.com 4.14.256-rh294-20211127025231.xenU.x86_64 #1 SMP Sat Nov 27 02:58:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
    echo "dss:error: old glibc error.  This glibc cannot handle kernels with minor versions > 255.  e.g. $(uname -a).  Try restarting the server with a kernel with a lower minor version.  e.g. a 5.10.96 kernel would be OK, but 4.14.264 is not OK.  For RimuHosting customers use https://rimuhosting.com/cp/vps/kernel.jsp to do this."
    return 1
  fi
  [  $rmed -eq 0 ] && return 1
  return 0
}

# Reuse work only within this invocation; never persist success across script runs.
apt_state_updated=
apt_state_healthy=
apt_state_upgraded=
apt_state_dist_upgraded=

function apt_state_invalidate_packages() {
  apt_state_healthy=
  apt_state_upgraded=
  apt_state_dist_upgraded=
}

# This signature is a change-detection fingerprint, not a trust check.
# Reuse needs unchanged sources, indexes, tools and relevant package state, not just a matching release name.
# Local checks are cheaper than APT resolution/network work. A failed probe disables reuse.
function apt_state_output_signature() {
(
  [ "${apt_state_cache_disabled:-false}" = false ] || return 1
  [ -z "$APT_CONFIG$DPKG_ADMINDIR$DPKG_ROOT" ] || return 1
  case "$APT_GET_INSTALL_OPTIONS" in *Dir::*|*--admindir*|*--root*|*--simulate*|*--download-only*|*--print-uris*) return 1;; esac
  local kind=$1 config path sources keypaths binary metadata foreign_architectures dpkg_help
  set -o pipefail
  config=$(apt-config dump) || return 1
  # Custom roots can move inputs outside the paths inspected below; run normally there.
  apt_config_has_standard_paths "$config" || return 1
  sources=$(apt_sources_files) || return 1
  {
    printf '%s\n' "$config" "$APT_GET_INSTALL_OPTIONS"
    printf 'defer-autoremove:%s\n' "${apt_defer_autoremove:-false}"
    dpkg --print-architecture || exit 1
    if foreign_architectures=$(dpkg --print-foreign-architectures 2>/dev/null); then :
    else
      # Pre-Multiarch dpkg has no foreign list; genuine errors on newer dpkg stay fatal.
      dpkg_help=$(LC_ALL=C dpkg --help) || exit 1
      case "$dpkg_help" in *--print-foreign-architectures*) exit 1;; esac
      foreign_architectures=
    fi
    printf '%s\n' "$foreign_architectures"
    for binary in apt-get apt-cache apt-config dpkg; do
      path=$(command -v "$binary") || exit 1
      [ -f "$path" ] || exit 1
      stat -L -c '%n %i %s %y %z' -- "$path" || exit 1
    done
    for path in "/etc/apt" "/usr/share/keyrings"; do
      if [ -e "$path" ]; then
        find -L "$path" -maxdepth 2 -type f -exec cksum {} + || exit 1
      else
        printf 'absent:%s\n' "$path"
      fi
    done
    # Signed-By may reference keys outside the normal keyring directories.
    # [signed-by=/etc/apt/keyrings/debian.gpg] or Signed-By: /etc/apt/keyrings/debian.gpg -> that absolute path.
    # Embedded key text and fingerprint-only values do not yield file paths.
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      keypaths=$(awk '
        {
          text=$0
          if (FILENAME ~ /\.sources$/) {
            if ($0 ~ /^[^ \t#]/) signed=(tolower($0) ~ /^signed-by:/)
            if (!signed) next
            sub(/^[^:]+:/, "", text)
          } else {
            if (!match(tolower(text), /signed-by=[^] \t]+/)) next
            text=substr(text,RSTART+10,RLENGTH-10)
          }
          gsub(/,/, " ", text); n=split(text,words,/[ \t]+/)
          for (i=1;i<=n;i++) if (words[i] ~ /^\//) print words[i]
        }
      ' "$path") || exit 1
      while IFS= read -r path; do
        [ -n "$path" ] || continue
        cksum "$path" || exit 1
      done <<< "$keypaths"
    done <<< "$sources"
    # Hash indexes with coarse ctimes; precise metadata avoids scanning large index contents.
    if [ "$kind" = inputs ]; then :
    elif [ -d "/var/lib/apt/lists" ]; then
      find -L "/var/lib/apt/lists" -maxdepth 1 -type f ! -name lock -print0 |
        while IFS= read -r -d '' path; do
          metadata=$(stat -L -c '%n %i %s %y %z' -- "$path") || exit 1
          printf '%s\n' "$metadata"
          if [[ ! "$metadata" =~ [.][0-9]+[[:space:]][+-][0-9]+$ ]] ||
              [[ "$metadata" =~ [.]0+[[:space:]][+-][0-9]+$ ]]; then
            cksum "$path" || exit 1
          fi
        done || exit 1
    else
      exit 1
    fi
    if [ "$kind" = packages ]; then
      cksum "/var/lib/dpkg/status" || exit 1
      for path in "/var/lib/dpkg/arch" "/var/lib/apt/extended_states"; do
        if [ -e "$path" ]; then cksum "$path" || exit 1; else printf 'absent:%s\n' "$path"; fi
      done
      for path in "/var/lib/dpkg/updates" "/var/lib/dpkg/triggers"; do
        if [ -e "$path" ]; then
          find -L "$path" -maxdepth 1 -type f ! -name Lock ! -name lock -exec cksum {} + || exit 1
        else
          printf 'absent:%s\n' "$path"
        fi
      done
    fi
  } | LC_ALL=C sort | cksum
)
}

function apt_state_repositories_are_current() {
  local signature
  [ -n "${apt_state_updated:-}" ] || return 1
  signature=$(apt_state_output_signature repositories 2>/dev/null) || return 1
  [ -n "$signature" ] && [ "$signature" = "$apt_state_updated" ]
}

function apt_state_record_healthy() {
  apt_state_healthy=$(apt_state_output_signature packages 2>/dev/null) || apt_state_healthy=
  return 0
}

function apt_get_remove() {
  pause_check
  local tmplog
  apt_state_invalidate_packages
  tmplog=$(mktemp "tmplog.aptgetremove.log.XXXXXX") || return 1
  apt_get_apply $APT_GET_INSTALL_OPTIONS remove $@ 2>&1 | tee "$tmplog"
  local ret=${PIPESTATUS[0]}
  [  $ret -ne 0 ] && rm_overwrite_files "$tmplog" && apt_get_apply $APT_GET_INSTALL_OPTIONS remove $@ && ret=$?
  #if [  $ret -ne 0 ] && echo "$@" | egrep -qai 'gcc-6-base:i386'; then
  #fi
  if [  $ret -ne 0 ] && echo "$@" | egrep -qai 'gcc-6-base:i386'; then
    if egrep -qai 'systemd : Depends: libcap2-bin' "$tmplog"; then
      echo "dss:info: attempting to install libcap2-bin since gcc-6-base remove failed." && apt_get_install libcap2-bin:amd64 && apt_get_apply $APT_GET_INSTALL_OPTIONS remove $@ && ret=$?
    fi
  fi
  local essentialissuepackages="$(grep --after-context 50 'WARNING: The following essential packages will be removed.' "$tmplog" | grep '^ ' | tr '\n' ' ' | sed  -r 's/\(due to +\S*?\)//g')"
  [ ! -z "$essentialissuepackages" ] && echo "dss:warn: apt_get_remove $@ essential package issues for: $essentialissuepackages"
  echo "$essentialissuepackages" | egrep -qai 'libgcc-s1:i386' && echo "dss:warn: This issue may be related to this bug report: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=992317"
  rm -f "$tmplog"
  if [ "$ret" -eq 0 ]; then apt_state_record_healthy; fi
  return $ret
}

function apt_get_install() {
  pause_check
  local tmplog
  apt_state_invalidate_packages
  tmplog=$(mktemp "tmplog.aptgetinstall.log.XXXXXX") || return 1
  apt_get_apply $APT_GET_INSTALL_OPTIONS install $@ 2>&1 | tee "$tmplog"
  local ret=${PIPESTATUS[0]}
  [  $ret -ne 0 ] && rm_overwrite_files "$tmplog" && apt_get_apply $APT_GET_INSTALL_OPTIONS install $@ && ret=$?
  local essentialissuepackages="$(grep --after-context 50 'WARNING: The following essential packages will be removed.' "$tmplog" | grep '^ ' | tr '\n' ' ' | sed  -r 's/\(due to +\S*?\)//g')"
  [ ! -z "$essentialissuepackages" ] && echo "dss:warn: apt_get_install $@ essential package issues for: $essentialissuepackages"

  rm -f "$tmplog"
  if [ "$ret" -eq 0 ]; then apt_state_record_healthy; fi
  return $ret
}

function apt_get_f_install() {
  pause_check
  local tmplog signature audit
  signature=$(apt_state_output_signature packages 2>/dev/null) || signature=
  if [ -n "$signature" ] && [ "$signature" = "${apt_state_healthy:-}" ]; then
    echo "dss:trace:apt_get_f_install: dependency state already checked."
    return 0
  fi
  printf 'dss:stage: Checking package dependencies%s\n' "${1:+ $1}" >&2
  apt_state_invalidate_packages
  tmplog=$(mktemp "tmplog.aptgetfinstall.log.XXXXXX") || return 1
  apt_get_apply $APT_GET_INSTALL_OPTIONS -f install 2>&1 | tee "$tmplog"
  local ret=${PIPESTATUS[0]}
  if [  $ret -ne 0 ]; then
    rm_overwrite_files "$tmplog" && apt_get_apply $APT_GET_INSTALL_OPTIONS -f install && ret=$?
  fi
  echo "dss:trace:apt_get_f_install:$1 results $(egrep 'upgraded' "$tmplog")"
  local essentialissuepackages="$(grep --after-context 50 'WARNING: The following essential packages will be removed.' "$tmplog" | grep '^ ' | tr '\n' ' ' | sed  -r 's/\(due to +\S*?\)//g')"
  [ ! -z "$essentialissuepackages" ] && echo "dss:warn: apt_get_f_install $@ essential package issues for: $essentialissuepackages"
  if [ ! -z "$essentialissuepackages" ] && echo "$essentialissuepackages" | grep -qai 'perl-base:amd64'; then
    echo "dss:trace: Checking perl-base:i386 for dependency recovery."
    if dpkg -l | grep perl-base | grep i386 | grep -qai ii; then
      echo "dss:trace: perl-base:i386 is already installed."
    else
      apt-get download perl-base:i386
      dpkg -i perl-base*i386*deb
      apt_get_apply $APT_GET_INSTALL_OPTIONS -f install 2>&1 | tee "$tmplog"
      local ret=${PIPESTATUS[0]}
    fi
  fi

  rm -f "$tmplog"
  if [ $ret -ne 0 ]; then
    if audit=$(LC_ALL=C dpkg --audit); then
      if [ -n "$audit" ]; then
        printf '%s\n' "$audit" | awk '{ print "dss:warn: " $0 }'
      else
        echo 'dss:warn: APT dependency repair failed; dpkg reports no incomplete package configurations.' >&2
      fi
    else
      echo 'dss:warn: Cannot inspect incomplete package configurations after APT failed.' >&2
    fi
  fi
  if [ "$ret" -eq 0 ]; then apt_state_record_healthy; fi
  return $ret
}

function dpkg_install() {
  [  -z "$1" ] && return 0
  local tmplog
  apt_state_invalidate_packages
  tmplog=$(mktemp "tmplog.dpkginstall.log.XXXXXX") || return 1
  dpkg --force-confnew --force-confmiss --install $@ 2>&1 | tee "$tmplog"
  ret=${PIPESTATUS[0]}
  if [  $ret -eq 0 ]; then
    # dpkg: error processing archive /var/cache/apt/archives/bash_4.4-5_amd64.deb (--install):
    # pre-dependency problem - not installing bash
    # Errors were encountered while processing:
    # /var/cache/apt/archives/bash_4.4-5_amd64.deb

    # Errors were encountered while processing:
    # gcj-6-jre-lib
    # openjdk-8-jre-headless:amd64
    # postfix
    # dss:warn: dpkg install lied about the return code(#2).  will need to retry the install.

    egrep -qai 'Errors |pre-dependency problem|dpkg: error' "$tmplog" && ret=1 && echo "dss:warn: dpkg install lied about the return code.  will need to retry the install."
    # maybe it never lied?  Changed from ret=$? to ret=${PIPESTATUS[0]} because of the pipe to tee

  fi
  # https://bugs.launchpad.net/ubuntu/+source/perl/+bug/1574351
  # dpkg: error processing archive libperl5.22_5.22.1-9ubuntu0.2_amd64.deb (--install):
  # trying to overwrite shared '/usr/share/doc/libperl5.22/changelog.Debian.gz', which is different from other instances of package libperl5.22:amd64

  [  $ret -ne 0 ] && rm_overwrite_files "$tmplog"
  if [ $ret -ne 0 ]; then
    # first dpkg --install fails.  second one should work ok.  e.g.:
    # Errors were encountered while processing:
     # /var/cache/apt/archives/dpkg_1.18.24_amd64.deb
     # /var/cache/apt/archives/tar_1.29b-1.1_amd64.deb
    local failedinstalls=$(cat "$tmplog" | grep --after-context 50 'Errors were encountered while processing:' | sed 's/.*Errors were encountered while processing://' | grep '.deb')
    if [  ! -z "$failedinstalls" ]; then
      echo "dss:trace:dpkg_install: some .deb packages had issues.  retrying those: $failedinstalls"
      dpkg --force-confnew --force-confmiss --install $failedinstalls
      ret=$?
      echo "dss:trace:dpkg_install: retry install $([ $ret -eq 0 ] && echo "succeeded" || echo "failed")"
    fi
  fi
  if [ $ret -ne 0 ]; then
    echo "dss:trace:dpkg_install: some .deb packages had issues.  retrying to install all packages."
    dpkg --force-confnew --force-confmiss --install $@  2>&1 | tee "$tmplog"
    ret=${PIPESTATUS[0]}
    if [  $ret -eq 0 ]; then
      egrep -qai 'Errors |pre-dependency problem|dpkg: error' "$tmplog" && ret=1 && echo "dss:warn: dpkg install lied about the return code(#2).  will need to retry the install."
    fi
  fi
  [  -f "$tmplog" ] && rm -f "$tmplog"
  return $ret
}

function check_systemd_install_matches_init() {
  [ -f "/etc/debian_version" ] || return 0
  local running selected running_family selected_family
  running=$(readlink "/proc/1/exe") || { echo 'dss:error: Cannot read the running PID 1 executable; inspect init before crossgrading.' >&2; return 1; }
  # Package upgrades can unlink the running binary; its old path still identifies the init family.
  running=${running%" (deleted)"}
  selected=$(readlink -f "/sbin/init") || { echo 'dss:error: Cannot resolve /sbin/init; inspect the selected init before crossgrading.' >&2; return 1; }
  if [ ! -f "/sbin/init" ] || [ ! -x "/sbin/init" ]; then
    echo 'dss:error: /sbin/init does not select an executable file; inspect init before crossgrading.' >&2; return 1
  fi
  case "$running" in
    /lib/systemd/systemd|/usr/lib/systemd/systemd) running_family=systemd;;
    /sbin/init|/usr/sbin/init) running_family=init;;
    *) echo "dss:error: Unknown running PID 1 executable: $running. Inspect init before crossgrading." >&2; return 1;;
  esac
  case "$selected" in
    /lib/systemd/systemd|/usr/lib/systemd/systemd) selected_family=systemd;;
    /sbin/init|/usr/sbin/init) selected_family=init;;
    *) echo "dss:error: Unknown executable selected by /sbin/init: $selected. Inspect init before crossgrading." >&2; return 1;;
  esac
  if [ "$running_family" != "$selected_family" ]; then
    echo "dss:error: Running PID 1 is $running_family ($running), but /sbin/init selects $selected_family ($selected). Complete the init transition and boot with the selected init before crossgrading." >&2
    return 1
  fi
  return 0
}

# shellcheck shell=bash
# shellcheck shell=bash
# Bookworm crossgrade keeps unavailable foreign applications and never autoremoves.
# https://wiki.debian.org/CrossGrading (Bookworm dpkg/tar/apt bootstrap recipe)
# Candidate: 2.36-1 plus madison "libc6 | 2.36-1 | https://deb.debian.org/debian bookworm/main amd64 Packages" -> 2.36-1.
# Candidate: (none), or a matching version available only for i386, produces no candidate.
function crossgrade_bookworm_output_candidate() {
  local package=$1 version rows policy
  policy=$(LC_ALL=C apt-cache policy "$package:amd64") || return 2
  version=$(printf '%s\n' "$policy" | awk '$1 == "Candidate:" { print $2; exit }')
  [ -n "$version" ] && [ "$version" != '(none)' ] || return 1
  rows=$(LC_ALL=C apt-cache madison "$package:amd64") || return 2
  printf '%s\n' "$rows" | awk -F '|' -v version="$version" '
    { gsub(/^[ \t\r\f\013]+|[ \t\r\f\013]+$/, "", $2) }
    $2 == version && $3 ~ /[ \t\r\f\013]amd64[ \t\r\f\013]+Packages[ \t\r\f\013]*$/ { found=1 }
    END { exit !found }' || return 1
  printf '%s\n' "$version"
}

# Every executed removal needs its native replacement or a verified obsolete-package opt-in.
# Bootstrap only downloads; raw dpkg
# never applies the simulated removals of the two installed architecture-all task selectors.
# Remv libc6:i386 [2.36-1] plus Inst libc6:amd64 (2.36-1 Debian:12 [amd64]) can satisfy replacement checks.
# Purg libc6:i386 is rejected; the saved target and installed inventories must also permit each removal.
function crossgrade_bookworm_check_plan() {
  local plan=$1 targets=$2 installed=$3 phase=${4:-remaining} obsolete=${5:-/dev/null}
  awk -F '\t' -v phase="$phase" '
    FILENAME == ARGV[1] { wanted[$1]=1; if ($3 == "same") coinstall[$1]=1; next }
    FILENAME == ARGV[2] {
      if ($1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/) {
        if ($3 == "amd64") native[$2]=1
        if ($3 == "i386") foreign[$2]=1
        if ($4 == "yes") essential[$2]=1
        if ($1 == "install ok installed" && $3 == "all" && $2 ~ /^(tasksel|tasksel-data)$/) bootstrap_all[$2]=1
      }
      next
    }
    FILENAME == ARGV[3] { approved[$1]=1; next }
    {
      line=$0; split(line, field, /[ \t\r\f\013]+/); name=field[2]; sub(/:.*/, "", name)
      if (field[1] == "Inst") {
        if (field[2] ~ /:i386$/ || line ~ /\[i386\]\)$/) { if (phase == "cleanup" || !(name in coinstall)) bad=1 }
        else replaced[name]=1
      }
      if (field[1] == "Remv" || field[1] == "Purg") {
        if (phase == "cleanup" && name in essential) { bad=1; next }
        if (phase == "bootstrap" && field[1] == "Remv" && name in bootstrap_all &&
            (field[2] == name || field[2] == name ":all")) next
        if ((phase == "remaining" || phase == "cleanup") && field[1] == "Remv" && name in approved && name in foreign &&
            !(name in native) && (field[2] == name || field[2] == name ":i386")) next
        if (field[1] == "Purg" || field[2] ~ /:amd64$/ || (!(field[2] ~ /:/) && name in native) || !(name in wanted)) bad=1
        removed[name]=1
      }
    }
    END { for (name in removed) if (!(name in replaced) && !(name in native)) bad=1; exit bad }
  ' "$targets" "$installed" "$obsolete" "$plan"
}

# APT's essential-removal switch also covers coinstalled Protected libraries.
# Permit those foreign duplicates only after their exact native versions and runtime are ready.
function crossgrade_bookworm_output_protected_removal_permission() {
  local packages
  crossgrade_bookworm_check_package_tools || { echo 'dss:error: Native package tools are not ready for foreign-library cleanup.' >&2; return 1; }
  [ "$(od -An -tu1 -j4 -N1 /proc/1/exe 2>/dev/null | tr -d ' ')" = 2 ] || {
    echo 'dss:error: Verify 64-bit PID1 before removing protected foreign libraries.' >&2; return 1;
  }
  packages=$(dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Essential}\t${Protected}\t${Version}\n') || return 1
  printf '%s\n' "$packages" | awk -F '\t' '
    $1 == "install ok installed" && $3 == "amd64" { ready[$2]=$6 }
    $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ && $3 == "i386" {
      if ($4 == "yes") { print "dss:error: Active foreign Essential package blocks cleanup: " $2 > "/dev/stderr"; bad=1 }
      if ($5 == "yes") protected[$2]=$6
    }
    END {
      permission="false"
      for (package in protected) {
        if (!(package in ready) || ready[package] == "" || ready[package] != protected[package]) {
          print "dss:error: Protected foreign package needs its configured native version before cleanup: " package > "/dev/stderr"; bad=1
        }
        permission="true"
      }
      if (bad) exit 1
      print permission
    }
  '
}

# Download to an empty private cache, check the simulated removals, then inspect every archive.
function crossgrade_bookworm_download() {
  local directory=$1 targets=$2 installed=$3 phase=$4 file package version arch cache candidates status retries=0 progress cleanup_permission
  local -a apt_options=()
  local -a learned=()
  local -a essential_options=(--allow-remove-essential)
  shift 4
  read -r -a apt_options <<< "$APT_GET_INSTALL_OPTIONS"
  if [ "$phase" = cleanup ]; then
    cleanup_permission=$(crossgrade_bookworm_output_protected_removal_permission) || return 1
    essential_options=(-o "APT::Get::allow-remove-essential=$cleanup_permission" -o APT::Force-LoopBreak=false)
  fi
  cache=$(mktemp -d "$directory/$phase.XXXXXX") || return 1
  mkdir "$cache/partial" || return 1
  printf '%s\n' "$cache" > "$directory/$phase.cache" || return 1
  while :; do
    printf '%s\n' "$@" > "$directory/$phase.arguments.new" || return 1
    if LC_ALL=C apt-get "${apt_options[@]}" -o APT::Get::AllowUnauthenticated=false \
      -o APT::Get::AutomaticRemove=false -o APT::Get::Purge=false "${essential_options[@]}" --fix-broken --simulate install "$@" \
      > "$directory/$phase.plan" 2>&1; then break; fi
    [ "$phase" != cleanup ] || echo "dss:error: APT could not simulate foreign-package cleanup; inspect $directory/$phase.plan." >&2
    # APT 2.6 can omit new direct dependencies while repairing a broken crossgrade.
    [ "$phase" = remaining ] && [ "$retries" -lt 8 ] || return 1
    retries=$((retries+1))
    # English APT rows: "owner : Depends: child ...", followed by indented Depends rows.
    candidates=$(awk '
      FILENAME == ARGV[1] {
        if ($0 ~ /^[a-z0-9][a-z0-9+.-]*:amd64(=[^ \t\r\f\013]+)?$/) {
          name=$0; sub(/:amd64(=.*)?$/, "", name); requested[name]=1
        }
        next
      }
      {
        text=$0
        if (text ~ /^[ \t\r\f\013]*[^ \t\r\f\013]+[ \t\r\f\013]+:[ \t\r\f\013]+/) {
          sub(/^[ \t\r\f\013]*/, "", text); owner=text; sub(/[ \t\r\f\013].*/, "", owner)
          if (owner ~ /:/ && owner !~ /:amd64$/) owner=""
          sub(/:amd64$/, "", owner)
          sub(/^[^ \t\r\f\013]+[ \t\r\f\013]+:[ \t\r\f\013]+/, "", text)
        } else if (text !~ /^[ \t\r\f\013]+(Pre-?Depends|Depends):/) { owner=""; next }
        sub(/^[ \t\r\f\013]*/, "", text)
        if (!(owner in requested) || text !~ /^(Pre-?Depends|Depends):[ \t\r\f\013]+/) next
        sub(/^[^:]+:[ \t\r\f\013]+/, "", text); name=text; sub(/[ \t\r\f\013].*/, "", name)
        if (name !~ /^[a-z0-9][a-z0-9+.-]*(:amd64)?$/) next
        sub(/:amd64$/, "", name)
        if (!(name in requested) && !(name in seen)) { seen[name]=1; print name }
      }
    ' "$directory/$phase.arguments.new" "$directory/$phase.plan") || return 1
    progress=false
    while IFS= read -r package; do
      [ -n "$package" ] || continue
      if version=$(crossgrade_bookworm_output_candidate "$package"); then :
      else status=$?; [ "$status" -eq 1 ] && continue; return 1; fi
      [ "${#learned[@]}" -lt 64 ] || return 1
      set -- "$@" "$package:amd64=$version"
      learned+=("$package")
      progress=true
      echo "dss:info: Selecting required native dependency $package:amd64=$version for crossgrade." >&2
    done <<< "$candidates"
    if ! $progress; then
      echo "dss:error: Cannot resolve native dependencies safely; inspect $directory/$phase.plan before retrying." >&2
      return 1
    fi
  done
  crossgrade_bookworm_check_plan "$directory/$phase.plan" "$targets" "$installed" "$phase" "${crossgrade_obsolete_approved:-/dev/null}" || {
    echo "dss:error: Crossgrade plan would remove a protected package or reverse architecture; inspect $directory/$phase.plan." >&2
    return 1
  }
  LC_ALL=C apt-get "${apt_options[@]}" -o APT::Get::AllowUnauthenticated=false \
    -o APT::Get::AutomaticRemove=false -o APT::Get::Purge=false -o Dir::Cache::archives="$cache" \
    "${essential_options[@]}" --fix-broken --download-only install "$@" || return 1
  : > "$directory/$phase.archives" || return 1
  for file in "$cache/"*.deb; do
    [ -f "$file" ] || continue
    package=$(dpkg-deb -f "$file" Package) && version=$(dpkg-deb -f "$file" Version) && arch=$(dpkg-deb -f "$file" Architecture) || return 1
    case "$arch" in
      amd64|all) :;;
      i386) if [ "$phase" = cleanup ] || ! awk -F '\t' -v package="$package" '$1 == package && $3 == "same" { found=1 } END { exit !found }' "$targets"; then
        echo "dss:error: Unapproved i386 archive: $file" >&2; return 1;
      fi;;
      *) echo "dss:error: Unexpected $arch archive: $file" >&2; return 1;;
    esac
    printf '%s\t%s\t%s\t%s\n' "$package" "$version" "$arch" "$file" >> "$directory/$phase.archives" || return 1
  done
  # Retain auto-mark intent if installation succeeds but a later recovery step fails.
  : > "$directory/$phase.dependencies.new" || return 1
  if [ -f "$directory/$phase.dependencies" ]; then
    cat "$directory/$phase.dependencies" > "$directory/$phase.dependencies.new" || return 1
  fi
  for package in "${learned[@]}"; do
    if awk -F '\t' -v package="$package" '$1 ~ / installed$/ { name=$2; sub(/:.*/, "", name); if (name == package) found=1 } END { exit !found }' "$directory/original.packages"; then :
    else
      status=$?; [ "$status" -eq 1 ] || return 1
      printf '%s:amd64\n' "$package" >> "$directory/$phase.dependencies.new" || return 1
    fi
  done
  LC_ALL=C sort -u "$directory/$phase.dependencies.new" -o "$directory/$phase.dependencies.new" || return 1
  mv "$directory/$phase.dependencies.new" "$directory/$phase.dependencies" &&
    mv "$directory/$phase.arguments.new" "$directory/$phase.arguments" || return 1
}

function crossgrade_bookworm_check_completion() {
  local directory=$1 audit package version status plan records
  records=$(crossgrade_output_foreign_packages) || return 1
  if [ -n "$records" ]; then
    printf '%s\n' "$records" >&2
    echo 'dss:error: Crossgrade incomplete: active packages must all be amd64 or all. Replace or remove the packages above before continuing; residual configuration-only records are allowed.' >&2
    return 1
  fi
  crossgrade_bookworm_check_native || { echo 'dss:error: Crossgrade core package architecture check failed.' >&2; return 1; }
  [ "$(/usr/bin/dpkg --print-architecture)" = amd64 ] || { echo 'dss:error: Crossgrade incomplete: dpkg native architecture is not amd64.' >&2; return 1; }
  [ "$(apt-config dump | awk '$1 == "APT::Architecture" { gsub(/[";]/,"",$2); print $2; exit }')" = amd64 ] || {
    echo 'dss:error: Crossgrade incomplete: APT native architecture is not amd64; inspect APT architecture overrides.' >&2; return 1;
  }
  /bin/bash -c '[ "$(getconf LONG_BIT)" = 64 ]' || { echo 'dss:error: A freshly started Bash/userland is not 64-bit.' >&2; return 1; }
  while IFS=$'\t' read -r package version; do
    [ -n "$package" ] || continue
    if ! status=$(dpkg-query -W -f='${Status}\t${Architecture}' "$package:amd64" 2>/dev/null); then
      status=$(dpkg-query -W -f='${Status}\t${Architecture}' "$package:all") || return 1
    fi
    case "$status" in $'install ok installed\tamd64'|$'install ok installed\tall') :;; *)
      echo "dss:error: Crossgrade incomplete: required replacement $package:amd64 is not configured." >&2; return 1;;
    esac
  done < "$directory/targets"
  audit=$(LC_ALL=C dpkg --audit 2>&1) || { printf '%s\n' "$audit" >&2; return 1; }
  [ -z "$audit" ] || { printf '%s\n' "$audit" >&2; return 1; }
  LC_ALL=C apt-get -o APT::Get::AllowUnauthenticated=false check || return 1
  plan=$(LC_ALL=C apt-get -s dist-upgrade 2>&1) || { printf '%s\n' "$plan" >&2; return 1; }
  if printf '%s\n' "$plan" | grep -Eq '^(Inst|Conf|Remv|Purg) '; then
    printf '%s\n' "$plan" >&2
    echo 'dss:error: Package changes remain; complete --dist-update and retry the crossgrade before changing release.' >&2
    return 1
  fi
  # A running 32-bit PID1 must not be mistaken for a fully restarted 64-bit system.
  if [ ! -r /proc/1/exe ] || [ "$(od -An -tu1 -j4 -N1 /proc/1/exe 2>/dev/null | tr -d ' ')" != 2 ]; then
    echo 'dss:error: Packages converted, but PID1 is not a verified 64-bit executable. Reboot with the verified 64-bit kernel, reconnect, and retry before Debian 13.' >&2
    return 1
  fi
}

# Keep Apache stopped while its executable and loadable modules change architecture.
# The original target inventory and service state remain valid across partial retries.
function crossgrade_bookworm_apache_handoff() {
  local directory=$1 action=$2 package state file
  case "$action" in
    prepare)
      if [ ! -f "$directory/apache.state" ] && [ ! -f "$directory/apache.legacy" ]; then
        if awk -F '\t' '$1 ~ /^(apache2(-bin)?|libapache2-mod-.*)$/ { found=1 } END { exit !found }' "$directory/targets"; then :
        else state=$?; [ "$state" -eq 1 ] && return 0; return 1; fi
      fi
      if [ ! -f "$directory/apache.php-enabled" ]; then
        if [ -f "$directory/apache.state" ] || [ -f "$directory/apache.legacy" ]; then
          echo "dss:error: Original PHP enablement inventory is missing; review $directory before resuming Apache handoff." >&2
          return 1
        fi
        file=$(mktemp "$directory/apache.php-enabled.XXXXXX") || return 1
        if (
          while IFS=$'\t' read -r package _; do
            case "$package" in libapache2-mod-php[0-9]*)
              if upgrade_php_apache_module_is_enabled "$package"; then
                printf '%s\n' "$package" || exit 1
              else state=$?; [ "$state" -eq 1 ] || exit 1; fi
              ;;
            esac
          done < "$directory/targets"
        ) > "$file" && mv -f -- "$file" "$directory/apache.php-enabled"; then :
        else
          rm -f -- "$file"
          echo "dss:error: Cannot record original PHP handler enablement; Apache handoff has not started. Review $directory." >&2
          return 1
        fi
      fi
      upgrade_php_apache_control "$directory" prepare || return 1
      ;;
    finish)
      [ -f "$directory/apache.state" ] || [ -f "$directory/apache.legacy" ] || return 0
      while IFS= read -r package; do
        [ -n "$package" ] || continue
        state=$(dpkg-query -W -f='${Status}\t${Architecture}' "$package:amd64") || return 1
        if [ "$state" != $'install ok installed\tamd64' ] || ! upgrade_php_apache_module_is_enabled "$package"; then
          echo "dss:error: Native PHP handler $package is not configured and enabled; Apache remains stopped. Review $directory before retrying." >&2
          return 1
        fi
      done < "$directory/apache.php-enabled" || return 1
      upgrade_php_apache_control "$directory" finish || return 1
      ;;
    *) return 1;;
  esac
  return 0
}

# Recovery compares contents; package-created timestamps do not invalidate it.
function crossgrade_bookworm_output_config_signature() {
(
  local path
  [ -z "${APT_CONFIG:-}${DPKG_ADMINDIR:-}${DPKG_ROOT:-}" ] || return 1
  case "$APT_GET_INSTALL_OPTIONS" in *Dir::*|*--admindir*|*--root*|*--simulate*|*--download-only*|*--print-uris*) return 1;; esac
  set -o pipefail
  {
    printf 'options:%s\n' "$APT_GET_INSTALL_OPTIONS"
    for path in /etc/apt /usr/share/keyrings; do
      if [ -e "$path" ]; then
        find -L "$path" -maxdepth 2 -type f -exec sha256sum -- {} + || exit 1
      else printf 'absent:%s\n' "$path"; fi
    done
  } | LC_ALL=C sort | sha256sum
)
}

# Record authenticated archives and their exact plan before any raw package mutation.
function crossgrade_bookworm_record_archives() {
  local directory=$1 phase=$2 package version arch file
  local -a archives=()
  case "$phase" in bootstrap|remaining) :;; *) return 1;; esac
  while IFS=$'\t' read -r package version arch file; do archives+=("$file"); done < "$directory/$phase.archives" || return 1
  [ "${#archives[@]}" -gt 0 ] || return 1
  (
    umask 077
    cp "$directory/installed" "$directory/$phase.installed" &&
      cp "$directory/targets" "$directory/$phase.targets" || exit 1
    : > "$directory/$phase.obsolete" || exit 1
    if [ "$phase" = remaining ] && [ -f "${crossgrade_obsolete_approved:-/dev/null}" ]; then
      cp "$crossgrade_obsolete_approved" "$directory/$phase.obsolete" || exit 1
    fi
    if [ "$phase" = remaining ]; then
      cat "$directory/remaining.dependencies" > "$directory/remaining.dependencies.new" || exit 1
      awk -F '\t' '
        FILENAME == ARGV[1] { if ($1 ~ / installed$/) { sub(/:.*/, "", $2); original[$2]=1 }; next }
        FILENAME == ARGV[2] { explicit[$1]=1; next }
        ($3 == "amd64" || $3 == "all") && !($1 in original) && !($1 in explicit) { print $1 ":amd64" }
      ' "$directory/original.packages" "$directory/targets" "$directory/remaining.archives" >> "$directory/remaining.dependencies.new" || exit 1
      LC_ALL=C sort -u "$directory/remaining.dependencies.new" -o "$directory/remaining.dependencies.new" &&
        mv "$directory/remaining.dependencies.new" "$directory/remaining.dependencies" || exit 1
    fi
    sha256sum -- "${archives[@]}" > "$directory/$phase.sha256.new" &&
      mv "$directory/$phase.sha256.new" "$directory/$phase.sha256" || exit 1
    crossgrade_bookworm_output_config_signature > "$directory/$phase.configuration.new" &&
      mv "$directory/$phase.configuration.new" "$directory/$phase.configuration" || exit 1
    sha256sum -- "$directory/$phase.archives" "$directory/$phase.cache" "$directory/$phase.arguments" \
      "$directory/$phase.plan" "$directory/$phase.installed" "$directory/$phase.targets" \
      "$directory/$phase.obsolete" "$directory/$phase.configuration" "$directory/$phase.sha256" \
      > "$directory/$phase.metadata.sha256.new" &&
      mv "$directory/$phase.metadata.sha256.new" "$directory/$phase.metadata.sha256" || exit 1
    : > "$directory/$phase.started"
  )
}

# One inventory per pass; retry only archives not configured at their exact saved version.
function crossgrade_bookworm_output_pending_archives() {
  local directory=$1 phase=$2 records
  records=$(dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Version}\n') || return 1
  printf '%s\n' "$records" | awk -F '\t' '
    FILENAME == ARGV[1] { count++; name[count]=$1; version[count]=$2; arch[count]=$3; file[count]=$4; next }
    $1 == "install ok installed" { sub(/:.*/, "", $2); configured[$2 SUBSEP $3]=$4 }
    END { for (row=1; row<=count; row++) if (configured[name[row] SUBSEP arch[row]] != version[row]) print file[row] }
  ' "$directory/$phase.archives" -
}

function crossgrade_bookworm_check_package_tools() {
  local configuration shell
  crossgrade_bookworm_check_native || return 1
  for shell in /bin/sh /bin/bash; do
    [ "$(od -An -tu1 -j4 -N1 "$shell" 2>/dev/null | tr -d ' ')" = 2 ] || {
      echo "dss:error: $shell is not a verified native ELF shell; repair it from a trusted console before continuing." >&2; return 1;
    }
    "$shell" -c ':' || { echo "dss:error: Cannot execute $shell; its binary or ELF loader needs repair from a trusted console." >&2; return 1; }
  done
  [ "$(/usr/bin/dpkg --print-architecture)" = amd64 ] || return 1
  configuration=$(apt-config dump) || return 1
  printf '%s\n' "$configuration" | awk '$1 == "APT::Architecture" { gsub(/[";]/, "", $2); if ($2 == "amd64") found=1 } END { exit !found }' || return 1
  apt-get --version >/dev/null
}

# Replacing dpkg, libc and shells can temporarily prevent normal APT operation.
# Save the selected archives and hashes first so recovery can replay the same transaction without resolving it again.
# Replay only the exact authenticated archive set; simulated removals are never executed.
function crossgrade_bookworm_apply_archives() {
  local directory=$1 phase=$2 prepare=${3:-false} cache package version arch file hashes configuration status installed targets obsolete pending attempt previous success=false
  local -a archives=()
  local -a retry=()
  case "$phase" in bootstrap|remaining) :;; *) return 1;; esac
  cache=$(cat "$directory/$phase.cache") || return 1
  case "$cache" in "$directory/$phase".*) :;; *) return 1;; esac
  [ -d "$cache" ] && [ ! -L "$cache" ] || return 1
  installed="$directory/installed"; targets="$directory/targets"; obsolete=/dev/null
  if [ -f "$directory/$phase.metadata.sha256" ]; then
    sha256sum --check --status "$directory/$phase.metadata.sha256" || {
      echo "dss:error: Saved $phase archive metadata changed; no package recovery attempted." >&2; return 1;
    }
    installed="$directory/$phase.installed"; targets="$directory/$phase.targets"; obsolete="$directory/$phase.obsolete"
  elif [ "$phase" = remaining ]; then
    echo 'dss:error: Remaining crossgrade archives have no verified replay metadata; use a trusted console to inspect or restore the system.' >&2; return 1
  fi
  configuration=$(crossgrade_bookworm_output_config_signature) || return 1
  [ "$configuration" = "$(cat "$directory/$phase.configuration")" ] || {
    echo 'dss:error: APT configuration or source contents changed after package conversion started; review cached recovery manually.' >&2; return 1;
  }
  crossgrade_bookworm_check_plan "$directory/$phase.plan" "$targets" "$installed" "$phase" "$obsolete" || return 1
  while IFS=$'\t' read -r package version arch file; do
    case "$file" in "$cache/"*.deb) :;; *) return 1;; esac
    [ -f "$file" ] && [ ! -L "$file" ] || return 1
    archives+=("$file")
  done < "$directory/$phase.archives" || return 1
  [ "${#archives[@]}" -gt 0 ] || return 1
  hashes=$(sha256sum -- "${archives[@]}") || return 1
  [ "$hashes" = "$(cat "$directory/$phase.sha256")" ] || {
    echo "dss:error: Cached $phase archive hashes changed or are missing; no package recovery attempted." >&2; return 1;
  }
  while IFS=$'\t' read -r package version arch file; do
    [ "$(dpkg-deb -f "$file" Package)" = "$package" ] &&
      [ "$(dpkg-deb -f "$file" Version)" = "$version" ] &&
      [ "$(dpkg-deb -f "$file" Architecture)" = "$arch" ] || return 1
    case "$arch" in amd64|all) :;; i386)
      awk -F '\t' -v package="$package" '$1 == package && $3 == "same" { found=1 } END { exit !found }' "$targets" || return 1;;
      *) return 1;;
    esac
  done < "$directory/$phase.archives" || return 1
  if [ "$phase" = bootstrap ]; then
    for package in dpkg tar apt; do
      awk -F '\t' -v package="$package" '$1 == package && $3 == "amd64" { found=1 } END { exit !found }' "$directory/$phase.archives" || return 1
    done
  fi
  if [ "$prepare" = true ]; then crossgrade_bookworm_apache_handoff "$directory" prepare || return 1; fi
  if [ "$phase" = bootstrap ]; then
    if ! dpkg --force-confnew --force-confmiss --refuse-downgrade --install "${archives[@]}"; then
      dpkg --force-confnew --force-confmiss --refuse-downgrade --install "${archives[@]}" || return 1
    fi
  else
    retry=("${archives[@]}"); previous=${#retry[@]}
    for attempt in 1 2 3 4 5 6 7 8; do
      status=0
      dpkg --force-confnew --force-confmiss --refuse-downgrade --abort-after="$((2*${#archives[@]}+50))" --install "${retry[@]}" || status=$?
      pending=$(crossgrade_bookworm_output_pending_archives "$directory" "$phase") || return 1
      if [ -z "$pending" ]; then
        [ "$status" -eq 0 ] || return 1
        success=true; break
      fi
      retry=()
      while IFS= read -r file; do retry+=("$file"); done <<< "$pending"
      if [ "$attempt" -ge 2 ] && [ "${#retry[@]}" -ge "$previous" ]; then
        echo 'dss:error: Raw package conversion stopped making progress; verified archives and the Apache maintenance mask were retained.' >&2; return 1
      fi
      previous=${#retry[@]}
    done
    $success || { echo 'dss:error: Raw package conversion reached its eight-pass limit; inspect the retained package state from a trusted console.' >&2; return 1; }
  fi
  [ "$(dpkg --print-architecture)" = amd64 ] || return 1
  apt-config dump >/dev/null && apt-get --version >/dev/null || return 1
  if [ "$phase" = remaining ]; then crossgrade_bookworm_check_package_tools || return 1; fi
  for package in tasksel tasksel-data; do
    if awk -F '\t' -v package="$package" '$1 == "install ok installed" && $2 == package && $3 == "all" { found=1 } END { exit !found }' "$installed"; then
      status=$(dpkg-query -W -f='${Status}\t${Architecture}' "$package:all") || return 1
      [ "$status" = $'install ok installed\tall' ] || {
        echo "dss:error: Package conversion did not preserve configured $package:all; inspect package state before resuming." >&2; return 1;
      }
    else status=$?; [ "$status" -eq 1 ] || return 1; fi
  done
  (umask 077; : > "$directory/$phase.completed") || return 1
}

function crossgrade_bookworm_recover_bootstrap() {
  local permission=${1:-${UPGRADE_CROSSGRADE:-false}} context=${2:-caller} directory status file native phase
  if directory=$(crossgrade_bookworm_output_pending_directory); then :
  else status=$?; [ "$status" -eq 1 ] && return 0; return "$status"; fi
  phase=bootstrap
  if [ -f "$directory/remaining.archives" ] && [ ! -f "$directory/remaining.started" ] && [ ! -f "$directory/remaining.completed" ] &&
    ! { [ -f "$directory/remaining.preparing" ] && [ ! -L "$directory/remaining.preparing" ] &&
      [ ! -L "$directory" ] && [ "$(stat -c '%u:%a' -- "$directory")" = 0:700 ] &&
      [ "$(stat -c %u -- "$directory/remaining.preparing")" = 0 ]; }; then
    echo 'dss:error: A legacy remaining transaction has no verified raw-replay marker; inspect or restore it from a trusted console before package work.' >&2; return 1
  fi
  if [ -f "$directory/remaining.started" ] && [ ! -f "$directory/remaining.completed" ]; then phase=remaining
  elif [ -f "$directory/bootstrap.started" ] && [ ! -f "$directory/bootstrap.completed" ]; then :
  else
    [ "$context" != packages ] && return 0
    echo 'dss:error: A Bookworm crossgrade is unfinished. Run --to-64bit to finish verified conversion and cleanup, then retry the package command.' >&2; return 1
  fi
  if [ "$permission" != true ]; then
    echo 'dss:error: An interrupted Bookworm package conversion needs explicit crossgrade recovery. Run --to-64bit, or retry the release command with --crossgrade, before other package work.' >&2; return 1
  fi
  [ "$(id -u)" = 0 ] && [ "$(uname -m)" = x86_64 ] && [ "$(distro_output_codename)" = bookworm ] || return 1
  [ ! -L "$directory" ] && [ "$(stat -c '%u:%a' -- "$directory")" = 0:700 ] || return 1
  for file in original.i386 "$phase.started" "$phase.cache" "$phase.archives" "$phase.sha256" "$phase.configuration" "$phase.plan" targets installed; do
    [ -f "$directory/$file" ] && [ ! -L "$directory/$file" ] && [ "$(stat -c %u -- "$directory/$file")" = 0 ] || return 1
  done
  if [ "$phase" = remaining ]; then
    for file in remaining.metadata.sha256 remaining.arguments remaining.targets remaining.installed remaining.obsolete; do
      [ -f "$directory/$file" ] && [ ! -L "$directory/$file" ] && [ "$(stat -c %u -- "$directory/$file")" = 0 ] || return 1
    done
  fi
  pause_check && check_disk_space && check_systemd_install_matches_init || return 1
  if ! native=$(dpkg --print-architecture); then
    echo 'dss:error: Cached package conversion recovery requires working dpkg; use a verified rescue environment to repair the package tools.' >&2; return 1
  fi
  case "$native" in i386|amd64) :;; *) return 1;; esac
  apt_sources_check_releases_and_vendors bookworm || return 1
  echo "dss:stage: Replaying verified interrupted Bookworm $phase archives before APT checks." >&2
  crossgrade_bookworm_apply_archives "$directory" "$phase" true || return 1
  [ "$context" != packages ] && return 0
  echo 'dss:error: Verified package replay finished. Run --to-64bit to complete crossgrade cleanup, then retry the package command.' >&2
  return 1
}

# Old priorities survive package renames; inspect the payload before retaining a remnant.
function crossgrade_bookworm_can_retain_legacy() {
  local package=$1 essential=$2 priority=$3 multi_arch=$4 original=$5 files file evidence=false existing_library=false missing_library=false
  case "$essential:$package" in
    yes:*|*:dpkg|*:apt|*:apt-utils|*:bash|*:coreutils|*:tar|*:perl-base|*:systemd|*:systemd-sysv|*:udev|*:init|*:init-system-helpers|*:sysvinit-core|*:sysvinit-utils|*:libc6|*:libc-bin|*:libgcc-s1|*:libstdc++6|*:libapt-pkg6.0|*:openssh-server|*:ifupdown|*:iproute2|*:apache2|*:apache2-bin|*:postfix|*:dovecot-core|*:mariadb-server*) return 1;;
  esac
  case "$priority" in required|important) :;; *) return 0;; esac
  files=$(dpkg-query -L "$package:i386") || return 2
  if [ "$package" = sysvinit ]; then
    case "$(readlink /proc/1/exe)" in */systemd|*/'systemd (deleted)') :;; *) return 1;; esac
    case "$(readlink -f /sbin/init)" in */systemd) :;; *) return 1;; esac
    awk -F '\t' '$1 == "install ok installed" && $2 == "systemd-sysv" { found=1 } END { exit !found }' "$original" || return 1
  fi
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    [ ! -d "$file" ] || continue
    case "$file" in
      /usr/share/doc/*|/usr/share/lintian/overrides/*) :;;
      /usr/share/locale/*/LC_MESSAGES/libapt-*.mo)
        case "$package" in libapt-inst1.5|libapt-pkg4.12) :;; *) return 1;; esac;;
      # Jessie shipped this CLI helper inside the library package, not a separate utility.
      /usr/lib/i386-linux-gnu/lognorm/lognormalizer) [ "$package" = liblognorm1 ] || return 1;;
      /usr/lib/ssl/engines/*.so) [ "$package" = libssl0.9.8 ] || return 1;;
      /usr/lib/i386-linux-gnu/openssl-1.0.0/engines/*.so) [ "$package" = libssl1.0.0 ] || return 1;;
      /usr/lib/i386-linux-gnu/openssl-1.0.2/engines/*.so) [ "$package" = libssl1.0.2 ] || return 1;;
      /usr/share/locale/*/LC_MESSAGES/gnutls-deb0-28.mo|/usr/share/locale/*/LC_MESSAGES/libgnutls26.mo)
        case "$package:${file##*/}" in libgnutls-deb0-28:gnutls-deb0-28.mo|libgnutls26:libgnutls26.mo) :;; *) return 1;; esac;;
      /usr/lib/libdb-[0-9]*.so|/usr/lib/i386-linux-gnu/libdb-[0-9]*.so)
        case "$package" in libdb[0-9]*) :;; *) return 1;; esac
        [ -f "$file" ] || return 1
        existing_library=true;;
      /lib/sysvinit/init|/lib/sysvinit/telinit) [ "$package" = sysvinit ] || return 1;;
      /lib/*.so.[0-9]*|/usr/lib/*.so.[0-9]*)
        case "$package:$multi_arch" in lib*:*|*:same) :;; *) return 1;; esac
        # A stale dpkg alias is harmless only while another owned library remains.
        if [ ! -f "$file" ]; then missing_library=true; continue; fi
        existing_library=true;;
      *) return 1;;
    esac
    [ -f "$file" ] || [ -L "$file" ] || return 1
    evidence=true
  done <<< "$files"
  if $missing_library && ! $existing_library; then return 1; fi
  $evidence
}

# Only known retired packages are predictable before future-release indexes are active.
function upgrade_output_crossgrade_obsolete_packages() {
  local packages
  packages=$(dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\n') || return 1
  printf '%s\n' "$packages" | awk -F '\t' '
    $1 == "install ok installed" && $3 == "i386" &&
      ($2 ~ /^(gcc|cpp)-(4\.[0-9]+|[5-9]|10)$/ || $2 ~ /^libgcc-(4\.[0-9]+|[5-9]|10)-dev$/ || $2 ~ /^(liblensfun0|liblvm2cmd2\.02|libssl1\.0\.2|metamail|ufraw-batch|mysql-client)$/) { print $2 }
  '
}

# Default removal still requires verified compiler roles, library/doc payloads and a backup.
function crossgrade_bookworm_prepare_obsolete() {
  local compiler_pattern='^(gcc|cpp)-[0-9]+([.][0-9]+)?$|^libgcc-[0-9]+([.][0-9]+)?-dev$'
  local directory=$1 blockers=$2 remove=${DR_REMOVE_OBSOLETE_CROSSGRADE_PACKAGES:-true} package dependency reason packages compiler_role level=trace
  local -a obsolete_packages=()
  [ -n "$blockers" ] || return 0
  if ! $remove; then level=warn; fi
  while IFS=$'\t' read -r package dependency reason; do
    printf 'dss:%s: %s:i386 requires verified removal: %s; %s.\n' "$level" "$package" "$dependency" "$reason" >&2
  done <<< "$blockers"
  if ! $remove; then
    echo 'dss:error: Automatic obsolete-package removal is disabled. Remove or migrate these packages manually before crossgrading, or unset DR_REMOVE_OBSOLETE_CROSSGRADE_PACKAGES to permit verified backed-up removal.' >&2
    return 1
  fi
  packages=$(printf '%s\n' "$blockers" | cut -f1 | LC_ALL=C sort -u) || return 1
  while IFS= read -r package; do
    [[ "$package" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] || return 1
    awk -F '\t' -v package="$package" '$1 == package { found=1 } END { exit !found }' "$directory/retained-i386" || return 1
    awk -F '\t' -v package="$package" '$1 == "install ok installed" && $2 == package && $3 == "i386" && $5 != "yes" { found=1 } END { exit !found }' "$directory/original.packages" || return 1
    if [[ "$package" =~ $compiler_pattern ]]; then
      # Retired compiler components need their current default compiler/preprocessor converted.
      compiler_role=gcc
      case "$package" in cpp-*) compiler_role=cpp;; esac
      awk -F '\t' -v role="$compiler_role" '$1 == role { found=1 } END { exit !found }' "$directory/targets" || return 1
    elif [ "$package" = metamail ] || [ "$package" = ufraw-batch ]; then
      # These retired Debian utilities have no native Bookworm package; keep service/data guards.
      upgrade_cleanup_output_safe_package "$package:i386" i386 true "$directory/original.packages" >/dev/null || return 1
    else
      # Force payload inspection even for old optional packages; unknown executables stay manual.
      crossgrade_bookworm_can_retain_legacy "$package" no required no "$directory/original.packages" || {
        echo "dss:error: Obsolete package $package has an unverified payload; remove or migrate it manually." >&2; return 1;
      }
    fi
    obsolete_packages+=("$package:i386")
  done <<< "$packages"
  if [ ! -s "$directory/pre-crossgrade.tar.gz" ] || [ -L "$directory/pre-crossgrade.tar.gz" ] || ! tar -tzf "$directory/pre-crossgrade.tar.gz" >/dev/null; then
    echo 'dss:error: Verified original configuration/package backup is required before obsolete package removal.' >&2
    return 1
  fi
  upgrade_packages_backup_modified_files "$directory" "${obsolete_packages[@]}" || { echo "dss:error: Cannot preserve local package-file changes before crossgrade obsolete cleanup; removal stopped. Review $directory." >&2; return 1; }
  (
    umask 077
    printf '%s\n' "$blockers" > "$directory/obsolete.dependencies.new" || exit 1
    : > "$directory/obsolete.approved.new" || exit 1
    if [ -f "$directory/obsolete.approved" ]; then cat "$directory/obsolete.approved" > "$directory/obsolete.approved.new" || exit 1; fi
    printf '%s\n' "$packages" >> "$directory/obsolete.approved.new" || exit 1
    LC_ALL=C sort -u "$directory/obsolete.approved.new" -o "$directory/obsolete.approved.new" || exit 1
    mv "$directory/obsolete.dependencies.new" "$directory/obsolete.dependencies" &&
      mv "$directory/obsolete.approved.new" "$directory/obsolete.approved" || exit 1
  ) || return 1
  echo "dss:stage: Verified ${#obsolete_packages[@]} obsolete 32-bit packages for removal; backup: $directory/pre-crossgrade.tar.gz." >&2
  echo "dss:trace: Verified obsolete foreign package removal: ${packages//$'\n'/ }." >&2
}

function print_crossgrade_obsolete_package_changes() {
  local directory="$1.crossgrade-bookworm" package status
  [ -f "$directory/obsolete.approved" ] || return 0
  while IFS= read -r package; do
    [ -n "$package" ] || continue
    if status=$(dpkg-query -W -f='${Status}' "$package:i386" 2>/dev/null); then :
    else status=$?; [ "$status" -eq 1 ] || return "$status"; status=absent; fi
    case "$status" in *' installed'|*' unpacked'|*' half-configured'|*' half-installed'|*' triggers-awaited'|*' triggers-pending')
      echo "dss:warn: Obsolete removal requested for $package:i386; completion unconfirmed. Original backup: $directory/pre-crossgrade.tar.gz.";;
      *) echo "dss:warn: Obsolete package removed during crossgrade: $package:i386. Review a supported replacement if still needed. Original backup: $directory/pre-crossgrade.tar.gz.";;
    esac
  done < "$directory/obsolete.approved"
}

# Co-installable extensions may still depend on a runtime that must change architecture.
function crossgrade_bookworm_output_foreign_replacements() {
  local targets=$1 retained=${2-} packages
  packages=$(dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Multi-Arch}\t${Pre-Depends}\t${Depends}\n') || return 1
  printf '%s\n' "$packages" | awk -F '\t' -v retained_mode="${retained:+true}" '
    function incompatible(name, qualifier, value, kind) {
      if (name in all_mode) { value=all_mode[name]; kind="Architecture: all" }
      else if (name in requested) { value=mode[name]; kind="requested amd64 replacement" }
      else return 0
      if (value == "") value="no"
      if ((qualifier == "" && ((kind == "Architecture: all" && value != "foreign") ||
              (kind != "Architecture: all" && value != "same" && value != "foreign"))) ||
          (qualifier == "i386" && (kind == "Architecture: all" || value != "same")) ||
          (qualifier == "any" && value != "allowed" && value != "foreign")) {
        reason=name " (" kind ", Multi-Arch: " value ")"; return 1
      }
      return 0
    }
    FILENAME == ARGV[1] { requested[$1]=1; mode[$1]=$3; next }
    FILENAME == ARGV[2] { retained[$1]=1; next }
    $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ {
      if ($3 == "all") all_mode[$2]=$4
      if ($3 == "i386") { foreign_mode[$2]=$4; dependencies[$2]=$5 "," $6 }
    }
    END {
      for (package in dependencies) {
        if (retained_mode ? !(package in retained) : (foreign_mode[package] != "same" || !(package in requested))) continue
        groups=split(dependencies[package], group, /,/)
        for (part=1; part<=groups; part++) {
          text=group[part]; gsub(/^[ \t\r\f\013]+|[ \t\r\f\013]+$/, "", text)
          if (text == "") continue
          alternatives=split(text, alternative, /[|]/); blocked=0; details=""
          for (choice=1; choice<=alternatives; choice++) {
            name=alternative[choice]; gsub(/\([^)]*\)/, "", name)
            gsub(/^[ \t\r\f\013]+|[ \t\r\f\013]+$/, "", name)
            qualifier=""; if (name ~ /:/) { qualifier=name; sub(/^[^:]*:/, "", qualifier); sub(/:.*/, "", name) }
            if (incompatible(name, qualifier)) {
              blocked++; details=details (details == "" ? "" : "; ") reason
              if (!retained_mode) replace[package]=1
            }
          }
          if (retained_mode && blocked == alternatives) print package "\t" text "\t" details
        }
      }
      if (!retained_mode) for (package in replace) print package
    }
  ' "$targets" "${retained:-/dev/null}" -
}

function crossgrade_debian_bookworm() {
  local apt_state_cache_disabled=true current native file
  local baseline directory package installed_version essential priority multi_arch candidate status audit version oldmark held cache attempt foreign_replacements retained_blockers obsolete_removals foreign_packages removed_obsolete cleanup_permission
  # The download checker reads only the removals verified for this invocation.
  local crossgrade_obsolete_approved=/dev/null
  local -a arguments=()
  local -a bootstrap=()
  local -a backups=()
  local -a archives=()
  local -a apt_options=()
  read -r -a apt_options <<< "$APT_GET_INSTALL_OPTIONS"
  pause_check || return 1
  current=$(distro_output_codename) || return 1
  [ "$current" = bookworm ] || { echo 'dss:error: This crossgrade backend requires Debian 12 bookworm.' >&2; return 1; }
  [ "$(uname -m)" = x86_64 ] || { echo 'dss:error: Boot a verified x86_64 kernel before crossgrading.' >&2; return 1; }
  [ "$(id -u)" = 0 ] || return 1
  check_disk_space || return 1
  crossgrade_bookworm_recover_bootstrap true backend || return $?
  native=$(dpkg --print-architecture) || return 1
  case "$native" in i386|amd64) :;; *) return 1;; esac
  if directory=$(crossgrade_bookworm_output_pending_directory); then :
  else
    status=$?
    [ "$status" -eq 1 ] || { echo 'dss:error: Cannot select an unambiguous pending Bookworm crossgrade.' >&2; return 1; }
    if [ "$native" = amd64 ]; then
      crossgrade_bookworm_check_native || { echo 'dss:error: Mixed native packages without an original crossgrade inventory require manual review.' >&2; return 1; }
      foreign_packages=$(crossgrade_output_foreign_packages) || return 1
      [ -z "$foreign_packages" ] || {
        printf '%s\n' "$foreign_packages" >&2
        echo 'dss:error: Active foreign packages without an original crossgrade inventory require manual migration; success requires amd64/all only.' >&2; return 1;
      }
      upgrade_php_runtime_verify || return 1
      echo 'dss:stage: Bookworm native amd64 conversion is already complete.' >&2
      return 0
    fi
  fi
  crossgrade_check_apt_architecture_config || return 1
  check_systemd_install_matches_init || return 1
  apt_sources_check_releases_and_vendors bookworm || return 1
  crossgrade_check_source_architectures || return 1
  upgrade_check_crossgrade_package_blockers || return 1
  if [ -z "$directory" ]; then
    baseline=$(config_state_output_baseline) || {
      record_config_state || return 1
      baseline=$(config_state_output_baseline) || return 1
    }
    directory="$baseline.crossgrade-bookworm"
  fi
  if [ ! -f "$directory/original.i386" ]; then
    upgrade_migrate_php_packages bookworm || return 1
    [ "$native" = i386 ] || { echo 'dss:error: No original crossgrade inventory; inspect this mixed system manually before resuming.' >&2; return 1; }
    audit=$(LC_ALL=C dpkg --audit 2>&1) || return 1
    [ -z "$audit" ] || { printf '%s\n' "$audit" >&2; return 1; }
    LC_ALL=C apt-get check || return 1
    held=$(apt-mark showhold) || return 1
    [ -z "$held" ] || { echo 'dss:error: Review held packages before crossgrading.' >&2; return 1; }
    (umask 077; mkdir -p "$directory" && chmod 700 "$directory") || return 1
    dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Version}\t${Essential}\t${Priority}\t${Multi-Arch}\n' > "$directory/original.packages" || return 1
    awk -F '\t' '$1 == "install ok installed" && $3 == "i386" { print $2 "\t" $4 "\t" ($5 == "yes" ? "yes" : "no") "\t" ($6 == "" ? "unknown" : $6) "\t" ($7 == "" ? "no" : $7) }' \
      "$directory/original.packages" > "$directory/original.i386.new" || return 1
    apt-mark showauto > "$directory/original.auto" || return 1
    for file in etc var/lib/dpkg var/lib/apt/extended_states; do [ ! -e "/$file" ] || backups+=("$file"); done
    (umask 077; tar -C / -czpf "$directory/pre-crossgrade.tar.gz" "${backups[@]}") || return 1
    mv "$directory/original.i386.new" "$directory/original.i386" || return 1
  fi
  echo "dss:stage: Bookworm crossgrade inventory/backups: $directory" >&2
  if [ "$native" = i386 ]; then dpkg --add-architecture amd64 || return 1; fi
  apt_get_update || return 1
  dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Essential}\n' > "$directory/installed" || return 1
  removed_obsolete=''
  if [ -f "$directory/obsolete.approved" ]; then
    removed_obsolete=$(awk -F '\t' '
      FILENAME == ARGV[1] { approved[$1]=1; next }
      $3 == "i386" && $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ { active[$2]=1 }
      END { for (package in approved) if (!(package in active)) print package }
    ' "$directory/obsolete.approved" "$directory/installed") || return 1
  fi
  : > "$directory/targets.new" || return 1
  : > "$directory/retained-i386.new" || return 1
  echo "dss:stage: Checking 64-bit replacements for installed 32-bit packages" >&2
  while IFS=$'\t' read -r package installed_version essential priority multi_arch; do
    [ -n "$package" ] || continue
    # Previously reviewed removals need no vanished payload inspection on completion retries.
    case $'\n'"$removed_obsolete"$'\n' in *$'\n'"$package"$'\n'*) continue;; esac
    if candidate=$(crossgrade_bookworm_output_candidate "$package"); then status=0; else status=$?; fi
    [ "$status" -ne 2 ] || { echo "dss:error: Cannot inspect APT availability for $package:amd64." >&2; return 1; }
    if [ -n "$candidate" ] && dpkg --compare-versions "$candidate" ge "$installed_version"; then
      printf '%s\t%s\t%s\n' "$package" "$candidate" "${multi_arch:-no}" >> "$directory/targets.new" || return 1
    else
      crossgrade_bookworm_can_retain_legacy "$package" "$essential" "$priority" "$multi_arch" "$directory/original.packages" || {
        echo "dss:error: No suitable archive amd64 replacement for protected or unverified package $package; manual migration required." >&2; return 1;
      }
      printf '%s\t%s\n' "$package" "$installed_version" >> "$directory/retained-i386.new" || return 1
      case "$package" in libapache2-mod-*)
        upgrade_compatibility_apache_module_enabled "$package"; status=$?
        case "$status" in
          0) echo "dss:error: Active unavailable 32-bit Apache module package $package needs manual migration before changing Apache architecture." >&2; return 1;;
          1) :;;
          *) echo "dss:error: Cannot inspect Apache module configuration for $package." >&2; return 1;;
        esac;;
      esac
      echo "dss:trace: No native replacement for $package:i386 ($installed_version); verifying safe removal before conversion." >&2
    fi
  done < "$directory/original.i386"
  mv "$directory/targets.new" "$directory/targets" && mv "$directory/retained-i386.new" "$directory/retained-i386" || return 1
  # These binaries must be native, even if they were absent from the original inventory.
  for package in dpkg tar apt bash coreutils perl-base systemd udev openssh-server ifupdown; do
    candidate=$(crossgrade_bookworm_output_candidate "$package") || return 1
    if ! awk -F '\t' -v package="$package" '$1 == package { found=1 } END { exit !found }' "$directory/targets"; then
      printf '%s\t%s\tno\n' "$package" "$candidate" >> "$directory/targets" || return 1
    fi
  done
  retained_blockers=$(crossgrade_bookworm_output_foreign_replacements "$directory/targets" "$directory/retained-i386") || return 1
  # Every unavailable package must be removed with proof, even if its old dependencies still work.
  retained_blockers=$(printf '%s\n' "$retained_blockers" | awk -F '\t' '
    FILENAME == ARGV[1] { if (NF >= 3) { seen[$1]=1; print }; next }
    !($1 in seen) { print $1 "\tunavailable native package\tamd64/all completion required" }
  ' - "$directory/retained-i386") || return 1
  crossgrade_bookworm_prepare_obsolete "$directory" "$retained_blockers" || return 1
  if "${DR_REMOVE_OBSOLETE_CROSSGRADE_PACKAGES:-true}" && [ -f "$directory/obsolete.approved" ]; then
    crossgrade_obsolete_approved="$directory/obsolete.approved"
  fi
  dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Essential}\n' > "$directory/installed" || return 1
  foreign_replacements=$(crossgrade_bookworm_output_foreign_replacements "$directory/targets") || return 1
  while IFS=$'\t' read -r package candidate multi_arch; do
    arguments+=("$package:amd64=$candidate")
    case $'\n'"$foreign_replacements"$'\n' in
      *$'\n'"$package"$'\n'*) arguments+=("$package:i386-");;
      *) [ "$multi_arch" = same ] || arguments+=("$package:i386-");;
    esac
  done < "$directory/targets"
  # A previous transaction may have removed an obsolete name that current indexes no longer know.
  obsolete_removals=$(awk -F '\t' '
    FILENAME == ARGV[1] { approved[$1]=1; next }
    $3 == "i386" && $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ && $2 in approved { print $2 }
  ' "$crossgrade_obsolete_approved" "$directory/installed") || return 1
  while IFS= read -r package; do
    [ -z "$package" ] || arguments+=("$package:i386-")
  done <<< "$obsolete_removals"
  if [ "$native" = i386 ]; then
    bootstrap=(dpkg:amd64 tar:amd64 apt:amd64 dpkg:i386- tar:i386- apt:i386-)
    if awk -F '\t' '$2 == "apt-utils" && $1 == "install ok installed" { found=1 } END { exit !found }' "$directory/original.packages"; then
      bootstrap+=(apt-utils:amd64 apt-utils:i386-)
    fi
    crossgrade_bookworm_download "$directory" "$directory/targets" "$directory/installed" bootstrap "${bootstrap[@]}" || return 1
    for package in dpkg tar apt; do
      awk -F '\t' -v package="$package" '$1 == package && $3 == "amd64" { found=1 } END { exit !found }' "$directory/bootstrap.archives" || {
        echo "dss:error: Verified bootstrap archive missing: $package:amd64." >&2; return 1;
      }
    done
    while IFS=$'\t' read -r package version status file; do archives+=("$file"); done < "$directory/bootstrap.archives"
    [ "${#archives[@]}" -gt 0 ] || { echo 'dss:error: No verified bootstrap archives downloaded.' >&2; return 1; }
    crossgrade_bookworm_record_archives "$directory" bootstrap || return 1
    crossgrade_bookworm_apply_archives "$directory" bootstrap true || return 1
    apt_get_update || return 1
  fi
  if [ ! -f "$directory/remaining.completed" ]; then
    # No raw mutation can precede .started; interrupted preparation may be safely replanned.
    (umask 077; : > "$directory/remaining.preparing") || return 1
    dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Essential}\n' > "$directory/installed" || return 1
    crossgrade_bookworm_download "$directory" "$directory/targets" "$directory/installed" remaining "${arguments[@]}" || return 1
    crossgrade_bookworm_record_archives "$directory" remaining || return 1
    crossgrade_bookworm_apply_archives "$directory" remaining true || return 1
  fi
  crossgrade_bookworm_check_package_tools || return 1
  if [ "$(od -An -tu1 -j4 -N1 /proc/1/exe 2>/dev/null | tr -d ' ')" != 2 ]; then
    systemctl daemon-reexec || return 1
    for attempt in 1 2 3 4 5; do
      [ "$(od -An -tu1 -j4 -N1 /proc/1/exe 2>/dev/null | tr -d ' ')" != 2 ] || break
      [ "$attempt" -eq 5 ] || sleep 1
    done
  fi
  # Rebuild a fresh cleanup plan; never execute the raw download plan or its removal requests.
  dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Essential}\n' > "$directory/installed" || return 1
  arguments=()
  while IFS=$'\t' read -r package candidate multi_arch; do
    arguments+=("$package:amd64=$candidate")
  done < "$directory/targets"
  obsolete_removals=$(awk -F '\t' '
    FILENAME == ARGV[1] { wanted[$1]=1; next }
    FILENAME == ARGV[2] { approved[$1]=1; next }
    $1 == "install ok installed" && ($3 == "amd64" || $3 == "all") { native[$2]=1 }
    $3 == "i386" && $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ { foreign[$2]=1 }
    END {
      for (package in foreign) {
        if ((package in wanted && package in native) || package in approved) print package
        else { print "dss:error: Cannot remove foreign package without a configured native replacement or verified obsolete payload: " package ":i386" > "/dev/stderr"; bad=1 }
      }
      exit bad
    }
  ' "$directory/targets" "$crossgrade_obsolete_approved" "$directory/installed") || return 1
  while IFS= read -r package; do
    [ -z "$package" ] || arguments+=("$package:i386-")
  done <<< "$obsolete_removals"
  crossgrade_bookworm_download "$directory" "$directory/targets" "$directory/installed" cleanup "${arguments[@]}" || return 1
  arguments=()
  while IFS= read -r package; do
    [ -n "$package" ] || return 1
    arguments+=("$package")
  done < "$directory/cleanup.arguments" || return 1
  [ "${#arguments[@]}" -gt 0 ] || return 1
  cache=$(cat "$directory/cleanup.cache") || return 1
  crossgrade_bookworm_apache_handoff "$directory" prepare || return 1
  cleanup_permission=$(crossgrade_bookworm_output_protected_removal_permission) || return 1
  LC_ALL=C apt-get "${apt_options[@]}" -o APT::Get::AllowUnauthenticated=false \
    -o APT::Get::AutomaticRemove=false -o APT::Get::Purge=false -o Dir::Cache::archives="$cache" \
    -o "APT::Get::allow-remove-essential=$cleanup_permission" -o APT::Force-LoopBreak=false \
    --no-download --fix-broken install "${arguments[@]}" || return 1
  # Restore converted native packages in one APT load; leave foreign/all marks unchanged.
  local auto_marks
  local -a converted_auto=()
  auto_marks=$(awk -F '\t' '
    FILENAME == ARGV[1] { converted[$1]=1; next }
    { package=$0; sub(/:i386$/, "", package); if (package in converted) print package ":amd64" }
  ' "$directory/targets" "$directory/original.auto") || return 1
  while IFS= read -r oldmark; do
    [ -z "$oldmark" ] || converted_auto+=("$oldmark")
  done <<< "$auto_marks"
  if [ -s "$directory/remaining.dependencies" ]; then
    auto_marks=$(dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\n') || return 1
    auto_marks=$(printf '%s\n' "$auto_marks" | awk -F '\t' '
      FILENAME == ARGV[1] { name=$0; sub(/:amd64$/, "", name); learned[name]=1; next }
      $1 == "install ok installed" && ($3 == "amd64" || $3 == "all") {
        sub(/:.*/, "", $2); if ($2 in learned) print $2 ":" $3
      }
    ' "$directory/remaining.dependencies" -) || return 1
    while IFS= read -r oldmark; do
      [ -z "$oldmark" ] || converted_auto+=("$oldmark")
    done <<< "$auto_marks"
  fi
  if [ "${#converted_auto[@]}" -gt 0 ]; then
    apt-mark auto "${converted_auto[@]}" || return 1
  fi
  crossgrade_bookworm_check_completion "$directory" || return 1
  crossgrade_bookworm_apache_handoff "$directory" finish || return 1
  upgrade_php_runtime_verify || return 1
  (umask 077; : > "$directory/completed") || return 1
  echo 'dss:stage: Bookworm native amd64 packages, package state and 64-bit PID1 verified.' >&2
}


function crossgrade_debian() {
  local apt_state_cache_disabled=true
  [  ! -f /etc/debian_version ] && echo "dss:info: Only debian derived distro crossgrades are supported, but not $(print_distro_info)." && return 0
  check_disk_space || return 1
  # see https://wiki.debian.org/CrossGrading
  ! uname -a | grep -qai x86_64 && echo "dss:error: Not running a 64 bit kernel. Cannot crossgrade." 2>&1 && return 1

  lsb_release -a 2>/dev/null | egrep -qai 'stretch|lenny|squeeze|wheezy|jessie' && echo "dss:error: Older (pre stretch) Debian distros have dependency issues preventing crossgrades.  $0 --to-latest prior to cross grading." 2>&1 && return 1

  ! "${DR_ENABLE_UBUNTU_CROSSGRADE:-false}" && lsb_release -a 2>/dev/null | egrep -qai 'ubuntu' && echo "dss:error: Ubuntu cross grades have not been successful.  To ignore this warning and attempt one at your own peril: export DR_ENABLE_UBUNTU_CROSSGRADE=true" 2>&1 && return 1

  crossgrade_check_apt_architecture_config || return 1
  upgrade_check_crossgrade_package_blockers || return 1

  if ! check_systemd_install_matches_init; then
    echo 'dss:error: Running and selected init must be verified and agree before crossgrading; review the diagnostic above.' >&2
    return 1
  fi

  local bittedness=$(getconf LONG_BIT)
  if echo $bittedness | grep -qai 64; then
    echo "dss:info: FYI getconf reports 64 bits."
    #[ $(dpkg -l | grep '^ii ' | grep ':i386' | wc -l ) -gt 0 ] && echo "i386 packages on this server (may need tidying up): $(dpkg -l | grep '^ii ' | grep ':i386')"
    #return 0
    # may be part way through.  may still be 386 packages.  so carry on with the cross grade.
  fi
  local now=$(date +%s)

  #(Reading database ... 42551 files and directories currently installed.)
  #Removing wpasupplicant (2.4-0ubuntu6.2) ...
  #Processing triggers for dbus:amd64 (1.10.6-1ubuntu3.3) ...
  #=> root     11133  0.1  4.4  70196 66740 pts/2    S+   07:12   0:09      \_ apt-get -y -o APT::Get::AllowUnauthenticated=yes -o Acquire::Check-Valid-Until=false -o Dpkg::Options::=--force-confnew -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confmiss install wpasupplicant:amd64
  #root     13076  1.7  0.6  12920 10036 pts/0    Ss+  09:09   0:00          \_ /usr/bin/dpkg --force-confnew --force-confdef --force-confmiss --status-fd 29 --unpack --auto-deconfigure /var/cache/apt/archives/libnl-3-200_3.2.27-1ubuntu0.16.04.1_amd64.deb /var/cache/apt/archives/libnl-genl-3-200_3.2.27-1ubuntu0.16.04.1_amd64.deb /var/cache/apt/archives/libpcsclite1_1.8.14-1ubuntu1.16.04.1_amd64.deb /var/cache/apt/archives/wpasupplicant_2.4-0ubuntu6.2_amd64.deb
  #root     13640  0.0  0.0   2372   636 pts/0    S+   09:09   0:00              \_ /bin/sh /var/lib/dpkg/info/dbus.postinst triggered /etc/dbus-1/system.d /usr/share/dbus-1/system-services
  #root     13641  0.2  0.0  25520  1392 pts/0    S+   09:09   0:00                  \_ dbus-send --print-reply --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig
  #=> dbus-send non responsive
  #=> kill 13641

  print_distro_info | grep -qai ubuntu && dpkg -l | grep '^ii' | grep wpasupplicant && echo "dss:warn: There have been issues with updates on Ubuntu where the wpasupplicant is installed.  Run apt-get remove wpasupplicant to remove it first." && return 1

  # slightly different config file state name.  e.g. regular upgrade can remove things like dovecot if they were not used.
  # and this different file means they won't get reinstalled by mistake
  [  ! -f /root/distrorejuveinfo/crossgrade.preupgrade.dpkg.$$ ] && record_config_state /root/distrorejuveinfo/crossgrade.preupgrade.dpkg.$$
  [  -f /root/distrorejuveinfo/crossgrade.preupgrade.dpkg.$$ ] && [  ! -f /root/distrorejuveinfo/preupgrade.dpkg.$$ ] && cp /root/distrorejuveinfo/crossgrade.preupgrade.dpkg.$$ /root/distrorejuveinfo/preupgrade.dpkg.$$

  echo "dss:trace:Current architecture: $(dpkg --print-architecture)"
  echo "dss:trace:Foreign architectures: $(dpkg --print-foreign-architectures)"
  echo "dss:info: cross grading distro from 32 to 64 bit."
  local vimpkg="$(dpkg -l | grep '^.*ii' | grep -qai vim && echo vim)"
  local apachepkg="$(dpkg -l | grep '^.*ii' | grep -qai apache2-bin && echo apache2-bin)"
  apt_get_update || return 1
  apt_get_install apt-rdepends

  if [ $? -ne 0 ]; then
    if dpkg -l | egrep apt-rdepends | grep -qai ii; then
      echo "dss:warn: getting an error on apt-get install apt-rdpends.  However it is installed.  So let's proceed."
    else
      echo "dss:error: failed to install apt-rdpends.  Which we rely on to download necessary dependencies."
    fi
  fi

  [  ! -x /usr/bin/apt-show-versions ] && echo "dss:info:installing apt-show-versions" && apt_get_install apt-show-versions
  ! "${DR_SKIP_OLD_PACKAGE_CHECK:-false}" && has_leftover_packages oldpkg && show_leftover_packages oldpkg && echo "dss:warn:There are some old packages installed.  Best to remove them before proceeding.  Do that by running bash $0 --list-leftover-packages followed by bash $0 --remove-leftover-packages.  Or to ignore that, run export DR_SKIP_OLD_PACKAGE_CHECK=true and re-run this command. " && return 1

  dpkg --add-architecture amd64
  [ $? -ne 0 ] && echo "dss:error: Failed adding amd64 architecture." 2>&1 && return 1

  # needed to load amd package info.  e.g. on debian.
  apt_get_update || return 1
  #apt-get $APT_GET_INSTALL_OPTIONS autoremove

  apt-get $APT_GET_INSTALL_OPTIONS --allow-downgrades upgrade
  [  ! -d /root/distrorejuveinfo/$$ ] && mkdir /root/distrorejuveinfo/$$
  debs="$(find /var/cache/apt/archives -type f  | egrep 'amd64.deb$|all.deb$')"
  [ ! -z "$debs" ] && echo "dss:info:moving 64bit packages out of the way" && mv $debs /root/distrorejuveinfo/$$/
  apt-get clean

  #WARNING: The following essential packages will be removed.
  #This should NOT be done unless you know exactly what you are doing!
  #perl-base:amd64
  # => apt-get download perl-base:i386; dpkg -i perl-base*; apt-get -f install
  # download lots of amd64 packages if you get stuck, e.g. on ubuntu
  # for i in $(dpkg -l | grep ii | grep i386  | awk '{print $2}' | sed 's/:i386//' | grep -v "^ "|grep -v "libc-dev" | awk '{print $0":amd64"}'); do apt-get download $i; done

  #if ! dpkg -l | egrep -qai '^ii.*dpkg.*amd64'; then
  if true; then
    echo "dss:trace: cross grading.  grabbing key amd64 deb packages."
    apt-get --reinstall --download-only $APT_GET_INSTALL_OPTIONS install dpkg:amd64 tar:amd64 apt:amd64 apt-utils:amd64
    [  $? -ne 0 ] && apt-get download dpkg:amd64 tar:amd64 apt:amd64 apt-utils:amd64
    # error if we append perl-base:amd64 to the line above...
    # and if we don't have perl-base then apt-get -f install has this error: E: Unmet dependencies
    echo "dss:trace: cross grading.  grabbing extra amd64 deb packages."
    apt-get --reinstall --download-only $APT_GET_INSTALL_OPTIONS install perl-base:amd64 perl-base:i386
    # above will also fail due to dependency hell
    [  $? -ne 0 ] && apt-get download perl-base:amd64
    apt-get --reinstall --download-only $APT_GET_INSTALL_OPTIONS install perl:amd64 perl:i386
    [  $? -ne 0 ] && apt-get download perl:amd64
    # apt-rdepends can emit python3:any; replace its qualifier, not python3:any:amd64.
    requiredlist="$(apt-rdepends apt apt-listchanges| grep -v "^ "|grep -v "libc-dev" | awk -F: '{print $1":amd64"}')"
    echo "dss:trace: cross grading.  doing a 'download only' on $requiredlist."
    for i in $requiredlist; do apt-get --reinstall --download-only  $APT_GET_INSTALL_OPTIONS install $i; done
     dpkg -l | grep ii | grep -v lib | awk '{print $2}' | grep -v "^ "|grep -v "libc-dev" | awk '{print $0":amd64"}'

    #E: Unable to locate package libbz2-1.0:amd64
    #E: Couldn't find any package by glob 'libbz2-1.0'


    echo "dss:trace: cross grading.  installing key amd64 deb packages: dpkg:amd64 tar:amd64 apt:amd64 perl-base:amd64"
    # something about this removes apache2.  figure out why...
    cd /root/distrorejuveinfo/$$ || return 1
    local debs="$(find /var/cache/apt/archives -type f  | egrep 'amd64.deb$|all.deb$') $(find . -maxdepth 1 -type f  | egrep 'amd64.deb$|all.deb$')"
    while true; do
      pause_check
      #Preparing to replace libblkid1:amd64 2.20.1-5.3 (using libblkid1_2.20.1-5.3_amd64.deb) ...
      #Unpacking replacement libblkid1:amd64 ...
      #dpkg: dependency problems prevent configuration of libblkid1:amd64:
      #libblkid1:amd64 depends on libuuid1 (>= 2.16).
      #Unpacking replacement sysvinit ...
      #dpkg: regarding .../util-linux_2.20.1-5.3_amd64.deb containing util-linux, pre-dependency problem:
      #util-linux pre-depends on libblkid1 (>= 2.20.1)
      #mime-support depends on mailcap; however:
      #Package mailcap is not configured yet.
      #mailcap depends on perl.

      local predeps="$(dpkg_install $debs 2>&1 | grep 'depends on' | sed 's/.*depends on //' | sed 's/;however.*//' | sed 's/.$//' | sed  -r  's/\([^)]+\)//g' | sed 's/;//' | awk '{print $1":amd64"}' | sort | uniq)"
      [ -z "$predeps" ] && break
      echo "dss:info: loading more pre-dependencies: $predeps"
      apt-get download $predeps
      local debs2="$(find /var/cache/apt/archives -type f  | egrep 'amd64.deb$|all.deb$') $(find . -maxdepth 1 -type f  | egrep 'amd64.deb$|all.deb$')"
      if [ "$debs" == "$debs2" ]; then
        echo "dss:info: not making any progress with downloading pre-dependencies.  Going to try and install some."
        break
      fi
      debs="$debs2"
    done
    if [  ! -z "$debs" ]; then
      echo "dss:info: installing packages via dpkg -i including: $(echo "$debs" | head | tr '\n' ' ')..."
      if ! dpkg_install $debs; then
        echo "dss:error: dpkg install amd64.deb files failed" >&2
        cd - || return 1
        return 1
      fi
      mv $debs /root/distrorejuveinfo/$$
    fi
    cd - || return 1
  fi
  #apt-get $APT_GET_INSTALL_OPTIONS autoremove
  echo "dss:trace: cross grading.  force installing to see what amd64 packages need to be installed/fixed."
  local i=0 pkg
  for i in 0 1; do
    pause_check
    apt_get_f_install "during the crossgrade"
    ret=$?
    [ $ret -eq 0 ] && break;
    # apt-get -f install=>
    # The following NEW packages will be installed:
    #  dash:i386
    # WARNING: The following essential packages will be removed.
    # This should NOT be done unless you know exactly what you are doing!
    #  dash
    #0 upgraded, 1 newly installed, 1 to remove and 0 not upgraded.
    # remove 'due to stuff' e.g.:
    #   dpkg:amd64 tar:amd64 (due to dpkg:amd64) perl-base:amd64

    local essentialtoinstall="$(apt-get $APT_GET_INSTALL_OPTIONS -f install 2>&1 | grep --after-context 50 'WARNING: The following essential packages will be removed.' | grep '^ ' | tr '\n' ' ' | sed  -r 's/\(due to +\S*?\)//g')"
    [  -z "$essentialtoinstall" ] && echo "dss:info: all essential packages appear to be installed." && break
    mkdir -p distrorejuveinfo/$$/essentialdebs
    cd distrorejuveinfo/$$/essentialdebs || return 1
    echo "dss:trace: apt-get -f install had errors.  there may be some essential packages not installed.  trying to install 32 and 64 bit versions of: $essentialtoinstall"
    for pkg in ${essentialtoinstall}; do
      pkg=$(echo "${pkg}" | sed 's/:i386//')
      pkg=$(echo "${pkg}" | sed 's/:amd64//')
      # had been downloading 64 and 32 bit versions.  but installing both (for say perl-base) resulted in dpkg -l listing just the i386 version.
      #apt-get download $i
      #apt-get download $i:i386
      apt-get download "${pkg}:amd64"
    done
    dpkg_install $(find . -name '*.deb')
    cd - || return 1
  done
  apt_get_f_install
  ret=$?
  if [  $ret -ne 0 ]; then
    if [ -z "$essentialtoinstall" ]; then
      echo "dss:warn: apt-get -f install failed.  However it appears we have all essential 64 bit packages.  Trying to continue."
      # dpkg --remove --force-remove-reinstreq python3-lxml:amd64
      # dpkg-query: error: --listfiles needs a valid package name but 'python3-lxml' is not: ambiguous package name 'python3-lxml' with more than one installed instance
      # mkdir /root/t
      # mv /var/lib/dpkg/info/python3-lxml\:amd64.* .
      # apt-get install --reinstall python3-lxml
    else
      echo "dss:error: apt-get -f install failed.  we are stuck."
      return 1
    fi
  fi
  #apt-get $APT_GET_INSTALL_OPTIONS autoremove

  # doesn't seem to achieve much...  should result in apt-get install blah installing the amd64 (vs. i386) version
  dpkg --get-selections | grep :i386 | sed -e s/:i386/:amd64/ | dpkg --set-selections
  lsb_release -a 2>/dev/null | grep -qai Ubuntu && echo "dss:trace: Trying Ubuntu amd64 package selection defaults." &&
  echo "dss:info: cross grading.  force installing of amd64 packages after dpkg --set-selections."
  apt_get_f_install
  if [  $? -ne 0 ]; then
    if [ -z "$essentialtoinstall" ]; then
      echo "dss:warn: apt-get -f install failed.  However it appears we have all essential 64 bit packages.  Trying to continue."
    else
      echo "dss:error: cross grading failed after initial amd64 package installs.  See crossgrade_debian for a few suggestions to resolve manually."
      return 1
    fi
  fi
  #apt-get $APT_GET_INSTALL_OPTIONS autoremove

  for i in 0; do
    echo "dss:info: cross grading figuring out essential packages."
    local essentialpackages=
    local i386apps="$(dpkg -l | grep '^ii' | grep ':i386' | awk '{print $2}' | sed 's/:i386$//' | grep -v '^lib' )"
    local i386app=
    local essentialdeps=
    for i386app in $i386apps; do
      pause_check
      local needsdeps=
      apt-cache show $i386app | egrep -qai 'Essential: yes|Priority: required|Priority: important' && ! dpkg -l | egrep -qai '^ii.*${i386app}.*amd64' && essentialpackages="$essentialpackages ${i386app}:amd64" && needsdeps=true
      [ -z "$needsdeps" ] && continue
      # pre-depends can include options (one of n).  e.g. init
      # apt-cache show init | grep Pre-Depends
      # Pre-Depends: systemd-sysv | sysvinit-core | runit-init
      # can also have versions
      # Pre-Depends: libc6 (>= 2.15), libgmp10, libmpfr6 (>= 3.1.3), libreadline7 (>= 6.0), libsigsegv2 (>= 2.9)
      local addep=""
      for pkg in $(apt-cache show $i386app | grep Pre-Depends  | sed  -r  's/\([^)]+\)//g' | sed 's/,//g' | sed 's/.*://' | sed 's/ | /____/g'); do
        if echo "${pkg}" | grep -qai '____'; then
          local j="$(echo "${pkg}" | sed 's/____/ /g')"
          for k in $j; do
            if dpkg -l | grep 'ii' | grep -qai " $k"; then
              echo "dss:info:selecting $k as the pre-dependency for $i386app from options of '$j' since that is what is installed"
              pkg="$k"
            fi
          done
          [ -z "${pkg}" ] && pkg="$(echo $j | awk '{print $0}')" &&  echo "dss:info:selecting ${pkg} as the pre-dependencies for ${i386} from options of '${pkg}' since it that is the first one listed and the others were not installed"
        fi
        addep="$addep ${pkg}:amd64"
      done
      essentialdeps="$essentialdeps $addep"
    done
    # => essentialpackages=base-files:amd64 base-passwd:amd64...

    [ -z "$essentialpackages" ] && echo "dss:info: no essential packages missing.  moving to next step." && break
    local debs="$(find /var/cache/apt/archives -type f  | egrep 'amd64.deb$|all.deb$')"
    [  ! -d /root/distrorejuveinfo/$$ ] && mkdir /root/distrorejuveinfo/$$
    [  ! -z "$debs" ] && mv $debs /root/distrorejuveinfo/$$
    echo "dss:info: cross grading essential packages.  Downloading essentialpackages: $essentialpackages"
    echo "dss:info: cross grading essential packages.  Downloading essentialdependencies: $essentialdeps"

    essentialpackages="$(for i in $essentialpackages; do echo $i; done | sort | uniq)"
    essentialdeps="$(for i in $essentialdeps; do echo $i; done | sort | uniq)"
    cd /root/distrorejuveinfo/$$ || return 1
    [ ! -z "$essentialpackages" ] && apt-get --reinstall --download-only $APT_GET_INSTALL_OPTIONS install $essentialpackages || apt-get download $essentialpackages
    [ ! -z "$essentialdeps" ] && apt-get --reinstall --download-only $APT_GET_INSTALL_OPTIONS install $essentialdeps || apt-get download $essentialdeps
    apt-get --reinstall --download-only $APT_GET_INSTALL_OPTIONS install init:amd64
    #apt-get --reinstall --download-only -y install systemd-sysv:amd64
    apt-get --reinstall --download-only $APT_GET_INSTALL_OPTIONS install libc-bin:amd64
    echo "dss:trace: cross grading dpkg installing essential packages."
    #apt-get download e2fsprogs:amd64 util-linux:amd64 sed:amd64
    local debs="$(find /var/cache/apt/archives -type f |  egrep 'amd64.deb$|all.deb$')"
    local debs2="$(find . -type f  | egrep 'amd64.deb$|all.deb$')"
    [  ! -z "$debs" ] && dpkg_install $debs $debs2
    ret=$?
    [  ! -z "$debs" ] && mv $debs /root/distrorejuveinfo/$$
    [ $ret -ne 0 ] && echo "dss:error: dpkg install essential amd64.deb files failed" 2>&1
    cd - || return 1
  done

  # getting a dependency issue on apt-get remove a few things: libpam-modules : PreDepends: libpam-modules-bin (= 1.1.8-3.6)
  # workaround is:
  apt_get_install libpam-modules-bin:amd64

  # these seem to be uninstalled by something above.
  # now handled by other code
  # [ ! -z "${vimpkg}${apachepkg}" ] && echo "dss:trace: cross grading and installing vim/apache2." && apt-get $APT_GET_INSTALL_OPTIONS install $apachepkg $vimpkg

  for i in 0 1; do
    # for all i386 apps, install the amd64 and remove the i386.  some will fail, that's ok.
    # do
    #apt-get $APT_GET_INSTALL_OPTIONS autoremove

    local i386toremove="$(dpkg -l | grep 'i386' | grep '^ii' | awk '{print $2}' | grep -v '^lib' | sed 's/:i386//' | sed 's/$/:i386/' | tr '\n' ' ')"
    # => e.g. apache2-utils:i386 bc:i386 bind9-host:i386...
    local amd64toinstall="$(echo $i386toremove | sed 's/:i386/:amd64/g')"
    # e.g. => apache2-utils:amd64 bc:amd64 bind9-host:amd64
    [  -z "$amd64toinstall" ] && [  -z "$i386toremove" ] && break
    local ret=0
    # tends to remove necessities.  like ifupdown
    # echo "dss:trace: cross grading and bulk replacing i386 apps with 64 bit versions.  Round #$i"
    # apt_get_install $amd64toinstall && apt_get_remove $i386toremove
    #[  $? -ne 0 ] && ret=$(($ret+1))

    local i386toremove="$(dpkg -l | grep 'i386' | grep '^ii' | awk '{print $2}' | grep -v '^lib' | sed 's/:i386//')"
    echo "dss:trace: cross grading and individually installing 64 bit versions of all i386 packages: $i386toremove"
    # => e.g. apache2-utils bc bind9-host
    local i386toremove2=""
    # install them all
    for pkg in ${i386toremove} ifupdown; do
      apt_get_install "${pkg}:amd64"
      local lret=$?
      # fwiw apt-get install $alreadyinstalled returns 0
      [  $lret -eq 0 ] && echo $pkg | egrep -qai 'gcc.*base' && echo "dss:info: not apt-get remove-ing $pkg, as has tended to remove lots of necessary things.  e.g. ifupdown."
      if [ "$lret" -eq 0 ] && ! echo "$pkg" | egrep -qai 'gcc.*base'; then
        i386toremove2="$i386toremove2 $pkg"
      fi
    done
    echo "dss:trace: removing 32 bit versions of packages where we were able to install the 64bit version: $i386toremove2"
    # then remove the i386 version.  Used to this after installing each amd64 package, but that sometimes led to other things being removed that broke things
    # fwiw when you install $pkg:amd4 it will typically remove the $pkg:i386, so hopefully not will actually happen in this section?
    for pkg in $i386toremove2 ; do
      local lret=0
      if echo "${pkg}" | egrep -qai 'gcc.*base'; then
        true
      else
        apt_get_remove "${pkg}:i386"
        lret=$?
        if [  $lret -ne 0 ]; then
          echo "dss:warn: apt-get remove ${pkg}:i386 failed.  Trying an apt-get -f install.  Will continue irregardless."
          ret=$(($ret+1))
          apt_get_f_install "after removing $pkg"
        fi
      fi
    done
    
    echo "dss:trace: completed individual install and removal of i386 packages.  Ret code of $ret (0 means we are done, otherwise we go for another round)."
    [  $ret -eq 0 ] && break
  done

  # try to install
  while true; do
      mkdir -p distrorejuveinfo/$$/extra64debs
      cd distrorejuveinfo/$$/extra64debs || return 1
      for pkg in ${amd64toinstall}; do
        pause_check
        ! dpkg -l | grep '^ii' | awk '{print $2}' | grep -qai "${pkg}" && echo "dss:trace: downloading amd64 debian file for ${pkg}" && apt-get download "${pkg}"
      done
      local amdfilestoinstall="$(find . -type f  | egrep 'amd64.deb$|all.deb$')"
      if [ -z "$amdfilestoinstall" ]; then
        echo "dss:trace: not finding any extra amd64 files to install"
        cd - || return 1
        break;
      fi
      cd - || return 1
      echo "dss:trace: attempting a dpkg install of non-lib packages: $(echo $amd64toinstall)"
      dpkg_install $(find distrorejuveinfo/$$/extra64debs -type f  | egrep 'amd64.deb$|all.deb$')
      local lret=$?
      echo "dss:trace: dpkg install $( [ $lret -eq 0 ] && echo "succeeded" || echo "failed")"
      break
  done

  while true; do
      mkdir -p distrorejuveinfo/$$/settheory
      cd distrorejuveinfo/$$/settheory || return 1
      #[ir] e.g. to find desired = install or remove where status = installed
      dpkg -l | egrep '^[ir]i.*i386' | awk '{print $2}' | sed 's/:i386//' | sort > pkgs.386.log
      dpkg -l | egrep '^ii.*amd64' | awk '{print $2}' | sed 's/:amd64//' | sort> pkgs.amd64.log
      amd64toinstall="$(for i in $(comm -3  --check-order pkgs.amd64.log pkgs.386.log | grep -v '^[a-z]'); do echo "$i:amd64 "; done)"

      for pkg in ${amd64toinstall}; do
        pause_check
        echo "dss:trace: downloading amd64 debian file for ${pkg}"
        apt-get download "${pkg}"
      done
      cd - || return 1
      local amdfilestoinstall=$(find distrorejuveinfo/$$/settheory -type f  | egrep 'amd64.deb$|all.deb$')
      if [ -z "$amdfilestoinstall" ]; then
        echo "dss:trace: not finding any extra amd64 files to install per distrorejuveinfo/$$/settheory"
        break;
      fi
      echo "dss:trace: using set theory method for lib and non-lib packages: $(echo $amd64toinstall)"
      dpkg_install $(find distrorejuveinfo/$$/settheory -type f  | egrep 'amd64.deb$|all.deb$')
      local lret=$?
      echo "dss:trace: set theory dpkg install $( [ $lret -eq 0 ] && echo "succeeded" || echo "failed")"
      break
  done

  # apt-get $APT_GET_INSTALL_OPTIONS autoremove

  ## apt-show-versions  | grep amd64 | grep 'not installed'
  # acl:amd64 not installed
  # aptitude:amd64 not installed
  # banana not available for architecture amd64
  # tar:amd64/xenial-security 1.28-2.1ubuntu0.1 uptodate
  # tar:i386 not installed

  # =>
  # # echo "$available"
  #acl
  #aptitude
  #bsd-mailx
  local loop=
  for loop in 0; do
    local fromfile="$(find /root/distrorejuveinfo/ /root/deghostinfo/ -mtime -${DR_CONFIGURATION_HISTORY_DAYS} 2>/dev/null | grep crossgrade)"
    [ ! -z "$fromfile" ] && fromfile="$(ls -1rt $fromfile | head -n 1)"
    [  -z "$fromfile" ] && break
    local uninstalled="$(print_config_state_changes "$fromfile" | grep '^dss:configdiff:statechanges:-installed:' | sed 's/.*installed://' | sed 's/:i386//' | sed 's/:amd64//' | grep -v '^ *$' | grep -v wpasupplicant | tr '\n' ' ')"
    # => e.g. apache2 apache2-bin fontconfig-config fonts-dejavu-core php5-curl php5-gd php5-imap
    # apt-show-versions  ruby:amd64
    # ruby not available for architecture amd64
    # apt-show-versions  ruby
    # ruby:all not installed
    # rubygems-integration: not installed
    # systemd:amd64 not installed

    local available=$(apt-show-versions  $uninstalled | grep -v i386 | grep 'not installed' | sed 's/ not installed.*//' | sed 's/:.*$//')
    # => e.g. apache2 apache2-bin fontconfig-config
    # (excludes older packages that were uninstalled.  e.g. php5 on a newer ubuntu/debian)
    local toreinstall=
    local donotreinstallregex="linux-.*-686-pae|anotherpackagehere"
    for pkg in ${uninstalled}; do
      # sometimes packages are removed, but due to being deprecated.  $available will contain only the packages on the current distro
      echo "$available" | egrep -v "$donotreinstallregex" | egrep -qai "^${pkg}\$" && toreinstall="$toreinstall ${pkg}"
    done
    # => e.g. toreinstall=apache2 apache2-bin fontconfig-config fonts-dejavu-core
    [ ! -z "$toreinstall" ] && echo "dss:info: Will reinstall some packages that have been removed during the crossgrade: $(echo $toreinstall)"
    for pkg in ${toreinstall}; do
      apt_get_install "${pkg}"
    done
  done

  apt-get $APT_GET_INSTALL_OPTIONS autoremove

  if has_leftover_packages 32bit; then
    show_leftover_packages
    echo "dss:error:after cross grade, 32 bit packages remain." >&2
    return 1
  else 
    echo "dss:info:no 32 bit packages remain (good)"
  fi


  # A successful legacy conversion must meet the same package-architecture contract.
  local foreign_packages
  if [ "$(dpkg --print-architecture)" != amd64 ] ||
    [ "$(od -An -tu1 -j4 -N1 /bin/bash 2>/dev/null | tr -d ' ')" != 2 ] ||
    ! /bin/bash -c '[ "$(getconf LONG_BIT)" = 64 ]'; then
    echo 'dss:error: Crossgrade incomplete: native dpkg and a freshly executed 64-bit Bash/userspace are required.' >&2; return 1
  fi
  foreign_packages=$(crossgrade_output_foreign_packages) || return 1
  if [ -n "$foreign_packages" ]; then
    printf '%s\n' "$foreign_packages" >&2
    echo 'dss:error: Crossgrade incomplete: active packages must all be amd64 or all. Replace or remove the remaining foreign packages before continuing.' >&2; return 1
  fi
  echo "dss:info: Cross grade has completed."
  return 0

  # sample cleanup/finish up/suggestions:

  # bash : Conflicts: bash:i386
  # apt-get download bash; dpkg_install bash*64.deb

  #  libpam-modules : PreDepends: libpam-modules-bin (= 1.1.8-3.6) =>
  # apt-get install libpam-modules-bin:amd64

  # apt-get -s -o Debug::pkgProblemResolver=yes -f install

  # if "apt-get --download-only install perl-base:amd64" => E: Unmet dependencies. Try 'apt --fix-broken install'
  # try:
  # apt-get download perl-base:amd64
  # dpkg --install perl-base*amd64.deb

  #WARNING: The following essential packages will be removed.
  #This should NOT be done unless you know exactly what you are doing!
  # diffutils:i386
  #=>
  # apt-get download diffutils
  # dpkg --install diffutils*amd64.deb


  # apt-get install apache2
  #apt-get install $(dpkg -l | grep '^ii' | grep i386 | awk '{print $2}' | sed 's/:i386$//' | grep -v '^lib')

  # apt-get purge zlib1g:i386
  # remove i386 packages
  # for i in $(dpkg -l | grep 'i386' | grep '^ii' | awk '{print $2}' | sed 's/:i386//' | grep -v '^lib' ); do apt-get -y remove $i:i386; done

  #apt-get install sysvinit-core:amd64

  # pkgs installed for older/different distros
  # allpkgs="$(apt-cache pkgnames)"; for i in $(dpkg -l | grep 'i386' | grep '^ii' | awk '{print $2}' | grep -v '^lib' | sed 's/:i386//'); do echo " $allpkgs " | grep -qai " $i " && continue; echo $i; done


  # e2fsprogs pre-depends on libcomerr2 (>= 1.42~W
  # =>
  # dpkg_install e2fsprogs_1.42.13-1ubuntu1_amd64.deb  libcomerr2_1.42.13-1ubuntu1_amd64.deb  libss2_1.42.13-1ubuntu1_amd64.deb

  # check 64 bit versions here?
  # dpkg -l | grep libc-bin
  # return 0
}

# e.g. has_leftover_packages && show_leftover_packages && remove_leftover_packages
function has_leftover_packages() {
   leftover_packages0 has $1
   # returns 0 if leftover packages
   return $?
}
function show_leftover_packages() {
   leftover_packages0 show $1
   return $?
}

function remove_leftover_packages() {
   leftover_packages0 remove  $1
   local ret=$?
   [ "$ret" -eq 0 ] && echo "dss:trace:removed_leftover_packages completed."
   [ "$ret" -ne 0 ] && echo "dss:error:remove leftover packages failed." >&2
   return $ret
}

# Keep the six cleanup fields first; Description is multiline on historical dpkg.
# install ok installed<TAB>bash<TAB>amd64<TAB>5.2-1<TAB>yes<TAB>required<TAB>GNU shell -> one row.
# An indented Description continuation is skipped; a malformed non-indented record fails the inventory.
function apt_packages_output_inventory() {
(
  set -o pipefail
  LC_ALL=C dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Version}\t${Essential}\t${Priority}\t${Description}\n' |
    awk -F '\t' -v OFS='\t' '
      $1 ~ / not-installed$/ { next }
      $1 ~ /^[a-z-]+ [a-z-]+ [a-z-]+$/ && $2 ~ /^[a-z0-9][a-z0-9+.-]*$/ && $3 ~ /^[a-z0-9][a-z0-9-]*$/ && $4 != "" {
        print $1, $2, $3, $4, $5, $6, $7; next
      }
      /^[ \t]/ || !NF { next }
      { bad=1 }
      END { exit bad }
    '
)
}

# Report from existing indexes only; this deliberately does not use the mutating leftover helpers.
# Existing indexes only: package, query architecture, version, URI, suite/component.
# bash | 5.2-1 | https://deb.debian.org/debian bookworm/main amd64 Packages
# -> bash<TAB>amd64<TAB>5.2-1<TAB>https://deb.debian.org/debian<TAB>bookworm/main; Sources rows are skipped.
function apt_packages_output_repository_versions() {
  local inventory=$1 native=$2 directory=$3 architecture package arch status _ architectures
  architectures=$(awk -F '\t' -v native="$native" '$1 ~ / installed$/ { print ($3 == "all" ? native : $3) }' "$inventory" | LC_ALL=C sort -u) || return 1
  for architecture in $architectures; do
    : > "$directory/query" || return 1
    while IFS=$'\t' read -r status package arch _; do
      case "$status" in *' installed') :;; *) continue;; esac
      [ "$arch" != all ] || arch=$native
      [ "$arch" = "$architecture" ] || continue
      if [ "$arch" = "$native" ]; then printf '%s\0' "$package"; else printf '%s\0' "$package:$arch"; fi
    done < "$inventory" > "$directory/query" || return 1
    # APT1.x misparses multiple split -o arguments before the command.
    LC_ALL=C xargs -0 -r -n 256 apt-cache madison -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= \
      < "$directory/query" > "$directory/madison" || {
      echo "dss:error: Cannot read existing APT indexes for $architecture; package provenance is unverified." >&2
      return 1
    }
    awk -F '|' -v OFS='\t' -v architecture="$architecture" -v native="$native" '
      { text=$3; gsub(/^[ \t]+|[ \t]+$/, "", text); count=split(text, fields, /[ \t]+/)
        legacy=(count == 3 && fields[3] == "Packages" && architecture == native && fields[1] ~ /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\/]+\/?$/)
        if (!legacy && (fields[count] != "Packages" || fields[count-1] != architecture)) next
        name=$1; version=$2; gsub(/^[ \t]+|[ \t]+$/, "", name); gsub(/^[ \t]+|[ \t]+$/, "", version)
        sub(/:.*/, "", name)
        if (legacy) print name, architecture, version, fields[1], fields[2], "legacy-host"
        else print name, architecture, version, fields[1], fields[2]
      }
    ' "$directory/madison" || return 1
  done
}

# List installed versions that match official repositories, excluding ambiguous vendor matches.
# Installed bash/amd64/5.2-1 plus that version from an official bookworm source -> bash<TAB>amd64<TAB>5.2-1.
# The same version also matching a nonofficial source makes the origin ambiguous and suppresses the result.
function apt_packages_output_official_installed_versions() {
  local family=$1 release=$2 native=$3 sources=$4 inventory=$5 archive_records=$6
  awk -F '\t' -v OFS='\t' -v family="$family" -v release="$release" -v native="$native" '
    # Old APT removes path, credentials and port from index descriptions.
    function legacy_origin(uri, scheme, host) {
      scheme=tolower(uri); sub(/:.*/, "", scheme)
      host=uri; sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", host); sub(/\/.*$/, "", host)
      sub(/^.*@/, "", host); sub(/:[0-9]+$/, "", host)
      return scheme "://" tolower(host)
    }
    FILENAME == ARGV[1] {
      if ($4 != "deb") next
      uri=$5; sub(/\/$/, "", uri); origin=legacy_origin(uri) SUBSEP $6
      if (!seen[origin SUBSEP uri]++) { origins[origin]++; unique_uri[origin]=uri }
      if ($3 == family && $4 == "deb" && ($6 == release || index($6, release "-") == 1 || index($6, release "/") == 1)) {
        official[uri SUBSEP $6]=1
      }; next
    }
    FILENAME == ARGV[2] {
      if ($1 ~ / installed$/) {
        key=$2 SUBSEP ($3 == "all" ? native : $3); version[key]=$4; arch[key]=$3
      }; next
    }
    {
      key=$1 SUBSEP $2; if (!(key in version) || $3 != version[key]) next
      uri=$4; sub(/\/$/, "", uri); suite=$5; sub(/\/[^\/]*$/, "", suite)
      if ($6 == "legacy-host") {
        origin=legacy_origin(uri) SUBSEP suite
        if (origins[origin] != 1) { ambiguous[key]=1; next }
        uri=unique_uri[origin]
      }
      if ((uri SUBSEP suite) in official) found[key]=1; else ambiguous[key]=1
    }
    END { for (key in found) if (!(key in ambiguous)) { split(key, part, SUBSEP); print part[1], arch[key], version[key] } }
  ' "$sources" "$inventory" "$archive_records"
}

# Classification is evidence, not removal permission. Inputs retain installed-version metadata.
# Output: package, architecture, installed version, class, reason (tab-separated).
# deinstall ok config-files -> residual-config; install ok unpacked -> incomplete.
# No current binary plus exact previous official version -> obsolete; without that provenance -> unavailable.
# An available official installed version described as "transitional dummy package" -> transitional.
function apt_packages_output_classifications() {
  local inventory=$1 native=$2 archive_records=$3 previous_provenance=${4:-/dev/null} current_provenance=${5:-/dev/null}
  awk -F '\t' -v OFS='\t' -v native="$native" '
    FILENAME == ARGV[1] { available[$1 SUBSEP $2]=1; next }
    FILENAME == ARGV[2] { previous[$1 SUBSEP $2 SUBSEP $3]=1; next }
    FILENAME == ARGV[3] { current[$1 SUBSEP $2 SUBSEP $3]=1; next }
    {
      version_key=$2 SUBSEP $3 SUBSEP $4
      if ($1 ~ / not-installed$/) next
      if ($1 ~ / config-files$/) {
        class="residual-config"; reason="removed package retains configuration; purge safety is unverified"
      } else if ($1 !~ /^(install|hold) ok installed$/) {
        class="incomplete"; reason="package state or pending selection requires review"
      } else if (!(($2 SUBSEP ($3 == "all" ? native : $3)) in available)) {
        if (version_key in previous) {
          class="obsolete"; reason="installed version matched the previous official release; no binary version in current indexes"
        } else {
          class="unavailable"; reason="no binary version in current indexes; official origin is unverified"
        }
      # oldlibs alone includes real libraries; use only the installed short description.
      } else if (version_key in current && tolower($7) ~ /(^|[^a-z])(transitional( dummy)?|dummy( transitional)?) package([^a-z]|$)/) {
        class="transitional"; reason="official installed version describes a transitional package; replacement and removal safety need review"
      } else {
        class="available"; reason="binary version exists in current indexes"
      }
      print $2, $3, $4, class, reason
    }
  ' "$archive_records" "$previous_provenance" "$current_provenance" "$inventory"
}

function upgrade_record_package_origins() {
(
  umask 077
  set -o pipefail
  local family=$1 from=$2 to=$3 baseline directory native
  case "$family:$from:$to" in debian:*:*|ubuntu:*:*) :;; *) return 1;; esac
  case "$from$to" in ''|*[!a-z0-9]*) return 1;; esac
  [ -n "$from" ] && [ -n "$to" ] && [ "$from" != "$to" ] && [ "$(id -u)" = 0 ] || return 1
  baseline=$(config_state_output_baseline) || { record_config_state || return 1; baseline=$(config_state_output_baseline) || return 1; }
  directory="$baseline.obsolete-packages/$family-$from-to-$to"
  [ ! -L "$baseline.obsolete-packages" ] && [ ! -L "$directory" ] || return 1
  if [ -f "$directory/prepared" ]; then return 0; fi
  mkdir -p "$directory" && chmod 700 "$baseline.obsolete-packages" "$directory" || return 1
  native=$(dpkg --print-architecture) || return 1
  printf '%s\n' "$native" > "$directory/native" || return 1
  apt_sources_list > "$directory/sources.before" || return 1
  apt_packages_output_inventory > "$directory/packages.before" || return 1
  apt_packages_output_repository_versions "$directory/packages.before" "$native" "$directory" > "$directory/archives.before" || return 1
  apt_packages_output_official_installed_versions "$family" "$from" "$native" "$directory/sources.before" "$directory/packages.before" "$directory/archives.before" \
    > "$directory/provenance" || return 1
  : > "$directory/prepared"
)
}

# Reject package installation/configuration; status 3 identifies unapproved removals for the bounded fallback.
# Allowed bash<TAB>amd64 plus Remv bash [5.2-1] -> bash:amd64; unapproved Remv -> status 3.
# Any Inst, Conf or Purg row -> status 4, even when a removal is allowed.
function upgrade_cleanup_output_removals() {
  local plan=$1 allowed=$2 native=$3
  awk -F '\t' -v native="$native" '
    FILENAME == ARGV[1] { allowed[$1 ":" $2]=1; next }
    /^(Inst|Conf|Purg) / { unsafe=1 }
    /^Remv / {
      split($0, field, /[ \t]+/); name=field[2]
      if (name !~ /:/) {
        if ((name ":" native) in allowed) name=name ":" native
        else if ((name ":all") in allowed) name=name ":all"
      }
      if (!(name in allowed)) bad=1
      if (!seen[name]++) print name
    }
    END { exit unsafe ? 4 : (bad ? 3 : 0) }
  ' "$allowed" "$plan"
}

# Base/transitional exceptions allow documentation; MariaDB may retain its exact obsolete logcheck filters.
function upgrade_cleanup_payload_is_documentation() {
  local package=${1%:*} files=$2 logcheck=${3:-} file found=false
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    case "$file" in /.) :;; *'/../'*|*'/./'*|*/..|*/.) return 1;; esac
    case "$file" in
      /.|/|/usr|/usr/share|/usr/share/doc|/usr/share/lintian|/usr/share/lintian/overrides) :;;
      /usr/share/doc/"$package"|/usr/share/doc/"$package"/*|/usr/share/lintian/overrides/"$package") found=true;;
      /etc|/etc/logcheck|/etc/logcheck/ignore.d.workstation|/etc/logcheck/ignore.d.server|/etc/logcheck/ignore.d.paranoid|/etc/logcheck/ignore.d.workstation/"$logcheck"|/etc/logcheck/ignore.d.server/"$logcheck"|/etc/logcheck/ignore.d.paranoid/"$logcheck")
        [ -n "$logcheck" ] || return 1;;
      *) return 1;;
    esac
  done <<< "$files"
  $found
}

# Package cleanup keeps local edits in a private tree rather than renaming active files.
function upgrade_packages_backup_modified_files() {
(
  local directory=$1 attempt package files file checksum_file conffiles expected actual relative parent probe reason original_file lookup_file
  local modified=0 unverified=0
  local package_pattern='^[a-z0-9][a-z0-9+.-]*(:[a-z0-9][a-z0-9-]*)?$'
  shift
  [ "$#" -gt 0 ] || return 0
  [ ! -L "$directory" ] && [ "$(stat -c '%u:%a' -- "$directory")" = 0:700 ] || return 1
  umask 077
  attempt=$(mktemp -d "$directory/modified-files.XXXXXX") || return 1
  mkdir -m 700 -- "$attempt/root" && chmod 700 -- "$attempt" "$attempt/root" || return 1
  : > "$attempt/preserved.tsv" && chmod 600 -- "$attempt/preserved.tsv" || return 1
  for package in "$@"; do
    [[ "$package" =~ $package_pattern ]] || return 1
    files=$(LC_ALL=C dpkg-query -L "$package") || return 1
    conffiles=$(LC_ALL=C dpkg-query -W -f='${Conffiles}\n' "$package") || return 1
    checksum_file=$(LC_ALL=C dpkg-query --control-path "$package" md5sums 2>/dev/null) || checksum_file=
    if [ -z "$checksum_file" ]; then
      for file in "/var/lib/dpkg/info/$package.md5sums" "/var/lib/dpkg/info/${package%:*}.md5sums"; do
        if [ -f "$file" ]; then checksum_file=$file; break; fi
      done
    fi
    [ -z "$checksum_file" ] || [ -f "$checksum_file" ] || return 1
    original_file=
    while IFS= read -r file; do
      # Diversions relocate package files; another package's saved files have unknown defaults.
      case "$file" in
        'package diverts others to: '*) file=${file#* to: }; lookup_file=;;
        'locally diverted to: '*|'diverted by '*' to: '*)
          [ -n "$original_file" ] || return 1
          file=${file#* to: }; lookup_file=$original_file;;
        *) original_file=$file; lookup_file=$file;;
      esac
      case "$file" in /.) continue;; *'/../'*|*'/./'*|*/..|*/.|[!/]*) return 1;; /*) :;; *) return 1;; esac
      if [ -d "$file" ] && [ ! -L "$file" ]; then continue; fi
      # Merged-/usr aliases are shared directories, not package-specific file edits.
      case "$file" in /bin|/sbin|/lib|/lib32|/lib64) [ ! -d "$file" ] || continue;; esac
      if [ ! -e "$file" ] && [ ! -L "$file" ]; then continue; fi
      expected=; reason=unverified
      if [ ! -L "$file" ]; then
        [ -f "$file" ] || return 1
        if [ -n "$checksum_file" ] && [ -n "$lookup_file" ]; then
          expected=$(awk -v path="${lookup_file#/}" 'substr($0,35) == path { print substr($0,1,32); exit }' "$checksum_file") || return 1
        fi
        if [ -z "$expected" ] && [ -n "$lookup_file" ]; then
          expected=$(awk -v path="$lookup_file" '$1 == path { print $2; exit }' <<< "$conffiles") || return 1
        fi
        case "$expected" in *[!0-9a-fA-F]*) expected=;; esac
        if [ "${#expected}" -eq 32 ]; then
          actual=$(md5sum -- "$file") || return 1
          [ "${actual%% *}" != "$expected" ] || continue
          reason=modified
        fi
      fi
      # Package file lists can include children of shared directory aliases; preserve their real parents.
      parent=$(dirname -- "$file") || return 1
      parent=$(readlink -f -- "$parent") || return 1
      case "$parent" in /*) :;; *) return 1;; esac
      relative=${parent#/}/${file##*/}; relative=${relative#/}
      parent=$(dirname -- "$relative") || return 1
      probe=$parent
      while [ "$probe" != . ]; do
        [ ! -L "$attempt/root/$probe" ] || { echo "dss:error: Symlinked backup parent; preserving packages for review: $attempt/root/$probe" >&2; return 1; }
        case "$probe" in */*) probe=${probe%/*};; *) break;; esac
      done
      mkdir -p -- "$attempt/root/$parent" || return 1
      if [ ! -e "$attempt/root/$relative" ] && [ ! -L "$attempt/root/$relative" ]; then
        cp -a -- "$file" "$attempt/root/$relative" || return 1
      fi
      printf '%s\t%s\t%s\t%s\n' "$package" "$reason" "$file" "/$relative" >> "$attempt/preserved.tsv" || return 1
      case "$reason" in modified) modified=$((modified+1));; *) unverified=$((unverified+1));; esac
    done <<< "$files"
  done
  if [ "$modified:$unverified" != 0:0 ]; then
    echo "dss:stage: Preserved $modified locally modified package files and $unverified files without reliable checksums in $attempt/root" >&2
  fi
)
}

# Status 3 preserves a protected package; metadata failures remain fatal.
function upgrade_cleanup_output_safe_package() {
  local package=$1 native=$2 qualified_packages=$3 inventory=$4 query_package files file logcheck documentation_only=false status
  local gcc_base_pattern='^gcc-[0-9]+([.][0-9]+)?-base$' mariadb_transition_pattern='^mariadb-server-[0-9]+([.][0-9]+)+$'
  case "${package%:*}" in
    linux-*|grub*|lilo|init*|systemd*|udev*|network*|ifupdown*|netplan.io|resolvconf|dhcpcd*|isc-dhcp-client|iproute*|iptables*|nftables*|apt*|dpkg*|sudo|passwd|login|util-linux|openssh*|apache2*|libapache2-mod-*|nginx*|php*|mysql*|mariadb*|postgresql*|dovecot*|postfix*|exim*|sendmail*|fail2ban*|bind9*|rabbitmq*|slapd*|mailman*|redis*|caddy*|cron*|rsyslog*)
      if [[ "${package%:*}" =~ $mariadb_transition_pattern ]]; then
        if awk -F '\t' -v arch="${package##*:}" -v native="$native" '
          $1 == "install ok installed" && $2 == "mariadb-server" && $3 == (arch == "all" ? native : arch) { found=1 }
          END { exit !found }
        ' "$inventory"; then documentation_only=true
        else status=$?; [ "$status" -eq 1 ] || return 1
        fi
      fi
      if ! $documentation_only; then echo "dss:warn: Preserving service or system package $package." >&2; return 3; fi;;
  esac
  query_package=$package
  if ! $qualified_packages; then
    case "${package##*:}" in "$native"|all) query_package=${package%:*};; *) return 1;; esac
  fi
  files=$(dpkg-query -L "$query_package") || return 1
  if $documentation_only || [[ "${package%:*}" =~ $gcc_base_pattern ]]; then
    logcheck=
    if $documentation_only; then logcheck=${package%:*}; logcheck=${logcheck//./_}; fi
    if ! upgrade_cleanup_payload_is_documentation "$package" "$files" "$logcheck"; then
      echo "dss:warn: Preserving unverified base/transitional payload for $package." >&2; return 3
    fi
  fi
  while IFS= read -r file; do
    case "$file" in /etc/init.d/?*|/etc/init/?*|/etc/cron*|/etc/systemd/system/?*|/etc/systemd/user/?*|/lib/systemd/system/?*|/lib/systemd/user/?*|/usr/lib/systemd/system/?*|/usr/lib/systemd/user/?*|/etc/network/?*|/etc/netplan/?*|/etc/NetworkManager/?*|/etc/kernel/?*|/boot/?*|/var/lib/?*|/var/spool/?*|/srv/?*|/home/?*|/var/www/?*)
      echo "dss:warn: Preserving $package because it owns service/data path $file." >&2; return 3;;
    esac
  done <<< "$files"
  printf '%s\n' "$query_package"
}

# Append only to the current private run; no arguments validates the optional destination.
function upgrade_cleanup_record() {
  local directory=${DR_RUN_DIRECTORY:-} file
  [ -n "$directory" ] || return 0
  file="$directory/cleanup.outcomes"
  [ -d "$directory" ] && [ ! -L "$directory" ] && [ ! -L "$file" ] || return 1
  [ ! -e "$file" ] || [ -f "$file" ] || return 1
  [ "$#" -gt 0 ] || return 0
  (umask 077; printf '%s\t%s\t%s\t%s\n' "$1" "$2" "${3:--}" "${4:-}" >> "$file")
}

function upgrade_remove_retired_packages() {
(
  local package_umask
  package_umask=$(umask) || return 1
  umask 077
  set -o pipefail
  local family=$1 from=$2 to=$3 baseline directory native attempt package audit removals query_package signature current_signature
  local direct_plan plan allowed rejection status dpkg_help qualified_packages=false name architecture version config preserved
  local planning_automatic
  local -a planning_options=()
  local -a planning_packages=()
  local -a options=()
  local -a obsolete=()
  local -a selected=()
  case "$family:$from:$to" in debian:*:*|ubuntu:*:*) :;; *) return 1;; esac
  case "$from$to" in ''|*[!a-z0-9]*) return 1;; esac
  [ -n "$from" ] && [ -n "$to" ] && [ "$from" != "$to" ] && [ "$(id -u)" = 0 ] || return 1
  if ! baseline=$(config_state_output_baseline); then
    upgrade_cleanup_record obsolete deferred - "no original provenance for $family $from -> $to" || return 1
    echo "dss:warn: No original distro provenance for $family $from -> $to; preserving packages and skipping obsolete cleanup." >&2; return 0
  fi
  directory="$baseline.obsolete-packages/$family-$from-to-$to"
  if [ ! -f "$directory/prepared" ] || [ ! -s "$directory/provenance" ] || [ -L "$directory" ]; then
    upgrade_cleanup_record obsolete deferred - "no original provenance for $family $from -> $to" || return 1
    echo "dss:warn: No original distro provenance for $family $from -> $to; preserving packages and skipping obsolete cleanup." >&2; return 0
  fi
  native=$(dpkg --print-architecture) || return 1
  [ "$native" = "$(cat "$directory/native")" ] || return 1
  dpkg_help=$(LC_ALL=C dpkg --help) || return 1
  case "$dpkg_help" in *--print-foreign-architectures*) qualified_packages=true;; esac
  attempt=$(mktemp -d "$directory/cleanup.XXXXXX") || return 1
  signature=$(apt_state_output_signature packages) || return 1
  [ -n "$signature" ] || return 1
  apt_sources_list > "$attempt/sources" || return 1
  apt_packages_output_inventory > "$attempt/packages" || return 1
  apt_packages_output_repository_versions "$attempt/packages" "$native" "$attempt" > "$attempt/archives" || return 1
  apt_packages_output_official_installed_versions "$family" "$to" "$native" "$attempt/sources" "$attempt/packages" "$attempt/archives" > "$attempt/provenance" || return 1
  apt_packages_output_classifications "$attempt/packages" "$native" "$attempt/archives" "$directory/provenance" "$attempt/provenance" \
    > "$attempt/classifications" || return 1
  # Removal closures may include current official dependencies; unknown packages stay protected.
  awk -F '\t' -v OFS='\t' '
    FILENAME == ARGV[1] { if ($4 == "obsolete") retired[$1 SUBSEP $2]=$3; next }
    FILENAME == ARGV[2] { current[$1 SUBSEP $2]=$3; next }
    $1 == "install ok installed" && $5 != "yes" {
      key=$2 SUBSEP $3; obsolete=(retired[key] == $4)
      # Retired GCC base packages can be required despite containing only documentation.
      if (($6 != "required" && $6 != "important") || (obsolete && $2 ~ /^gcc-[0-9]+([.][0-9]+)?-base$/))
        if ($4 == current[key] || obsolete) print $2, $3, $4
    }
  ' "$attempt/classifications" "$attempt/provenance" "$attempt/packages" > "$attempt/eligible" || return 1
  awk -F '\t' '$4 == "obsolete" { print $1 ":" $2 }' "$attempt/classifications" > "$attempt/obsolete" || return 1
  while IFS= read -r package; do
    [ -n "$package" ] || continue
    if $qualified_packages; then obsolete+=("$package")
    else
      case "${package##*:}" in "$native"|all) obsolete+=("${package%:*}");; *) return 1;; esac
    fi
  done < "$attempt/obsolete"
  read -r -a options <<< "$APT_GET_INSTALL_OPTIONS"
  umask "$package_umask"
  pause_check || return 1
  # Remove proven obsolete packages only; use private solver state if their direct removal is unsafe.
  for direct_plan in true false; do
    plan="$attempt/plan.obsolete"
    allowed="$attempt/eligible"
    planning_options=()
    planning_automatic=false
    planning_packages=("${obsolete[@]}")
    if ! $direct_plan; then
      config=$(LC_ALL=C apt-config dump) || return 1
      if ! awk 'tolower($1) == "dir::state::extended_states" { found=1 } END { exit !found }' <<< "$config"; then
        echo 'dss:error: This APT cannot isolate automatic-package state; preserve packages and review cleanup manually.' >&2; return 1
      fi
      plan="$attempt/plan.protected"
      allowed="$attempt/obsolete.safe"
      : > "$allowed" && : > "$attempt/extended_states" || return 1
      awk -F '\t' '
        FILENAME == ARGV[1] { eligible[$1 ":" $2]=$0; next }
        $0 in eligible { print eligible[$0] }
      ' "$attempt/eligible" "$attempt/obsolete" > "$attempt/obsolete.candidates" || return 1
      while IFS=$'\t' read -r name architecture version; do
        package="$name:$architecture"
        if upgrade_cleanup_output_safe_package "$package" "$native" "$qualified_packages" "$attempt/packages" > /dev/null; then
          printf '%s\t%s\t%s\n' "$name" "$architecture" "$version" >> "$allowed" || return 1
          # Packages omitted from this private file are manual roots during simulation only.
          printf 'Package: %s\nArchitecture: %s\nAuto-Installed: 1\n\n' "$name" "$architecture" >> "$attempt/extended_states" || return 1
        else
          status=$?; [ "$status" -eq 3 ] || return 1
          upgrade_cleanup_record obsolete deferred "$package" 'protected system/service/data payload' || return 1
        fi
      done < "$attempt/obsolete.candidates"
      if [ ! -s "$allowed" ]; then
        upgrade_cleanup_record obsolete deferred - 'no safe obsolete cleanup candidates' || return 1
        echo "dss:warn: No safe obsolete cleanup candidates remain; preserved packages for manual review in $attempt." >&2; return 0
      fi
      planning_options=(-o "Dir::State::extended_states=$attempt/extended_states")
      planning_packages=()
      planning_automatic=true
    fi
    selected=()
    rejection=
    LC_ALL=C apt-get "${options[@]}" "${planning_options[@]}" -o APT::Get::Purge=false -o APT::Get::allow-remove-essential=false \
      -o APT::Get::AutomaticRemove="$planning_automatic" --simulate remove "${planning_packages[@]}" > "$plan" 2>&1 || return 1
    if removals=$(upgrade_cleanup_output_removals "$plan" "$allowed" "$native"); then :
    else
      status=$?
      if [ "$status" -ne 3 ]; then
        echo "dss:error: Cannot validate removal-only cleanup plan. Review $plan; no cleanup attempted." >&2; return 1
      fi
      rejection='protected or unknown packages'
    fi
    if [ -z "$rejection" ]; then
      if ! $direct_plan; then
        printf '%s\n' "$removals" > "$attempt/protected.removals" || return 1
        preserved=$(awk -F '\t' 'FILENAME == ARGV[1] { removed[$0]=1; next } !(($1 ":" $2) in removed) { print $1 ":" $2 }' \
          "$attempt/protected.removals" "$allowed") || return 1
        if [ -n "$preserved" ]; then
          while IFS= read -r package; do
            upgrade_cleanup_record obsolete deferred "$package" 'required by preserved packages or APT policy' || return 1
          done <<< "$preserved"
          printf 'dss:warn: Retaining obsolete packages required by preserved packages or APT policy: %s. Review %s.\n' "${preserved//$'\n'/, }" "$plan" >&2
        fi
      fi
      if [ -z "$removals" ]; then
        upgrade_cleanup_record obsolete none - 'no obsolete packages selected' || return 1
        return 0
      fi
      while IFS= read -r package; do
        if query_package=$(upgrade_cleanup_output_safe_package "$package" "$native" "$qualified_packages" "$attempt/packages"); then selected+=("$query_package")
        else
          status=$?
          [ "$status" -eq 3 ] || return 1
          rejection="protected package $package"; break
        fi
      done <<< "$removals"
    fi
    [ -n "$rejection" ] || break
    if $direct_plan; then
      echo "dss:warn: Obsolete cleanup plan includes $rejection; preserving blockers and planning a safe obsolete subset. Review $plan." >&2
    else
      echo "dss:error: Protected cleanup still includes $rejection; migrate manually. Review $plan; no cleanup attempted." >&2; return 1
    fi
  done
  # Recheck exact explicit removals with autoremove disabled before allowing package changes.
  LC_ALL=C apt-get "${options[@]}" -o APT::Get::Purge=false -o APT::Get::allow-remove-essential=false \
    -o APT::Get::AutomaticRemove=false --simulate remove "${selected[@]}" > "$attempt/final.plan" 2>&1 || return 1
  upgrade_cleanup_output_removals "$attempt/final.plan" <(printf '%s\n' "$removals" | tr ':' '\t') "$native" > "$attempt/removals.requested" || return 1
  [ "$(LC_ALL=C sort "$attempt/removals.requested")" = "$(printf '%s\n' "$removals" | LC_ALL=C sort)" ] || return 1
  upgrade_packages_backup_modified_files "$attempt" "${selected[@]}" || { echo "dss:error: Cannot preserve local package-file changes before obsolete cleanup; removal stopped. Review $attempt." >&2; return 1; }
  (umask 077; tar -C / -czpf "$attempt/configuration.tar.gz" etc) || return 1
  current_signature=$(apt_state_output_signature packages) || return 1
  if [ -z "$current_signature" ] || [ "$current_signature" != "$signature" ]; then
    echo 'dss:error: Package, source or index state changed during cleanup planning; no removal attempted. Retry with stable package state.' >&2; return 1
  fi
  LC_ALL=C apt-get "${options[@]}" -o APT::Get::Purge=false -o APT::Get::allow-remove-essential=false \
    -o APT::Get::AutomaticRemove=false --no-download remove "${selected[@]}" 2>&1 | tee "$attempt/removal.log" || return 1
  dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Version}\t${Essential}\t${Priority}\n' > "$attempt/packages.after" || return 1
  awk -F '\t' '
    FILENAME == ARGV[1] { selected[$1]=1; next }
    $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ && (($2 ":" $3) in selected) { bad=1 }
    END { exit bad }
  ' "$attempt/removals.requested" "$attempt/packages.after" || return 1
  audit=$(LC_ALL=C dpkg --audit 2>&1) || return 1
  [ -z "$audit" ] || { printf '%s\n' "$audit" >&2; return 1; }
  LC_ALL=C apt-get check || return 1
  (umask 077; cp "$attempt/removals.requested" "$attempt/packages.removed" && : > "$attempt/completed") || return 1
  while IFS= read -r package; do
    upgrade_cleanup_record obsolete removed "$package" 'verified obsolete cleanup' || return 1
  done < "$attempt/removals.requested"
  echo "dss:info: Removed obsolete distro packages without purging configs. Inventory, removal log and config backup: $attempt." >&2
)
}

# APT autoremove follows automatic-install marks; an obsolete package instead
# lacks a counterpart in the target release. Treat these as separate cleanup decisions to protect services and local software.
# Ordinary autoremove needs no original archive provenance; keep protected packages as solver roots.
function upgrade_autoremove_packages() {
(
  local package_umask parent directory native dpkg_help qualified_packages=false signature current_signature
  local capabilities config audit removals package status name architecture version essential priority query_package reason outcome_kind outcome_status outcome_package outcome_reason outcome_exit_status
  local -a options=()
  local -a selected=()
  package_umask=$(umask) || return 1
  umask 077
  set -o pipefail
  [ "$(id -u)" = 0 ] || return 1
  upgrade_cleanup_record || return 1
  parent="/root/distrorejuveinfo/autoremove"
  [ ! -L "/root/distrorejuveinfo" ] && [ ! -L "$parent" ] && mkdir -p -- "$parent" && chmod 700 "$parent" || return 1
  directory=$(mktemp -d "$parent/attempt.XXXXXX") || return 1
  : > "$directory/outcomes" || return 1
  trap 'outcome_exit_status=$?; while IFS="	" read -r outcome_kind outcome_status outcome_package outcome_reason; do
    upgrade_cleanup_record "$outcome_kind" "$outcome_status" "$outcome_package" "$outcome_reason" || { [ "$outcome_exit_status" -ne 0 ] || outcome_exit_status=1; }
  done < "$directory/outcomes"; exit "$outcome_exit_status"' EXIT
  capabilities=$(LC_ALL=C apt-get --help) || return 1
  case "$capabilities" in *autoremove*) :;; *) printf 'autoremove\tdeferred\t-\tAPT has no autoremove support\n' > "$directory/outcomes"; return $?;; esac
  config=$(LC_ALL=C apt-config dump) || return 1
  if ! awk 'tolower($1) == "dir::state::extended_states" { found=1 } END { exit !found }' <<< "$config"; then
    echo 'dss:error: Cannot isolate APT automatic-package state; no autoremove attempted.' >&2; return 1
  fi
  native=$(dpkg --print-architecture) || return 1
  dpkg_help=$(LC_ALL=C dpkg --help) || return 1
  case "$dpkg_help" in *--print-foreign-architectures*) qualified_packages=true;; esac
  audit=$(LC_ALL=C dpkg --audit 2>&1) || return 1
  [ -z "$audit" ] || { printf '%s\n' "$audit" >&2; return 1; }
  LC_ALL=C apt-get check || return 1
  signature=$(apt_state_output_signature packages) || return 1
  [ -n "$signature" ] || return 1
  dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Version}\t${Essential}\t${Priority}\n' > "$directory/packages.before" || return 1
  awk -F '\t' -v OFS='\t' '$1 ~ / installed$/ { print $2, $3, $4 }' "$directory/packages.before" > "$directory/installed" || return 1
  read -r -a options <<< "$APT_GET_INSTALL_OPTIONS"
  pause_check || return 1
  umask "$package_umask"
  LC_ALL=C apt-get "${options[@]}" -o APT::Get::Purge=false -o APT::Get::allow-remove-essential=false \
    -o APT::Get::AutomaticRemove=true --simulate remove > "$directory/plan.auto" 2>&1 || return 1
  removals=$(upgrade_cleanup_output_removals "$directory/plan.auto" "$directory/installed" "$native") || {
    echo "dss:error: Autoremove proposed non-removal work or packages outside the installed snapshot. Review $directory/plan.auto." >&2; return 1;
  }
  if [ -z "$removals" ]; then printf 'autoremove\tnone\t-\tno unused packages\n' > "$directory/outcomes"; return $?; fi
  printf '%s\n' "$removals" > "$directory/removals.auto" || return 1
  awk -F '\t' 'FILENAME == ARGV[1] { candidate[$0]=1; next } ($2 ":" $3) in candidate' \
    "$directory/removals.auto" "$directory/packages.before" > "$directory/candidates" || return 1
  : > "$directory/safe" && : > "$directory/extended_states" || return 1
  while IFS=$'\t' read -r status name architecture version essential priority; do
    package="$name:$architecture"; reason=
    if [ "$status" != 'install ok installed' ]; then reason='held or not fully installed'
    elif [ "$essential" = yes ]; then reason=Essential
    else case "$priority" in required|important) reason="priority $priority";; esac
    fi
    if [ -z "$reason" ]; then
      if upgrade_cleanup_output_safe_package "$package" "$native" "$qualified_packages" "$directory/packages.before" > /dev/null 2> "$directory/reason"; then :
      else
        status=$?; cat "$directory/reason" >&2 || return 1
        [ "$status" -eq 3 ] || return 1
        reason='protected system/service/data payload'
      fi
    fi
    if [ -n "$reason" ]; then
      printf 'dss:warn: Deferring unused %s: %s.\n' "$package" "$reason" >&2
      printf 'autoremove\tdeferred\t%s\t%s\n' "$package" "$reason" >> "$directory/outcomes" || return 1
      continue
    fi
    printf '%s\t%s\t%s\n' "$name" "$architecture" "$version" >> "$directory/safe" || return 1
    printf 'Package: %s\nArchitecture: %s\nAuto-Installed: 1\n\n' "$name" "$architecture" >> "$directory/extended_states" || return 1
  done < "$directory/candidates"
  if [ ! -s "$directory/safe" ]; then printf 'autoremove\tnone\t-\tall unused packages protected\n' >> "$directory/outcomes"; return $?; fi
  # Every omitted package is a manual root in this simulation; real APT marks are untouched.
  LC_ALL=C apt-get "${options[@]}" -o Dir::State::extended_states="$directory/extended_states" \
    -o APT::Get::Purge=false -o APT::Get::allow-remove-essential=false -o APT::Get::AutomaticRemove=true \
    --simulate remove > "$directory/plan.protected" 2>&1 || return 1
  removals=$(upgrade_cleanup_output_removals "$directory/plan.protected" "$directory/safe" "$native") || return 1
  printf '%s\n' "$removals" > "$directory/removals.protected" || return 1
  awk -F '\t' 'FILENAME == ARGV[1] { removed[$0]=1; next } !(($1 ":" $2) in removed) { print $1 ":" $2 }' \
    "$directory/removals.protected" "$directory/safe" > "$directory/deferred.dependencies" || return 1
  while IFS= read -r package; do
    [ -n "$package" ] || continue
    echo "dss:warn: Deferring unused $package: required by protected packages or APT policy." >&2
    printf 'autoremove\tdeferred\t%s\trequired by protected packages or APT policy\n' "$package" >> "$directory/outcomes" || return 1
  done < "$directory/deferred.dependencies"
  if [ -z "$removals" ]; then printf 'autoremove\tnone\t-\tunused packages retained by protected roots\n' >> "$directory/outcomes"; return $?; fi
  while IFS= read -r package; do
    query_package=$(upgrade_cleanup_output_safe_package "$package" "$native" "$qualified_packages" "$directory/packages.before") || return 1
    selected+=("$query_package")
  done <<< "$removals"
  LC_ALL=C apt-get "${options[@]}" -o APT::Get::Purge=false -o APT::Get::allow-remove-essential=false \
    -o APT::Get::AutomaticRemove=false --simulate remove "${selected[@]}" > "$directory/plan.final" 2>&1 || return 1
  upgrade_cleanup_output_removals "$directory/plan.final" "$directory/safe" "$native" > "$directory/removals.final" || return 1
  [ "$(LC_ALL=C sort "$directory/removals.final")" = "$(LC_ALL=C sort "$directory/removals.protected")" ] || return 1
  upgrade_packages_backup_modified_files "$directory" "${selected[@]}" || { echo "dss:error: Cannot preserve local package-file changes before autoremove; removal stopped. Review $directory." >&2; return 1; }
  (umask 077; tar -C / -czpf "$directory/configuration.tar.gz" etc) || return 1
  current_signature=$(apt_state_output_signature packages) || return 1
  if [ -z "$current_signature" ] || [ "$current_signature" != "$signature" ]; then
    echo 'dss:error: Package/repository state changed during autoremove planning; no removal attempted.' >&2; return 1
  fi
  LC_ALL=C apt-get "${options[@]}" -o APT::Get::Purge=false -o APT::Get::allow-remove-essential=false \
    -o APT::Get::AutomaticRemove=false --no-download remove "${selected[@]}" 2>&1 | tee "$directory/removal.log" || return 1
  dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Version}\n' > "$directory/packages.after" || return 1
  awk -F '\t' 'FILENAME == ARGV[1] { removed[$0]=1; next }
    $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ && (($2 ":" $3) in removed) { bad=1 }
    END { exit bad }' "$directory/removals.final" "$directory/packages.after" || return 1
  while IFS= read -r package; do printf 'autoremove\tremoved\t%s\tunused noncritical package\n' "$package" >> "$directory/outcomes" || return 1; done < "$directory/removals.final"
  audit=$(LC_ALL=C dpkg --audit 2>&1) || return 1
  [ -z "$audit" ] || { printf '%s\n' "$audit" >&2; return 1; }
  LC_ALL=C apt-get check || return 1
  echo "dss:info: Removed ${#selected[@]} unused packages without purging configs; inventory, deferred reasons and backup: $directory." >&2
)
}

function apt_packages_print_review() {
(
  [ -f /etc/debian_version ] || return 0
  umask 077
  set -o pipefail
  local directory native current family=unknown baseline file
  native=$(dpkg --print-architecture) || return 1
  directory=$(mktemp -d) || return 1
  trap 'rm -rf -- "$directory"' EXIT
  apt_packages_output_inventory > "$directory/status" || return 1
  if ! apt_packages_output_repository_versions "$directory/status" "$native" "$directory" > "$directory/available"; then
    echo 'dss:error: Cannot assess installed package availability from existing APT indexes; no packages were changed.' >&2
    return 1
  fi
  current=$(distro_output_codename) || return 1
  case " $ALL_DEBIAN " in *" $current "*) family=debian;; esac
  case " $ALL_UBUNTU " in *" $current "*) family=ubuntu;; esac
  apt_sources_list > "$directory/sources" || return 1
  apt_packages_output_official_installed_versions "$family" "$current" "$native" "$directory/sources" "$directory/status" "$directory/available" \
    > "$directory/current" || return 1
  : > "$directory/previous" || return 1
  if baseline=$(config_state_output_baseline); then
    for file in "$baseline.obsolete-packages/$family-"*"-to-$current/provenance"; do
      if [ -f "$file" ] && [ ! -L "$file" ]; then
        cat -- "$file" >> "$directory/previous" || return 1
      fi
    done
  fi
  apt_packages_output_classifications "$directory/status" "$native" "$directory/available" "$directory/previous" "$directory/current" \
    > "$directory/classifications" || return 1
  awk -F '\t' '
    $4 == "obsolete" || $4 == "unavailable" {
      print "dss:warn: Installed package " $1 ":" $2 " (" $3 ") has no versions in active APT indexes. Classification: " $4 ". " $5 ". Review manually and migrate if needed; package preserved."
    }
    $4 == "transitional" {
      print "dss:info: Transitional package " $1 ":" $2 " (" $3 "). " $5 "; package preserved."
    }
  ' "$directory/classifications"
)
}

function print_no_available_versions() {
  [ ! -f /etc/debian_version ] && return 0
  [ ! -x /usr/bin/apt-show-versions ] && echo "dss:error:apt-show-versions is not installed." >&2 && return 1
  local not_available="$(mktemp "not_available.log.XXXXXX")"
  local amd64_available="$(mktemp "available.log.XXXXXX")"
  apt-show-versions | grep 'No available version' | awk '{print $1}' | sed 's/:.*//' | sort > $not_available
  dpkg --print-architecture | grep -qai amd64 && cat $not_available && rm -f $not_available && return 0
  local remove_amd64=""
  # add amd64 and update list if we need it
  # dpkg --print-architecture
  #i386
  # dpkg --print-foreign-architectures
  #amd64
  ! dpkg --print-foreign-architectures  | grep -qai amd64 && dpkg --add-architecture amd64 && remove_amd64="dpkg --remove-architecture amd64" && apt_get_update > /dev/null
  apt-show-versions | grep -v 'No available version' | grep amd64 | awk '{print $1}' | sed 's/:.*//'| sort > $amd64_available
  # on ubuntu (at least) we get, say, postfix 'No available version in archive' for the i386, but there exists an amd64 package
  # /usr/bin/apt-show-versions | egrep 'subversion|postfix|iproute|multiarch-support|php5-json'
  # iproute:all 1:4.3.0-1ubuntu3.16.04.5 installed: No available version in archive
  # iproute2:amd64 not installed
  # iproute2:i386/focal 5.5.0-1ubuntu1 uptodate
  # multiarch-support:i386 2.27-3ubuntu1.4 installed: No available version in archive
  # php5-json:i386 1.3.2-2build1 installed: No available version in archive
  # postfix:amd64 not installed
  # postfix:i386 3.3.0-1ubuntu0.3 installed: No available version in archive
  # remove it if we added it
  # suppress 2 (lines unique in amd64_available) and 3 (lines in both) leaving 1 (just lines that only exist in not_available)
  comm  -2 -3  $not_available $amd64_available
  rm -f $not_available $amd64_available
  $remove_amd64
}

# e.g. leftover_packages0 show 32bit
function leftover_packages0() {
  [  ! -f /etc/debian_version ] && return 0
  if [ ! -x /usr/bin/apt-show-versions ]; then apt_get_install apt-show-versions || return $?; fi
  local leftover_log=$(mktemp "leftover-packages.log.XXXXXX")
  [ "$1" = "show" ] && local show="true"
  [ "$1" = "has" ] && local has="true" && local hasold="yes" && local has32bit="true"
  [ "$1" = "remove" ] || [  -z "$1" ]&& local remove="true"
  local oldpkg=true
  local bit32=true
  [ "$2" = "oldpkg" ] && oldpkg=true && bit32=
  [ "$2" = "32bit" ] && bit32=true && oldpkg=

  local leftover_count=0
  local commandret=0

  # apt-show-versions
  # ruby:i386 not installed
  # openssl-blacklist:all 0.5-3 installed: No available version in archive
  # ruby-did-you-mean:all/stretch 1.0.0-2 uptodate

  #echo "dss:trace: leftover show=$show has=$has remove=$remove oldpkg=$oldpgk 32bit=$bit32"

  ignorable_leftovers="^lib|webmin|virtualmin|usermin"
  if [  ! -z "$oldpkg" ] && [ -x /usr/bin/apt-show-versions ]  && [  0 -ne $(print_no_available_versions | egrep -v "$ignorable_leftovers" | wc -l) ]; then
    leftover_count=$((leftover_count+1))
    [  ! -z "$show" ] && echo "dss:warn: Applications from non-current distro versions installed: $(print_no_available_versions |egrep -v "$ignorable_leftovers" | grep -v '^lib' | awk '{print $1}' | tr '\n' ' ')"
    if [  ! -z "$remove" ]; then
      echo "dss:trace: Working out the old packages to resume."
      local oldpkgstoremove="$(print_no_available_versions | egrep -v "$ignorable_leftovers" | awk '{print $1}' | tr '\n' ' ')"
      # e.g. oldpkgstoremove has mysql-server-5.0:i386 mysql-server-core-5.0:i386
      [  $? -ne 0 ] && commandret=$((commandret+1))
      # /var/log/mysql/error.log:
      # [Warning] Failed to set up SSL because of the following SSL library error: SSL context is not usable without certificate and private key
      # =>
      # mysql_ssl_rsa_setup

      # may also need to add skip-grant-tables to /etc/mysql/my.cnf [mysqld] section
      echo "$oldpkgstoremove" | grep -qai mysql-ser && apt_get_install mysql-server
      echo "$oldpkgstoremove" | grep -qai mariadb-server && apt_get_install mariadb-server
      apt_get_remove $oldpkgstoremove || commandret=$((commandret+1))
      #apt-get $APT_GET_INSTALL_OPTIONS autoremove
    fi
  fi
  if [  ! -z "$oldpkg" ] && [ -x /usr/bin/apt-show-versions ]  && [  0 -ne $(print_no_available_versions | grep '^lib' | wc -l) ]; then
    leftover_count=$((leftover_count+1))
    [  ! -z "$show" ] && echo "dss:warn: Libraries from non-current distro versions installed: $(print_no_available_versions | grep '^lib' | awk '{print $1}' | tr '\n' ' ')"
    if [  ! -z "$remove" ]; then
      apt_get_remove $(print_no_available_versions | grep '^lib' | awk '{print $1}' | tr '\n' ' ')
      [  $? -ne 0 ] && commandret=$((commandret+1))
      #apt-get $APT_GET_INSTALL_OPTIONS autoremove
    fi
  fi
  if [  ! -z "$bit32" ]; then
    if [ $(getconf LONG_BIT) -eq 64 ]; then
      dpkg -l | grep 'i386' | grep '^ii' | awk '{print $2}' > "$leftover_log"
      if [  $(cat "$leftover_log" | head | wc -l ) -gt 0 ]; then
        leftover_count=$((leftover_count+1))
        [  ! -z "$show" ] && echo "dss:warn: There are some i386 application packages still installed.  They can be removed by running bash $0 --remove-leftover-packages.  They are: $(grep -v '^lib' "$leftover_log" | tr '\n' ' ') $(grep '^lib' "$leftover_log" | tr '\n' ' ')."
        if [  ! -z "$remove" ]; then

          local loop=0
          for loop in 0; do
            # dead code.  rely on --to-64bit call to crossgrade to sort this out.
            break;
            echo "dss:trace: cross grading figuring out essential packages."
            local essentialpackages=; for i in $(dpkg -l | grep '^ii' | grep :i386 | awk '{print $2}' | sed 's/:i386$//' | grep -v '^lib' ); do apt-cache show $i | egrep -qai 'Essential: yes|Priority: required|Priority: important' && essentialpackages="$essentialpackages $i:amd64"; done
            echo "dss:trace: cross grading downloading essential packages via download and dpkg_install."
            [  ! -z "$essentialpackages" ] && if apt-get --reinstall --download-only $APT_GET_INSTALL_OPTIONS install $essentialpackages; then
              dpkg_install $(find /var/cache/apt/archives -type f  | egrep 'amd64.deb$|all.deb$')
              [  ! -d /root/distrorejuveinfo/$$ ] && mkdir /root/distrorejuveinfo/$$
              mv $(find /var/cache/apt/archives/ -type f | egrep 'amd64.deb$|all.deb$')  /root/distrorejuveinfo/$$
              dpkg -l | grep 'i386' | grep '^ii' | awk '{print $2}' > "$leftover_log"
            else
              echo "dss:trace: cross grading downloading essential packages (after download+install failed) via download and separate install"
              apt-get $APT_GET_INSTALL_OPTIONS download $essentialpackages
              dpkg_install $(find . -type f |  egrep 'amd64.deb$|all.deb$')
              [  ! -d /root/distrorejuveinfo/$$ ] && mkdir /root/distrorejuveinfo/$$
              mv $(find /var/cache/apt/archives/ -type f  | egrep 'amd64.deb$|all.deb$') /root/distrorejuveinfo/$$
              dpkg -l | grep 'i386' | grep '^ii' | awk '{print $2}' > "$leftover_log"
            fi
          done

          # install 64 versions of the packages if we can.
          local lib64="$(grep -v '^lib' "$leftover_log" | sed 's/:i386/:amd64/g' | tr '\n' ' ')"
          echo "dss:trace: bulk installing 64bit versions of installed i386 apps: $lib64"
          apt_get_install $lib64
          echo "dss:trace: force install check"
          apt_get_f_install
          local lib32="$(dpkg -l | grep ':i386' | grep '^ii' | awk '{print $2}' | grep -v '^lib' | sed 's/:i386//')"
          echo "dss:trace: individually installing 64bit versions of installed i386 apps: $lib32"
          for i in $lib32; do apt_get_install $i:amd64 && apt_get_remove $i:i386; done
          echo "dss:trace: force install check"
          apt_get_f_install
          # [  $? -ne 0 ] && commandret=$((commandret+1))
          echo "dss:trace: removing 32 bit libraries"
          apt_get_remove $(grep -v '^lib' "$leftover_log" | sed 's/:i386//' | sed 's/$/:i386/' | tr '\n' ' ' )
          local lib32="$(dpkg -l | grep ':i386' | grep '^ii' | awk '{print $2}' | grep 'lib' )"
          echo "dss:trace: individually removing i386 libraries: $lib32"
          for i in $lib32; do apt_get_remove $i; done
          #apt-get $APT_GET_INSTALL_OPTIONS autoremove
          [  $(dpkg -l | grep ':i386' | grep '^ii' | wc -l) -gt 0 ] && commandret=$((commandret+1))
        fi
      fi
    fi
  fi # if32
  [  -f "$leftover_log" ] && rm -f "$leftover_log"
  # returns 0 if leftover packages
  [  ! -z "$remove" ] && return $commandret
  if [  ! -z "$has" ]; then [ $leftover_count -gt 0 ] && return 0 || return 1; fi
  [  ! -z "$show" ] && return 0
}

function tweak_broken_configs() {
  echo "dss:trace:tweak_broken_configs: tweaking certain broken configs if they exist."
  # error of sshd[1762]: Missing privilege separation directory: /var/run/sshd
  # => mkdir /var/run/sshd
  # FIXME: https://wiki.debian.org/ReleaseGoals/RunDirectory
  # => do we need to if -d /var/run; then mv -f /var/run/* /run/; rm -rf /var/run; ln -s /run /var/run; fi
  while true; do
    # not debian-ish
    if ! command -v dpkg >/dev/null 2>&1; then break; fi

    # Core binaries alone do not provide the server service or its upgrade scripts.
    if dpkg -l | egrep -qai '^ii[[:space:]]+(mysql|mariadb)-server(-[0-9]+([.][0-9]+)*)?(:[a-z0-9-]+)?[[:space:]]'; then break; fi

    # skip if they never had a mysql server installed.  don't skip if they had an rc=removed,configured
    # if they had mysql they'll have something like:
    # rc  mysql-server-5.1                 5.1.73-1   ...
    if ! dpkg -l | grep -qai '^rc.*mysql-server'; then break; fi

    # if mysql or maria db something is installed, quit here.
    # replaced by check above for ii.*mysql-server
    # and otherwise you'd need to be wary of packages like libdbd-mysql;  mysql-commo; libmariadbclient
    # if dpkg -l | egrep -v 'mysql-common|libmariad' | egrep -qai '^ii.*mysql-|^ii.*mariadb'; then break; fi

    # no mysql conf dir, quit
    if [ ! -d /etc/mysql ]; then break; fi

    dpkg -l | egrep -i 'mysql|mariadb' | awk '{print "dss:mysqlrelatedpackages:pre:" $0}'
    local dbpkg=
    local dbpkgret=0
    if dpkg -l | egrep ii | egrep -qai 'mariadb'; then
      dbpkg=mariadb-server
    elif dpkg -l | egrep ii | egrep -qai 'mysql.*server'; then
      dbpkg=mysql-server
    fi
    if [ ! -z "$dbpkg" ]; then
      echo "dss:stage: Restoring missing database server package $dbpkg from the current release"
      apt_get_install $dbpkg
      dbpkgret=$?
      if [ $dbpkgret -ne 0 ]; then
        apt_get_install default-mysql-server
        dbpkgret=$?
      fi
    fi
    dpkg -l | egrep -i 'mysql|mariadb' | awk '{print "dss:mysqlrelatedpackages:post:" $0}'
    [ "$dbpkgret" -eq 0 ] || return "$dbpkgret"
    break
  done

  #Failed because this line in /etc/mysql/my.cnf.migrated
  #log_slow_queries      = /var/log/mysql/mysql-slow.log
  #needed to change to:
  #slow_query_log                  = 1
  #slow_query_log_file             = /var/log/mysql/mysql-slow.log
  #find /var/log -type f | xargs --no-run-if-empty grep log_slow | grep ERROR
  #/var/log/daemon.log:Apr  6 19:14:44 examplehost mysqld_safe[13273]: 2020-04-06 19:14:44 3079187200 [ERROR] /usr/sbin/mysqld: unknown variable 'log_slow_queries=/var/log/mysql/mysql-slow.log'
  if [ -f /var/log/daemon.log ] && grep -qai "unknown variable 'log_slow" /var/log/daemon.log; then
    echo "dss:info: Disabling log_slow settings, they are now slow_query_log"
    [ -d /etc/mysql ] && for file in $(find /etc/mysql/ -type f | xargs --no-run-if-empty grep -l '^log_slow'); do
      sed -i 's/^log_slow/#log_slow/' "$file" || return $?
      echo "dss:info: disabled log_slow in $file"
    done
    if [ -f /etc/init.d/mysql ] && ps auxf | grep -qai '[m]ysqld_safe'; then
      /etc/init.d/mysql restart || return $?
      echo "dss:info: issued a mysql restart"
    fi
  fi

  for i in $(find /etc/cron.* -type f -name 000loaddelay); do
    #old style ifconfig
    ifconfig | grep -qai 'inet addr' && continue
    # not our script
    grep -qai 'random=.*ifconfig.*sed' $i || continue
    echo '#!/bin/bash
# This is to delay cron jobs by up to 10 minutes to relieve host server load.
# needs to parse inet 203.0.113.10  B203.0.113.15  M255.255.255.248 and
# inet addr:203.0.113.10  Bcast:203.0.113.15  Mask:255.255.255.248
declare -i random=$(expr $(ifconfig | grep -v inet6  | grep  "inet" | head -n 1 | sed -e "s/[^0-9 ]//g" | sed "s/^  *//" |  cut -f 1 -d\ ) % 900)
sleep ${random}
exit 0' > "$i" || return 1
    echo "dss:info: updating load delay script: $i"
  done
  # fix missing udev
  while true; do
    # not debian-ish
    if ! command -v dpkg >/dev/null 2>&1; then break; fi

    # dpkg -l | grep '/dev'
    # ii  makedev                          2.3.1-93                       all          creates device files in /dev
    # rc  udev                             232-25+deb9u1                  i386         /dev/ and hotplug management daemon
    if dpkg -l | grep -qai '^ii.*udev-'; then break; fi

    apt_get_install udev
    ret=$?
    echo "dss:info: udev install result $ret $(dpkg -l | grep udev)"
    [ "$ret" -eq 0 ] || return "$ret"
    break
  done
  return 0
}

# Release metadata can change before dpkg finishes; checking the codename alone is insufficient.
function debian_check_release_completion() {
  local target=$1 current audit plan apt_sources_transition_target=''
  current=$(distro_output_codename) || return 1
  case " $ALL_DEBIAN " in *" $current "*) :;; *) echo "dss:error: Expected a Debian release when checking completion." >&2; return 1;; esac
  if is_distro_name_newer "$current" "$target"; then return 0; fi
  if [ "$current" != "$target" ]; then
    echo "dss:error: Requested Debian $target has not been reached; installed release is $current." >&2
    return 1
  fi
  # This check must remain read-only: do not run upgrade_precondition_checks (DR_REMOVE_X11_PACKAGES can remove packages).
  if ! apt_sources_check_releases_and_vendors; then
    echo "dss:error: Debian $target completion check blocked by APT source policy; review the repository warnings above; package verification has not run." >&2
    return 1
  fi
  if ! audit=$(LC_ALL=C dpkg --audit 2>&1); then
    printf '%s\n' "$audit" >&2
    echo "dss:error: Cannot verify Debian $target package state. Review dpkg errors, repair with --dist-update, then retry the release command." >&2
    return 1
  fi
  if [ -n "$audit" ]; then
    printf '%s\n' "$audit" >&2
    echo "dss:error: Debian $target still has incomplete package work. Review dpkg errors, repair with --dist-update, then retry the release command." >&2
    return 1
  fi
  if ! plan=$(LC_ALL=C apt-get -s dist-upgrade 2>&1); then
    printf '%s\n' "$plan" >&2
    echo "dss:error: Cannot verify Debian $target upgrade completion. Review APT errors, repair with --dist-update, then retry the release command." >&2
    return 1
  fi
  # Jessie APT documents these simulated dpkg action records; no indexes are refreshed here.
  if printf '%s\n' "$plan" | grep -Eq '^(Inst|Conf|Remv|Purg) '; then
    printf '%s\n' "$plan" >&2
    echo "dss:error: Debian $target still has pending package changes. Review the plan, complete --dist-update, then retry the release command." >&2
    return 1
  fi
  upgrade_outcome_record release verified "$target" || return 1
  upgrade_outcome_record packages verified "$target" || return 1
  upgrade_php_runtime_verify || return 1
  upgrade_services_verify
}

# A failed hop may leave target indexes active while the installed release is still old.
function upgrade_prepare_php_source_retry() {
  local family=$1 target=$2 records provider type suite _ target_present=false old_present=false
  case "$family" in
    debian) is_distro_name_older "$target" stretch && return 0;;
    ubuntu) is_distro_name_older "$target" xenial && return 0;;
    *) return 1;;
  esac
  records=$(apt_sources_list) || return 1
  while IFS=$'\t' read -r _ _ provider type _ suite _ _; do
    if [ "$provider" != "$family" ] || [ "$type" != deb ]; then continue; fi
    if [ "${suite%%[-/]*}" = "$target" ]; then target_present=true; else old_present=true; fi
  done <<< "$records"
  $target_present || return 0
  # A target security source alone must not suppress rewriting an older base source.
  if ! $old_present; then upgrade_target_sources_selected=true; fi
  apt_get_update "with $target sources already present" || return 1
  record_config_state || return 1
  apt_get_f_install "before resuming package work on $target" || return 1
  apt_get_install dpkg || return 1
  upgrade_migrate_php_packages "$target"
}

# Complete each release hop before advancing sources again. A changed release
# label alone is insufficient: base-files can update before the remaining packages finish configuring.
function dist_upgrade_x_to_y() {
pause_check
[ ! -f /etc/debian_version ] && return 0
echo "dss:trace:dist_upgrade_x_to_y:checking:olddistro=$old_distro:oldver=$old_ver:newdistro=$new_distro"

local current baseline checkpoint='' resuming=false upgrade_target_sources_selected=false
local apt_sources_transition_target=$new_distro apt_defer_autoremove=true upgrade_php_runtime_defer_check=true
current=$(distro_output_codename) || return 1
if baseline=$(config_state_output_baseline); then
  checkpoint="$baseline.obsolete-packages/debian-$old_distro-to-$new_distro"
fi
if [ "$current" != "$old_distro" ]; then
  # base-files can report the new release before its package work and cleanup finish.
  if [ "$current" = "$new_distro" ] && [ -n "$checkpoint" ] && [ -f "$checkpoint/prepared" ] && [ ! -e "$checkpoint/completed" ]; then
    resuming=true
  else
    echo "dss:info: Installed release is $current; skipping $old_distro to $new_distro."
    return 0
  fi
fi

if $resuming; then echo "dss:stage: Finishing interrupted Debian $old_distro -> $new_distro"
else echo "dss:stage: Upgrading Debian $old_distro -> $new_distro"; fi
check_disk_space || return 1
upgrade_prepare_nss_lookup

upgrade_check_path debian "$old_distro" "$new_distro" transition || return $?
if [ "$old_distro" = bookworm ] && [ "$new_distro" = trixie ]; then
  upgrade_crossgrade_before_release debian "$old_distro" "$new_distro" || return $?
fi

if [ "$new_distro" = trixie ]; then
  local arch
  arch=$(dpkg --print-architecture) || return 1
  case "$arch" in i386|mipsel|mips64el)
    echo "dss:error: Debian 13 cannot upgrade native $arch; migrate or crossgrade before proceeding." >&2
    return 1;;
  esac
fi

if [ "$old_distro" = etch ] || [ "$old_distro" = lenny ]; then
  add_missing_debian_keys || return $?
  [ ! -d "/dev/pts" ] && mkdir /dev/pts && echo "dss:info: created /dev/pts"
fi

upgrade_precondition_checks "$new_distro" || return 1
apt_sources_prepare || return 1
if [ "$new_distro" = bookworm ] || [ "$new_distro" = trixie ]; then check_usrmerge || return 1; fi
retain_etc_networking_naming_re_enX0
fix_missing_lsb_release || return 1

upgrade_prepare_php_source_retry debian "$new_distro" || return 1
echo "dss:trace:dist_upgrade_x_to_y:pre_apt_get_upgrade:old:$old_distro:new:$new_distro"
local ret=0
if ! $upgrade_target_sources_selected; then
  apt_get_upgrade "on $old_distro before switching releases"
  ret=$?
  if [ "$ret" -ne 0 ]; then
    echo "dss:error: Package upgrade on $old_distro failed; sources were not advanced to $new_distro." >&2
    return "$ret"
  fi
  apt-get clean
fi
upgrade_record_package_origins debian "$old_distro" "$new_distro" || return 1
baseline=$(config_state_output_baseline) || return 1
checkpoint="$baseline.obsolete-packages/debian-$old_distro-to-$new_distro"
# Lenny's release notes require transferring Etch aptitude marks before switching to APT.
if [ "$old_distro:$new_distro" = etch:lenny ] && command -v aptitude >/dev/null; then
  aptitude search '?false' >/dev/null || return 1
fi

if ! $upgrade_target_sources_selected; then
  apt_sources_upgrade debian "$old_distro" "$new_distro" || return 1
  apt_get_update "after switching sources to $new_distro" || return 1
  if [ "$old_distro:$new_distro" = etch:lenny ]; then
    # Upgrade APT itself before asking Etch's resolver to perform Lenny's full upgrade.
    apt_get_install apt || return 1
    apt_get_upgrade || return 1
  fi
  if ! is_distro_name_older "$new_distro" stretch; then
    apt_get_install dpkg || return 1
    upgrade_migrate_php_packages "$new_distro" || return 1
  fi
fi

echo "dss:trace:dist_upgrade_x_to_y:pre_apt_get_dist_upgrade::olddistro=$old_distro:oldver=$old_ver:newdistro=$new_distro"
apt_get_dist_upgrade "to $new_distro"
ret=$?
if [ $ret -eq 0 ]; then
  echo "dss:trace:dist_upgrade_x_to_y:post_apt_get_dist_upgrade::olddistro=$old_distro:oldver=$old_ver:newdistro=$new_distro:ret=$ret"
	if lsb_release -a 2>/dev/null| egrep -qai "${new_distro}|${new_ver:-xxxxx}"; then
	  # dist-upgrade returned ok, and lsb_release thinks we are wheezy
	  debian_check_release_completion "$new_distro" || {
	    upgrade_outcome_record cleanup deferred "release verification did not complete"; return 1;
	  }
	  upgrade_remove_retired_packages debian "$old_distro" "$new_distro" || {
	    upgrade_outcome_record cleanup failed "obsolete cleanup"; return 1;
	  }
	  echo "dss:stage: Checking unused packages after verifying $new_distro" >&2
	  upgrade_autoremove_packages || {
	    upgrade_outcome_record cleanup failed "guarded autoremove"; return 1;
	  }
	  debian_check_release_completion "$new_distro" || return 1
	  [ -d "$checkpoint" ] && [ ! -L "$checkpoint" ] && [ ! -L "$checkpoint/completed" ] || return 1
	  (umask 077; : > "$checkpoint/completed") || return 1
	  echo "dss:info: Debian $new_distro package upgrade and post-cleanup checks passed."
	  return 0;
	else
	  echo "dss:warn: dist-upgrade from ${old_distro} appears to have failed.  lsb_release does not match '${new_distro}' or '${new_ver:-xxxxx}': $(lsb_release -a)"
	  return 1
	fi
fi
echo "dss:error:dist_upgrade_x_to_y:post_apt_get_dist_upgrade::olddistro=$old_distro:oldver=$old_ver:newdistro=$new_distro:ret=$ret"

return 1

}

function print_minimal_config() {
  local status
  [ -f "$1" ] && [ -r "$1" ] || return 2
  grep -Ev '^[[:space:]]*#|^$' -- "$1"
  status=$?
  [ "$status" -le 1 ] || return "$status"
  return 0
}
function print_pkg_to_modified_diff() {
  local mode=${1:-} records line package=unknown file checksum actual state sidecar status report_status=0 sidecars=0
  local package_status since stamp summary_state seen=''
  local -a pipeline_status=()
  case "$mode" in
    ''|summary) :;;
    review) since=$(stat -c %Y -- "$2") || return 1;;
    *) echo 'dss:error: Unknown configuration report mode.' >&2; return 1;;
  esac
  records=$(LC_ALL=C dpkg-query -W -f='Package: ${Package}\t${Status}\n${Conffiles}\n' '*') || {
    echo 'dss:error: Cannot query package conffiles; configuration verification is incomplete.' >&2; return 1;
  }
  if [ "$mode" = review ] && [ -r /var/lib/ucf/registry ] && [ -r /var/lib/ucf/hashfile ]; then
    # UCF: registry is "package /path"; hashfile is "md5 /path", including generated SSH configs.
    records="$records"$'\n'"$(awk '
      FILENAME == ARGV[1] {
        if (/^Package: /) { split($0, parts, "\t"); installed[substr(parts[1],10)]=parts[2] }
        next
      }
      FILENAME == ARGV[2] { path=$0; sub(/^[^ \t]+[ \t]+/, "", path); owner[path]=$1; next }
      { path=$0; sub(/^[^ \t]+[ \t]+/, "", path); package=owner[path]
        if (installed[package] ~ / ok installed$/) printf "Package: %s\t%s\n %s %s\n", package, installed[package], path, $1
      }
    ' <(printf '%s\n' "$records") /var/lib/ucf/registry /var/lib/ucf/hashfile)" || return 1
  fi
  while IFS= read -r line; do
    case "$line" in
      'Package: '*) package=${line#Package: }; package_status=${package#*$'\t'}; package=${package%%$'\t'*}; continue;;
      ' '*) line=${line# };;
      '') continue;;
      *) echo 'dss:warn: Unrecognized package conffile metadata; configuration verification is incomplete.' >&2; report_status=1; continue;;
    esac
    if [ "$mode" = review ]; then case "$package_status" in *' ok installed') :;; *) continue;; esac; fi
    # Retired conffiles are not shipped, including newconffile remove-on-upgrade records.
    # " /etc/ssh/sshd_config 0123456789abcdef0123456789abcdef" -> absolute path plus trailing MD5.
    # A trailing obsolete or remove-on-upgrade marker skips the record before checksum extraction.
    case "$line" in *' obsolete'|*' remove-on-upgrade') continue;; esac
    checksum=${line##* }; file=${line% *}
    case "$file" in /*) :;; *) echo 'dss:warn: Invalid conffile path in package metadata.' >&2; report_status=1; continue;; esac
    if [ "$mode" = review ]; then
      # Most installed configs have no replaced copy; avoid hashing them for this summary.
      [ -e "$file.dpkg-old" ] || [ -e "$file.ucf-old" ] || [ -e "$file.rpmsave" ] || continue
      case "$seen" in *$'\n'"$file"$'\n'*) continue;; esac
      seen="$seen"$'\n'"$file"$'\n'
    fi
    case "$checksum" in *[!0-9a-fA-F]*) checksum=;; esac
    state=unknown
    if [ "${#checksum}" -ne 32 ]; then :
    elif [ ! -e "$file" ] && [ ! -L "$file" ]; then state=missing
    elif [ -f "$file" ] && [ -r "$file" ]; then
      if actual=$(md5sum < "$file"); then
        if [ "${actual%% *}" = "$checksum" ]; then state=unchanged; else state=modified; fi
      fi
    fi
    if [ "$mode" != review ]; then
      case "$state" in
        modified) printf 'dss:info: Modified package conffile: %s (%s).\n' "$file" "$package";;
        missing) printf 'dss:info: Missing package conffile: %s (%s); this may be intentional.\n' "$file" "$package";;
        unknown) printf 'dss:warn: Cannot verify package conffile: %s (%s).\n' "$file" "$package" >&2; report_status=1;;
      esac
    fi
    for sidecar in "$file".dpkg-dist "$file".dpkg-old "$file".ucf-dist "$file".ucf-old "$file".rpmnew "$file".rpmsave; do
      [ -e "$sidecar" ] || [ -L "$sidecar" ] || continue
      if [ "$mode" = review ]; then
        case "$sidecar" in *.dpkg-old|*.ucf-old|*.rpmsave) :;; *) continue;; esac
        # Rename/copy can preserve mtime; ctime identifies copies changed during this baseline.
        stamp=$(stat -c %Z -- "$sidecar") || { report_status=1; continue; }
        [ "$stamp" -ge "$since" ] || continue
        [ "$state" != unknown ] || report_status=1
        [ -f "$sidecar" ] || continue
        if [ "$state" = missing ]; then
          printf 'dss:warn: Review configuration: %s (%s) is missing. Previous copy: %s\n' "$file" "$package" "$sidecar"; continue
        fi
        [ -f "$file" ] || continue
        cmp -s -- "$file" "$sidecar"; status=$?
        case "$status" in 0) continue;; 1) :;; *) report_status=1; continue;; esac
        if [ "$state" = unchanged ]; then summary_state='matches package defaults'; else summary_state='differs from the previous copy; defaults unconfirmed'; fi
        printf 'dss:warn: Review configuration: %s (%s) %s. Previous copy: %s\n' "$file" "$package" "$summary_state" "$sidecar"
        continue
      fi
      sidecars=$((sidecars+1))
      printf 'dss:info: Existing configuration sidecar: %s.\n' "$sidecar"
      if [ "$mode" = summary ] || [ ! -f "$file" ] || [ ! -r "$file" ]; then continue; fi
      print_minimal_config_diff "$sidecar" "$file" | awk -v package="$package" -v path="$file" '{print "dss:configdiff:modifiedconfig:" package ":" path ":" $0}'
      pipeline_status=("${PIPESTATUS[@]}")
      status=${pipeline_status[0]}
      if [ "$status" -gt 1 ] || [ "${pipeline_status[1]}" -ne 0 ]; then
        printf 'dss:error: Cannot compare configuration sidecar %s with %s.\n' "$sidecar" "$file" >&2
        report_status=1
      fi
    done
  done <<< "$records"
  if [ "$mode" != review ] && [ "$sidecars" -eq 0 ]; then
    echo 'dss:info: No existing package conffile sidecars found; local configuration changes may still exist.'
  fi
  return "$report_status"
}

function print_minimal_config_diff() {
  local a=$1 b=$2 ta tb status
  [ -f "$a" ] && [ -r "$a" ] && [ -f "$b" ] && [ -r "$b" ] || return 2
  ta=$(mktemp "${TMPDIR:-/tmp}/distrorejuve-configdiff.XXXXXX") || return 2
  if ! tb=$(mktemp "${TMPDIR:-/tmp}/distrorejuve-configdiff.XXXXXX"); then rm -f -- "$ta"; return 2; fi
  if print_minimal_config "$a" > "$ta" && print_minimal_config "$b" > "$tb"; then
    diff --ignore-all-space -u --label "$a" --label "$b" "$ta" "$tb"
    status=$?
  else status=2; fi
  if ! rm -f -- "$ta" "$tb"; then
    echo 'dss:error: Cannot remove private configuration-diff temporary files.' >&2; return 2
  fi
  return "$status"
}
function print_config_state_changes() {
  prepare_output_dir
  local availability_ret=0 report_status now fromfile=$1 file files post_recorded=false
  local -a pipeline_status=()
  apt_packages_print_review || availability_ret=$?
  if ! now=$(date +%s); then
    echo 'dss:error: Cannot timestamp the current configuration report.' >&2
    [ "$availability_ret" -ne 0 ] || availability_ret=1
    return "$availability_ret"
  fi
  if record_config_state "/root/distrorejuveinfo/postupgrade.dpkg.$now"; then post_recorded=true
  else
    echo 'dss:error: Cannot record current configuration state; comparison is incomplete.' >&2
    [ "$availability_ret" -ne 0 ] || availability_ret=1
  fi
  if [ -z "$fromfile" ]; then fromfile=$(config_state_output_baseline) || fromfile=; fi
  if [ -z "$fromfile" ] || [ ! -f "$fromfile" ]; then
    echo 'dss:warn: No recent pre-upgrade baseline; before/after comparison is unavailable.' >&2
    return "$availability_ret"
  fi
  print_incompatible_package_changes "$fromfile"
  print_crossgrade_obsolete_package_changes "$fromfile" || { report_status=$?; [ "$availability_ret" -ne 0 ] || availability_ret=$report_status; }
  echo 'dss:info: Configuration changes are review observations; changed or missing files may be intentional. Sidecars are compared only when already present.'
  if $post_recorded; then
    print_minimal_config_diff "$fromfile" "/root/distrorejuveinfo/postupgrade.dpkg.$now" | awk '{print "dss:configdiff:statechanges:" $0}'
    pipeline_status=("${PIPESTATUS[@]}")
    if [ "${pipeline_status[0]}" -gt 1 ] || [ "${pipeline_status[1]}" -ne 0 ]; then
      echo 'dss:error: Cannot compare original and current configuration state.' >&2
      [ "$availability_ret" -ne 0 ] || availability_ret=1
    fi
  fi
  manifest_compare_baseline "$fromfile" || :
  print_pkg_to_modified_diff '' || { report_status=$?; [ "$availability_ret" -ne 0 ] || availability_ret=$report_status; }
  if [ -d /etc/apache2/sites-available ] && [ -f /etc/apache2/apache2.conf ] && grep -qai 'Include.*sites-.*conf' /etc/apache2/apache2.conf; then
    if files=$(find /etc/apache2/sites-available -type f ! -name '*.conf' ! -name '*dpkg-*'); then
      while IFS= read -r file; do
        [ -n "$file" ] || continue
        printf 'dss:warn: Apache configuration file %s has no .conf extension; review whether it should be enabled.\n' "$file"
      done <<< "$files"
    else
      echo 'dss:error: Cannot inspect Apache site filenames.' >&2
      [ "$availability_ret" -ne 0 ] || availability_ret=1
    fi
  fi
  return "$availability_ret"
}

# Share the first baseline in the history window across release hops and retries.
# Replacing the baseline at each hop would hide changes made earlier in the upgrade. This report is not a full backup.
# Keep purge reminders attached to the same oldest recent baseline used for configuration diffs.
function config_state_output_baseline() {
  local file baseline='' days=${DR_CONFIGURATION_HISTORY_DAYS:-7}
  for file in "/root/distrorejuveinfo/"*preupgrade* "/root/deghostinfo/"*preupgrade*; do
    [ -f "$file" ] || continue
    [ -n "$(find "$file" -maxdepth 0 -mtime "-$days" -print)" ] || continue
    if [ -z "$baseline" ] || [ "$file" -ot "$baseline" ]; then baseline=$file; fi
  done
  [ -n "$baseline" ] || return 1
  printf '%s\n' "$baseline"
}

function print_incompatible_package_changes() {
  local baseline=$1 manifest package backup confirmed reminder advice status
  for manifest in "$baseline.purged-incompatible/"*/packages.purged "$baseline.purged-incompatible/"*/packages.requested; do
    [ -f "$manifest" ] || continue
    backup=${manifest%/*}
    confirmed=false
    case "$manifest" in
      */packages.purged) confirmed=true;;
      *) [ -f "$backup/packages.purged" ] && continue;;
    esac
    while IFS= read -r package; do
      [ -n "$package" ] || continue
      if $confirmed; then
        reminder="dss:warn: Package purged before upgrading: $package. Backup: $backup."
        advice='Reinstall manually if needed:'
      else
        reminder="dss:warn: Purge completion unconfirmed for selected package: $package. Backup/attempt directory: $backup."
        advice='Review package state before manual reinstall:'
      fi
      if upgrade_php_has_candidate "$package"; then
        echo "$reminder $advice apt-get install $package"
      else
        status=$?
        if [ "$status" -eq 1 ]; then
          echo "$reminder Original package is unavailable in current APT archives; review its current package name before reinstalling."
        else
          echo "$reminder Current archive availability is unknown (APT query failed); review current package names before reinstalling."
        fi
      fi
    done < "$manifest"
  done
}

function record_config_state() {
  prepare_output_dir
  local file=$1
  if [ -z "$file" ]; then
    if ! file=$(config_state_output_baseline); then
      file="/root/distrorejuveinfo/preupgrade.dpkg.$$"
      [ -e "$file" ] && file="$file.$(date +%s)"
    fi
  fi
  # don't overwrite the preupgrade file
  echo "$file" | grep -qai preupgrade && [ -f "$file" ] && return 0
  echo "dss:trace:record_config_state:$file"
  local files=$(find "/etc" -type f | egrep '.ucf-old|.ucf-diff|.dpkg-new|.dpkg-old|dpkg-dist|\.rpmnew|.rpmsave' | sort)
  > "$file" || return 1
  # conf files
  echo "Date: $(date)" >> "$file"
  [ ! -z "$files" ] && ls -lrt $files | awk '{print "configfiles:" $0}' >> "$file"
  echo "Listening ports:" >> "$file"
  echo "" >> "$file"
  # listening ports
  # Listen ports: 0.0.0.0:995 dovecot
  netstat -ntpl | grep LISTEN | awk '{print "Listen ports: " $4 " " $7}' | sed 's/ [0-9]*\// /' | sed 's/0.0.0.0:/:::/' | sort -k 3 | uniq >> "$file"
  echo "Apache vhosts:" >> "$file"
  echo "" >> "$file"
  print_distro_info >> "$file"
  # vhosts
  [ -x /usr/sbin/apache2ctl ] && /usr/sbin/apache2ctl -S 2>&1 | awk '{print "ApacheStatus: " $0}' >> "$file"
  echo "" >> "$file"
  echo "Running processes:" >> "$file"
  echo "" >> "$file"
  ps ax | awk '{print "process: " $5 " " $6 " " $7 " " $8 " " $9}' | egrep -v '^process: \[|COMMAND|init' | sort | uniq >> "$file"

  [  -x /usr/bin/dpkg ] && echo "Installed packages:" >> "$file" && dpkg -l | grep '^ii' | awk '{print $2}' | sed 's/:.*//' | sort | grep -v '^lib' | awk '{ print "installed: " $0 }' >> "$file"
  case "${file##*/}" in preupgrade.dpkg.*)
    # Capture active web roles before package work, independently of the optional manifest.
    (umask 077; mkdir -m 700 -- "$file.php-runtime" && upgrade_php_runtime_snapshot "$file.php-runtime") || return 1
    (umask 077; mkdir -m 700 -- "$file.services" && upgrade_services_snapshot "$file.services") || return 1
    # Save original site/runtime relationships once, without DNS or mail-store traversal.
    if ! manifest_capture "$file.applications"; then
      echo "dss:warn: Original application manifest was not completed; review $file.applications before relying on it." >&2
    fi;;
  esac
  return 0
}

function apt_get_update() {
pause_check
apt_configure_archive_authentication || return 1
local tmplog signature completed inputs current_inputs warning_status phase=indexes
local -a update_status
signature=$(apt_state_output_signature repositories 2>/dev/null) || signature=
if [ -n "$signature" ] && [ "$signature" = "${apt_state_updated:-}" ]; then
  ret=0
  echo "dss:trace:apt_get_update: indexes already refreshed for these repositories."
  return 0
fi
inputs=$(apt_state_output_signature inputs 2>/dev/null) || inputs=
printf 'dss:stage: Refreshing APT package indexes%s\n' "${1:+ $1}" >&2
apt_state_updated=
apt_state_upgraded=
apt_state_dist_upgraded=
tmplog=$(mktemp "tmplog.aptgetupdate.log.XXXXXX") || return 1
apt-get $APT_GET_INSTALL_OPTIONS update 2>&1 | tee "$tmplog"
update_status=("${PIPESTATUS[@]}")
ret=${update_status[0]}

# E: Release file expired, ignoring http://archive.debian.org/debian/dists/squeeze-lts/Release (invalid since 14d 8h 58min 38s)
if [ "$ret" -ne 0 ]; then
  local -a release_options=()
  # E: Repository 'URI suite InRelease' changed its 'Suite' value from 'stable' to 'oldstable'
  # Quoted fields 6/8 must age together in EVERY repository, preserving pocket suffixes.
  # https://manpages.debian.org/trixie/apt/apt-get.8.en.html#allow-releaseinfo-change
  if awk -F"'" '
    /^E: Repository / && $4 == "Suite" {
      found=1
      if ($6 !~ /^(stable|oldstable)(-(updates|security))?$/ || $8 != "old" $6) bad=1
    }
    END { exit (!found || bad) }
  ' "$tmplog"; then
    echo "dss:info: Retrying APT update with Suite aging accepted; other release metadata checks remain enabled."
    release_options=(-o Acquire::AllowReleaseInfoChange::Suite=true)
  fi
  echo "dss:stage: Retrying index refresh over IPv4 after APT update failed (status $ret)" >&2
  apt-get $APT_GET_INSTALL_OPTIONS -o Acquire::ForceIPv4=true "${release_options[@]}" update 2>&1 | tee -a "$tmplog"
  update_status=("${PIPESTATUS[@]}")
  ret=${update_status[0]}
fi
if [ "$ret" -eq 0 ] && [ "${update_status[1]}" -ne 0 ]; then
  ret=${update_status[1]}; phase=index_log_capture
fi

# https://www.debian.org/releases/bookworm/amd64/release-notes/ch-information.html#non-free-split
if egrep -qai "Repository 'Debian bookworm' changed its 'non-free component' value from 'non-free' to 'non-free non-free-firmware'" "$tmplog" && [ -d /etc/apt/apt.conf.d/ ]; then
  echo "dss:info: disabling the warning around non-free/non-free-firmware per /etc/apt/apt.conf.d/no-bookworm-firmware.conf and https://www.debian.org/releases/bookworm/amd64/release-notes/ch-information.html#non-free-split" && echo 'APT::Get::Update::SourceListWarnings::NonFreeFirmware "false";' > /etc/apt/apt.conf.d/no-bookworm-firmware.conf
fi

# A stale APT::Default-Release can break package selection even after a good update.
if [ "$ret" -eq 0 ]; then
  phase=policy
  apt-cache policy >/dev/null
  ret=$?
  [ "$ret" -ne 0 ] && echo "dss:error: APT policy is invalid. Review APT::Default-Release (apt-config dump) and release pins before retrying; policy files were not changed." >&2
fi
# Exit-zero partial downloads/warnings must not suppress the next update attempt.
grep -Eq '^[WE]:' "$tmplog"
warning_status=$?
if [ "$ret" -eq 0 ] && [ "$warning_status" -eq 1 ]; then
  completed=$(apt_state_output_signature repositories 2>/dev/null) || completed=
  current_inputs=$(apt_state_output_signature inputs 2>/dev/null) || current_inputs=
  # Post-update hooks must not change repository inputs underneath a successful refresh.
  if [ -n "$inputs" ] && [ "$inputs" = "$current_inputs" ] && [ -n "$completed" ]; then
    apt_state_updated=$completed
  fi
fi
rm -f "$tmplog"
[ "$ret" -ne 0 ] && echo "dss:error:apt_get_update failed (phase $phase, status $ret)." >&2
return $ret
}

# Release hops run their checked obsolete/dependency cleanup after the target is configured.
function apt_get_autoremove() {
  case "${apt_defer_autoremove:-false}" in
    true) return 0;;
    false) :;;
    *) echo 'dss:error: Internal autoremove policy must be true or false.' >&2; return 1;;
  esac
  local capabilities
  capabilities=$(LC_ALL=C apt_get_apply --help) || return 1
  case "$capabilities" in *autoremove*) :;; *) return 0;; esac
  apt_get_apply $APT_GET_INSTALL_OPTIONS autoremove
}

function apt_get_upgrade() {
  pause_check
  [ ! -f /etc/debian_version ] && return 0
  [ -e /etc/redhat-release ] && return 0
  upgrade_precondition_checks || return $?
  apt_sources_archive || return 1
  apt_get_update "${2:-before upgrading packages}" || return 1
  upgrade_php_runtime_prepare || return 1
  local signature completed current operation_ret cacheable=true
  signature=$(apt_state_output_signature packages 2>/dev/null) || signature=
  if apt_state_repositories_are_current && [ -n "$signature" ] && [ "$signature" = "${apt_state_upgraded:-}" ]; then
    ret=0
    echo "dss:trace:apt_get_upgrade: packages already upgraded for this state."
    if [ "${upgrade_php_runtime_defer_check:-false}" != true ]; then
      upgrade_php_runtime_verify || { ret=$?; return "$ret"; }
    fi
    return 0
  fi
  printf 'dss:stage: Upgrading current packages%s\n' "${1:+ $1}" >&2
  apt_state_upgraded=
  apt_state_dist_upgraded=
  echo "dss:trace:apt_get_upgrade"
  record_config_state
  echo "dss:info: Configuring pending packages before the package upgrade (dpkg --configure -a)." >&2
  if ! dpkg --configure -a --force-confnew --force-confmiss; then
    cacheable=false; apt_state_healthy=
  fi
  if ! apt_get_autoremove; then cacheable=false; apt_state_healthy=; fi
  apt_get_f_install "before the package upgrade" || cacheable=false
  echo "dss:info: running an apt-get upgrade"
  apt_state_healthy=
  apt_get_apply $APT_GET_INSTALL_OPTIONS upgrade
  operation_ret=$?
  if [ "$operation_ret" -eq 0 ]; then
    completed=$(apt_state_output_signature packages 2>/dev/null) || completed=
    $cacheable && apt_state_healthy=$completed
  else
    cacheable=false
  fi
  if ! apt_get_autoremove; then cacheable=false; apt_state_healthy=; fi
  apt_get_f_install "after package changes" || cacheable=false
  if [ "$operation_ret" -ne 0 ]; then
    echo "dss:stage: Trying the full upgrade after the package upgrade failed (APT status $operation_ret)" >&2
    apt_get_apply $APT_GET_INSTALL_OPTIONS dist-upgrade
    operation_ret=$?
    if [ "$operation_ret" -eq 0 ]; then
      echo "dss:info: apt-get dist-upgrade succeeded when an upgrade failed."
      ret=0
      if [ "${upgrade_php_runtime_defer_check:-false}" != true ]; then
        upgrade_php_runtime_verify || { ret=$?; return "$ret"; }
      fi
      return 0
    else
      echo "dss:warn: apt-get upgrade/dist-upgrade failed."
      ret=1
      return 1
    fi
  fi
  apt-get clean || cacheable=false
  current=$(apt_state_output_signature packages 2>/dev/null) || current=
  if $cacheable && apt_state_repositories_are_current && [ -n "$completed" ] && [ "$completed" = "$current" ] &&
      [ "$completed" = "${apt_state_healthy:-}" ]; then
    apt_state_upgraded=$completed
  fi
  ret=$operation_ret
  if [ "${upgrade_php_runtime_defer_check:-false}" != true ]; then
    upgrade_php_runtime_verify || { ret=$?; return "$ret"; }
  fi
  return "$ret"
}

function apt_get_dist_upgrade() {
  pause_check
  [ ! -f /etc/debian_version ] && return 0
  upgrade_precondition_checks || return $?
  upgrade_php_runtime_prepare || return 1
  local signature completed current first_ret upgrade_ret repair_ret retry_log cacheable=true
  signature=$(apt_state_output_signature packages 2>/dev/null) || signature=
  if apt_state_repositories_are_current && [ -n "$signature" ] && [ "$signature" = "${apt_state_dist_upgraded:-}" ]; then
    ret=0
    echo "dss:trace:apt_get_dist_upgrade: packages already upgraded for this state."
    if [ "${upgrade_php_runtime_defer_check:-false}" != true ]; then
      upgrade_php_runtime_verify || { ret=$?; return "$ret"; }
    fi
    return 0
  fi
  printf 'dss:stage: Preparing full package upgrade%s\n' "${1:+ $1}" >&2
  apt_state_dist_upgraded=
  echo "dss:trace:apt_get_dist_upgrade:pre_apt_get_upgrade:"
  upgrade_php_runtime_defer_check=true apt_get_upgrade "before the full upgrade" || return 1
  echo "dss:trace:apt_get_dist_upgrade"
  apt_get_f_install "before the full upgrade" || cacheable=false
  apt_get_install dpkg || cacheable=false
  if ! apt_get_autoremove; then cacheable=false; apt_state_healthy=; fi
  printf 'dss:stage: Performing full package upgrade%s\n' "${1:+ $1}" >&2
  apt_get_apply $APT_GET_INSTALL_OPTIONS dist-upgrade
  first_ret=$?
  # Keep recovery retries unconditional after a failure, including immediate-configuration workarounds.
  if [ "$first_ret" -ne 0 ]; then
    cacheable=false; apt_state_healthy=
    echo "dss:stage: Retrying the full upgrade after APT failed (status $first_ret)" >&2
    retry_log=$(mktemp) || return 1
    apt_get_apply $APT_GET_INSTALL_OPTIONS dist-upgrade 2>&1 | tee "$retry_log"
    local -a retry_status=("${PIPESTATUS[@]}")
    if [ "${retry_status[1]}" -ne 0 ]; then
      rm -f -- "$retry_log"
      echo 'dss:error: Cannot capture full-upgrade retry output.' >&2
      [ "${retry_status[0]}" -eq 0 ] || return "${retry_status[0]}"
      return "${retry_status[1]}"
    fi
    if [ "${retry_status[0]}" -ne 0 ] && grep -qai "Could not perform immediate configuration on " "$retry_log"; then
      apt_get_apply -f $APT_GET_INSTALL_OPTIONS install libc6-dev
      echo "dss:stage: Retrying the full upgrade after an immediate-configuration failure, with immediate configuration disabled" >&2
      apt_get_apply dist-upgrade -f -o APT::Immediate-Configure=0 $APT_GET_INSTALL_OPTIONS
    fi
    rm -f -- "$retry_log"
  fi
  [ -e /var/log/syslog ] && [ -e /etc/my/my.cnf ] && if grep "unknown variable 'lc-messages-dir" /var/log/syslog; then
    echo "dss:info: Commenting out the my.cnf lc-messages-dir directive in case it is causing problems."
    sed -i "s@^lc-messages-dir\(.*\)@#lc-messages-dir\1@" /etc/my/my.cnf
  fi
  echo "dss:info: Rechecking package configuration after the full upgrade (dpkg --configure -a)." >&2
  if ! dpkg --configure -a --force-confnew --force-confmiss; then
    cacheable=false; apt_state_healthy=
  fi
  if ! apt_get_autoremove; then cacheable=false; apt_state_healthy=; fi
  apt-get -y autoclean || cacheable=false
  apt_state_healthy=
  echo "dss:stage: Rechecking the full upgrade after the package configuration pass" >&2
  apt_get_apply $APT_GET_INSTALL_OPTIONS dist-upgrade
  ret=$?
  if [ "$ret" -eq 0 ]; then
    completed=$(apt_state_output_signature packages 2>/dev/null) || completed=
    $cacheable && apt_state_healthy=$completed
  else
    cacheable=false
    echo "dss:warn: Got an error after an apt-get dist-upgrade. trying an apt-get -f install"
    apt_get_f_install "after the full upgrade failed (APT status $ret)"
    echo "dss:stage: Retrying the full upgrade after the dependency repair attempt" >&2
    apt_get_apply $APT_GET_INSTALL_OPTIONS dist-upgrade
    ret=$?
    if [ "$ret" -ne 0 ]; then
      check_systemd_install_matches_init
      echo "dss:error: Got an error after an apt-get dist-upgrade"
    fi
  fi
  # Config repairs may change packages or fail after the final successful dist-upgrade.
  upgrade_ret=$ret
  if tweak_broken_configs; then :
  else
    repair_ret=$?
    cacheable=false; apt_state_healthy=
    [ "$upgrade_ret" -ne 0 ] || upgrade_ret=$repair_ret
  fi
  current=$(apt_state_output_signature packages 2>/dev/null) || current=
  if $cacheable && apt_state_repositories_are_current && [ -n "$completed" ] && [ "$completed" = "$current" ] &&
      [ "$completed" = "${apt_state_healthy:-}" ]; then
    apt_state_dist_upgraded=$completed
    apt_state_upgraded=$completed
  fi
  ret=$upgrade_ret
  if [ "$ret" -eq 0 ] && [ "${upgrade_php_runtime_defer_check:-false}" != true ]; then
    upgrade_php_runtime_verify || { ret=$?; return "$ret"; }
  fi
  echo "dss:trace:apt_get_dist_upgrade completed $(print_distro_info). ret=$ret"
  return "$ret"
}

# LTS releases move to the next LTS; interim releases move to the next release.
function ubuntu_output_next_release() {
  local current=$1 release found=false lts=false
  case " $LTS_UBUNTU " in *" $current "*) lts=true;; esac
  for release in $ALL_UBUNTU; do
    if $found; then
      if $lts; then case " $LTS_UBUNTU " in *" $release "*) :;; *) continue;; esac; fi
      printf '%s\n' "$release"
      return 0
    fi
    [ "$release" = "$current" ] && found=true
  done
  $found && return 0
  echo "dss:error: Unknown Ubuntu release: $current" >&2
  return 1
}

# Use the last configured LTS; a newer interim release cannot be downgraded to it.
function ubuntu_output_latest_lts() {
  local current=$1 target=''
  for target in $LTS_UBUNTU; do :; done
  [ -n "$target" ] || { echo 'dss:error: No Ubuntu LTS target is configured.' >&2; return 1; }
  if [ "$current" != "$target" ] && ! is_distro_name_older "$current" "$target"; then
    echo "dss:error: No forward upgrade path from Ubuntu $current to the latest LTS $target." >&2
    return 1
  fi
  printf '%s\n' "$target"
}

# First argument limits the number of release transitions; LTS to LTS counts as one.
function dist_upgrade_ubuntu_to_latest() {
  pause_check
  [ -f /etc/debian_version ] || return 0
  local remaining=${1:-1000} current next arch ret apt_sources_transition_target='' apt_defer_autoremove=true upgrade_php_runtime_defer_check=true
  current=$(distro_output_codename) || return 1
  case " $ALL_UBUNTU " in *" $current "*) :;; *) return 0;; esac
  local planned=$current steps=$remaining
  if [ -z "${1:-}" ]; then
    planned=$(ubuntu_output_latest_lts "$current") || return 1
  else
    while [ "$steps" -gt 0 ]; do
      next=$(ubuntu_output_next_release "$planned") || return 1
      [ -n "$next" ] || break
      planned=$next
      steps=$((steps-1))
    done
  fi
  upgrade_check_path ubuntu "$current" "$planned" || return $?
  while [ "$remaining" -gt 0 ]; do
    current=$(distro_output_codename) || return 1
    if [ "$current" = "$planned" ]; then upgrade_php_runtime_verify; return $?; fi
    next=$(ubuntu_output_next_release "$current") || return 1
    if [ -z "$next" ]; then
      echo "dss:error: Ubuntu upgrade stopped at $current before reaching $planned." >&2
      return 1
    fi
    check_disk_space || return 1
    upgrade_check_path ubuntu "$current" "$next" transition || return $?
    if [ "$current" = bionic ]; then
      upgrade_crossgrade_before_release ubuntu "$current" "$next" || return $?
    fi
    arch=$(dpkg --print-architecture) || return 1
    if [ "$arch" = i386 ] && ! is_distro_name_older "$current" bionic; then
      echo "dss:error: Native i386 Ubuntu cannot upgrade past 18.04." >&2
      return 1
    fi
    echo "dss:stage: Upgrading Ubuntu $current -> $next"
    upgrade_prepare_nss_lookup
    apt_sources_transition_target=$next
    upgrade_precondition_checks "$next" || return 1
    apt_sources_prepare || return 1
    if ! is_distro_name_older "$next" hirsute; then check_usrmerge || return 1; fi
    upgrade_prepare_php_source_retry ubuntu "$next" || return 1
    apt_get_upgrade "on $current before switching releases" || return 1
    retain_etc_networking_naming_re_enX0
    upgrade_record_package_origins ubuntu "$current" "$next" || return 1
    apt_sources_upgrade ubuntu "$current" "$next" || return 1
    apt_get_update "after switching sources to $next" || return 1
    if ! is_distro_name_older "$next" xenial; then
      apt_get_install dpkg || return 1
      upgrade_migrate_php_packages "$next" || return 1
    fi
    apt_get_dist_upgrade "to $next"
    ret=$?
    if [ "$ret" -ne 0 ] || [ "$(distro_output_codename)" != "$next" ]; then
      echo "dss:error: Ubuntu upgrade from $current to $next failed." >&2
      return 1
    fi
    upgrade_check_crossgrade_checkpoint ubuntu "$next" || {
      upgrade_outcome_record cleanup deferred "release verification did not complete"; return 1;
    }
    upgrade_remove_retired_packages ubuntu "$current" "$next" || {
      upgrade_outcome_record cleanup failed "obsolete cleanup"; return 1;
    }
    echo "dss:stage: Checking unused packages after verifying $next" >&2
    upgrade_autoremove_packages || {
      upgrade_outcome_record cleanup failed "guarded autoremove"; return 1;
    }
    upgrade_check_crossgrade_checkpoint ubuntu "$next" || return 1
    echo "dss:info: Ubuntu upgrade from $current to $next completed."
    remaining=$((remaining-1))
  done
  return 0
}

function print_distro_info() {
if [ -f /etc/redhat-release ]; then
  local foo="dss:distroinfo: REDHAT $(cat /etc/redhat-release)"
  echo $foo
elif [ -x /usr/bin/lsb_release ] || [ -x /bin/lsb_release ] ; then
  local foo="dss:distroinfo: $(lsb_release -a 2>/dev/null | grep -i description)"
  echo $foo
elif [ -f /etc/debian_version ]; then
  local foo="dss:distroinfo: DEBIAN $(cat /etc/debian_version)"
  echo $foo
else echo "dss:distroinfo: NA"; fi
return 0
}


function fix_missing_lsb_release() {
command -v lsb_release >/dev/null 2>&1 && return 0
! [ -f /etc/debian_version ] && return 0
echo "dss:info: Missing lsb release command.  trying to install it."
apt_get_update || return $?
apt_get_install lsb-release
ret=$?
return $ret
}


# Read identity as data, never source release files or infer a derivative from ID_LIKE.
# One tab-separated record: distribution ID, installed version, linux|stream.
# os-release input (separate lines):
# ID=centos
# VERSION_ID="8"
# VARIANT_ID=stream
# -> centos<TAB>8<TAB>stream.
# Legacy line "CentOS Linux release 7.9.2009 (Core)" -> centos<TAB>7.9.2009<TAB>linux.
function rpm_distro_output_identity() {
  local root=${1:-} records file LC_ALL=C
  if [ -e "$root/etc/os-release" ]; then
    records=$(head -c 16385 -- "$root/etc/os-release") || return 1
    [ "${#records}" -le 16384 ] || return 1
    awk '
      /^[ \t]*(ID|VERSION_ID|VARIANT_ID|NAME)=/ {
        line=$0; sub(/^[ \t]*/, "", line); key=line; sub(/=.*/, "", key)
        value=substr(line,length(key)+2); sub(/[ \t\r]+$/, "", value)
        if (value ~ /^".*"$/ || value ~ /^\047.*\047$/) value=substr(value,2,length(value)-2)
        if (key in seen) bad=1; seen[key]=1; fields[key]=value
      }
      END {
        id=fields["ID"]; version=fields["VERSION_ID"]
        if (bad || id !~ /^(centos|rhel|almalinux|rocky|ol|fedora)$/ ||
            version !~ /^[0-9]+([.][0-9]+)*$/ || length(version)>32) exit 1
        variant="linux"
        if (id=="centos" && (fields["VARIANT_ID"]=="stream" || fields["NAME"] ~ /^CentOS Stream([ \t]|$)/)) variant="stream"
        printf "%s\t%s\t%s\n",id,version,variant
      }
    ' <<< "$records"
    return $?
  fi
  for file in "$root/etc/centos-release" "$root/etc/redhat-release"; do
    [ -e "$file" ] || continue
    records=$(head -c 4097 -- "$file") || return 1
    [ "${#records}" -le 4096 ] || return 1
    awk '
      NR==1 {
        if ($0 ~ /^CentOS( Linux| Stream)? release /) id="centos"
        else if ($0 ~ /^Red Hat Enterprise Linux.* release /) id="rhel"
        else if ($0 ~ /^AlmaLinux release /) id="almalinux"
        else if ($0 ~ /^Rocky Linux release /) id="rocky"
        else if ($0 ~ /^Oracle Linux.* release /) id="ol"
        else if ($0 ~ /^Fedora release /) id="fedora"
        if (!id || !match($0,/ release [0-9]+([.][0-9]+)*([ \t(]|$)/)) exit 1
        version=substr($0,RSTART+9,RLENGTH-9); sub(/[ \t(].*/,"",version)
        variant=($0 ~ /^CentOS Stream / ? "stream" : "linux")
      }
      END { if (NR!=1 || !version) exit 1; printf "%s\t%s\t%s\n",id,version,variant }
    ' <<< "$records"
    return $?
  done
  return 1
}

# Only verified archive trees; these restore historical packages, not security support.
function rpm_sources_output_vault_location() {
  local version=$1 variant=$2 architecture=$3 release prefix=''
  local version_pattern='^[0-9]+([.][0-9]+)*$'
  [[ "$version" =~ $version_pattern ]] || return 1
  case "$variant:${version%%.*}:$architecture" in
    linux:4:i386|linux:4:x86_64) release=4.9;;
    linux:5:i386|linux:5:x86_64) release=5.11;;
    linux:6:i386|linux:6:x86_64) release=6.10;;
    linux:7:x86_64) release=7.9.2009;;
    linux:7:i386|linux:7:aarch64|linux:7:ppc64le) release=7.9.2009; prefix=altarch/;;
    linux:8:x86_64|linux:8:aarch64|linux:8:ppc64le) release=8.5.2111;;
    stream:8:x86_64|stream:8:aarch64|stream:8:ppc64le) release=8-stream;;
    *) return 1;;
  esac
  printf 'https://vault.centos.org/%s%s\n' "$prefix" "$release"
}

function rpm_sources_output_vault_rewrite() {
    local file="$1" base_url="$2" major="$3"
    case "$major" in 4|5|6|7|8) ;; *) return 1 ;; esac
    case "$base_url" in https://vault.centos.org/*) ;; *) return 1 ;; esac
    awk -v base="${base_url%/}" -v major="$major" '
        function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
        function fail() { failed=1; exit 1 }
        function version_ok(s) {
            return s == "$releasever" || s == "$releasever_major" ||
                (major == 8 && (s == "$stream" || s == "8-stream")) ||
                s == major || s ~ ("^" major "\\.[0-9]+([.][0-9]+)*$")
        }
        function component_name(s, value) {
            value=tolower(s)
            if (value == "base" || value == "os") value="os"
            if (major == 8) {
                if (value == "baseos") return "BaseOS"
                if (value == "appstream") return "AppStream"
                if (value == "powertools") return "PowerTools"
                if (value == "extras" || value == "centosplus") return value
            } else {
                if (value == "os" || value == "updates" || value == "extras" ||
                    value == "centosplus" || value == "contrib" || value == "fasttrack") return value
                if (value == "update") return "updates"
                if (major <= 5 && value == "addons") return value
            }
            return ""
        }
        function url_component(url, rest, count, part, i, pair, release, component) {
            # /centos/7/os/$basearch/ and ?release=7&repo=os -> component=os for major=7.
            # /centos/8/AppStream/$basearch/os/ -> component=AppStream for major=8.
            rest=url; sub(/^https?:\/\/[^/]+/, "", rest)
            if (rest ~ /\?/) {
                sub(/^[^?]*\?/, "", rest)
                count=split(rest,part,"&")
                for (i=1;i<=count;i++) {
                    split(part[i],pair,"=")
                    if (pair[1] == "release") { if (release != "") fail(); release=pair[2] }
                    if (pair[1] == "repo") { if (component != "") fail(); component=pair[2] }
                }
                if (!version_ok(release)) fail()
                return component_name(component)
            }
            count=split(rest,part,"/")
            for (i=1;i<=count;i++) {
                if (part[i] == "" || part[i] == "centos" || part[i] == "altarch" || part[i] == "$contentdir") continue
                if (!version_ok(part[i])) fail()
                return component_name(part[i+1])
            }
            return ""
        }
        function flush( i, line, active, key, value, host, component, selected, official, custom, seen, target, disabled) {
            if (!n) return
            for (i=1;i<=n;i++) {
                line=tolower(trim(lines[i]))
                if (line ~ /^enabled[ \t]*=/) {
                    sub(/^[^=]*=[ \t]*/, "", line)
                    sub(/[ \t]*[#;].*$/, "", line)
                    disabled=(line == "0" || line == "false" || line == "no")
                }
            }
            if (disabled) {
                for (i=1;i<=n;i++) print lines[i]
                delete lines; n=0
                return
            }
            for (i=1;i<=n;i++) {
                line=trim(lines[i]); active=(line !~ /^[#;]/)
                if (!active) continue
                if (line !~ /^(baseurl|mirrorlist|metalink)[ \t]*=/) continue
                key=line; sub(/[ \t]*=.*/, "", key)
                value=line; sub(/^[^=]*=[ \t]*/, "", value); value=trim(value)
                host=value; sub(/^https?:\/\//, "", host); sub(/\/.*/, "", host)
                if (value !~ /^https?:\/\// || host !~ /^(mirrorlist[.]centos[.]org|mirror[.]centos[.]org|vault[.]centos[.]org|mirror[.]stream[.]centos[.]org)$/) {
                    if (active) custom++
                    continue
                }
                if (value ~ /[ \t\\]/) fail()
                component=url_component(value)
                if (component == "") fail()
                if (selected != "" && selected != component) fail()
                selected=component
                if (active) {
                    official++
                    if (seen[key]++) fail()
                }
                rewrite[i]=key
            }
            if (official && (custom || section == "")) fail()
            if (official) {
                for (i=1;i<=n;i++) {
                    line=trim(lines[i])
                    if (line != "" && line !~ /^[#;\[]/ && line !~ /^[A-Za-z0-9_]+[ \t]*=/) fail()
                }
                target=base "/" selected "/$basearch/" (major == 8 ? "os/" : "")
                for (i=1;i<=n;i++) {
                    if (rewrite[i] != "") {
                        if (rewrite[i] == "baseurl" && trim(lines[i]) == "baseurl=" target) {
                            if (!inserted++) print lines[i]
                        } else {
                            if (!inserted++) print "baseurl=" target
                            print "# " lines[i]
                        }
                    } else print lines[i]
                }
            } else for (i=1;i<=n;i++) print lines[i]
            delete lines; delete rewrite; n=0; inserted=0
        }
        /^[ \t]*\[/ {
            flush()
            section=trim($0); sub(/\].*$/, "]", section)
            if (sections[section]++) fail()
        }
        { lines[++n]=$0 }
        END { if (!failed) flush(); if (failed) exit 1 }
    ' "$file" || {
        printf 'Cannot safely rewrite CentOS repository file: %s\n' "$file" >&2
        return 1
    }
}

function rpm_sources_install_file() {
  local source=$1 destination=$2 temporary
  [ -f "$destination" ] && [ ! -L "$destination" ] || return 1
  temporary=$(mktemp "$destination.distrorejuve.XXXXXXXX") || return 1
  if cp -p -- "$source" "$temporary" && mv -f -- "$temporary" "$destination"; then return 0; fi
  rm -f -- "$temporary"
  return 1
}

# Validate the staged repositories before replacing any live file; keep originals for recovery.
function rpm_sources_prepare() {
  local manager=$1 directory=$2 base=$3 major=$4 file metadata settings name rollback_file changed=false count=0 restored=true
  local -a repository_files=()
  local -a changed_repository_files=()
  for file in /etc/yum.conf /etc/dnf/dnf.conf; do
    [ -f "$file" ] || continue
    settings=$(awk '
      # [main] followed by reposdir=/etc/yum.repos.d -> no finding; include=/etc/yum.conf -> include.
      /^[ \t]*\[/ { main=($0 ~ /^[ \t]*\[main\][ \t]*$/) }
      main && /^[ \t]*reposdir[ \t]*=/ { value=$0; sub(/^[^=]*=[ \t]*/,"",value); sub(/[ \t]+[#;].*$/,"",value); sub(/[ \t]+$/,"",value); if (value != "/etc/yum.repos.d") print "custom" }
      /^[ \t]*include[ \t]*=/ { print "include" }
    ' "$file") || return 1
    if [ -n "$settings" ]; then echo "dss:error: Custom reposdir/include in $file requires manual repository recovery; nothing was rewritten." >&2; return 1; fi
  done
  mkdir -m 700 -- "$directory/repository-stage" "$directory/repository-original" || return 1
  for file in /etc/yum.repos.d/*.repo; do
    [ -e "$file" ] || continue
    count=$((count+1))
    if [ "$count" -gt 200 ] || [ -L "$file" ] || [ ! -f "$file" ]; then echo 'dss:error: Unsupported repository file layout; review repository files manually.' >&2; return 1; fi
    name=${file##*/}
    case "$name" in *$'\n'*|*$'\r'*|*$'\t'*) return 1;; esac
    metadata=$(stat -c %s -- "$file") || return 1
    case "$metadata" in ''|*[!0-9]*) return 1;; esac
    if [ "$metadata" -gt 1048576 ]; then echo "dss:error: Repository file is too large to rewrite: $file" >&2; return 1; fi
    repository_files+=("$file")
    cp -p -- "$file" "$directory/repository-original/$name" && cp -p -- "$file" "$directory/repository-stage/$name" || return 1
    rpm_sources_output_vault_rewrite "$file" "$base" "$major" > "$directory/repository-stage/$name" || return 1
    if ! cmp -s -- "$file" "$directory/repository-stage/$name"; then changed_repository_files+=("$file"); changed=true; fi
  done
  if [ "$count" -eq 0 ]; then echo 'dss:error: No repository files found. Restore the native CentOS repository definitions and signing keys first.' >&2; return 1; fi
  $changed || return 0
  echo 'dss:stage: Checking staged CentOS archive repositories before changing live files.' >&2
  rpm_packages_run "$manager" --setopt="reposdir=$directory/repository-stage" makecache || return 1
  # Check every original before the first replacement, so concurrent changes are not overwritten.
  for file in "${repository_files[@]}"; do
    if [ -L "$file" ] || ! cmp -s -- "$file" "$directory/repository-original/${file##*/}"; then echo "dss:error: Repository changed during preparation: $file" >&2; return 1; fi
  done
  for file in "${changed_repository_files[@]}"; do
    if ! rpm_sources_install_file "$directory/repository-stage/${file##*/}" "$file"; then
      for rollback_file in "${changed_repository_files[@]}"; do rpm_sources_install_file "$directory/repository-original/${rollback_file##*/}" "$rollback_file" || restored=false; done
      echo "dss:error: Repository replacement failed; original files restored: $restored. Backups: $directory/repository-original" >&2
      return 1
    fi
  done
  printf 'dss:stage: CentOS sources now use the frozen archive; originals: %s/repository-original\n' "$directory" >&2
}

# EL means Enterprise Linux. A same-major conversion changes the distro
# within an EL release; EL7-to-EL8 is a separate major upgrade. Swapping repository URLs is not a complete conversion.
function rpm_migration_check_choice() {
  local id=$1 version=$2 variant=$3 target=${DR_RPM_MIGRATION_TARGET:-} script=${DR_RPM_MIGRATION_SCRIPT:-} owner mode parent
  [ "$id" = centos ] || return 0
  case "$variant:${version%%.*}:$target" in
    stream:9:|stream:10:) return 0;;
    *:4:centos-vault|*:5:centos-vault|*:6:centos-vault|*:7:centos-vault|*:8:centos-vault) return 0;;
    *:8:alma|stream:9:alma|stream:10:alma|*:8:rocky|stream:9:rocky) :;;
    *:4:alma|*:5:alma|*:6:alma|*:7:alma|*:4:rocky|*:5:rocky|*:6:rocky|*:7:rocky)
      echo "dss:error: There is no same-major $target equivalent for CentOS $version. Use a reviewed ELevate migration or reinstall; repositories were not changed." >&2
      echo 'dss:stage: Migration guidance: https://wiki.almalinux.org/elevate/' >&2
      return 1;;
    *)
      echo 'dss:error: Choose DR_RPM_MIGRATION_TARGET=alma or rocky for an eligible same-major conversion, or centos-vault for frozen archive packages only. No repository or package changes were made.' >&2
      return 1;;
  esac
  [ -n "$script" ] || { echo 'dss:error: Set DR_RPM_MIGRATION_SCRIPT to the reviewed vendor migration script.' >&2; return 1; }
  if [ ! -f "$script" ] || [ -L "$script" ]; then echo 'dss:error: The migration script must be a regular, non-symlink file.' >&2; return 1; fi
  owner=$(stat -c '%u' -- "$script") && mode=$(stat -c '%a' -- "$script") || return 1
  case "$mode" in ''|*[!0-7]*) return 1;; esac
  if [ "$owner" != 0 ] || [ "$((8#$mode & 022))" -ne 0 ]; then
    echo 'dss:error: The reviewed migration script must be owned by root and not writable by group/others.' >&2; return 1
  fi
  parent=${script%/*}
  while :; do
    [ -n "$parent" ] || parent=/
    if [ -L "$parent" ] || [ ! -d "$parent" ]; then echo 'dss:error: Migration script directories must not be symlinks.' >&2; return 1; fi
    owner=$(stat -c %u -- "$parent") && mode=$(stat -c %a -- "$parent") || return 1
    case "$mode" in ''|*[!0-7]*) return 1;; esac
    if [ "$owner" != 0 ] || [ "$((8#$mode & 022))" -ne 0 ]; then
      echo 'dss:error: Store the reviewed migration script under trusted root-owned directories without group/other write access (for example /root).' >&2; return 1
    fi
    [ "$parent" != / ] || break
    parent=${parent%/*}
  done
  bash -n "$script" || return 1
}

# A failed vendor conversion may already have changed release packages and keys.
# Keep the pending marker until the requested identity is verified; retrying ordinary updates could mix distributions.
function rpm_migration_run() {
  local target=$1 directory=$2 before_major=$3 before_variant=$4 expected records id version variant
  local marker=/root/distrorejuveinfo/rpm-migration.pending
  case "$target" in alma) expected=almalinux;; rocky) expected=rocky;; *) return 1;; esac
  [ ! -L /root/distrorejuveinfo ] && mkdir -p -- /root/distrorejuveinfo || return 1
  (umask 077; set -C; printf '%s\t%s\n' "$target" "$directory" > "$marker") || return 1
  echo "dss:stage: Running the operator-selected $target conversion; no reboot will be requested by distrorejuve." >&2
  if [ "$target" = rocky ]; then bash "$directory/vendor-migration.sh" -r || return $?
  elif [ "$before_variant" = stream ]; then
    echo 'dss:warn: CentOS Stream to AlmaLinux may downgrade packages to stable EL versions.' >&2
    bash "$directory/vendor-migration.sh" --downgrade || return $?
  else bash "$directory/vendor-migration.sh" || return $?; fi
  records=$(rpm_distro_output_identity "") || return 1
  IFS=$'\t' read -r id version variant <<< "$records"
  if [ "$id" != "$expected" ] || [ "${version%%.*}" != "$before_major" ]; then
    echo 'dss:error: Vendor tool did not establish the requested distribution and same major version. Stop and review; no automatic rollback or reboot was attempted.' >&2
    return 1
  fi
  rm -- "$marker" || return 1
}

# RPM actions stay within the installed EL major; migration requires an explicit operator choice.
function rpm_packages_output_manager() {
  if command -v dnf >/dev/null 2>&1; then printf '%s\n' dnf
  elif command -v yum >/dev/null 2>&1; then printf '%s\n' yum
  else echo 'dss:error: Neither dnf nor yum is installed. Restore the native package manager from verified distribution media.' >&2; return 1; fi
}

# Package managers can skip an unavailable repository and still report success.
# Require enabled repositories to respond, with TLS and package signatures checked, so a partial refresh cannot look complete.
function rpm_packages_run() {
  local manager=$1
  local LC_ALL=C
  export LC_ALL
  shift
  case "$manager" in
    dnf) dnf -y --refresh --best --setopt=gpgcheck=1 --setopt='*.gpgcheck=1' --setopt=sslverify=1 --setopt='*.sslverify=1' --setopt='*.skip_if_unavailable=0' "$@";;
    yum) yum -y --setopt=gpgcheck=1 --setopt='*.gpgcheck=1' --setopt=sslverify=1 --setopt='*.sslverify=1' --setopt=metadata_expire=0 --setopt='*.metadata_expire=0' --setopt='*.skip_if_unavailable=0' "$@";;
    *) return 1;;
  esac
}

function rpm_packages_upgrade() {
  pause_check
  local records id version variant manager directory base='' architecture target=${DR_RPM_MIGRATION_TARGET:-} status
  if [ -e /root/distrorejuveinfo/rpm-migration.pending ] || [ -L /root/distrorejuveinfo/rpm-migration.pending ]; then
    echo 'dss:error: A previous RPM migration is incomplete. Review /root/distrorejuveinfo/rpm-migration.pending and the vendor logs; finish recovery and verify the migration before removing that marker and retrying.' >&2
    upgrade_preflight_blocked=true
    return 1
  fi
  records=$(rpm_distro_output_identity "") || { echo 'dss:error: Cannot identify this RPM distribution; no packages or sources changed.' >&2; return 1; }
  IFS=$'\t' read -r id version variant <<< "$records"
  if ! rpm_migration_check_choice "$id" "$version" "$variant"; then upgrade_preflight_blocked=true; return 1; fi
  check_disk_space || return 1
  manager=$(rpm_packages_output_manager) || return 1
  # Very old yum versions lack per-repository overrides needed for strict acquisition.
  records=$(LC_ALL=C "$manager" --help) || return 1
  if ! grep -q -- --setopt <<< "$records"; then echo 'dss:error: This package manager lacks --setopt; use reviewed manual archive recovery. Signature/TLS checks were not weakened.' >&2; return 1; fi
  if [ "$id" = centos ]; then
    case "$variant:${version%%.*}" in linux:*|stream:8)
      architecture=$(rpm --eval '%{_arch}') || return 1
      case "$architecture" in i?86) architecture=i386;; esac
      base=$(rpm_sources_output_vault_location "$version" "$variant" "$architecture") || { echo 'dss:error: No verified CentOS archive layout for this release/architecture.' >&2; return 1; }
      echo 'dss:warn: CentOS archive packages are frozen and do not fix vulnerabilities disclosed after end of life. Plan migration to a supported release.' >&2;;
    esac
  fi
  if [ -n "${DR_RUN_DIRECTORY:-}" ]; then directory=$DR_RUN_DIRECTORY
  else
    directory=/root/distrorejuveinfo
    [ ! -L "$directory" ] && (umask 077; mkdir -p -- "$directory") || return 1
  fi
  directory=$(umask 077; mktemp -d "$directory/rpm-upgrade.XXXXXXXX") || return 1
  echo "dss:stage: RPM update evidence and repository backups: $directory" >&2
  if [ "$id" = centos ] && { [ "$target" = alma ] || [ "$target" = rocky ]; }; then
    cp -- "$DR_RPM_MIGRATION_SCRIPT" "$directory/vendor-migration.sh" && chmod 600 -- "$directory/vendor-migration.sh" || return 1
    sha256sum -- "$directory/vendor-migration.sh" > "$directory/vendor-migration.sha256" || return 1
  fi
  packages_output_inventory rpm > "$directory/packages.before.tsv" || { echo 'dss:error: RPM database query failed; no automatic database rebuild was attempted.' >&2; return 1; }
  if ! manifest_capture "$directory/before"; then echo 'dss:warn: Original manifest incomplete; package updates still require manual application checks.' >&2; fi
  [ -z "$base" ] || rpm_sources_prepare "$manager" "$directory" "$base" "${version%%.*}" || return 1
  rpm_packages_run "$manager" makecache || return $?
  records=$(rpm_packages_run "$manager" -v repolist enabled) || return $?
  if ! grep -qE '^[[:space:]]*Repo-id[[:space:]]*:' <<< "$records"; then
    echo 'dss:error: No enabled RPM repository could be established; check repository/subscription configuration.' >&2
    return 1
  fi
  echo "dss:stage: Updating packages with $manager on $id $version." >&2
  rpm_packages_run "$manager" upgrade || return $?
  if [ "$id" = centos ] && { [ "$target" = alma ] || [ "$target" = rocky ]; }; then
    rpm_migration_run "$target" "$directory" "${version%%.*}" "$variant" || return $?
    manager=$(rpm_packages_output_manager) || return 1
    rpm_packages_run "$manager" makecache && rpm_packages_run "$manager" upgrade || return $?
  fi
  # check-update uses 100 for updates remaining; it must not become a successful all-current claim.
  if rpm_packages_run "$manager" check-update; then :
  else status=$?; echo "dss:error: Update verification failed (status $status; 100 means updates remain). Check exclusions, version locks and dependencies." >&2; return "$status"; fi
  packages_output_inventory rpm > "$directory/packages.after.tsv" || return 1
  if ! manifest_capture "$directory/after"; then echo 'dss:warn: Final manifest incomplete; inspect services and applications manually.' >&2; fi
  if [ -f "$directory/before/manifest.review" ] && [ -f "$directory/after/manifest.review" ]; then
    diff -u "$directory/before/manifest.review" "$directory/after/manifest.review" > "$directory/manifest-changes.diff"
    status=$?; [ "$status" -le 1 ] || return "$status"
  fi
  echo 'dss:stage: RPM package transaction completed. Review services, PHP-FPM/Apache and application compatibility; restart affected services or arrange a reboot as needed.' >&2
  return 0
}

# Replacing files on disk does not replace code already loaded by a process.
# RPM transaction success alone cannot establish that PHP-FPM, Apache or another runtime is using the updated libraries.
function rpm_packages_finish_run() {
  local status=$1 logfile=$2 directory=${DR_RUN_DIRECTORY:-}
  if [ -n "$directory" ]; then
    if [ -L "$directory/outcome.incomplete" ] || ! (umask 077; : > "$directory/outcome.incomplete"); then
      echo 'dss:error: Cannot record incomplete RPM service verification.' >&2
      [ "$status" -ne 0 ] || status=1
    fi
  fi
  echo "dss:stage: RPM outcome: action status $status; service/application health not verified. Detailed run log: $logfile" >&2
  echo 'dss:warn: A successful package transaction does not establish that PHP is patched or that processes have loaded the new libraries. No automatic reboot was performed.' >&2
  return "$status"
}

# Historical names remain available to callers using --source.
function yum_upgrade() {
  [ -f /etc/redhat-release ] || return 0
  check_disk_space || return 1
  rpm_packages_upgrade
}

function yum_enable_rhel4() {
  [ -f /etc/redhat-release ] || return 0
  rpm_packages_output_manager >/dev/null
}

function improve_yum_setup() {
  [ -f /etc/redhat-release ] || return 0
  echo 'dss:info: Repository preparation is handled by the guarded RPM update path.'
}

function report_unsupported() {
  local current
  if [ -f /etc/debian_version ]; then
    current=$(distro_output_codename) || return 1
    case " $DEBIAN_CURRENT " in *" $current "*) return 0;; esac
    case " $UNSUPPORTED_DEBIAN $UNSUPPORTED_UBUNTU " in *" $current "*)
      echo "dss:warn: $current is outside Debian/Ubuntu community support. Review extended-support coverage or upgrade." >&2
      return 1;;
    esac
    return 0
  fi

  [ -f /etc/redhat-release ] || return 0
  local identity id version variant
  identity=$(rpm_distro_output_identity "") || { echo 'dss:warn: RPM distribution support could not be identified.' >&2; return 1; }
  IFS=$'\t' read -r id version variant <<< "$identity"
  case "$id:$variant:${version%%.*}" in
    centos:linux:*|centos:stream:8)
      echo "dss:warn: CentOS $version $variant is end of life. Archive packages do not restore security support. Select DR_RPM_MIGRATION_TARGET before running --upgrade." >&2
      return 1;;
    rhel:*) echo 'dss:info: RHEL update availability depends on enabled subscription/extended-support repositories.';;
  esac
  return 0
}

function packages_upgrade() {
local backend
backend=$(packages_output_backend) || return 1
if [ "$backend" = rpm ]; then rpm_packages_upgrade; return $?; fi
crossgrade_bookworm_recover_bootstrap "${UPGRADE_CROSSGRADE:-false}" packages || return $?
usrmerge_recover_pending || return $?
upgrade_prepare_nss_lookup
upgrade_precondition_checks || return $?

apt_sources_prepare || return 1

fix_missing_lsb_release || return $?

add_missing_debian_keys || return $?

upgrade_precondition_checks || return $?

# A retry may already report the new release while old PHP packages remain installed.
if [ -f /etc/debian_version ]; then
  local current php_migration=false
  current=$(distro_output_codename) || return 1
  case " $ALL_DEBIAN " in *" $current "*)
    is_distro_name_older "$current" stretch || php_migration=true;;
  esac
  case " $ALL_UBUNTU " in *" $current "*)
    is_distro_name_older "$current" xenial || php_migration=true;;
  esac
  if $php_migration; then
    apt_get_update || return 1
    record_config_state || return 1
    apt_get_install dpkg || return 1
    upgrade_migrate_php_packages "$current" || return 1
  fi
fi

echo "dss:trace:packages_upgrade:pre_apt_get_upgrade:"
apt_get_upgrade || return $?

return 0
}

function dist_upgrade_to_latest() {
  pause_check
  local debian_target='' ubuntu_target='' current='' family=''
  echo "dss:trace:dist_upgrade_to_latest"
  upgrade_preflight_action --to-latest || return $?

  if [ -f /etc/debian_version ]; then
    current=$(distro_output_codename) || return 1
    case " $ALL_DEBIAN " in *" $current "*) family=debian;; esac
    case " $ALL_UBUNTU " in *" $current "*) family=ubuntu;; esac
  fi
  if [ "$family" = debian ]; then
    debian_target=trixie
    if ! dist_upgrade_etch_to_lenny; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_etch_to_lenny:failed" && return 1; fi
    if ! dist_upgrade_lenny_to_squeeze; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_lenny_to_squeeze:failed" && return 1; fi
    if ! dist_upgrade_squeeze_to_wheezy; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_squeeze_to_wheezy:failed" && return 1; fi
    if ! dist_upgrade_wheezy_to_jessie; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_wheezy_to_jessie:failed" && return 1; fi
    if ! dist_upgrade_jessie_to_stretch; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_jessie_to_stretch:failed" && return 1; fi
    if ! dist_upgrade_stretch_to_buster; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_stretch_to_buster:failed" && return 1; fi
    if ! dist_upgrade_buster_to_bullseye; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_buster_to_bullseye:failed" && return 1; fi
    if ! dist_upgrade_bullseye_to_bookworm; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_bullseye_to_bookworm:failed" && return 1; fi
    if ! dist_upgrade_bookworm_to_trixie; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_bookworm_to_trixie:failed" && return 1; fi

  fi
  if [ "$family" = ubuntu ]; then
    ubuntu_target=$(ubuntu_output_latest_lts "$current") || return 1
    if ! dist_upgrade_ubuntu_to_latest; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_ubuntu_to_latest:failed" && return 1; fi
  fi
  if ! packages_upgrade; then echo "dss:error:dist_upgrade_to_latest:packages_upgrade:failed" && return 1; fi
  if ! apt_get_dist_upgrade; then echo "dss:error:dist_upgrade_to_latest:apt_get_dist_upgrade:failed" && return 1; fi
  if [ -n "$debian_target" ]; then debian_check_release_completion "$debian_target" || return 1; fi
  if [ -n "$ubuntu_target" ]; then upgrade_check_crossgrade_checkpoint ubuntu "$ubuntu_target" || return 1; fi
}

# Application/service manifest: bounded read-only collection.
# Parser examples use reserved example.invalid names, standard layouts and explicit USER placeholders.
# shellcheck shell=bash
# Manifest collection is read-only: parse configuration and application metadata, never run application code.
function manifest_json_string() {
  local value="$1" character i
  printf '"'
  for ((i=0; i<${#value}; i++)); do
    character=${value:i:1}
    case "$character" in
      '"') printf '\\"' ;;
      \\) printf '%s' "\\\\" ;;
      $'\n') printf '\\n' ;;
      $'\r') printf '\\r' ;;
      $'\t') printf '\\t' ;;
      *)
        if [[ "$character" < ' ' ]]; then
          printf '\\u%04x' "'$character"
        else
          printf '%s' "$character"
        fi ;;
    esac
  done
  printf '"'
}

# Stable records for review; omit timestamps and DNS observations from upgrade comparisons.
function manifest_output_review_record() {
  local type=$1 key value
  shift
  # Process IDs and counts are transient observations, not migration configuration.
  case "$type:${2:-}" in security_indicator:*|warning:security_*) return 0;; esac
  printf '%s' "$type"
  while [ "$#" -ge 2 ]; do
    key=$1; value=$2; shift 2
    case "$key" in generated_utc|version_file_modified|date_basis|dns|dns_addresses|dns_reason) continue;; esac
    printf '\t%s=' "$key"
    manifest_json_string "$value"
  done
  printf '\n'
}

function manifest_emit() {
  if [ -n "${manifest_review_file:-}" ]; then
    manifest_output_review_record "$@" >> "$manifest_review_file" || manifest_collection_failed=true
  fi
  local record_type="$1" key value
  shift
  if [ "$manifest_format" = json ]; then
    printf '%s{"type":' "$manifest_separator"
    manifest_json_string "$record_type"
    while [ "$#" -ge 2 ]; do
      key="$1"; value="$2"; shift 2
      printf ','; manifest_json_string "$key"; printf ':'; manifest_json_string "$value"
    done
    printf '}'
    manifest_separator=,
  else
    printf '%s' "$record_type"
    while [ "$#" -ge 2 ]; do
      key="$1"; value="$2"; shift 2
      # Keep each finding on one line, even when filenames contain control characters.
      value=${value//$'\n'/\\n}; value=${value//$'\r'/\\r}; value=${value//$'\t'/\\t}; value=${value//$'\e'/\\e}; value=${value//$'\b'/\\b}; value=${value//$'\f'/\\f}
      printf ' | %s=%s' "$key" "$value"
    done
    printf '\n'
  fi
}

# A listening socket proves a local bind, not public reachability. Firewalls,
# NAT and proxies can change which service an external visitor reaches.
function manifest_listeners() {
  local raw parsed source protocol address port program scope application listener_options=-lntp
  if "${manifest_unprivileged:-false}"; then listener_options=-lnt; fi
  if command -v ss >/dev/null 2>&1 && raw=$(ss "$listener_options" 2>/dev/null); then
    source=ss
  elif command -v netstat >/dev/null 2>&1 && raw=$(netstat "$listener_options" 2>/dev/null); then
    source=netstat
  else
    manifest_emit warning area listeners reason 'ss/netstat unavailable or permission denied'
    manifest_collection_failed=true
    return
  fi
  # ss: LISTEN 0 128 127.0.0.1:25 *:* users:(("master",pid=12,fd=3))
  # Older ss -lntp omits State: header "Recv-Q Send-Q ...", then "0 128 127.0.0.1:25 *:* ...".
  # netstat: tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN 12/apache2
  # These yield address=127.0.0.1, port=25, program=master (ss), or 0.0.0.0/80/apache2 (netstat).
  if ! parsed=$(printf '%s\n' "$raw" | awk -v source="$source" '
    source == "ss" && $1 == "Recv-Q" && $2 == "Send-Q" { implicit_listen=1; next }
    source == "ss" && $1 == "State" { implicit_listen=0; next }
    source == "ss" {
      if ($1 == "LISTEN") endpoint=$4
      else if (implicit_listen && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/) {
        # A wildcard peer distinguishes these listener rows from current connections.
        if ($4 !~ /^(\*|0[.]0[.]0[.]0|::|\[::\]):\*$/) next
        endpoint=$3
      } else next
      program="unknown"
      if (match($0, /users:\(\("[^"]+/)) {
        program=substr($0, RSTART+9, RLENGTH-9)
      }
      port=endpoint; sub(/^.*:/,"",port); address=endpoint; sub(/:[^:]*$/,"",address)
      print "tcp\t" address "\t" port "\t" program
    }
    source == "netstat" && $1 ~ /^tcp/ && $6 == "LISTEN" {
      endpoint=$4; program=$7; sub(/^[0-9]+\//,"",program)
      if (program == "-" || program == "") program="unknown"
      port=endpoint; sub(/^.*:/,"",port); address=endpoint; sub(/:[^:]*$/,"",address)
      print "tcp\t" address "\t" port "\t" program
    }'); then
    manifest_emit warning area listeners reason 'listener parser failed; inventory unknown'
    manifest_collection_failed=true
    return
  fi
  while IFS=$'\t' read -r protocol address port program; do
    [ -n "$port" ] || continue
    case "$address" in
      127.*|::1|'[::1]') scope=loopback ;;
      '*'|0.0.0.0|::|'[::]') scope=all_interfaces ;;
      *) scope=specific_interface ;;
    esac
    application=unknown
    case "$program" in
      master|postfix*|smtpd) application=Postfix ;;
      exim*) application=Exim ;;
      sendmail*) application=Sendmail ;;
      dovecot*|imap-login|pop3-login) application=Dovecot ;;
      courier*) application=Courier ;;
      apache2|httpd) application=Apache ;;
      nginx*) application=nginx ;;
      caddy*) application=Caddy ;;
    esac
    case "$port" in
      25|465|587) protocol=smtp ;;
      110|995) protocol=pop3 ;;
      143|993) protocol=imap ;;
      80|443|8080|8443) protocol=http ;;
      *) protocol=tcp ;;
    esac
    manifest_emit listener service "$protocol" address "$address" port "$port" program "$program" application "$application" binding "$scope" reachability unknown
    # program=.example -> dot_prefixed_listener; program=nginx -> no name-based indicator.
    case "$program" in .*)
      manifest_emit security_indicator indicator dot_prefixed_listener program "$program" address "$address" port "$port" assessment requires_review reason 'Dot-prefixed listening process name; inspect its owner and executable. A name alone does not establish compromise.';;
    esac
  done <<< "$parsed"
}

# Inspect arguments as data only; emit fixed indicators and numeric references, never raw commands.
# Explicit C whitespace and escaped regex slashes also work with pre-POSIX-class AWK.
# Detection examples are invented. USER, HIDDEN, URL, ENCODED and TOKEN are placeholders.
function manifest_process_indicators() {
  local records indicator count pid ppid uid reason
  # ps -eww -o pid=,ppid=,uid=,vsz=,args=, for example:
  # 101 50 1001 9000 tee -a /etc/sudoers -> sudoers_write_command.
  # 102 50 1001 4000 [kworker/0:0] 47128 -> userspace_kernel_name, not a kernel thread.
  if ! records=$(set -o pipefail; LC_ALL=C manifest_run_bounded 5 ps -eww -o pid=,ppid=,uid=,vsz=,args= 2>/dev/null | LC_ALL=C awk '
    function record(indicator, key) {
      key=indicator SUBSEP $2 SUBSEP $3
      if (!(key in counts)) {
        if (groups >= 200) { limited=1; return }
        groups++; kinds[key]=indicator; pids[key]=$1; parents[key]=$2; uids[key]=$3
      }
      counts[key]++
    }
    NR > 20000 { limited=1; next }
    $1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ || NF < 5 { bad=1; next }
    {
      args=$0; sub(/^[ \t\r\013\014]*[0-9]+[ \t\r\013\014]+[0-9]+[ \t\r\013\014]+[0-9]+[ \t\r\013\014]+[0-9]+[ \t\r\013\014]+/, "", args)
      # printf RULE >> /etc/sudoers or tee -a /etc/sudoers -> sudoers_write_command.
      # cat /etc/sudoers > /tmp/example.txt -> no write indicator.
      if (args ~ />[ \t\r\013\014]*[\047\042]?\/etc\/sudoers([.]d\/|[ \t\r\013\014\047\042;|&]|$)/ ||
          args ~ /(^|[ \t\r\013\014\/])tee([ \t\r\013\014]+-[a-zA-Z]+)*[ \t\r\013\014]+[\047\042]?\/etc\/sudoers([.]d\/|[ \t\r\013\014\047\042;|&]|$)/) record("sudoers_write_command")
      # printf ENCODED | base64 -d | sh -> encoded_shell_pipeline; base64 -d /tmp/example.txt alone does not match.
      if (args ~ /(^|[ \t\r\013\014\/])base64([ \t\r\013\014]|$)/ &&
          args ~ /(^|[ \t\r\013\014])(-d|--decode)([ \t\r\013\014]|$)/ &&
          args ~ /\|[ \t\r\013\014]*((\/usr)?\/bin\/)?(sh|bash|dash|ash|ksh|zsh)([ \t\r\013\014\047\042;|&]|$)/) record("encoded_shell_pipeline")
      # 103 1 1001 9000 [kswapd0] -> userspace_kernel_name; 104 2 0 0 [kswapd0] does not match.
      if ($5 ~ /^[[]?(kworker\/|kthreaddi?(]|$)|kswapd[0-9]+(]|$)|khugepaged(]|$)|ksoftirqd\/|migration\/|rcu_(sched|gp|par_gp|tasks))/ && ($3 != 0 || $4 > 0)) record("userspace_kernel_name")
      # -o stratum+tcp://127.0.0.1:3333 or --algo rx/0 --url URL --user TOKEN -> mining_command_arguments.
      if (args ~ /stratum(\+(tcp|ssl))?:\/\// ||
          (args ~ /(^|[ \t\r\013\014])--(algo|coin)([= \t\r\013\014]|$)/ &&
           args ~ /(^|[ \t\r\013\014])(-o|--url)([= \t\r\013\014]|$)/ &&
           args ~ /(^|[ \t\r\013\014])(-u|--user)([= \t\r\013\014]|$)/)) record("mining_command_arguments")
      # curl -fsSL URL | /bin/sh -> download_shell_pipeline; curl -o /tmp/example.txt URL does not match.
      if (args ~ /(^|[ \t\r\013\014\/\047\042])(curl|wget)([ \t\r\013\014]|$)/ &&
          args ~ /\|[ \t\r\013\014]*((\/usr)?\/bin\/)?(sh|bash|dash|ash|ksh|zsh)([ \t\r\013\014\047\042;|&]|$)/) record("download_shell_pipeline")
      # /dev/shm/example --flag -> temporary_executable; /usr/bin/sleep 60 does not match.
      if ($5 ~ /^\/(tmp|var\/tmp|dev\/shm)\//) record("temporary_executable")
      # perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf: 20 rows with the same PPID/UID -> panel_worker_concentration.
      if (args ~ /\/webmin\/miniserv[.]pl([ \t\r\013\014]|$)/ && args ~ /\/etc\/webmin\/miniserv[.]conf([ \t\r\013\014]|$)/) record("panel_worker_concentration")
      program=$5; sub(/^.*\//, "", program)
      if (program ~ /^(sh|bash|dash|ash|ksh|zsh|python([0-9]+([.][0-9]+)*)?|perl|ruby|node)$/) {
        # python3 -u /tmp/example.py -> temporary_script; python3 -c CODE has no script pathname.
        i=6
        while (i <= NF && $i ~ /^-/ && $i !~ /^--$/) {
          if ($i ~ /^-[^-]*[ce]/) break
          i++
        }
        if ($i == "--") i++
        if ($i ~ /^\/(tmp|var\/tmp|dev\/shm)\//) record("temporary_script")
      }
    }
    END {
      for (key in counts) {
        if (kinds[key] == "panel_worker_concentration" && counts[key] < 20) continue
        printf "%s\t%d\t%s\t%s\t%s\n", kinds[key], counts[key], pids[key], parents[key], uids[key]
      }
      if (limited) print "limit"
      if (bad) print "parse_failed"
    }
  ' | LC_ALL=C sort); then
    manifest_emit warning area security_processes reason 'Process snapshot failed or timed out; potential compromise indicators could not be evaluated.'
    return
  fi
  while IFS=$'\t' read -r indicator count pid ppid uid; do
    case "$indicator" in
      '') continue;;
      limit) manifest_emit warning area security_processes reason 'Only the first 20000 processes and 200 indicator/parent/UID groups were examined; coverage is incomplete.'; continue;;
      parse_failed) manifest_emit warning area security_processes reason 'Some process rows could not be parsed; coverage is incomplete.'; continue;;
      sudoers_write_command) reason='Command references a sudoers write; verify authorization and whether the write succeeded.';;
      encoded_shell_pipeline) reason='Command decodes Base64 and pipes to a shell; review its origin without executing the payload.';;
      mining_command_arguments) reason='Command contains a mining protocol or correlated algorithm, pool and user options; verify whether mining is authorized.';;
      download_shell_pipeline) reason='Command references a download tool and a shell pipeline; verify its origin and authorization.';;
      panel_worker_concentration) reason='At least 20 Webmin workers share a parent and UID; review sessions, logs and expected concurrency. High concurrency alone does not establish compromise.';;
      userspace_kernel_name) reason='Kernel-thread-style command name has a nonzero UID or userspace memory; investigate possible masquerading.';;
      temporary_executable|temporary_script) reason='Executable or interpreter script starts from a temporary directory; legitimate installers can also do this.';;
      *) continue;;
    esac
    manifest_emit security_indicator indicator "$indicator" process_count "$count" sample_pid "$pid" parent_pid "$ppid" uid "$uid" assessment requires_review reason "$reason"
  done <<< "$records"
}

# Inspect the kernel's executable links too: argv can hide a running, unlinked binary.
function manifest_executable_indicators() {
  local records indicator count pid location reason incomplete=false
  [ -d "$manifest_root/proc" ] || return
  # find prints parent<TAB>link, e.g. /proc/101<TAB>/root/example (deleted).
  # Never follow the link, read the binary or print its potentially sensitive pathname.
  if ! records=$(set -o pipefail; LC_ALL=C manifest_run_bounded 5 find "$manifest_root/proc" -mindepth 2 -maxdepth 2 -name exe -type l -printf '%h\t%l\n' 2>/dev/null | LC_ALL=C awk -F '\t' '
    function record(kind, place, key) {
      key=kind SUBSEP place; counts[key]++; kinds[key]=kind; locations[key]=place
      if (!(key in pids)) pids[key]=pid
    }
    NR > 20000 { limited=1; next }
    {
      pid=$1; sub(/^.*\//, "", pid)
      if (pid !~ /^[0-9]+$/ || NF != 2 || $2 == "") next
      path=$2; deleted=sub(/ [(]deleted[)]$/, "", path)
      # /proc/101<TAB>/tmp/example -> temporary_executable_target, even if argv says sshd.
      if (path ~ /^\/(tmp|var\/tmp|dev\/shm)\//) record("temporary_executable_target", "temporary_directory")
      # /usr/bin/.HIDDEN/example -> hidden_system_executable; /home/USER/.local/bin/example does not match this rule.
      if (path ~ /^\/(usr\/)?(s?bin|lib|lib64)\/([^\/]+\/)*[.][^\/]+\//) record("hidden_system_executable", "hidden_system_directory")
      # /home/USER/example (deleted) -> deleted_executable_in_writable_location; /usr/bin/sleep (deleted) does not match.
      if (deleted && path ~ /^\/(root|home[0-9]*|var\/lib|tmp|var\/tmp|dev\/shm)\//) {
        place=(path ~ /^\/var\/lib\// ? "application_state_directory" : "home_or_temporary_directory")
        record("deleted_executable_in_writable_location", place)
      }
    }
    END {
      for (key in counts) printf "%s\t%d\t%s\t%s\n", kinds[key], counts[key], pids[key], locations[key]
      if (limited) print "limit"
    }' | LC_ALL=C sort); then incomplete=true; fi
  while IFS=$'\t' read -r indicator count pid location; do
    case "$indicator" in
      '') continue;;
      limit) incomplete=true; continue;;
      temporary_executable_target) reason='Kernel executable link points into temporary storage, even if the process command name hides it.';;
      hidden_system_executable) reason='Kernel executable link points into a hidden directory under a system binary or library path; check for masquerading or command wrappers.';;
      deleted_executable_in_writable_location) reason='A running executable was unlinked from a home, application-state or temporary directory. Legitimate application updates can also do this.';;
      *) continue;;
    esac
    manifest_emit security_indicator indicator "$indicator" process_count "$count" sample_pid "$pid" location "$location" evidence proc_exe assessment requires_review reason "$reason"
  done <<< "$records"
  if $incomplete; then
    manifest_emit warning area security_executables reason 'Executable-link coverage is incomplete: permissions, exited processes or limits (5 seconds, 20000 links).'
  fi
}

# Inspect a small set of website files as text; never invoke PHP or decode a payload.
function manifest_web_indicators() {
  local document_root=$1 resolved relative directory depth files file size content records indicator line mode
  if [ $((SECONDS-manifest_web_started)) -ge 15 ]; then manifest_web_incomplete=true; return; fi
  case "$document_root" in /*) ;; *) return;; esac
  resolved=$(readlink -f -- "$manifest_root$document_root" 2>/dev/null) || return
  [ -d "$resolved" ] || return
  case "$resolved/" in "$manifest_root/"*) ;; *) manifest_web_incomplete=true; return;; esac
  relative=${resolved#"$manifest_root"}
  # Reject broad or special roots even when reached through an alias in a vhost.
  case "$relative" in ''|/|/home|/root|/srv|/var|/var/www|/tmp|/var/tmp|/usr|/opt|/etc|/etc/*|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*) return;; esac
  manifest_web_roots=$((manifest_web_roots+1))
  if [ "$manifest_web_roots" -gt 20 ]; then manifest_web_incomplete=true; return; fi
  for directory in "$resolved" "$resolved/tmp" "$resolved/uploads" "$resolved/images" "$resolved/cache" "$resolved/wp-content/uploads" "$resolved/wp-content/plugins"; do
    if [ ! -d "$directory" ] || [ -L "$directory" ]; then continue; fi
    if [ $((SECONDS-manifest_web_started)) -ge 15 ] || [ "$manifest_web_findings" -ge 200 ]; then manifest_web_incomplete=true; return; fi
    relative=$(readlink -f -- "$directory" 2>/dev/null) || { manifest_web_incomplete=true; continue; }
    case "$relative" in "$resolved"|"$resolved"/*) ;; *) manifest_web_incomplete=true; continue;; esac
    mode=$(stat -c %a -- "$directory" 2>/dev/null) || { manifest_web_incomplete=true; continue; }
    # stat mode 777 or 1777 -> world_writable_web_directory; 755 does not match.
    case "$mode" in *[2367])
      manifest_web_findings=$((manifest_web_findings+1))
      manifest_emit security_indicator indicator world_writable_web_directory path "${directory#"$manifest_root"}" assessment requires_review reason 'Directory permits writes by any local user; check ownership and intended access. Permissions alone do not establish compromise.';;
    esac
    depth=3; [ "$directory" != "$resolved" ] || depth=1
    # Prune control-character names before using newline-delimited paths. Root-level
    # PHP files and common upload/cache directories take priority over vendor libraries.
    if ! files=$(set -o pipefail; LC_ALL=C manifest_run_bounded 3 find "$directory" -maxdepth "$depth" \( -name '*[[:cntrl:]]*' -prune \) -o \( -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[0-9]' -o -iname '*.jpg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.css' -o -iname '*.js' -o -iname '*.txt' -o -iname '*.html' \) -print \) 2>/dev/null | head -n 201); then manifest_web_incomplete=true; fi
    while IFS= read -r file; do
      [ -n "$file" ] || continue
      if [ "$manifest_web_files" -ge 200 ] || [ $((SECONDS-manifest_web_started)) -ge 15 ]; then manifest_web_incomplete=true; return; fi
      manifest_web_files=$((manifest_web_files+1))
      # Resolve again before reading: never cross out of the selected website via a link.
      relative=$(readlink -f -- "$file" 2>/dev/null) || { manifest_web_incomplete=true; continue; }
      case "$relative" in "$resolved"/*) ;; *) manifest_web_incomplete=true; continue;; esac
      if [ ! -f "$file" ] || [ ! -r "$file" ]; then manifest_web_incomplete=true; continue; fi
      size=$(stat -c %s -- "$file" 2>/dev/null) || { manifest_web_incomplete=true; continue; }
      if [ "$size" -gt 262144 ]; then manifest_web_incomplete=true; continue; fi
      # Strip NUL bytes from bounded binary/image samples without shell substitution warnings.
      content=$(set -o pipefail; manifest_run_bounded 1 head -c 262144 -- "$file" 2>/dev/null | LC_ALL=C tr -d '\000') || { manifest_web_incomplete=true; continue; }
      records=$(LC_ALL=C awk '
        # Correlated features, not an assertion of PHP data flow: eval(base64_decode(...))
        # or request input plus command execution and file-manager/error-suppression features.
        # <?php eval(base64_decode("ENCODED")); -> php_encoded_execution.
        # <?php error_reporting(0); system($_POST["cmd"]); -> php_webshell_features.
        # <?php base64_decode($data); alone lacks execution and does not match either rule.
        # hacked by example -> possible_web_defacement in an upload/cache/plugin sample, excluding the document-root level.
        {
          text=tolower($0)
          if (text ~ /<[?](php|=)/) php=1
          if (text ~ /(^|[^a-z0-9_])(eval|assert)[ \t\r\013\014]*[(]/) { evaluate=1; if (!eval_line) eval_line=NR }
          if (text ~ /(^|[^a-z0-9_])(base64_decode|gzinflate|gzuncompress|str_rot13)[ \t\r\013\014]*[(]/) decode=1
          if (text ~ /(^|[^a-z0-9_])(shell_exec|exec|system|passthru|popen|proc_open)[ \t\r\013\014]*[(]/) { execute=1; if (!exec_line) exec_line=NR }
          if (text ~ /\$_(get|post|request|cookie)[ \t\r\013\014]*\[/) request=1
          if (text ~ /error_reporting[ \t\r\013\014]*[(][ \t\r\013\014]*0[ \t\r\013\014]*[)]/ || text ~ /move_uploaded_file[ \t\r\013\014]*[(]/ || text ~ /open_basedir/) manager=1
          if (text ~ /hacked[ \t\r\013\014]+by[ \t\r\013\014]+[a-z0-9_]/ && !deface_line) deface_line=NR
        }
        END {
          if (php && evaluate && decode) print "php_encoded_execution\t" eval_line
          if (php && request && execute && manager) print "php_webshell_features\t" exec_line
          if (deface_line) print "possible_web_defacement\t" deface_line
        }' <<< "$content") || { manifest_web_incomplete=true; continue; }
      while IFS=$'\t' read -r indicator line; do
        [ -n "$indicator" ] || continue
        if [ "$indicator" = possible_web_defacement ] && [ "$directory" = "$resolved" ]; then continue; fi
        if [ "$manifest_web_findings" -ge 200 ]; then manifest_web_incomplete=true; return; fi
        manifest_web_findings=$((manifest_web_findings+1))
        manifest_emit security_indicator indicator "$indicator" path "${file#"$manifest_root"}" line "$line" assessment requires_review reason 'Website file contains correlated code or defacement markers; review manually. Comments, examples and authorized tools can also match. File contents are omitted.'
      done <<< "$records"
    done <<< "$files"
  done
}

# Inspect job bodies as data; never emit command bodies or environment values.
function manifest_schedule_commands() {
  local path=$1 kind=$2 content=$3 records indicator line target
  # User crontab: @reboot /bin/sh /tmp/example.sh -> command=/bin/sh /tmp/example.sh.
  # System crontab: */10 * * * * root /bin/sh /tmp/example.sh -> the same command after dropping the account field.
  records=$(LC_ALL=C awk -v kind="$kind" '
    function output(indicator, target) { printf "%s\t%d\t%s\n", indicator, NR, target }
    /^[ \t\r\013\014]*#/ || /^[ \t\r\013\014]*$/ { next }
    {
      command=$0; sub(/^[ \t\r\013\014]+/, "", command)
      # TMPDIR=/tmp -> skip; SHELL=/tmp/example.sh -> inspect /tmp/example.sh as the command.
      if (command ~ /^[A-Za-z_][A-Za-z0-9_]*[ \t\r\013\014]*=/) {
        if (command !~ /^SHELL[ \t\r\013\014]*=/) next
        sub(/^SHELL[ \t\r\013\014]*=[ \t\r\013\014]*/, "", command)
      } else if (kind != "script") {
        fields=(kind == "anacron" ? 3 : (command ~ /^@/ ? 1 : 5))
        if (kind == "system") fields++
        for (i=0; i<fields; i++) sub(/^[^ \t\r\013\014]+[ \t\r\013\014]+/, "", command)
      }
      # sh /tmp/example.sh --flag or exec /dev/shm/example -> scheduled_temporary_execution.
      # The first example extracts target=/tmp/example.sh; rm -f /tmp/example.sh does not match.
      if (command ~ /(^|[;|&])[ \t\r\013\014]*[\047\042]?\/(tmp|var\/tmp|dev\/shm)\// ||
          command ~ /(^|[ \t\r\013\014;|&])((\/usr)?\/bin\/)?(exec|nohup|sh|bash|dash|ash|ksh|zsh|python[0-9.]*|perl|ruby|node|source|[.])[ \t\r\013\014]+(-[a-zA-Z]+[ \t\r\013\014]+)*[\047\042]?\/(tmp|var\/tmp|dev\/shm)\//) {
        if (match(command, /\/(tmp|var\/tmp|dev\/shm)\/[^ \t\r\013\014\047\042;|&<>]+/)) target=substr(command,RSTART,RLENGTH)
        else target="unknown"
        output("scheduled_temporary_execution", target)
      }
      # cd /tmp && python3 ./example.py -> scheduled_temporary_workdir, target=temporary_directory.
      if (command ~ /(^|[ \t\r\013\014;|&])cd[ \t\r\013\014]+[\047\042]?\/(tmp|var\/tmp|dev\/shm)(\/|[ \t\r\013\014\047\042;|&]|$)/ &&
          command ~ /[;&][ \t\r\013\014]*((python[0-9.]*|sh|bash|perl)[ \t\r\013\014]+(-[a-zA-Z]+[ \t\r\013\014]+)*)?([.]\/|[.][A-Za-z0-9_])/) output("scheduled_temporary_workdir", "temporary_directory")
      # /root/.cache/example.sh or cd /home/USER/.cache && ./example -> scheduled_hidden_execution.
      # target=hidden_directory; rm /root/.cache/example.sh does not match.
      hidden="/(root|home[0-9]*/[^/]+|var/lib/[^/]+|var/www|((usr/)?(s?bin|lib|lib64)))/([^/ \t\r\013\014]+/)*[.][^/ \t\r\013\014]+"
      if (command ~ "(^|[;|&])[ \t\r\013\014]*[\047\042]?" hidden "/" ||
          command ~ "(^|[ \t\r\013\014;|&])((/usr)?/bin/)?(exec|nohup|sh|bash|dash|ash|ksh|zsh|python[0-9.]*|perl|ruby|node|source|[.])[ \t\r\013\014]+(-[a-zA-Z]+[ \t\r\013\014]+)*[\047\042]?" hidden "/" ||
          (command ~ "(^|[ \t\r\013\014;|&])cd[ \t\r\013\014]+[\047\042]?" hidden "(/|[ \t\r\013\014\047\042;|&]|$)" &&
           command ~ /[;&][ \t\r\013\014]*((python[0-9.]*|sh|bash|perl)[ \t\r\013\014]+(-[a-zA-Z]+[ \t\r\013\014]+)*)?[.]\//)) output("scheduled_hidden_execution", "hidden_directory")
      # wget -qO- URL | sh -> scheduled_download_shell, target=unknown; wget URL alone does not match.
      if (command ~ /(^|[ \t\r\013\014\/\047\042])(curl|wget)([ \t\r\013\014]|$)/ &&
          command ~ /\|[ \t\r\013\014]*((\/usr)?\/bin\/)?(sh|bash|dash|ash|ksh|zsh)([ \t\r\013\014\047\042;|&]|$)/) output("scheduled_download_shell", "unknown")
      # printf ENCODED | base64 --decode | /bin/bash -> scheduled_encoded_shell, target=unknown.
      if (command ~ /(^|[ \t\r\013\014\/])base64([ \t\r\013\014]|$)/ &&
          command ~ /(^|[ \t\r\013\014])(-d|--decode)([ \t\r\013\014]|$)/ &&
          command ~ /\|[ \t\r\013\014]*((\/usr)?\/bin\/)?(sh|bash|dash|ash|ksh|zsh)([ \t\r\013\014\047\042;|&]|$)/) output("scheduled_encoded_shell", "unknown")
      # printf RULE >> /etc/sudoers or tee -a /etc/sudoers -> scheduled_sudoers_write, target=/etc/sudoers.
      if (command ~ />[ \t\r\013\014]*[\047\042]?\/etc\/sudoers([.]d\/|[ \t\r\013\014\047\042;|&]|$)/ ||
          command ~ /(^|[ \t\r\013\014\/])tee([ \t\r\013\014]+-[a-zA-Z]+)*[ \t\r\013\014]+[\047\042]?\/etc\/sudoers([.]d\/|[ \t\r\013\014\047\042;|&]|$)/) output("scheduled_sudoers_write", "/etc/sudoers")
    }
  ' <<< "$content") || { manifest_schedule_incomplete=true; return; }
  while IFS=$'\t' read -r indicator line target; do
    [ -n "$indicator" ] || continue
    if [ "$manifest_schedule_findings" -ge 200 ]; then manifest_schedule_incomplete=true; break; fi
    manifest_schedule_findings=$((manifest_schedule_findings+1))
    manifest_emit security_indicator indicator "$indicator" path "$path" line "$line" target "$target" assessment requires_review reason 'Scheduled command has a potential compromise indicator; review its source and authorization. Command arguments are omitted.'
  done <<< "$records"
}

function manifest_current_crontab_indicators() {
  local jobs status
  if ! command -v crontab >/dev/null 2>&1; then manifest_schedule_incomplete=true; return; fi
  jobs=$(LC_ALL=C manifest_run_bounded 2 crontab -l 2>&1)
  status=$?
  if [ "$status" -eq 0 ]; then manifest_schedule_commands current_user_crontab user "$jobs"
  elif [ "$status" -eq 1 ] && [[ "$jobs" == *'no crontab for '* ]]; then :
  else manifest_schedule_incomplete=true; fi
}

function manifest_schedule_indicators() {
  local file directory kind size content count=0 manifest_schedule_findings=0 manifest_schedule_incomplete=false
  for directory in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs; do
    if [ -d "$manifest_root$directory" ] && { [ ! -r "$manifest_root$directory" ] || [ ! -x "$manifest_root$directory" ]; }; then manifest_schedule_incomplete=true; fi
  done
  for file in "$manifest_root"/etc/crontab "$manifest_root"/etc/anacrontab \
      "$manifest_root"/etc/cron.d/* "$manifest_root"/etc/cron.hourly/* "$manifest_root"/etc/cron.daily/* \
      "$manifest_root"/etc/cron.weekly/* "$manifest_root"/etc/cron.monthly/* \
      "$manifest_root"/var/spool/cron/* "$manifest_root"/var/spool/cron/crontabs/*; do
    [ -f "$file" ] || continue
    count=$((count+1))
    if [ "$count" -gt 200 ] || [ "$manifest_schedule_findings" -ge 200 ]; then manifest_schedule_incomplete=true; break; fi
    size=$(stat -L -c %s -- "$file" 2>/dev/null) || { manifest_schedule_incomplete=true; continue; }
    if [ "$size" -gt 1048576 ] || [ ! -r "$file" ]; then manifest_schedule_incomplete=true; continue; fi
    content=$(manifest_read_metadata "$file") || { manifest_schedule_incomplete=true; continue; }
    case "${file#"$manifest_root"}" in
      /etc/crontab|/etc/cron.d/*) kind=system;;
      /etc/anacrontab) kind=anacron;;
      /var/spool/cron/*) kind=user;;
      *) kind=script;;
    esac
    manifest_schedule_commands "${file#"$manifest_root"}" "$kind" "$content"
  done
  # The crontab tool can expose the current users jobs even when its spool is private.
  if [ -z "$manifest_root" ] && "${manifest_unprivileged:-false}"; then manifest_current_crontab_indicators; fi
  if $manifest_schedule_incomplete; then
    manifest_emit warning area security_schedules reason 'Schedule coverage is incomplete: unreadable/failed probes or collection limits (200 files, 1 MiB per file, 200 findings).'
  fi
}

# Perl's alarm survives exec; use the already-installed interpreter when old coreutils lacks timeout.
function manifest_run_bounded() {
  local seconds=$1
  shift
  if command -v timeout >/dev/null 2>&1; then timeout "$seconds" "$@"
  elif command -v perl >/dev/null 2>&1; then perl -e 'alarm shift; exec @ARGV or exit 127' "$seconds" "$@"
  else return 127; fi
}

function manifest_service() {
  local name=$1 package=$2 version=$3 selector=$1 running=unknown enabled=unknown state result link processes
  local systemd=false
  local enabled_source=unknown running_source=unknown clusters row cluster_version cluster port cluster_state
  if [ -d "$manifest_root/run/systemd/system" ]; then
    case "$(readlink "$manifest_root/proc/1/exe" 2>/dev/null)" in */systemd|*/'systemd (deleted)') systemd=true;; esac
  fi
  case "$name" in
    mariadb) if [ -x "$manifest_root/etc/init.d/mysql" ] && [ ! -x "$manifest_root/etc/init.d/mariadb" ]; then selector=mysql; fi;;
    postgresql-*) if [ "$manifest_package_backend" = dpkg ] && [ ! -e "$manifest_root/etc/init.d/$name" ]; then selector=postgresql; fi;;
  esac
  if [ "$manifest_package_backend" = dpkg ] && [[ "$name" == postgresql-* ]] && command -v pg_lsclusters >/dev/null 2>&1; then
    # pg_lsclusters: 15 main 5432 online ... -> running=yes for postgresql-15; down -> running=no.
    if clusters=$(manifest_run_bounded 2 pg_lsclusters 2>/dev/null); then
      while read -r cluster_version cluster port cluster_state row; do
        [ "$cluster_version" = "${name#postgresql-}" ] || continue
        case "$cluster_state" in online|online,*) running=yes; break;; down|down,*) running=no;; esac
      done <<< "$clusters"
      running_source=pg_lsclusters
    fi
  elif ! "${manifest_unprivileged:-false}" && command -v upgrade_services_is_active >/dev/null 2>&1; then
    if upgrade_services_is_active "$name" "$selector"; then running=yes; running_source=service_status
    else
      result=$?
      # Old init scripts can return 1 for an unsupported status action; do not call that stopped.
      if [ "$result" -eq 1 ] && { $systemd || [ "$name" = postfix ]; }; then running=no; running_source=service_status; fi
    fi
  fi
  # Exact command names are positive evidence only; no TCP listener does not mean a service is stopped.
  if [ "$running" = unknown ]; then
    processes=$manifest_processes
    case "$name" in
      apache2|httpd) state='apache2|httpd';; nginx) state=nginx;; caddy) state=caddy;; dovecot) state=dovecot;;
      mysql|mariadb) state='mysqld|mariadbd';; exim4|exim) state='exim|exim4';; courier) state='couriertcpd|courierimaplogin|imapd|pop3d';;
      postgresql) state=postgres;; sendmail) state=sendmail;; mailman) state='mailman|mailmanctl';; *) state=$selector;;
    esac
    if printf '%s\n' "$processes" | grep -qxE "$state"; then running=yes; running_source=process_name; fi
  fi
  if $systemd && command -v systemctl >/dev/null 2>&1; then
    # UnitFileState=enabled-runtime -> enabled=yes; UnitFileState=masked -> enabled=no.
    if state=$(manifest_run_bounded 2 systemctl show -p UnitFileState "$selector.service" 2>/dev/null); then
      case "$state" in UnitFileState=enabled|UnitFileState=enabled-runtime) enabled=yes;; UnitFileState=disabled|UnitFileState=masked|UnitFileState=masked-runtime) enabled=no;; esac
      enabled_source=systemd
    fi
  elif [ -f "$manifest_root/etc/init/$selector.conf" ]; then
    enabled_source=upstart_job_not_checked
  elif [ -e "$manifest_root/etc/init.d/$selector" ]; then
    enabled=no; enabled_source=sysv_start_links
    for link in "$manifest_root"/etc/rc[2345].d/S[0-9][0-9]"$selector"; do
      [ -e "$link" ] || continue
      enabled=yes; break
    done
  fi
  case "$name" in postgresql-*) enabled=unknown; enabled_source=cluster_start_policy_not_checked;; esac
  manifest_emit service name "$name" package "$package" version "$version" running "$running" enabled "$enabled" status_source "$running_source" enabled_source "$enabled_source"
}

function manifest_packages() {
  local postgres_pattern='^postgresql-[0-9]+([.][0-9]+)*$'
  local package version status architecture records name release seen_services='|'
  if ! records=$(packages_output_inventory "$manifest_package_backend" 2>/dev/null); then
    manifest_emit warning area packages reason "$manifest_package_backend query failed; package inventory unknown"
    manifest_collection_failed=true
    return
  fi
  # Prefer the daemon owner over plugins and transitional package names.
  # nginx:amd64<TAB>1.24.0<TAB>install ok installed<TAB>amd64 -> name=nginx, version=1.24.0.
  # dovecot-core plus dovecot-imapd -> one service owned by dovecot-core; residual config-files rows are skipped.
  records=$(set -o pipefail; printf '%s\n' "$records" | awk -F '\t' '
    $3 ~ /(^| )installed$/ {
      name=$1; sub(/:.*/, "", name); key=$1 SUBSEP $4; rows[key]=$0; names[key]=name; score=0
      if (name == "dovecot-core") score=5
      else if (name == "dovecot-common") score=4
      else if (name == "dovecot") score=3
      else if (name == "dovecot-imapd") score=2
      else if (name == "dovecot-pop3d") score=1
      if (score > best) { best=score; dovecot=name }
      if (name ~ /^mariadb-server($|-[0-9])/) maria=1
    }
    END {
      for (package in rows) {
        name=names[package]
        if (name ~ /^dovecot(-core|-common|-imapd|-pop3d)?$/ && name != dovecot) continue
        if (maria && name ~ /^mysql-server($|-[0-9])/) continue
        print rows[package]
      }
    }
  ' | LC_ALL=C sort) || { manifest_collection_failed=true; return; }
  while IFS=$'\t' read -r package version status architecture; do
    case "$status" in installed|*' installed') :;; *) continue;; esac
    package=${package%%:*}
    case "$package" in
      libapache2-mod-php*|php|php-*|php[0-9]*|rh-php[0-9]*-php*)
        manifest_php_packages+=("$package"); manifest_php_versions+=("$version")
        manifest_emit package name "$package" version "$version" architecture "${architecture:-unknown}" package_backend "$manifest_package_backend";;
    esac
    name=''
    case "$package" in
      apache2|apache2-bin|apache2.2-common) name=apache2;; httpd) name=httpd;; nginx|nginx-core|nginx-full|nginx-light|nginx-extras) name=nginx;;
      caddy|postfix|redis|redis-server|fail2ban) name=$package;; exim4*daemon*|exim4) name=exim4;; exim) name=exim;;
      sendmail|sendmail-bin) name=sendmail;; dovecot|dovecot-core|dovecot-common|dovecot-imapd|dovecot-pop3d) name=dovecot;; courier*) name=courier;; mailman*) name=mailman;;
      mysql-server|mysql-server-[0-9]*) name=mysql;; mariadb-server|mariadb-server-[0-9]*|MariaDB-server) name=mariadb;; postgresql-server) name=postgresql;; postgresql[0-9][0-9]-server)
        release=${package#postgresql}; release=${release%-server}
        case "$release" in 8?|9?) release="${release:0:1}.${release:1}";; esac
        name=postgresql-$release;; postgresql-[0-9]*)
        if [[ "$package" =~ $postgres_pattern ]]; then name=$package; fi;;
    esac
    if [ -n "$name" ]; then
      case "$seen_services" in *"|$name|"*) continue;; esac
      seen_services="$seen_services$name|"
      manifest_service "$name" "$package" "$version"
    else
      case "$package" in
        perl|perl-base|ruby|ruby[0-9].[0-9]|ruby[0-9].[0-9].[0-9]|python2|python2.[0-9]|python3|python3.[0-9]|python3.[0-9][0-9]|nodejs)
          manifest_emit package name "$package" version "$version" architecture "${architecture:-unknown}" package_backend "$manifest_package_backend";;
      esac
    fi
  done <<< "$records"
}

function manifest_read_metadata() {
  # Configuration/metadata only: cap individual files even when they contain a huge single line.
  [ -f "$1" ] && [ -r "$1" ] || return 1
  head -c 1048576 -- "$1" 2>/dev/null
}

# These conventional paths give migration hints, not complete server configuration.
# Custom include trees or startup flags can select other files; missing findings do not prove a service is absent.
function manifest_config_files() {
  local kind="$1" file count=0
  local -a files=()
  case "$kind" in
    apache) files=("$manifest_root"/etc/apache2/apache2.conf "$manifest_root"/etc/apache2/sites-enabled/* "$manifest_root"/etc/apache2/conf-enabled/* "$manifest_root"/etc/httpd/conf/httpd.conf "$manifest_root"/etc/httpd/conf.d/*.conf) ;;
    apache-modules) files=("$manifest_root"/etc/apache2/apache2.conf "$manifest_root"/etc/apache2/mods-enabled/*.load "$manifest_root"/etc/apache2/conf-enabled/*.conf "$manifest_root"/etc/apache2/sites-enabled/*.conf "$manifest_root"/etc/httpd/conf/httpd.conf "$manifest_root"/etc/httpd/conf.modules.d/*.conf "$manifest_root"/etc/httpd/conf.d/*.conf) ;;
    nginx) files=("$manifest_root"/etc/nginx/nginx.conf "$manifest_root"/etc/nginx/sites-enabled/* "$manifest_root"/etc/nginx/conf.d/*.conf) ;;
    caddy) files=("$manifest_root"/etc/caddy/Caddyfile) ;;
    fpm) files=("$manifest_root"/etc/php/*/fpm/pool.d/*.conf "$manifest_root"/etc/php5/fpm/pool.d/*.conf "$manifest_root"/etc/php-fpm.d/*.conf "$manifest_root"/etc/opt/remi/php*/php-fpm.d/*.conf "$manifest_root"/etc/opt/rh/rh-php*/php-fpm.d/*.conf) ;;
  esac
  for file in "${files[@]}"; do
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then continue; fi
    count=$((count+1))
    [ "$count" -le 200 ] || break
    printf '%s\n' "$file"
  done
}

# Match active LoadModule paths to installed package ownership; never load the module.
function manifest_apache_php() {
  local version_pattern='^([0-9]+[.][0-9]+([.][0-9]+)?)'
  local files records metadata
  local file module conditional owner package version source i server_root=/etc/httpd seen='' ambiguous=false count=0
  if [ -r "$manifest_root/etc/httpd/conf/httpd.conf" ]; then
    metadata=$(manifest_read_metadata "$manifest_root/etc/httpd/conf/httpd.conf") || { manifest_collection_failed=true; return; }
    server_root=$(awk '
      # ServerRoot "/etc/httpd" -> /etc/httpd; ServerRoot ${HTTPD_ROOT} -> unknown.
      BEGIN { root="/etc/httpd" }
      tolower($1) == "serverroot" { root=$2; gsub(/[\042\047]/,"",root); if (NF != 2 || root !~ /^\// || root ~ /[$%{}]/) root="unknown" }
      END { print root }' <<< "$metadata") || { manifest_collection_failed=true; return; }
  fi
  files=$(manifest_config_files apache-modules) || { manifest_collection_failed=true; return; }
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    metadata=$(manifest_read_metadata "$file") || { manifest_collection_failed=true; continue; }
    records=$(awk '
      FNR > 20000 { exit }
      /^[ \t]*#/ { next }
      tolower($1) ~ /^<if/ { conditional++ }
      tolower($1) ~ /^<\/if/ && conditional > 0 { conditional-- }
      tolower($1) == "loadmodule" && tolower($2) ~ /^php[0-9.]*_module$/ {
        # LoadModule php_module modules/libphp.so -> modules/libphp.so<TAB>false outside an If block.
        path=$3; gsub(/[\042\047]/,"",path)
        print path "\t" (conditional ? "true" : "false")
      }' <<< "$metadata") || { manifest_collection_failed=true; continue; }
    while IFS=$'\t' read -r module conditional; do
      [ -n "$module" ] || continue
      case "|$seen|" in *"|$module|"*) continue;; esac
      seen="$seen|$module"
      package=unknown; version=unknown; source=unknown
      # Common RPM module paths are relative to ServerRoot; never expand config expressions.
      case "$file:$module:$server_root" in "$manifest_root"/etc/httpd/*:modules/*:/*) module="$server_root/$module";; esac
      case "$module" in
        /*)
          if [ -f "$manifest_root$module" ] && [ "$conditional" = false ]; then
            if owner=$(packages_output_file_owner "$module" "$manifest_package_backend"); then
              owner=${owner%%:*}
              for ((i=0; i<${#manifest_php_packages[@]}; i++)); do
                [ "$owner" = "${manifest_php_packages[i]}" ] || continue
                if [ "$package" != unknown ]; then ambiguous=true; fi
                package=$owner
                version=${manifest_php_versions[i]#*:}
                if [[ "$version" =~ $version_pattern ]]; then version=${BASH_REMATCH[1]}
                else version=unknown; fi
              done
            fi
          fi;;
      esac
      count=$((count+1))
      [ "$conditional" = false ] || ambiguous=true
      [ "$version" = unknown ] || source=installed_module_package
      manifest_apache_php_version=$version
      manifest_apache_php_package=$package
      manifest_emit runtime kind apache-mod-php version "$version" package "$package" module "$module" config "${file#"$manifest_root"}" conditional "$conditional" version_source "$source"
    done <<< "$records"
  done <<< "$files"
  if [ "$count" -gt 1 ] || $ambiguous; then
    manifest_apache_php_version=unknown
    manifest_apache_php_package=unknown
  fi
  if [ "$count" -eq 1 ] && ! $ambiguous; then manifest_apache_php_available=true; fi
}

function manifest_has_php_document_root() {
  local root=$1 entry found
  for entry in index.php wp-includes/version.php administrator/manifests/files/joomla.xml core/lib/Drupal.php includes/constants.php includes/DefaultSettings.php version.php artisan; do
    [ ! -f "$manifest_root$root/$entry" ] || return 0
  done
  case "$root" in /*) :;; *) return 1;; esac
  case "$root" in /|*'$'*|*'%'*|*'{'*|*'}'*) return 1;; esac
  command -v timeout >/dev/null 2>&1 || command -v perl >/dev/null 2>&1 || return 1
  # Inspect immediate app children only; backup trees do not establish a site's PHP runtime.
  found=$(manifest_run_bounded 2 find -H "$manifest_root$root" -mindepth 1 -maxdepth 2 \
    \( -type d \( -name '.*' -o -name '*.bak' -o -name '*.backup' -o -name '*.old' -o -name '*~' -o -name backup -o -name backups \) -prune \) -o \
    \( -xtype f -name '*.php' -print -quit \) 2>/dev/null) || return 1
  [ -n "$found" ]
}

function manifest_fpm_pools() {
  local file pool socket user group chroot version package package_version source i
  local files records metadata candidate owner
  local version_pattern='^([0-9]+[.][0-9]+([.][0-9]+)?)'
  files=$(manifest_config_files fpm) || { manifest_collection_failed=true; return; }
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    version=${file#"$manifest_root"/etc/php/}; version=${version%%/*}
    case "$file" in
      */etc/php5/*) version=5;;
      */etc/php-fpm.d/*|*/etc/opt/*) version=unknown;;
    esac
    package=unknown; package_version=unknown; source=config_path
    [ "$version" != unknown ] || source=unknown
    if owner=$(packages_output_file_owner "${file#"$manifest_root"}" "$manifest_package_backend"); then
      owner=${owner%%:*}
      for ((i=0; i<${#manifest_php_packages[@]}; i++)); do
        [ "$owner" = "${manifest_php_packages[i]}" ] || continue
        candidate=${manifest_php_versions[i]#*:}
        if [[ "$candidate" =~ $version_pattern ]]; then
          version=${BASH_REMATCH[1]}; package=$owner; package_version=${manifest_php_versions[i]}; source=installed_pool_package
        fi
      done
    fi
    metadata=$(manifest_read_metadata "$file") || { manifest_collection_failed=true; continue; }
    # [www], listen = /run/php/php8.2-fpm.sock, user = USER (separate lines)
    # -> pool=www, socket=/run/php/php8.2-fpm.sock, user=USER; missing group/chroot stay unknown.
    records=$(awk '
      function reset() { socket="unknown"; user="unknown"; group="unknown"; chroot="unknown" }
      function output() { if (pool != "" && pool != "global") print pool "\t" socket "\t" user "\t" group "\t" chroot }
      BEGIN { reset() }
      FNR > 20000 { exit }
      /^[ \t]*[;#]/ { next }
      /^[ \t]*\[/ { output(); pool=$0; gsub(/^[ \t]*\[|\][ \t]*$/,"",pool); reset(); next }
      /^[ \t]*(listen|user|group|chroot)[ \t]*=/ {
        key=$0; sub(/[ \t]*=.*/,"",key); gsub(/^[ \t]+/,"",key)
        value=$0; sub(/^[^=]*=[ \t]*/,"",value); sub(/[ \t]*;.*/,"",value)
        if (key == "listen") socket=value
        else if (key == "user") user=value
        else if (key == "group") group=value
        else chroot=value
      }
      END { output() }' <<< "$metadata") || { manifest_collection_failed=true; continue; }
    while IFS=$'\t' read -r pool socket user group chroot; do
      [ -n "$pool" ] || continue
      manifest_fpm_sockets+=("$socket")
      manifest_fpm_users+=("$user")
      manifest_fpm_versions+=("$version")
      manifest_fpm_packages+=("$package")
      manifest_emit runtime kind php-fpm pool "$pool" listen "$socket" user "$user" version "$version" package "$package" package_version "$package_version" version_source "$source" group "$group" chroot "$chroot" config "${file#"$manifest_root"}"
    done <<< "$records"
  done <<< "$files"
}

function manifest_dns() {
  local lookup lookup_status diagnostic
  local domain="$1" address addresses='' match=false result reason i
  manifest_dns_addresses=unknown
  manifest_dns_result=unknown
  if ! $manifest_dns_enabled; then manifest_dns_reason=disabled; return; fi
  # example.invalid passes syntax checking; *.example.invalid and ${DOMAIN} remain unresolved names.
  if [[ ! "$domain" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[.][A-Za-z0-9-]+$ ]]; then
    manifest_dns_reason=wildcard_or_dynamic_name; return
  fi
  for ((i=0; i<${#manifest_dns_names[@]}; i++)); do
    if [ "${manifest_dns_names[i]}" = "$domain" ]; then
      manifest_dns_addresses=${manifest_dns_values[i]}
      manifest_dns_result=${manifest_dns_results[i]}
      manifest_dns_reason=${manifest_dns_reasons[i]}
      return
    fi
  done
  if [ "${#manifest_dns_names[@]}" -ge "$manifest_dns_limit" ]; then manifest_dns_reason=domain_limit; return; fi
  if { ! command -v timeout >/dev/null 2>&1 && ! command -v perl >/dev/null 2>&1; } ||
      { ! command -v getent >/dev/null 2>&1 && ! command -v host >/dev/null 2>&1; }; then
    manifest_dns_reason=resolver_or_timeout_unavailable; return
  fi
  if command -v getent >/dev/null 2>&1 && addresses=$(manifest_run_bounded 2 getent ahosts "$domain" 2>/dev/null); then
    # 192.0.2.1 STREAM example.invalid plus a DGRAM row for the same address -> one 192.0.2.1.
    addresses=$(printf '%s\n' "$addresses" | awk '!seen[$1]++ { if (value != "") value=value ","; value=value $1 } END { print value }')
    if [ -n "$addresses" ]; then
      for address in ${addresses//,/ }; do
        case " $manifest_local_addresses " in *" $address "*) match=true ;; esac
      done
      if [ -z "$manifest_local_addresses" ]; then result=unknown; reason=local_addresses_unavailable
      elif $match; then result=this_host; reason=resolved
      else result=other_address; reason=resolved; fi
    else addresses=unknown; result=unknown; reason=no_addresses; fi
  else
    lookup_status=$?; addresses=unknown; result=unknown; reason=resolution_failed_or_timed_out
    case "$lookup_status" in 124|142) reason=timed_out;; esac
  fi
  if [ "$addresses" = unknown ] && command -v host >/dev/null 2>&1; then
    # getent hides DNS error codes. Ask once for this absolute name, without importing resolver output.
    lookup=$(LC_ALL=C manifest_run_bounded 2 host -W 1 -R 1 -t A "$domain." 2>&1)
    lookup_status=$?
    case "$lookup_status" in
      0) :;;
      124|142) reason=timed_out;;
      *)
        diagnostic=$(awk -v requested="$domain" '
          # Host example.invalid not found: 3(NXDOMAIN) -> nxdomain for requested=example.invalid.
          # If example.invalid is an alias for missing.example.invalid., a target NXDOMAIN -> cname_target_not_found.
          BEGIN { requested=tolower(requested) }
          $2 == "is" && $3 == "an" && $4 == "alias" && $5 == "for" {
            name=tolower($1); sub(/[.]$/, "", name)
            if (name == requested || name == target) { alias=1; target=tolower($6); sub(/[.]$/, "", target) }
          }
          $1 == "Host" && $3 == "not" && $4 == "found:" {
            name=tolower($2); sub(/[.]$/, "", name)
            if (name != requested && name != target) next
            if ($5 == "3(NXDOMAIN)") reason="nxdomain"
            else if ($5 == "2(SERVFAIL)") reason="servfail"
            else if ($5 == "5(REFUSED)") reason="refused"
          }
          /connection timed out/ { if (reason == "") reason="timed_out" }
          END {
            # A CNAME can exist while its target does not; keep that distinction.
            if (reason == "nxdomain" && alias) reason="cname_target_not_found"
            print reason
          }
        ' <<< "$lookup") || diagnostic=''
        case "$diagnostic" in
          nxdomain) result=not_found; reason=nxdomain;;
          servfail|refused|timed_out|cname_target_not_found) reason=$diagnostic;;
        esac;;
    esac
  fi
  manifest_dns_names+=("$domain"); manifest_dns_values+=("$addresses")
  manifest_dns_results+=("$result"); manifest_dns_reasons+=("$reason")
  manifest_dns_addresses="$addresses"; manifest_dns_result="$result"; manifest_dns_reason="$reason"
}

# Read version declarations as text. Executing an application file to obtain
# its version could run customer code, load secrets or change the application during inventory collection.
function manifest_application() {
  local version_pattern='^[0-9][A-Za-z0-9.+_()\ -]{0,100}$'
  local document_root="$1" file='' application=unknown version=unknown language=unknown language_version=unknown version_source=unknown modified=unknown
  case "$document_root" in /*) ;; *) return ;; esac
  case "$document_root" in *'$'*|*'%'*|*'{'*|*'}'*) return ;; esac
  if [ -f "$manifest_root$document_root/wp-includes/version.php" ]; then
    file="$manifest_root$document_root/wp-includes/version.php"; application=WordPress; language=PHP
    # $wp_version = "6.5.3"; -> version=6.5.3.
    version=$(awk '/^[ \t]*\$wp_version[ \t]*=/ { line=$0; sub(/^[^=]*=[ \t]*[\047\042]/,"",line); sub(/[\047\042].*$/,"",line); print line; exit }' <<< "$(manifest_read_metadata "$file")")
  elif [ -f "$manifest_root$document_root/administrator/manifests/files/joomla.xml" ]; then
    file="$manifest_root$document_root/administrator/manifests/files/joomla.xml"; application=Joomla; language=PHP
    # <version>5.1.0</version> -> version=5.1.0.
    version=$(awk 'match($0,/<version>[^<]+/) { print substr($0,RSTART+9,RLENGTH-9); exit }' <<< "$(manifest_read_metadata "$file")")
  elif [ -f "$manifest_root$document_root/core/lib/Drupal.php" ]; then
    file="$manifest_root$document_root/core/lib/Drupal.php"; application=Drupal; language=PHP
    # const VERSION = "10.2.0"; -> version=10.2.0.
    version=$(awk '/const VERSION[ \t]*=/ { line=$0; sub(/^[^=]*=[ \t]*[\047\042]/,"",line); sub(/[\047\042].*$/,"",line); print line; exit }' <<< "$(manifest_read_metadata "$file")")
  elif [ -f "$manifest_root$document_root/includes/constants.php" ] && grep -q 'PHPBB_VERSION' <<< "$(manifest_read_metadata "$manifest_root$document_root/includes/constants.php")"; then
    file="$manifest_root$document_root/includes/constants.php"; application=phpBB; language=PHP
    # define("PHPBB_VERSION", "3.3.12"); -> version=3.3.12.
    version=$(awk '/define[ \t]*\([ \t]*[\047\042]PHPBB_VERSION[\047\042]/ { line=$0; sub(/^.*PHPBB_VERSION[\047\042][ \t]*,[ \t]*[\047\042]/,"",line); sub(/[\047\042].*$/,"",line); print line; exit }' <<< "$(manifest_read_metadata "$file")")
  elif [ -f "$manifest_root$document_root/includes/DefaultSettings.php" ] && grep -q "\\\$wgVersion" <<< "$(manifest_read_metadata "$manifest_root$document_root/includes/DefaultSettings.php")"; then
    file="$manifest_root$document_root/includes/DefaultSettings.php"; application=MediaWiki; language=PHP
    # $wgVersion = "1.41.0"; -> version=1.41.0.
    version=$(awk '/^[ \t]*\$wgVersion[ \t]*=/ { line=$0; sub(/^[^=]*=[ \t]*[\047\042]/,"",line); sub(/[\047\042].*$/,"",line); print line; exit }' <<< "$(manifest_read_metadata "$file")")
  elif [ -f "$manifest_root$document_root/version.php" ] && [ -f "$manifest_root$document_root/lib/moodlelib.php" ]; then
    file="$manifest_root$document_root/version.php"; application=Moodle; language=PHP
    # $release = "4.3.3"; -> version=4.3.3; a Build: suffix becomes unknown because the whitelist rejects colons.
    version=$(awk '/^[ \t]*\$release[ \t]*=/ { line=$0; sub(/^[^=]*=[ \t]*[\047\042]/,"",line); sub(/[\047\042].*$/,"",line); print line; exit }' <<< "$(manifest_read_metadata "$file")")
  elif [ -f "$manifest_root$document_root/artisan" ]; then application=Laravel; language=PHP
  elif [ -f "$manifest_root$document_root/config.ru" ] || [ -f "$manifest_root$document_root/Gemfile" ]; then language=Ruby
  elif [ -f "$manifest_root$document_root/package.json" ]; then language=JavaScript
  elif [ -f "$manifest_root$document_root/manage.py" ] || [ -f "$manifest_root$document_root/app.wsgi" ]; then language=Python
  elif [ -f "$manifest_root$document_root/index.php" ]; then language=PHP
  elif [ -f "$manifest_root$document_root/index.pl" ]; then language=Perl
  elif [ -f "$manifest_root$document_root/index.cgi" ]; then
    # First line #!/usr/bin/perl -> language=Perl; #!/usr/bin/python3 -> language=Python.
    language=$(awk 'NR == 1 { if ($0 ~ /^#!.*perl/) print "Perl"; else if ($0 ~ /^#!.*python/) print "Python"; else print "unknown"; exit }' <<< "$(manifest_read_metadata "$manifest_root$document_root/index.cgi")")
  fi
  # A version is metadata, never an arbitrary expression or configuration value.
  # 6.5.3 and 6.5.3 (stable) pass; VERSION_CONSTANT and 6.5.3;extra become unknown.
  if [[ ! "$version" =~ $version_pattern ]]; then version=unknown; fi
  if [ -n "$file" ]; then modified=$(stat -c '%y' -- "$file" 2>/dev/null) || modified=unknown; fi
  case "$language" in
    Ruby) file="$manifest_root$document_root/.ruby-version" ;;
    Python) file="$manifest_root$document_root/.python-version" ;;
    *) file= ;;
  esac
  if [ -n "$file" ] && [ -r "$file" ]; then
    # First line 3.11.8 in .python-version -> language_version=3.11.8, declared by the project.
    language_version=$(awk 'NR == 1 { print; exit }' <<< "$(manifest_read_metadata "$file")")
    if [[ "$language_version" =~ ^[0-9][0-9A-Za-z.+_-]{0,60}$ ]]; then version_source=project_declared_not_verified_runtime
    else language_version=unknown; fi
  fi
  manifest_emit application document_root "$document_root" application "$application" version "$version" language "$language" language_version "$language_version" language_version_source "$version_source" version_file_modified "$modified" date_basis filesystem_metadata_not_install_date
}

# Infer the website runtime from its handler, FPM pool or Apache module.
# The shell default php binary can serve a different purpose or version. Configured URLs still need application checks.
function manifest_website() {
  local name_port_pattern='^([^:]+|\[[^]]+\]):([0-9]+)$'
  local server="$1" names="$2" port="$3" tls="$4" document_root="$5" user="$6" runtime="$7" config="$8"
  local name url scheme=http primary_url=unknown primary=true runtime_version=unknown runtime_source=unknown runtime_package=unknown i matched_pool=-1 ambiguous_pool=false
  local certificate_file=${9:-unknown} certificate_file_present=unknown proxy=${10:-unknown}
  local url_host_pattern='^([A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9A-Fa-f:.]+\])$'
  # shortcut: Check direct paths only; resolve includes/automatic TLS if richer inventory is needed.
  case "$certificate_file" in
    *'$'*|*'%'*|*'{'*|*'}'*|*'"'*|*"'"*) certificate_file=unknown;;
    /*)
      if [ -f "$manifest_root$certificate_file" ] && [ -s "$manifest_root$certificate_file" ]; then
        certificate_file_present=true
      else
        certificate_file_present=false
      fi;;
    *) certificate_file=unknown;;
  esac
  for ((i=0; i<${#manifest_fpm_sockets[@]}; i++)); do
    if [ "$runtime" = "${manifest_fpm_sockets[i]}" ] && [ "$runtime" != unknown ]; then
      if [ "$matched_pool" -ge 0 ]; then ambiguous_pool=true; fi
      matched_pool=$i
    fi
  done
  if [ "$matched_pool" -ge 0 ]; then
    runtime=php-fpm
    if $ambiguous_pool; then
      user=unknown; runtime_source=ambiguous_fpm_pool_config
    else
      user=${manifest_fpm_users[matched_pool]}; runtime_version=${manifest_fpm_versions[matched_pool]}
      runtime_package=${manifest_fpm_packages[matched_pool]}; runtime_source=fpm_pool_config
    fi
  fi
  case "$runtime" in
    php-fpm|php_disabled) :;;
    /*|*fcgi*) runtime=fastcgi_handler_version_unknown;;
    *php*) runtime=php_handler_version_unknown;;
  esac
  if [ "$server" = apache ] && $manifest_apache_php_available; then
    if [ "$runtime" = php_handler_version_unknown ] || { [ "$runtime" = unknown ] && manifest_has_php_document_root "$document_root"; }; then
      runtime='apache-mod-php'; runtime_version=$manifest_apache_php_version; runtime_package=$manifest_apache_php_package
      runtime_source=enabled_module_inferred_for_php_site
    fi
  fi
  [ "$tls" != true ] || scheme=https
  # Configs use comma-separated names internally; whitespace and controls are removed by the parsers.
  # example.invalid:8443 -> name=example.invalid, port=8443; [2001:db8::1]:443 keeps the brackets.
  for name in ${names//,/ }; do
    case "$name" in https://*) scheme=https; name=${name#https://} ;; http://*) scheme=http; name=${name#http://} ;; esac
    if [[ "$name" =~ $name_port_pattern ]]; then
      port=${BASH_REMATCH[2]}; name=${BASH_REMATCH[1]}
    elif [[ "$name" == *:* ]] && [[ "$name" != \[*\] ]]; then name="[$name]"; fi
    url="$scheme://$name"
    case "$scheme:$port" in http:80|https:443|*:unknown) ;; *) url="$url:$port" ;; esac
    case "$name" in unknown|_) url=unknown;; esac
    if $primary; then
      if [[ "$name" =~ $url_host_pattern ]]; then primary_url=$url; fi
      primary=false
    fi
    manifest_dns "$name"
    manifest_emit website server "$server" name "$name" port "$port" tls "$tls" url "$url" primary_url "$primary_url" certificate_file "$certificate_file" certificate_file_present "$certificate_file_present" document_root "$document_root" user "$user" runtime "$runtime" runtime_version "$runtime_version" runtime_version_source "$runtime_source" runtime_package "$runtime_package" config "$config" dns "$manifest_dns_result" dns_addresses "$manifest_dns_addresses" dns_reason "$manifest_dns_reason" proxy "$proxy" proxy_basis literal_config_authority_not_resolved
  done
  case "|$manifest_seen_roots|" in *"|$document_root|"*) ;; *)
    manifest_seen_roots="$manifest_seen_roots|$document_root"
    manifest_application "$document_root"
    manifest_web_indicators "$document_root" ;;
  esac
}

function manifest_websites() {
  local server file names port tls document_root user runtime certificate proxy default_user
  local files records metadata
  for server in apache nginx caddy; do
    default_user=unknown
    case "$server" in
      apache)
        if [ -r "$manifest_root/etc/apache2/envvars" ]; then
          # export APACHE_RUN_USER=www-data -> default_user=www-data; variable expressions are not expanded.
          default_user=$(awk '/^[ \t]*(export[ \t]+)?APACHE_RUN_USER=[A-Za-z_][A-Za-z0-9_-]*[ \t]*$/ { sub(/^.*=/, ""); gsub(/[ \t]/, ""); print; exit }' <<< "$(manifest_read_metadata "$manifest_root/etc/apache2/envvars")")
          [ -n "$default_user" ] || default_user=unknown
        elif [ -r "$manifest_root/etc/httpd/conf/httpd.conf" ]; then
          default_user=$(awk 'tolower($1) == "user" && $2 ~ /^[A-Za-z_][A-Za-z0-9_-]*$/ { print $2; exit }' <<< "$(manifest_read_metadata "$manifest_root/etc/httpd/conf/httpd.conf")")
          [ -n "$default_user" ] || default_user=unknown
        fi ;;
      nginx)
        if [ -r "$manifest_root/etc/nginx/nginx.conf" ]; then
          default_user=$(awk '/^[ \t]*user[ \t]+[A-Za-z_][A-Za-z0-9_-]*[; \t]/ { value=$2; gsub(/;/,"",value); print value; exit }' <<< "$(manifest_read_metadata "$manifest_root/etc/nginx/nginx.conf")")
          [ -n "$default_user" ] || default_user=unknown
        fi ;;
    esac
    files=$(manifest_config_files "$server") || { manifest_collection_failed=true; return; }
    while IFS= read -r file; do
      [ -n "$file" ] || continue
      metadata=$(manifest_read_metadata "$file") || { manifest_collection_failed=true; continue; }
      records=$(awk -v server="$server" -v default_user="$default_user" '
        function reset( i) { names="unknown"; port="unknown"; tls="unknown"; root="unknown"; user=default_user; runtime="unknown"; certificate="unknown"; proxy="unknown"; listeners=0; for (i in ports) delete ports[i]; for (i in secure) delete secure[i] }
        function emit( i) {
          if (!active) return
          if (!listeners) print names "\t" port "\t" tls "\t" root "\t" user "\t" runtime "\t" certificate "\t" proxy
          else for (i=1; i<=listeners; i++) print names "\t" ports[i] "\t" secure[i] "\t" root "\t" user "\t" runtime "\t" certificate "\t" proxy
        }
        function certificate_path(value) {
          sub(/^[ \t]*[^ \t]+[ \t]+/,"",value); sub(/[; \t]+$/,"",value)
          return value
        }
        function record_certificate(value) {
          gsub(/^[\042\047]|[\042\047]$/,"",value)
          if (certificate == "unknown") certificate=value
          else if (certificate != value) certificate="multiple"
        }
        # Retain only a literal authority; userinfo, paths, query strings and fragments can contain secrets.
        # http://127.0.0.1:8080/private?token=TOKEN -> proxy=127.0.0.1:8080; http://${UPSTREAM} -> unresolved.
        function record_proxy(value, endpoint) {
          gsub(/^[\042\047]|[;\042\047]+$/,"",value)
          if (value ~ /[$%{}]/) { proxy="unresolved"; return }
          endpoint=value
          sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//,"",endpoint)
          sub(/[\/?#].*$/,"",endpoint); sub(/^.*@/,"",endpoint)
          if (endpoint !~ /^[A-Za-z0-9_.-]+(:[0-9]+)?$/ && endpoint !~ /^\[[0-9A-Fa-f:.]+\](:[0-9]+)?$/) { proxy="unresolved"; return }
          if (proxy == "unknown") proxy=endpoint
          else if (proxy != endpoint) proxy="multiple_or_unresolved"
        }
        function append_names(start, stop, i, v) {
          for (i=start; i<=stop; i++) { v=$i; gsub(/[;\042\047]/,"",v); if (v != "") { if (names == "unknown") names=v; else names=names "," v } }
        }
        BEGIN { reset() }
        FNR > 20000 { exit }
        /^[ \t]*#/ { next }
        {
          line=$0; sub(/[ \t]+#.*/,"",line); $0=line
          if (server == "apache") {
            # <VirtualHost *:443>, ServerName example.invalid, DocumentRoot /var/www/html (separate lines)
            # -> names=example.invalid, port=443, root=/var/www/html; SSLEngine on sets tls=true.
            key=tolower($1)
            if (key == "<virtualhost") { emit(); reset(); active=1; port=$2; gsub(/[>]/,"",port); sub(/^.*:/,"",port); next }
            if (key == "</virtualhost>") { emit(); active=0; next }
            if (!active) next
            # ServerName is primary even when ServerAlias appears first.
            if (key == "servername") {
              value=$2; gsub(/[;\042\047]/,"",value)
              if (names == "unknown") names=value; else names=value "," names
            }
            if (key == "serveralias") append_names(2,NF)
            if (key == "proxypass" || key == "proxypassmatch") record_proxy($3)
            if (key == "sslcertificatefile") record_certificate(certificate_path($0))
            if (key == "documentroot") { root=$0; sub(/^[ \t]*[^ \t]+[ \t]+/,"",root); gsub(/^[\042\047]|[\042\047][ \t]*$/,"",root) }
            if (key == "suexecusergroup" || key == "assignuserid") user=$2
            if (key == "sslengine" && tolower($2) == "on") tls="true"
            if ((key == "php_flag" || key == "php_admin_flag") && tolower($2) == "engine" && tolower($3) == "off") runtime="php_disabled"
            if (key == "sethandler" && tolower($2) ~ /^(none|default-handler)$/) runtime="php_disabled"
            if (key == "sethandler" || key == "proxypassmatch" || key == "fcgidwrapper") {
              if (match($0,/unix:[^| \t\042\047]+/)) { runtime=substr($0,RSTART+5,RLENGTH-5) }
              else if ($0 ~ /php/) runtime="php_handler_version_unknown"
              else if ($0 ~ /fcgi/) runtime="fastcgi_version_unknown"
            }
          } else if (server == "nginx") {
            # In a server block: listen 443 ssl; -> port=443, tls=true; root /var/www/html; -> root=/var/www/html.
            # fastcgi_pass unix:/run/php/php8.2-fpm.sock; -> runtime=/run/php/php8.2-fpm.sock.
            opens=gsub(/\{/,"{",line); closes=gsub(/\}/,"}",line)
            if (!active && $1 == "server" && opens > 0) { reset(); active=1; depth=0 }
            if (active) {
              if ($1 == "server_name") append_names(2,NF)
              if ($1 == "listen") {
                value=$2; gsub(/;/,"",value); port=value
                if (value ~ /:/) sub(/^.*:/,"",port)
                if (value !~ /[0-9]$/) port="unknown"
                listeners++; ports[listeners]=port; secure[listeners]="false"
                if ($0 ~ /(^|[ \t])ssl([ \t;]|$)/) secure[listeners]="true"
              }
              if ($1 == "ssl_certificate") { tls="true"; record_certificate(certificate_path($0)) }
              if ($1 == "root" && depth == 1) { root=$0; sub(/^[ \t]*root[ \t]+/,"",root); sub(/;[ \t]*$/,"",root); gsub(/^[\042\047]|[\042\047]$/,"",root) }
              if ($1 == "user") user=$2
              if ($1 == "fastcgi_pass") { runtime=$2; sub(/^unix:/,"",runtime); gsub(/;/,"",runtime) }
              if ($1 == "proxy_pass") { runtime="reverse_proxy"; record_proxy($2) }
              if ($1 == "uwsgi_pass") runtime="uwsgi"
              depth += opens-closes
              if (depth <= 0) { emit(); active=0 }
            }
          } else if (server == "caddy") {
            # example.invalid { starts a site on 443; root * /var/www/html sets root=/var/www/html.
            # php_fastcgi unix//run/php/php8.2-fpm.sock -> runtime=/run/php/php8.2-fpm.sock.
            opens=gsub(/\{/,"{",line); closes=gsub(/\}/,"}",line)
            if (!active && opens > 0 && $1 !~ /^\(/ && $1 != "{") { reset(); active=1; depth=0; append_names(1,NF-1); port="443"; tls="true"; if ($1 ~ /^http:\/\//) { port="80"; tls="false" }; sub(/^https?:\/\//,"",names) }
            if (active) {
              if ($1 == "root") { root=$0; sub(/^[ \t]*root[ \t]+(\*[ \t]+)?/,"",root); gsub(/^[\042\047]|[\042\047][ \t]*$/,"",root) }
              if ($1 == "tls" && NF >= 3 && $3 != "{") {
                if ($2 ~ /^[\042\047]/ && $2 !~ /[\042\047]$/) certificate="unresolved"
                else record_certificate($2)
              }
              if ($1 == "php_fastcgi") { runtime=$2; sub(/^unix\//,"",runtime) }
              if ($1 == "reverse_proxy") { runtime="reverse_proxy"; for (i=2;i<=NF;i++) { if ($i == "{") break; record_proxy($i) } }
              depth += opens-closes
              if (depth <= 0) { emit(); active=0 }
            }
          }
        }
        END { emit() }' <<< "$metadata") || { manifest_collection_failed=true; continue; }
      while IFS=$'\t' read -r names port tls document_root user runtime certificate proxy; do
        [ -n "$names" ] || continue
        manifest_website "$server" "$names" "$port" "$tls" "$document_root" "$user" "$runtime" "${file#"$manifest_root"}" "$certificate" "$proxy"
      done <<< "$records"
    done <<< "$files"
  done
}

# Limit both configured paths and resolved aliases before probing mail data.
# /home2/USER/Maildir is narrow; /home2/USER and /homebackup/USER/Maildir are not.
function manifest_mail_path_is_narrow() {
  local home_number
  case "$1" in
    "$manifest_root"/var/mail|"$manifest_root"/var/mail/*|\
    "$manifest_root"/var/spool/mail|"$manifest_root"/var/spool/mail/*|\
    "$manifest_root"/var/vmail|"$manifest_root"/var/vmail/*|\
    "$manifest_root"/home/vmail|"$manifest_root"/home/vmail/*|\
    "$manifest_root"/www/vmail|"$manifest_root"/www/vmail/*|\
    "$manifest_root"/var/customers/mail|"$manifest_root"/var/customers/mail/*|\
    "$manifest_root"/var/qmail/mailnames|"$manifest_root"/var/qmail/mailnames/*|\
    "$manifest_root"/root/Maildir|"$manifest_root"/root/.Maildir) return 0;;
    "$manifest_root"/home/*|"$manifest_root"/home[0-9]*/*)
      # cPanel can place accounts on /home2, /home10, etc.; reject other /home* trees.
      home_number=${1#"$manifest_root"/home}; home_number=${home_number%%/*}
      case "$home_number" in *[!0-9]*) return 1;; esac
      case "$1" in
        */Maildir|*/Maildir/*|*/.Maildir|*/.Maildir/*|*/mail|*/mail/*|*/imap|*/imap/*) return 0;;
      esac;;
  esac
  return 1
}

# Mail stores can contain millions of files. Bound scans by time and path
# instead of recursively measuring arbitrary configured directories; unknown size does not mean an empty mailbox.
function manifest_mail_root() {
  local path="$1" source="$2" size=unknown count=unknown reason=not_scanned count_reason=ambiguous_layout actual output inode resolved
  case "$path" in /*) ;; *) return ;; esac
  case "$path" in *'$'*|*'%'*|*'~'*|*'{'*|*'}'*)
    # Measure an existing literal parent, not an unresolved per-user template or a broad home tree.
    # /var/vmail/%d/%n -> /var/vmail; /home/%u/Maildir -> /home, which is rejected as too broad.
    path=${path%%\%*}; path=${path%%\$*}; path=${path%%\~*}; path=${path%%\{*}; path=${path%/*}
    case "$path" in ''|/|/home|/var|/srv) return;; esac
    source="$source:template_root";;
  esac
  case "|$manifest_mail_seen|" in *"|$path|"*) return ;; esac
  manifest_mail_seen="$manifest_mail_seen|$path"
  actual="$manifest_root$path"
  [ -d "$actual" ] || return
  resolved=$(readlink -f -- "$actual" 2>/dev/null) || resolved=
  if [ "$source" = conventional ] && manifest_mail_path_is_narrow "$resolved" &&
      output=$(manifest_run_bounded 2 find "$resolved" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null) && [ -z "$output" ]; then return; fi
  inode=$(stat -L -c '%d:%i' -- "$actual" 2>/dev/null) || inode=
  if [ -n "$inode" ]; then
    case "|$manifest_mail_inodes|" in *"|$inode|"*) return ;; esac
    manifest_mail_inodes="$manifest_mail_inodes|$inode"
  fi
  manifest_mail_count=$((manifest_mail_count+1))
  if [ -d "$actual/cur" ] && [ -d "$actual/new" ] && [ -d "$actual/tmp" ]; then count=1; count_reason=maildir; fi
  # Only conventional narrow mail roots are scanned; a configured / or /home is never traversed.
  if manifest_mail_path_is_narrow "$actual"; then
    if "${manifest_unprivileged:-false}"; then reason=unprivileged
    elif ! $manifest_mail_metrics; then reason=disabled
    elif [ "$manifest_mail_count" -gt 8 ]; then reason=directory_limit
    elif ! command -v timeout >/dev/null 2>&1 && ! command -v perl >/dev/null 2>&1; then reason=bounded_probe_unavailable
    else
      # Follow only the root alias; its resolved target must still be a narrow mail root.
      actual=$resolved
      if ! manifest_mail_path_is_narrow "$actual"; then actual=; reason=resolved_path_not_scanned; fi
      if [ -n "$actual" ]; then
        if output=$(manifest_run_bounded 3 du -skx -- "$actual" 2>/dev/null); then
          # du -skx: 1536<TAB>/var/mail -> size_mib=1.500; the value is allocated KiB divided by 1024.
          if size=$(awk '$1 ~ /^[0-9]+$/ { printf "%.3f", $1/1024; found=1 } END { exit !found }' <<< "$output"); then reason=measured
          else size=unknown; reason=invalid_du_output; fi
        else reason=limit_or_permissions; fi
        if [ -d "$actual/cur" ] && [ -d "$actual/new" ] && [ -d "$actual/tmp" ]; then count=1; count_reason=maildir
        elif [ "$path" = /var/mail ] || [ "$path" = /var/spool/mail ]; then
          if output=$(manifest_run_bounded 2 find "$actual" -mindepth 1 -maxdepth 1 -type f -printf '.\n' 2>/dev/null); then
            if [ -n "$output" ]; then count=$(printf '%s\n' "$output" | wc -l); count_reason=top_level_mbox_files; else count=unknown; fi
          fi
        fi
      fi
    fi
  else reason=nonstandard_path_not_scanned; fi
  manifest_emit mail_storage path "$path" source "$source" size_mib "$size" mailbox_count "$count" size_basis allocated_disk_mib count_reason "$count_reason" reason "$reason"
}

function manifest_mail() {
  local file path key value home home_base source count=0 file_count=0
  local records metadata account_mail_source='' directadmin=false interworx=false
  for file in "$manifest_root"/etc/postfix/main.cf "$manifest_root"/etc/dovecot.conf "$manifest_root"/etc/dovecot/dovecot.conf "$manifest_root"/etc/dovecot/conf.d/*.conf "$manifest_root"/etc/dovecot/conf.keyhelp.d/*.conf "$manifest_root"/etc/exim4/exim4.conf.template "$manifest_root"/etc/exim4/conf.d/main/* "$manifest_root"/etc/courier/imapd "$manifest_root"/etc/courier/pop3d "$manifest_root"/etc/psa/psa.conf; do
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then continue; fi
    file_count=$((file_count+1)); [ "$file_count" -le 200 ] || break
    metadata=$(manifest_read_metadata "$file") || { manifest_collection_failed=true; continue; }
    # virtual_mailbox_base = /var/vmail -> key=virtual_mailbox_base, value=/var/vmail.
    # mail_location = maildir:/var/vmail/%d/%n:INDEX=/tmp -> path=/var/vmail/%d/%n before template handling.
    records=$(awk '
      FNR > 20000 { exit }
      /^[ \t]*[#;]/ { next }
      $1 == "PLESK_MAILNAMES_D" { print $1 "\t" $2; next }
      /^[ \t]*(mail_spool_directory|virtual_mailbox_base|mail_location|default_mail_env|mail_path)[ \t]*=/ {
        key=$0; sub(/[ \t]*=.*/,"",key); gsub(/^[ \t]+/,"",key)
        value=$0; sub(/^[^=]*=[ \t]*/,"",value); sub(/[ \t]+#.*/,"",value); gsub(/^[\042\047]|[\042\047][ \t]*$/,"",value)
        print key "\t" value
      }' <<< "$metadata") || { manifest_collection_failed=true; continue; }
    while IFS=$'\t' read -r key value; do
      case "$key" in
        mail_spool_directory|virtual_mailbox_base|mail_path|PLESK_MAILNAMES_D) manifest_mail_root "$value" "${file#"$manifest_root"}:$key" ;;
        mail_location|default_mail_env)
          path=${value#*:}; path=${path%%:*}
          manifest_mail_root "$path" "${file#"$manifest_root"}:$key" ;;
      esac
    done <<< "$records"
  done
  manifest_mail_root /var/mail conventional
  manifest_mail_root /var/spool/mail conventional
  manifest_mail_root /var/vmail conventional
  manifest_mail_root /home/vmail conventional
  manifest_mail_root /www/vmail conventional
  manifest_mail_root /var/customers/mail conventional
  manifest_mail_root /var/qmail/mailnames conventional
  if [ -d "$manifest_root/usr/local/cpanel" ] || [ -d "$manifest_root/var/cpanel" ]; then account_mail_source=cpanel
  elif [ -d "$manifest_root/usr/local/hestia" ] || [ -d "$manifest_root/etc/hestiacp" ]; then account_mail_source=hestiacp
  elif [ -d "$manifest_root/usr/local/vesta" ]; then account_mail_source=vestacp
  elif [ -d "$manifest_root/etc/webmin/virtual-server" ] || [ -d "$manifest_root/usr/share/webmin/virtual-server" ]; then account_mail_source=virtualmin; fi
  [ ! -d "$manifest_root/usr/local/directadmin" ] || directadmin=true
  [ ! -d "$manifest_root/home/interworx" ] || interworx=true
  # Expand only known mailbox layouts, never recursively search or measure /home.
  for home_base in "$manifest_root"/home "$manifest_root"/home[0-9]*; do
    [ -d "$home_base" ] || continue
    case "${home_base#"$manifest_root"/home}" in *[!0-9]*) continue;; esac
    for home in "$home_base"/*/mail "$home_base"/*/imap "$home_base"/*/var/*/mail \
        "$home_base"/*/Maildir "$home_base"/*/.Maildir \
        "$home_base"/*/homes/*/Maildir "$home_base"/*/homes/*/.Maildir \
        "$home_base"/*/domains/*/Maildir "$home_base"/*/domains/*/.Maildir \
        "$home_base"/*/domains/*/homes/*/Maildir "$home_base"/*/domains/*/homes/*/.Maildir; do
      [ -d "$home" ] || continue
      source=conventional
      case "${home#"$home_base"}" in
        */var/*/mail) $interworx || continue; source=interworx;;
        */mail) [ -n "$account_mail_source" ] || continue; source=$account_mail_source;;
        */imap) $directadmin || continue; source=directadmin;;
      esac
      if [ "$count" -ge 20 ]; then
        manifest_emit warning area mail_storage reason 'Only the first 20 account mail directories were examined; coverage is incomplete.'
        return
      fi
      count=$((count+1))
      manifest_mail_root "${home#"$manifest_root"}" "$source"
    done
  done
  manifest_mail_root /root/Maildir conventional
  manifest_mail_root /root/.Maildir conventional
}

# Passive migration hints: paths and fixed identity fields, never configured commands or secrets.
function manifest_migration_systemd_target() {
  local file=$1 target name=${1##*/}
  target=$(readlink -- "$file" 2>/dev/null) || return 1
  case "$target" in /*) target="$manifest_root$target";; *) target="${file%/*}/$target";; esac
  target=$(readlink -f -- "$target" 2>/dev/null) || return 1
  # Resolve within the inventory root; masks, broken links and custom targets remain visible.
  case "${target%/*}" in "$manifest_root/lib/systemd/system"|"$manifest_root/usr/lib/systemd/system") ;; *) return 1;; esac
  [ -f "$target" ] && [ ! -L "$target" ] || return 1
  if [ "$name" != "${target##*/}" ]; then
    # A different name is routine only when the vendor unit declares that alias.
    # [Install] followed by Alias=example.service -> accepts a link named example.service; Alias= alone resets the list.
    (set -o pipefail; manifest_read_metadata "$target" | MANIFEST_UNIT_ALIAS="$name" awk '
      /^[ \t]*\[/ { install=($0 ~ /^[ \t]*\[Install\][ \t]*$/) }
      install && /^[ \t]*Alias[ \t]*=/ {
        sub(/^[^=]*=[ \t]*/, "")
        if (NF == 0) found=0
        for (i=1; i<=NF; i++) if ($i == ENVIRON["MANIFEST_UNIT_ALIAS"]) found=1
      }
      END { exit !found }') || return 1
  fi
  printf '%s\n' "$target"
}

function manifest_migration_path() {
  local kind=$1 file=$2 source=$3 records ownership=not_checked package=unknown checked_file=$2
  local housekeeping=false ownership_failed=false
  if [ "$kind" = scheduled_task ] || [ "$kind" = custom_service ]; then
    case "$source" in /etc/init.d|*/systemd/system|/etc/cron.*)
      # Package backups and cron placeholders are not live service or job definitions.
      case "${file##*/}" in *.dpkg-*|*.ucf-*|*.rpmnew|*.rpmsave|*.rpmorig|*~) return 0;; esac;;
    esac
    case "$source:${file##*/}" in
      /etc/cron.*:.placeholder|/etc/init.d:.depend.boot|/etc/init.d:.depend.start|/etc/init.d:.depend.stop|/etc/init.d:README|/etc/init.d:skeleton) return 0;;
    esac
    case "$source" in
      /etc/init.d)
        case "${file##*/}" in
          console-screen.sh|console-setup|console-setup.sh|hwclock|hwclock.sh|hwclockfirst.sh|keyboard-setup|keyboard-setup.sh|klogd|plymouth|plymouth-log|sysklogd)
            housekeeping=true;;
        esac;;
      /etc/cron.hourly|/etc/cron.daily|/etc/cron.weekly|/etc/cron.monthly)
        case "${file##*/}" in
          bsdmainutils|find|locate|mlocate|slocate|makewhatis|makewhatis.cron|man|man-db|rpm|sysklogd|upstart|apt-xapian-index)
            housekeeping=true;;
        esac;;
    esac
    case "$source" in */systemd/system)
      if [ -L "$file" ]; then checked_file=$(manifest_migration_systemd_target "$file") || checked_file=$file; fi;;
    esac
    if records=$(packages_output_file_origin "$checked_file" "$manifest_package_backend" "$manifest_root"); then
      IFS=$'\t' read -r ownership package <<< "$records"
      if [ "$ownership" = packaged ]; then
        # chmod -x is a common way to disable a packaged run-parts job; keep that migration hint.
        case "${file#"$manifest_root"}" in
          /etc/cron.hourly/*|/etc/cron.daily/*|/etc/cron.weekly/*|/etc/cron.monthly/*)
            if [ -x "$file" ]; then return 0; fi
            ownership=package_job_not_executable;;
          *) return 0;;
        esac
      fi
    else
      ownership=unknown; package=unknown; ownership_failed=true
    fi
    # Keep confirmed local edits even when the script normally performs OS housekeeping.
    if $housekeeping && [ "$ownership" != modified_package ]; then return 0; fi
    if $ownership_failed; then
      manifest_migration_unverified=$(( ${manifest_migration_unverified:-0} + 1 ))
      manifest_collection_failed=true
    fi
  fi
  manifest_emit migration_path kind "$kind" path "${file#"$manifest_root"}" source "$source" ownership "$ownership" package "${package:-unknown}" verification not_tested
}

function manifest_migration_paths() {
  local directory kind entry_kind file count records manifest_migration_unverified=0
  for directory in /usr/local/bin /usr/local/sbin /opt /etc/systemd/system /usr/local/lib/systemd/system /etc/init.d /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
    [ -d "$manifest_root$directory" ] || continue
    case "$directory" in
      */cron*) kind=scheduled_task;;
      */systemd/system|*/init.d) kind=custom_service;;
      *) kind=local_program;;
    esac
    # Skip control-character names so line-delimited paths also work without /dev/fd.
    if ! records=$(set -o pipefail; LC_ALL=C manifest_run_bounded 5 find "$manifest_root$directory" -maxdepth 2 \( -name '*[[:cntrl:]]*' -prune \) -o \( \( -type f -o -type l \) -print \) 2>/dev/null | LC_ALL=C sort); then
      manifest_emit warning area migration_paths path "$directory" reason 'Path scan failed or timed out; coverage is incomplete.'
      manifest_collection_failed=true
      continue
    fi
    count=0
    while IFS= read -r file; do
      [ -n "$file" ] || continue
      count=$((count+1))
      if [ "$count" -gt 200 ]; then
        manifest_emit warning area migration_paths path "$directory" reason 'More than 200 files; additional paths omitted.'
        break
      fi
      entry_kind=$kind
      case "$directory:$file" in */systemd/system:*.timer) entry_kind=scheduled_task;; esac
      manifest_migration_path "$entry_kind" "$file" "$directory"
    done <<< "$records"
  done
  for file in /etc/crontab /etc/anacrontab; do
    [ -f "$manifest_root$file" ] || continue
    manifest_migration_path scheduled_task "$manifest_root$file" system_schedule
  done
  if [ "$manifest_migration_unverified" -gt 0 ]; then
    manifest_emit warning area migration_paths unverified_paths "$manifest_migration_unverified" reason 'Package ownership could not be checked for these migration paths; entries with unknown ownership remain for review.'
  fi
}

function manifest_migration_identities() {
  local records user uid gid home shell count=0
  # USER:x:1000:1000::/home/USER:/bin/bash -> USER<TAB>1000<TAB>1000<TAB>/home/USER<TAB>/bin/bash.
  # The password placeholder and GECOS field are omitted; non-root accounts with unrelated homes are skipped.
  if ! records=$(set -o pipefail; manifest_read_metadata "$manifest_root/etc/passwd" | awk -F : '
    NF == 7 && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ && ($3 == 0 || $6 ~ /^\/(home|srv|var\/www|var\/vmail|opt)(\/|$)/) {
      printf "%s\t%s\t%s\t%s\t%s\n", $1, $3, $4, $6, $7
    }'); then
    manifest_emit warning area migration_identities reason 'Local account metadata could not be read.'
    manifest_collection_failed=true
    return
  fi
  while IFS=$'\t' read -r user uid gid home shell; do
    [ -n "$user" ] || continue
    count=$((count+1))
    if [ "$count" -gt 200 ]; then
      manifest_emit warning area migration_identities reason 'More than 200 selected accounts; additional accounts omitted.'
      break
    fi
    manifest_emit migration_identity user "$user" uid "$uid" gid "$gid" home "$home" shell "$shell" source /etc/passwd
  done <<< "$records"
}

function manifest_migration_mounts() {
  local records target type count=0
  [ -e "$manifest_root/etc/fstab" ] || return
  # Device fields and options may contain credentials; select target/type before emitting anything.
  # UUID=PLACEHOLDER /home ext4 defaults 0 2 -> /home<TAB>ext4; the device and options are omitted.
  if ! records=$(set -o pipefail; manifest_read_metadata "$manifest_root/etc/fstab" | awk '
    /^[ \t]*#/ || NF < 3 {next}
    {printf "%s\t%s\n", $2, $3}
  '); then
    manifest_emit warning area migration_mounts reason 'fstab metadata could not be read.'
    manifest_collection_failed=true
    return
  fi
  while IFS=$'\t' read -r target type; do
    [ -n "$target" ] || continue
    count=$((count+1))
    if [ "$count" -gt 200 ]; then
      manifest_emit warning area migration_mounts reason 'More than 200 mount entries; additional entries omitted.'
      break
    fi
    manifest_emit migration_mount target "$target" filesystem "$type" source /etc/fstab mounted unknown
  done <<< "$records"
}

function manifest_migration() {
  manifest_migration_paths
  manifest_migration_identities
  manifest_migration_mounts
  manifest_emit warning area migration_review reason 'Conventional paths only, depth 2 and at most 200 files per directory; scans stop after 5 seconds. Local account selection includes root and conventional application homes. LDAP/NSS users, commands, schedules, service enablement and mount availability are not evaluated. File metadata is capped at 1 MiB; paths may include package-managed files. Names containing control characters and their subdirectories are omitted. Service and scheduled-task files with matching package content, including routine links to vendor units, are omitted, except nonexecutable periodic jobs. Package backup artifacts, placeholders and routine OS housekeeping are omitted; confirmed package-content edits remain visible. Other permission/owner changes are not checked; retained modified, unowned and unverified paths need review, including stopped or disabled services.'
}

# FORMAT is text or json; ROOT is used only by isolated fixtures, never a chroot or executable source.
function manifest_hosting_panels() {
  local panels panel version
  panels=$(upgrade_panel_output_installed "$manifest_root") || return 1
  while IFS=$'\t' read -r panel version; do
    [ -n "$panel" ] || continue
    manifest_emit hosting_panel name "$panel" version "$version"
  done <<< "$panels"
}

function manifest_output() (
  local manifest_format="${1:-text}" manifest_dns_enabled="${2:-${DR_MANIFEST_DNS:-true}}" manifest_root="${3:-/}"
  local manifest_unprivileged=${DR_UNPRIVILEGED:-false}
  case "$manifest_unprivileged" in true|false) :;; *) return 1;; esac
  [ "$(id -u)" = 0 ] || manifest_unprivileged=true
  local manifest_processes='' manifest_package_backend=unknown
  local manifest_separator='' manifest_local_addresses='' manifest_seen_roots='' manifest_mail_seen='' manifest_mail_inodes='' manifest_mail_count=0
  local manifest_review_file=${4:-} manifest_collection_failed=false
  local manifest_web_roots=0 manifest_web_files=0 manifest_web_findings=0 manifest_web_incomplete=false manifest_web_started=$SECONDS
  local manifest_dns_limit=20 manifest_mail_metrics="${DR_MANIFEST_MAIL_METRICS:-true}"
  local manifest_dns_addresses manifest_dns_result manifest_dns_reason
  local manifest_apache_php_available=false manifest_apache_php_version=unknown manifest_apache_php_package=unknown
  local -a manifest_php_packages=()
  local -a manifest_php_versions=()
  local -a manifest_fpm_sockets=()
  local -a manifest_fpm_users=()
  local -a manifest_fpm_versions=()
  local -a manifest_fpm_packages=()
  local -a manifest_dns_names=()
  local -a manifest_dns_values=()
  local -a manifest_dns_results=()
  local -a manifest_dns_reasons=()
  case "$manifest_format:$manifest_dns_enabled" in
    text:true|text:false|json:true|json:false) ;;
    *) printf '%s\n' 'dss:error: invalid manifest format or boolean control' >&2; return 1 ;;
  esac
  [ "$manifest_root" = / ] && manifest_root=
  if command -v ip >/dev/null 2>&1; then
    manifest_local_addresses=$(ip -o address show 2>/dev/null | awk '{ for (i=1;i<NF;i++) if ($i == "inet" || $i == "inet6") { split($(i+1),a,"/"); if (!seen[a[1]]++) printf "%s ",a[1] } }')
  fi
  [ "$manifest_format" != json ] || printf '{"schema_version":1,"records":['
  manifest_package_backend=$(packages_output_backend "$manifest_root") || manifest_package_backend=unknown
  manifest_emit system package_backend "$manifest_package_backend" hostname "$(hostname 2>/dev/null || printf unknown)" generated_utc "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" local_addresses "${manifest_local_addresses:-unknown}"
  if $manifest_unprivileged; then
    manifest_emit warning area privileges reason 'Unprivileged collection: service status scripts, listener process ownership and mail size scans are skipped. Unreadable configuration, application files, private cron jobs and mail stores may be omitted; missing results are unknown.'
  fi
  manifest_hosting_panels || manifest_collection_failed=true
  manifest_listeners
  manifest_process_indicators
  manifest_executable_indicators
  manifest_schedule_indicators
  manifest_processes=$(ps -eo comm= 2>/dev/null) || manifest_processes=
  manifest_packages
  manifest_apache_php
  manifest_fpm_pools
  manifest_mail
  manifest_web_started=$SECONDS
  manifest_websites
  if $manifest_web_incomplete; then
    manifest_emit warning area security_websites reason 'Website security sampling is incomplete: unreadable, large or indirect files, failed probes or limits (20 roots, 200 files/findings, 256 KiB per file, 15 seconds plus the final probe). Only top-level files and common upload/cache and WordPress plugin directories to depth 3 are sampled.'
  fi
  manifest_migration
  if $manifest_collection_failed; then manifest_emit warning area collection reason 'One or more collectors failed; missing inventory sections are unknown.'; fi
  manifest_emit warning area interpretation reason 'Reads common configuration files; custom settings may be missed. Websites and applications are not tested. Certificate files are listed, but HTTPS and certificate validity are not checked.'
  manifest_emit warning area security_review reason 'Potential compromise indicators require manual review; missing findings do not establish a clean system.'
  [ "$manifest_format" != json ] || printf ']}\n' || return 1
  # Ordinary inventories retain partial findings; comparisons require their core collectors to succeed.
  [ -z "$manifest_review_file" ] || ! $manifest_collection_failed
)

# Publish a paired JSON inventory and sorted review file only after collection succeeds.
function manifest_capture() {
(
  umask 077
  local directory=$1 file
  mkdir -m 700 -- "$directory" && chmod 700 -- "$directory" || return 1
  # A parent's default ACL can override umask; secure files before writing private records.
  for file in records.tmp manifest.json.tmp manifest.review.tmp; do
    : > "$directory/$file" && chmod 600 -- "$directory/$file" || return 1
  done
  DR_MANIFEST_MAIL_METRICS=false manifest_output json false "${2:-/}" "$directory/records.tmp" > "$directory/manifest.json.tmp" || return 1
  printf '%s\n' manifest-review-v1 > "$directory/manifest.review.tmp" || return 1
  LC_ALL=C sort "$directory/records.tmp" >> "$directory/manifest.review.tmp" || return 1
  mv -- "$directory/manifest.review.tmp" "$directory/manifest.review" &&
    mv -- "$directory/manifest.json.tmp" "$directory/manifest.json" || return 1
  rm -f -- "$directory/records.tmp"
)
}

# Summarize recorded facts, without interpreting individual application settings.
function manifest_print_key_changes() {
  local baseline=$3
  # Review records use tab-separated key="JSON value" fields; retain escaping in display text.
  # listener<TAB>address="::1"<TAB>port="25"<TAB>program="master" -> endpoint=[::1]:25, program=master.
  awk -F '\t' '
    $1 == "listener" {
      for (key in fields) delete fields[key]
      for (i=2;i<=NF;i++) { key=$i; sub(/=.*/, "", key); value=substr($i,length(key)+2); fields[key]=substr(value,2,length(value)-2) }
      address=fields["address"]; if (index(address, ":") && address !~ /^\[/) address="[" address "]"
      endpoint=address ":" fields["port"]; name=fields["program"]
      if (FILENAME == ARGV[1]) before[name SUBSEP endpoint]=1; else after[name SUBSEP endpoint]=1
      names[name]=1
    }
    END {
      for (name in names) {
        removed=""; added=""
        for (entry in before) if (!(entry in after)) { split(entry, parts, SUBSEP); if (parts[1] == name) removed=removed (removed ? ", " : "") parts[2] }
        for (entry in after) if (!(entry in before)) { split(entry, parts, SUBSEP); if (parts[1] == name) added=added (added ? ", " : "") parts[2] }
        if (removed != "" || added != "") printf "dss:stage: Listening changes: %s; no longer: %s; added: %s.\n", name, (removed ? removed : "none"), (added ? added : "none")
      }
    }
  ' "$1" "$2" || return 1
  print_pkg_to_modified_diff review "$baseline"
}

# Status: 0 unchanged, 1 observations changed, 2 comparison unavailable. Never test application behaviour.
function manifest_compare_baseline() {
(
  umask 077
  local baseline=$1 original="$1.applications" directory result file
  if [ -z "$baseline" ] || [ -L "$original" ] || [ ! -f "$original/manifest.json" ] ||
      [ -L "$original/manifest.json" ] || [ ! -f "$original/manifest.review" ] || [ -L "$original/manifest.review" ] ||
      [ "$(head -n 1 -- "$original/manifest.review")" != manifest-review-v1 ]; then
    printf 'dss:warn: Manifest comparison unavailable: no comparable original inventory at %s. No baseline was reconstructed.\n' "$original" >&2
    return 2
  fi
  if [ "$(stat -c '%u' -- "$original")" != 0 ]; then
    echo 'dss:warn: Manifest comparison unavailable: original inventory directory is not root-owned.' >&2; return 2
  fi
  for file in "$original/manifest.json" "$original/manifest.review"; do
    if [ "$(stat -c '%u:%h' -- "$file")" != 0:1 ]; then
      echo 'dss:warn: Manifest comparison unavailable: original inventory owner/links require review.' >&2; return 2
    fi
  done
  # Repair inherited file modes without replacing or retimestamping the original observations.
  if ! chmod 700 -- "$original" || ! chmod 600 -- "$original/manifest.json" "$original/manifest.review"; then
    echo 'dss:warn: Manifest comparison unavailable: cannot secure the original inventory.' >&2; return 2
  fi
  directory=$(mktemp -d "$original/review.XXXXXX") || return 2
  if ! chmod 700 -- "$directory"; then
    echo 'dss:warn: Manifest comparison unavailable: cannot secure the review directory.' >&2; return 2
  fi
  if ! manifest_capture "$directory/current" "${2:-/}"; then
    printf 'dss:warn: Manifest comparison incomplete: current inventory failed; review %s.\n' "$directory" >&2
    return 2
  fi
  if ! { : > "$directory/changes.diff" && chmod 600 -- "$directory/changes.diff" &&
      : > "$directory/summary.txt" && chmod 600 -- "$directory/summary.txt"; }; then
    echo 'dss:warn: Manifest comparison unavailable: cannot create a private changes report.' >&2; return 2
  fi
  diff -u --label original-manifest --label current-manifest "$original/manifest.review" "$directory/current/manifest.review" > "$directory/changes.diff"
  result=$?
  case "$result" in
    0) printf 'dss:stage: Manifest comparison: unchanged observed setup. Inventory: %s/current/manifest.json\n' "$directory" >&2;;
    1)
      printf 'dss:stage: Manifest comparison: changes observed; review %s/changes.diff. Changes alone are not failures.\n' "$directory" >&2
      cat -- "$directory/changes.diff" || return 2;;
    *) printf 'dss:warn: Manifest comparison failed; review %s.\n' "$directory" >&2; return 2;;
  esac
  if ! manifest_print_key_changes "$original/manifest.review" "$directory/current/manifest.review" "$baseline" > "$directory/summary.txt"; then
    echo 'dss:warn: Key-change summary is incomplete; review the detailed configuration report.' >> "$directory/summary.txt" || return 2
  fi
  cat -- "$directory/summary.txt" >&2 || return 2
  return "$result"
)
}

# TODO: allow a small declarative before/after assertion file once its format is agreed.
# Keep customer application checks opt-in and separate from package/service verification.

function upgrade_print_check() {
  local backend family current target native audit status=0 identity id version variant
  # Checks must report removals/conversions as blockers, never apply inherited repair controls.
  local DR_REMOVE_X11_PACKAGES=false DR_PURGE_INCOMPATIBLE_PACKAGES=false DR_ALLOW_CROSSGRADE_BLOCKERS=false
  local UPGRADE_CROSSGRADE=false
  local DR_PREFER_PACKAGED_USRMERGE_FILES=false DR_REMOVE_OBSOLETE_CROSSGRADE_PACKAGES=false
  local DR_SKIP_DOVECOT_MIGRATION_CHECK=false DR_SKIP_KERNEL_CHECK=false DR_SKIP_X11_CHECK=false
  local DR_SKIP_DISK_SPACE_CHECK=false DR_SKIP_CURRENT_RELEASE_REPOSITORY_CHECK=false DR_ALLOW_BACKPORTS=false
  backend=$(packages_output_backend) || { echo 'dss:error: Cannot identify the package backend.' >&2; return 1; }
  if [ "$backend" = rpm ]; then
    identity=$(rpm_distro_output_identity '') || { echo 'dss:error: Cannot identify the RPM distribution.' >&2; return 1; }
    IFS=$'\t' read -r id version variant <<< "$identity"
    printf 'dss:info: Current distribution: %s %s (%s); kernel: %s\n' "$id" "$version" "$variant" "$(uname -rm)"
    report_unsupported || status=1
    check_disk_space || status=1
    upgrade_panel_refuse_generic || status=1
    echo 'dss:error: No automatic newer-major-release target is supported for this RPM distribution. Plan a clean installation/migration to a supported release, or a separately reviewed vendor/ELevate procedure.' >&2
    echo 'dss:info: Same-major CentOS conversion, where eligible, uses DR_RPM_MIGRATION_TARGET with --upgrade; it is not a major-release upgrade.'
    return 1
  fi
  current=$(distro_output_codename) || { echo 'dss:error: Cannot identify the installed distribution.' >&2; return 1; }
  case " $ALL_DEBIAN " in
    *" $current "*) family=debian; target=trixie;;
    *)
      case " $ALL_UBUNTU " in
        *" $current "*) family=ubuntu; target=$(ubuntu_output_latest_lts "$current") || return 1;;
        *) echo "dss:error: No known upgrade path for $current." >&2; return 1;;
      esac;;
  esac
  native=$(dpkg --print-architecture) || { native=unknown; status=1; }
  printf 'dss:info: Current distribution: %s %s; target: %s; architecture: %s; kernel: %s\n' "$family" "$current" "$target" "$native" "$(uname -rm)"
  [ "$current" != "$target" ] || echo 'dss:info: Already at the configured target release; checking current system prerequisites.'
  report_unsupported || :
  upgrade_precondition_checks || status=1
  if audit=$(LC_ALL=C dpkg --audit 2>&1); then
    if [ -n "$audit" ]; then printf 'dss:error: Incomplete package work:\n%s\n' "$audit" >&2; status=1; fi
  else
    printf 'dss:error: Cannot verify package database health:\n%s\n' "$audit" >&2; status=1
  fi
  upgrade_check_path "$family" "$current" "$target" review || status=1
  if [ "$status" -eq 0 ]; then
    echo 'dss:info: No known checked blockers found; application compatibility and target repository/package availability still need review.'
  else
    echo 'dss:error: Upgrade readiness blocked or incomplete; resolve the checks above.' >&2
  fi
  echo 'dss:info: Read-only review: no package indexes refreshed and no system changes made.'
  return "$status"
}

# Read-only handover facts for a developer or AI; existing APT indexes may be stale.
function upgrade_print_report() {
  local dns=${1:-${DR_MANIFEST_DNS:-true}} current=unknown family=unknown target=unknown native=unknown status=0 records audit file release crossgrade_release=''
  case "$dns" in true|false) :;; *) return 1;; esac
  printf '%s\n' 'distrorejuve upgrade review' "Captured UTC: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  current=$(distro_output_codename) || { current=unknown; status=1; }
  native=$(dpkg --print-architecture) || { native=unknown; status=1; }
  case " $ALL_DEBIAN " in *" $current "*) family=debian; target=trixie;; esac
  case " $ALL_UBUNTU " in *" $current "*)
    family=ubuntu; target=$current
    for release in $LTS_UBUNTU; do
      if is_distro_name_newer "$release" "$target"; then target=$release; fi
    done;;
  esac
  printf 'Release: %s %s; review target: %s; package architecture: %s; running kernel: %s\n' "$family" "$current" "$target" "$native" "$(uname -rm)"
  if [ "$native" = i386 ]; then
    case "$family" in
      debian) crossgrade_release=bookworm; printf '%s\n' 'Architecture review: native i386 upgrades stop at bookworm; a later target needs an explicit amd64 crossgrade and a running x86_64 kernel.';;
      ubuntu) crossgrade_release=bionic; printf '%s\n' 'Architecture review: native i386 upgrades stop at bionic; later releases need an experimental crossgrade.';;
    esac
  fi
  printf '\n%s\n' 'Known configuration migration concerns (target above; not an upgrade authorization):'
  if [ "$family" = unknown ]; then
    printf '%s\n' 'Unknown distribution: release-path concerns could not be evaluated.'; status=1
  elif records=$(DR_SKIP_DOVECOT_MIGRATION_CHECK=false upgrade_output_compatibility_issues "$family" "$current" "$target"); then
    printf '%s\n' "${records:-No matching known configuration blockers. Application compatibility is not assessed.}"
  else printf '%s\n' 'Unknown: compatibility-rule collection failed.'; status=1; fi
  printf '\n%s\n' 'Package database health:'
  if audit=$(LC_ALL=C dpkg --audit 2>&1); then
    printf '%s\n' "${audit:-No incomplete packages reported by dpkg.}"
  else printf 'Unknown: dpkg audit failed: %s\n' "$audit"; status=1; fi
  printf '\n%s\n' 'Installed/partial packages: name, version, architecture, selection/state (hold means held):'
  if records=$(dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n'); then
    printf '%s\n' "$records" | awk -F '\t' '$4 !~ / (not-installed|config-files)$/ {print}' || status=1
  else printf '%s\n' 'Unknown: package inventory failed.'; status=1; fi
  printf '\n%s\n' 'Active APT sources: file, line, provider, type, URL, suite, components, architecture filters:'
  if records=$(apt_sources_list); then
    # Keep origin/path for review, without URL credentials, query strings or fragments.
    printf '%s\n' "$records" | awk -F '\t' 'BEGIN {OFS="\t"} NF {
      sub(/\/\/[^\/]*@/, "//[redacted]@", $5); sub(/[?#].*$/, "", $5); print
    }' || status=1
  else printf '%s\n' 'Unknown: source inventory failed.'; status=1; fi
  printf '\n%s\n' 'Package availability and transitional packages (existing APT indexes; no refresh):'
  apt_packages_print_review || status=1
  printf '\n%s\n' 'APT preferences (package/pin/priority only):'
  for file in "/etc/apt/preferences" "/etc/apt/preferences.d/"*; do
    [ -f "$file" ] || continue
    printf 'File: %s\n' "$file"
    awk '/^[ \t\r\f\013]*(Package|Pin|Pin-Priority):/ {
      sub(/\/\/[^\/]*@/, "//[redacted]@"); sub(/[?#].*$/, ""); gsub(/[\001-\037\177]/, " "); print
    }' "$file" || status=1
  done
  printf '\n%s\n' 'Modified/missing package configuration (paths only; contents omitted):'
  print_pkg_to_modified_diff summary || status=1
  printf '\n%s\n' 'Local executable, service and scheduled-task file paths (at most 200 per directory, depth 2; ownership not inferred):'
  for file in "/usr/local/bin" "/usr/local/sbin" "/opt" "/etc/systemd/system" "/etc/init.d" "/etc/cron.d"; do
    [ -d "$file" ] || continue
    # Names only: do not expose command arguments, environment files or cron contents.
    if records=$(find "$file" -maxdepth 2 -type f -print 2>/dev/null); then
      printf '%s\n' "$records" | LC_ALL=C sort | head -n 200
    else printf 'Unknown: cannot list %s\n' "$file"; status=1; fi
  done
  printf '\n%s\n' 'Applications, websites, runtime associations, mail storage and listeners:'
  manifest_output text "$dns" || status=1
  printf '\n%s\n' 'Review limits: package/configuration facts only; conventional paths and bounded scans. Custom includes, containers, external services and application compatibility may require manual review. No packages, sources, configurations or services were changed. Treat this report as private.'
  [ "$status" -eq 0 ] || printf '%s\n' 'Report incomplete: one or more collectors failed; unknown facts must be checked separately.'
  return "$status"
}

# End application/service manifest.

# Build the public report from a small field allowlist. Trying to redact
# arbitrary logs is unreliable because commands and configuration can contain credentials or customer data.
# Public reports select fixed fields; raw logs/configuration are never copied or redacted.
function support_print_report() {
(
  set -o pipefail
  local directory=${1:-} status=0 release family=unknown architecture kernel digest run_digest=unknown
  local exit_status=unknown action=unknown crossgrade=unknown target=unknown verification=not_recorded counts available mount
  local tool version probe_status plan local_review=legacy
  if [ -n "$directory" ]; then
    if [ ! -d "$directory" ] || [ -L "$directory" ] || [ -L "$directory/support.context" ] || [ -L "$directory/output.log" ]; then
      printf '%s\n' 'dss:error: Choose an existing run directory without linked report files.' >&2; return 1
    fi
    if [ -f "$directory/support.context" ]; then
      IFS=$'\t' read -r exit_status action run_digest crossgrade target < "$directory/support.context" || status=1
    fi
  fi
  case "$exit_status" in ''|*[!0-9]*) exit_status=unknown;; *)
    if [ "${#exit_status}" -gt 3 ] || [ "$exit_status" -gt 255 ]; then exit_status=unknown; fi;;
  esac
  case "$action" in
    --upgrade|--dist-update|--to-latest|--to-debian-release|--to-next-ubuntu|--to-64bit|--remove-leftover-packages|--remove-deprecated-packages) :;;
    *) action=unknown;;
  esac
  case "$crossgrade" in true|false) :;; *) crossgrade=unknown;; esac
  [ "$action" != --to-64bit ] || crossgrade=true
  if [ "$action" = --to-debian-release ]; then
    case "$target" in 6|7|8|9|10|11|12|13) :;; *) target=unknown;; esac
  else target=unknown; fi
  if [ -n "$directory" ] && [ -f "$directory/outcome.incomplete" ] && [ ! -L "$directory/outcome.incomplete" ]; then verification=incomplete; fi
  digest=$(sha256sum -- "${BASH_SOURCE[0]}" 2>/dev/null) || digest=unknown
  digest=${digest%% *}
  case "$digest" in *[!a-f0-9]*|'') digest=unknown;; *) [ "${#digest}" -eq 64 ] || digest=unknown;; esac
  case "$run_digest" in *[!a-f0-9]*|'') run_digest=unknown;; *) [ "${#run_digest}" -eq 64 ] || run_digest=unknown;; esac
  [ "$digest" != unknown ] || status=1
  release=$(distro_output_codename 2>/dev/null) || release=unknown
  case "$release" in ''|*[!a-z]*) release=unknown;; esac
  case " $ALL_DEBIAN " in *" $release "*) family=debian;; esac
  case " $ALL_UBUNTU " in *" $release "*) family=ubuntu;; esac
  if [ "$family" = unknown ]; then release=unknown; status=1; fi
  architecture=$(dpkg --print-architecture 2>/dev/null) || architecture=unknown
  case "$architecture" in amd64|i386|arm64|armhf|armel|ppc64el|s390x|riscv64|mips|mipsel|mips64el) :;; *) architecture=unknown; status=1;; esac
  # uname -r: 6.1.0-18-amd64 -> kernel=6.1; build suffixes and host-specific text are omitted.
  kernel=$(uname -r 2>/dev/null | awk 'match($0,/^[0-9]+[.][0-9]+/) { print substr($0,RSTART,RLENGTH); exit }') || kernel=unknown
  if [ -z "$kernel" ] || [ "$kernel" = unknown ]; then kernel=unknown; status=1; fi
  printf '%s\n' 'distrorejuve support report v1' 'Review before posting. No raw logs, configuration, host identifiers or installed package lists are included.'
  printf 'collector_sha256: %s\nrun_script_sha256: %s\naction: %s\nexit_status: %s\n' "$digest" "$run_digest" "$action" "$exit_status"
  printf 'crossgrade_requested: %s\nrequested_debian_release: %s\n' "$crossgrade" "$target"
  printf 'current_distribution: %s\ncurrent_release: %s\ncurrent_package_architecture: %s\ncurrent_kernel_series: %s\ncollector_bash_version: %s.%s.%s\n' \
    "$family" "$release" "$architecture" "${kernel:-unknown}" "${BASH_VERSINFO[0]}" "${BASH_VERSINFO[1]}" "${BASH_VERSINFO[2]}"
  if counts=$(LC_ALL=C dpkg-query -W -f='${Status}\n' 2>/dev/null | awk '
    # hold ok installed -> installed++ and held++; deinstall ok config-files -> residual++.
    /^[a-z-]+ [a-z-]+ [a-z-]+$/ {
      if ($0 ~ /^(install|hold) ok installed$/) { installed++; if ($1 == "hold") held++ }
      else if ($3 == "config-files") residual++
      else if ($3 != "not-installed") incomplete++
      next
    }
    { bad=1 }
    END { if (bad) exit 1; printf "installed=%d held=%d incomplete=%d residual_config=%d", installed, held, incomplete, residual }
  '); then printf 'package_states: %s\n' "$counts"
  else printf '%s\n' 'package_states: unknown'; status=1; fi
  for tool in apt dpkg; do
    version=$(LC_ALL=C dpkg-query -W -f='${Version}\n' "$tool" 2>/dev/null | awk '
      NR == 1 { sub(/^[0-9]+:/, ""); if (match($0, /^[0-9]+([.][0-9]+)+/)) print substr($0, RSTART, RLENGTH); else exit 1 }
    ') || version=
    if [ -z "$version" ]; then version=unknown; status=1; fi
    printf 'current_%s_version: %s\n' "$tool" "$version"
  done
  LC_ALL=C apt-cache policy >/dev/null 2>&1
  probe_status=$?
  printf 'current_apt_policy_exit_status: %s\n' "$probe_status"
  [ "$probe_status" -ne 127 ] || status=1
  # A simulation describes current indexes, not completion of the requested release path.
  plan=$(LC_ALL=C apt-get -s dist-upgrade 2>/dev/null)
  probe_status=$?
  printf 'current_index_dist_upgrade_exit_status: %s\n' "$probe_status"
  if [ "$probe_status" -eq 0 ] && counts=$(printf '%s\n' "$plan" | awk '
    # Inst bash ... then Conf bash ... -> install_or_upgrade=1, configure=1; require the numeric summary too.
    /^[0-9]+ upgraded, [0-9]+ newly installed, [0-9]+ to remove/ { summary=1 }
    /^Inst / { install++ } /^Remv / { remove++ } /^Purg / { purge++ } /^Conf / { configure++ }
    END { if (!summary) exit 1; printf "install_or_upgrade=%d remove=%d purge=%d configure=%d", install, remove, purge, configure }
  '); then printf 'current_index_package_plan: %s\n' "$counts"
  else printf '%s\n' 'current_index_package_plan: unknown'; status=1; fi
  for mount in / /usr /var; do
    available=$(LC_ALL=C df -Pk -- "$mount" 2>/dev/null | awk 'END { if (NF >= 6 && $(NF-2) ~ /^[0-9]+$/) print int($(NF-2)/1024); else exit 1 }') || { available=unknown; status=1; }
    printf 'free_mib%s: %s\n' "$mount" "$available"
  done
  if [ -n "$directory" ] && [ -f "$directory/output.log" ]; then
    if [ -e "$directory/php-runtime.findings.tsv.pending" ] || [ -L "$directory/php-runtime.findings.tsv.pending" ]; then local_review=incomplete
    elif [ -f "$directory/php-runtime.findings.tsv" ] && [ ! -L "$directory/php-runtime.findings.tsv" ]; then
      local_review=$(awk -F '\t' '
        $1 == "check" && $2 == "php-runtime" { check++; if (NF != 5 || $4 != "complete") incomplete=1; next }
        NF != 5 || $1 !~ /^(error|warning|unknown)$/ { incomplete=1 }
        $1 == "unknown" || $4 == "unverified" { incomplete=1 }
        $1 == "warning" || $1 == "error" { review=1 }
        END { print (check != 1 || incomplete ? "incomplete" : (review ? "required" : "none")) }
      ' "$directory/php-runtime.findings.tsv") || { local_review=incomplete; status=1; }
    fi
    # Match known messages to fixed labels; only known distribution codenames may be copied.
    # E: Could not get lock /var/lib/dpkg/lock-frontend -> package_lock (and the generic apt label).
    # Temporary failure resolving example.invalid -> network_dns; raw log text is not copied.
    LC_ALL=C awk -v verification="$verification" -v run_status="$exit_status" -v known_releases="$ALL_DEBIAN $ALL_UBUNTU" -v current_review="$local_review" '
      function codename(text) {
        if (match(text, /[(][a-z]+[)]$/)) {
          text=substr(text, RSTART+1, RLENGTH-2)
          if (index(" " known_releases " ", " " text " ")) return text
        }
        return "unknown"
      }
      /^dss:stage: Outcome: release / {
        release=packages=services=release_name=package_release_name="unknown"; outcome=1
        split($0, checks, ";")
        if (/^dss:stage: Outcome: release verified [(]/) { release="verified"; release_name=codename(checks[1]) }
        else if (/^dss:stage: Outcome: release not verified;/) release="not_verified"
        if (/; packages verified [(]/) { packages="verified"; package_release_name=codename(checks[2]) }
        else if (/; packages not verified;/) packages="not_verified"
        else if (/; packages failed final verification;/) packages="failed"
        if (/; services verified[.]$/) services="verified"
        else if (/; services failed[.]$/) services="failed"
      }
      /^dss:warn: Local configuration needs review[:;]/ { if (current_review == "legacy") local_review=1 }
      /^dss:stage[: ]/ {
        if (/Checking complete requested upgrade path|Rechecking .* before this release transition/) stage="preflight"
        else if (/Refreshing APT package indexes/) stage="apt_update"
        else if (/Checking package dependencies|Rechecking dependencies/) stage="dependency_check"
        else if (/Performing full package upgrade|Rechecking the full upgrade|Retrying the full upgrade/) stage="full_upgrade"
        else if (/Upgrading current packages/) stage="package_upgrade"
        else if (/Checking package changes for PHP|Preparing Apache for PHP package changes|Updating installed PHP packages/) stage="php_migration"
        else if (/Checking unused packages/) stage="autoremove"
        else if (/Checking web services and PHP-FPM listeners/) stage="service_verification"
        else if (/Detected hosting panel|Checking (plesk|cpanel) vendor prerequisites|Handing .* to (plesk|cpanel)/) stage="hosting_panel"
      }
      { line=tolower($0)
        if (line ~ /unmet dependencies|held broken packages/) errors["dependencies"]=1
        if (line ~ /hash sum mismatch/) errors["download_checksum"]=1
        if (line ~ /^dss:error: apache\/php (preparation|completion) failed/) errors["php_apache_handoff"]=1
        if (line ~ /^dss:error: (cannot establish whether apache is in use|apache use changed)/) { errors["php_apache_usage"]=1; stage="php_migration" }
        if (line ~ /^dss:error: apache\/php removal plan (was rejected|rejected [(])/) {
          errors["php_migration_plan"]=1
          count=split("purge unapproved_removal unexpected_install unverified_install early_runtime_change unapproved_upgrade version_check_failed", php_reasons, " ")
          for (i=1; i<=count; i++)
            if (index(line, "dss:error: apache/php removal plan rejected (" php_reasons[i] "): ") == 1)
              errors["php_plan_" php_reasons[i]]=1
        }
        if (line ~ /no_pubkey|expkeysig|keyexpired|signatures couldn.t be verified|signatures were invalid|public key is not available|repository.* is not signed/) errors["repository_signature"]=1
        if (line ~ /release file.*expired|release file.*not valid yet/) errors["repository_freshness"]=1
        if (line ~ /does not have a release file|no longer has a release file|404[ :]+not found/) errors["repository_unavailable"]=1
        if (line ~ /401[ :]+unauthorized|403[ :]+forbidden/) errors["repository_access"]=1
        if (line ~ /temporary failure resolving|could not resolve|could not resolve host/) errors["network_dns"]=1
        if (line ~ /connection timed out|connection refused|could not connect|network is unreachable/) errors["network_connection"]=1
        if (line ~ /certificate verification failed|certificate.*not trusted|tls.*handshake/) errors["network_tls"]=1
        if (line ~ /failed to fetch|some index files failed to download/) errors["repository_fetch"]=1
        if (line ~ /changed its .* value|allow-releaseinfo-change/) errors["repository_metadata_change"]=1
        if (line ~ /apt::default-release|apt policy is invalid/) errors["apt_policy"]=1
        if (line ~ /^e:/) errors["apt"]=1
        if (line ~ /^dss:error:apt_get_update failed/) {
          errors["apt_update"]=1; update_phase="unknown"; update_status="unknown"
          if (line ~ /phase indexes,/) update_phase="indexes"
          else if (line ~ /phase index_log_capture,/) update_phase="index_log_capture"
          else if (line ~ /phase policy,/) update_phase="policy"
          if (match(line, /status [0-9]+/)) {
            code=substr(line, RSTART+7, RLENGTH-7)
            if (length(code) <= 3 && code+0 > 0 && code+0 <= 255) update_status=code+0
          }
        }
        if (line ~ /could not get lock|unable to acquire.*lock/) errors["package_lock"]=1
        if (line ~ /no space left on device|insufficient.*space/) errors["disk_space"]=1
        if (line ~ /trying to overwrite/) errors["package_file_conflict"]=1
        if (line ~ /^dss:error.*(service|socket|runtime|previously active)/ && line !~ /^dss:error: apache\/php removal plan rejected/) errors["service_or_runtime"]=1
        if (line ~ /^dss:error.*(configuration|incompatible)/) errors["configuration_compatibility"]=1
        if (line ~ /^dss:error: (nginx|fpm) configuration .* references missing unix socket /) {
          errors["web_socket_missing"]=1; stage="service_verification"
        }
        if (line ~ /^dss:error.*(hosting.panel|plesk|cpanel|virtualmin)/) errors["hosting_panel"]=1
        if (line ~ /dpkg: error|dpkg returned an error/) errors["dpkg"]=1
      }
      END {
        if (current_review != "legacy") local_review=(current_review != "none")
        if (outcome && verification != "incomplete")
          verification=(run_status == "0" && release == "verified" && packages == "verified" && services == "verified" && !local_review ? "verified" : "incomplete")
        printf "recorded_completion_verification: %s\n", verification
        printf "recorded_release_check: %s\nrecorded_package_check: %s\nrecorded_service_check: %s\n", (outcome ? release : "not_recorded"), (outcome ? packages : "not_recorded"), (outcome ? services : "not_recorded")
        printf "recorded_release_codename: %s\nrecorded_package_release_codename: %s\n", (outcome ? release_name : "not_recorded"), (outcome ? package_release_name : "not_recorded")
        printf "recorded_local_configuration_review: %s\n", (current_review != "legacy" ? current_review : (local_review ? "required" : "not_recorded"))
        printf "last_recorded_apt_update_failure_phase: %s\nlast_recorded_apt_update_exit_status: %s\n", (update_phase == "" ? "not_recorded" : update_phase), (update_status == "" ? "not_recorded" : update_status)
        printf "last_recognised_stage: %s\n", (stage == "" ? "unknown" : stage)
        printf "observed_error_categories:"
        for (error in errors) { printf " %s", error; found=1 }
        if (!found) printf " %s", (run_status == "0" ? "none_recognised" : (run_status == "unknown" ? "unclassified_or_none" : "unclassified_failure"))
        print ""
      }
    ' "$directory/output.log" 2>/dev/null || status=1
  else
    printf 'recorded_completion_verification: %s\n' "$verification"
    printf '%s\n' 'recorded_release_check: not_recorded' 'recorded_package_check: not_recorded' 'recorded_service_check: not_recorded' \
      'recorded_release_codename: not_recorded' 'recorded_package_release_codename: not_recorded' \
      'recorded_local_configuration_review: not_recorded' \
      'last_recorded_apt_update_failure_phase: not_recorded' 'last_recorded_apt_update_exit_status: not_recorded' \
      'last_recognised_stage: unknown' 'observed_error_categories: unknown'
    [ -z "$directory" ] || status=1
  fi
  printf '%s\n' 'Error categories are observations from the run, not a current service-health check.'
  printf '%s\n' 'Submit the reviewed report at https://github.com/pbkwee/distrorejuve/issues/new'
  printf '%s\n' 'Describe expected versus actual behavior. Do not attach private logs, traces, manifests or configurations.'
  if [ "$status" -ne 0 ]; then printf '%s\n' 'collector_complete: no (some fields are unknown)'; fi
  return "$status"
)
}

# The action, tee and console filter each have their own pipeline status.
# Preserve action failures even when logging succeeds, and detect a broken log rather than silently losing recovery evidence.
# Detailed logging and console progress.
# Only mutating actions use this wrapper; read-only reports retain normal stdout.
# LOG_VERBOSE and LOG_TRACE are validated booleans set by the main option parser.
function logging_run() (
	local logging_root="${DR_LOG_DIRECTORY:-/root/distrorejuveinfo/runs}"
	local logging_verbose="${LOG_VERBOSE:-false}" logging_trace="${LOG_TRACE:-false}"
	local logging_dir logging_log logging_line logging_status logging_original_umask logging_digest logging_action_status=0
	local logging_emphasis=false logging_summarize=false logging_level logging_required
	local logging_expected_stop=false
	local -a logging_pipeline_status

	case "$logging_verbose:$logging_trace" in
		true:true|true:false|false:true|false:false) ;;
		*) printf '%s\n' 'dss:error Invalid logging boolean.' >&2; return 1 ;;
	esac
	if [ "$#" -eq 0 ]; then
		printf '%s\n' 'dss:error No action supplied to logging_run.' >&2
		return 1
	fi
	if $logging_trace && (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 1) )); then
		printf '%s\n' 'dss:error --trace requires Bash 4.1 or newer.' >&2
		return 1
	fi

	case "$1:${DR_ACTION:-${2:-}}" in
		distrorejuve_main:--upgrade|distrorejuve_main:--dist-update|distrorejuve_main:--to-*) logging_summarize=true;;
	esac
	if $logging_summarize; then
		# A partial copy must fail before package changes, not at completion.
		for logging_required in upgrade_outcome_record upgrade_finish_run; do
			if ! declare -F "$logging_required" >/dev/null; then
				printf 'dss:error Incomplete distrorejuve script: required function %s is missing. Replace it with a complete copy; action was not started.\n' "$logging_required" >&2
				return 1
			fi
		done
	fi

	logging_original_umask=$(umask)
	if [ -t 2 ] && [ -z "${NO_COLOR+x}" ] && [ "${TERM:-dumb}" != dumb ]; then logging_emphasis=true; fi
	umask 077
	if ! mkdir -p -- "$logging_root"; then
		printf '%s\n' 'dss:error Cannot create the detailed-log directory; action was not started.' >&2
		return 1
	fi
	if ! logging_dir=$(mktemp -d "$logging_root/run.XXXXXXXXXX"); then
		printf '%s\n' 'dss:error Cannot create a private run directory; action was not started.' >&2
		return 1
	fi
	logging_log="$logging_dir/output.log"
	if ! chmod u=rwx,go= -- "$logging_dir" || ! : > "$logging_log" || ! chmod u=rw,go= -- "$logging_log"; then
		printf '%s\n' 'dss:error Cannot prepare the private detailed log; action was not started.' >&2
		return 1
	fi
	if $logging_trace; then
		if ! : > "$logging_dir/trace.log" || ! chmod u=rw,go= -- "$logging_dir/trace.log"; then
			printf '%s\n' 'dss:error Cannot prepare the private trace log; action was not started.' >&2
			return 1
		fi
	fi
	logging_digest=$(sha256sum -- "${BASH_SOURCE[0]}" 2>/dev/null) || logging_digest=unknown
	logging_digest=${logging_digest%% *}
	printf 'dss:stage Detailed run log: %s\n' "$logging_log" >&2

	# The subshell contains traps, tracing and callback exits; caller state is intact.
	# Terminal interrupts reach the foreground pipeline, including action children.
	trap 'printf "dss:error Action interrupted; details: %s\n" "$logging_log" >&2; exit 130' INT
	trap 'printf "dss:error Action terminated; details: %s\n" "$logging_log" >&2; exit 143' TERM
	trap 'printf "dss:error Action disconnected; details: %s\n" "$logging_log" >&2; exit 129' HUP
	(
		trap - INT TERM HUP
		if $logging_summarize; then
			DR_RUN_DIRECTORY=$logging_dir
			export DR_RUN_DIRECTORY
			# Bash 3.1 unwinds function locals before EXIT traps; keep this child flag global.
			upgrade_preflight_blocked=false
			# Main dispatch can exit directly; retain its status and still report final health.
			trap '
				logging_action_status=$?
				trap - EXIT
				if $upgrade_preflight_blocked && [ "$logging_action_status" -eq 1 ]; then
					logging_status=$logging_action_status
					if ! (umask 077; : > "$DR_RUN_DIRECTORY/preflight.blocked.tmp" && chmod 600 -- "$DR_RUN_DIRECTORY/preflight.blocked.tmp" && mv -- "$DR_RUN_DIRECTORY/preflight.blocked.tmp" "$DR_RUN_DIRECTORY/preflight.blocked"); then
						printf "dss:error Cannot record the preflight refusal.\n" >&2
					fi
				elif declare -F upgrade_finish_run >/dev/null; then
					upgrade_finish_run "$logging_action_status" "$DR_RUN_DIRECTORY/output.log"
					logging_status=$?
				else
					printf "dss:error Completion reporting is unavailable: upgrade_finish_run is missing; package and service health remain unverified.\n" >&2
					logging_status=1
				fi
				[ "$logging_action_status" -eq 0 ] || logging_status=$logging_action_status
				exit "$logging_status"
			' EXIT
		fi
		if $logging_trace; then
			if ! exec 9> "$logging_dir/trace.log"; then exit 1; fi
			BASH_XTRACEFD=9
			PS4='+ ${BASH_SOURCE}:${LINENO}:${FUNCNAME[0]}: '
			set -x
		fi
		umask "$logging_original_umask"
		"$@"
	) 2>&1 | tee "$logging_log" | (
		while IFS= read -r logging_line || [ -n "$logging_line" ]; do
			logging_level=
			case "$logging_line" in
				dss:stage:*|dss:stage\ *) logging_level=stage ;;
				dss:warn:*|dss:warn\ *) logging_level=warn ;;
				dss:error:*|dss:error\ *) logging_level=error ;;
			esac
			if [ -n "$logging_level" ] && $logging_emphasis; then
				# Keep the terminal palette; emphasise only the severity label.
				printf '\033[1mdss:%s\033[22m%s\n' "$logging_level" "${logging_line#"dss:$logging_level"}" >&2 || exit 1
			elif [ -n "$logging_level" ] || $logging_verbose; then
				printf '%s\n' "$logging_line" >&2 || exit 1
			fi
		done
	)
	logging_pipeline_status=("${PIPESTATUS[@]}")
	logging_status=${logging_pipeline_status[0]}
	if [ "${logging_pipeline_status[1]}" -ne 0 ] || [ "${logging_pipeline_status[2]}" -ne 0 ]; then
		printf 'dss:error Detailed logging or console output failed; inspect %s\n' "$logging_log" >&2
		if [ "$logging_status" -eq 0 ]; then logging_status=1; fi
	fi
	if [ -f "$logging_dir/preflight.blocked" ] && [ "${logging_pipeline_status[1]}" -eq 0 ] && [ "${logging_pipeline_status[2]}" -eq 0 ]; then
		logging_expected_stop=true
	fi
	if $logging_expected_stop; then
		printf 'dss:stage Upgrade not started; resolve the preflight checks above and retry. Details: %s\n' "$logging_log" >&2
	elif [ "$logging_status" -ne 0 ]; then
		printf 'dss:error Action failed (status %s); details: %s\n' "$logging_status" "$logging_log" >&2
	elif [ -f "$logging_dir/panel.handoff" ]; then
		printf 'dss:stage Vendor upgrade handoff; final completion is not verified. Details: %s\n' "$logging_log" >&2
	elif [ -f "$logging_dir/outcome.incomplete" ]; then
		printf 'dss:warn Action finished with incomplete service verification; details: %s\n' "$logging_log" >&2
	elif [ -f "$logging_dir/configuration-review.txt" ]; then
		printf 'dss:warn Action complete; configuration review required: %s/configuration-review.txt; details: %s\n' "$logging_dir" "$logging_log" >&2
	else
		printf 'dss:stage Action complete; details: %s\n' "$logging_log" >&2
	fi
	if ! (umask 077; printf '%s\t%s\t%s\t%s\t%s\n' "$logging_status" "${DR_ACTION:-${2:-}}" "$logging_digest" "${UPGRADE_CROSSGRADE:-false}" "${3:-unknown}" > "$logging_dir/support.context" && chmod 600 -- "$logging_dir/support.context"); then
		printf '%s\n' 'dss:warn Cannot record support-report context.' >&2
	fi
	if ! $logging_expected_stop && { [ "$logging_status" -ne 0 ] || [ -f "$logging_dir/outcome.incomplete" ]; }; then
		if declare -F support_print_report >/dev/null; then
			if (umask 077; : > "$logging_dir/support-report.txt" && chmod 600 -- "$logging_dir/support-report.txt" && support_print_report "$logging_dir" > "$logging_dir/support-report.txt"); then
				printf 'dss:stage Review the minimal support report before posting: %s/support-report.txt\n' "$logging_dir" >&2
			else printf 'dss:warn Support report is incomplete; review %s/support-report.txt.\n' "$logging_dir" >&2; fi
		fi
		printf '%s\n' 'dss:stage Report the problem at https://github.com/pbkwee/distrorejuve/issues/new; do not attach private detailed logs or configuration.' >&2
	fi
	return "$logging_status"
)

# End detailed logging.

function distrorejuve_main() {
ret=0
if [ "${DR_ACTION:-$1}" = --support-report ]; then
  [ "$#" -le 2 ] || { printf '%s\n' 'dss:error: Use --support-report [RUN_DIRECTORY].' >&2; return 1; }
  support_print_report "${2:-}"
  return $?
fi
[ "${DR_ACTION:-$1}" = --manifest ] || [ "${DR_ACTION:-$1}" = --manifest-json ] || [ "${DR_ACTION:-$1}" = --upgrade-report ] || echo "dss:trace:distrorejuve:main:starting:$(date -u '+%Y-%m-%d %H:%M:%S'):args:$@"
case "${DR_ACTION:-${1:-}}" in
  --upgrade|--dist-update|--to-latest|--to-debian-release|--to-next-ubuntu|--to-64bit|--remove-leftover-packages|--remove-deprecated-packages)
    upgrade_panel_dispatch "$@" || return $?
    if $upgrade_panel_handled; then return 0; fi;;
esac
if [ "${DR_ACTION:-$1}" = --manifest ] || [ "${DR_ACTION:-$1}" = --manifest-json ] || [ "${DR_ACTION:-$1}" = --upgrade-report ]; then
  local dns=${DR_MANIFEST_DNS:-true}
  [ "$#" -le 1 ] || { print_usage; exit 1; }
  if [ "${DR_ACTION:-$1}" = --upgrade-report ]; then upgrade_print_report "$dns"
  elif [ "${DR_ACTION:-$1}" = --manifest-json ]; then manifest_output json "$dns"
  else manifest_output text "$dns"; fi
  exit $?
elif [ "--help" = "${DR_ACTION:-$1}" ]; then
  print_usage
elif [ "--check-upgrade" = "${DR_ACTION:-$1}" ] || [ -z "${DR_ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  upgrade_print_check
elif [ "--to-debian-release" = "${DR_ACTION:-$1}" ] ; then
  version="$2"
  [ -z "$version" ] && echo "dss:error: Need a version e.g. 11 for --to-debian-release" && exit 1
  [ ! -z "$3" ] && print_usage && exit 1
  case "$version" in
      6) debian_target=squeeze;;
      7) debian_target=wheezy;;
      8) debian_target=jessie;;
      9) debian_target=stretch;;
      10) debian_target=buster;;
      11) debian_target=bullseye;;
      12) debian_target=bookworm;;
      13) debian_target=trixie;;
      *)
      echo "dss:error: Expecting a --to-debian-release version of 6 to 13" && exit 1
      ;;
  esac
  upgrade_preflight_action --to-debian-release "${2:-}" || exit $?
  print_info
  dist_upgrade_etch_to_lenny || exit 1
  if [ "$version" -gt 5 ]; then dist_upgrade_lenny_to_squeeze || exit 1; fi
  if [ "$version" -gt 6 ]; then dist_upgrade_squeeze_to_wheezy || exit 1; fi
  if [ "$version" -gt 7 ]; then dist_upgrade_wheezy_to_jessie || exit 1; fi
  if [ "$version" -gt 8 ]; then dist_upgrade_jessie_to_stretch || exit 1; fi
  if [ "$version" -gt 9 ]; then dist_upgrade_stretch_to_buster || exit 1; fi
  if [ "$version" -gt 10 ]; then dist_upgrade_buster_to_bullseye || exit 1; fi
  if [ "$version" -gt 11 ]; then dist_upgrade_bullseye_to_bookworm || exit 1; fi
  if [ "$version" -gt 12 ]; then dist_upgrade_bookworm_to_trixie || exit 1; fi
  debian_check_release_completion "$debian_target" || exit 1

  [ "$ret" -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ "$ret" -eq 0 ] && echo "dss:info: --to-debian-release $version completed. Use $0 --show-changes to see changes."
elif [ "--to-next-ubuntu" = "${DR_ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  upgrade_preflight_action --to-next-ubuntu "${2:-}" || exit $?
  print_info
  dist_upgrade_ubuntu_to_latest 1
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --to-next-ubuntu completed ok.  use $0 --show-changes to see changes"
elif [ "--source" = "${DR_ACTION:-$1}" ] ; then
  echo "dss:info:Loaded distrorejuve functions"
elif [ "--upgrade" = "${DR_ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  print_info
  DR_SKIP_CURRENT_RELEASE_REPOSITORY_CHECK=true
  packages_upgrade
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  if [ "$ret" -eq 0 ]; then
    if [ -f /etc/redhat-release ]; then echo 'dss:info: --upgrade completed; review the RPM evidence directory in the detailed run log.'
    else echo "dss:info: --upgrade completed ok. Use $0 --show-changes to see changes."; fi
  fi
elif [ "--to-latest" = "${DR_ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  upgrade_preflight_action --to-latest "${2:-}" || exit $?
  print_info
  dist_upgrade_to_latest
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --to-latest completed ok.  use $0 --show-changes to see changes"
elif [ "--dist-update" = "${DR_ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  print_info
  packages_upgrade || exit 1
  if [ -f /etc/debian_version ]; then apt_get_dist_upgrade; else true; fi
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  if [ "$ret" -eq 0 ]; then
    if [ -f /etc/redhat-release ]; then echo 'dss:info: --dist-update completed; review the RPM evidence directory in the detailed run log.'
    else echo "dss:info: --dist-update completed ok. Use $0 --show-changes to see changes."; fi
  fi
elif [ "--list-leftover-packages" = "${DR_ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  ! has_leftover_packages && echo "No leftover packages (all installed packages from the current distro.  No 32 bit packages on a 64 bit install)." && exit 0
  show_leftover_packages
  echo "To remove those packages, re-run with bash $0 --remove-leftover-packages"
  exit 0
elif [ "--remove-leftover-packages" = "${DR_ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  ! has_leftover_packages && echo "No leftover packages (all installed packages from the current distro.  No 32 bit packages on a 64 bit install).  Nothing to do.  All good." && exit 0
  remove_leftover_packages
  exit $?
elif [ "--remove-deprecated-packages" = "${DR_ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  ! has_leftover_packages oldpkg && echo "No leftover packages (all installed packages from the current distro).  Nothing to do.  All good." && exit 0
  remove_leftover_packages oldpkg
  exit $?
elif [ "--to-64bit" = "${DR_ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  check_disk_space || exit 1
  if [ "$(distro_output_codename)" = bookworm ]; then
    crossgrade_debian_bookworm
    exit $?
  fi
  if [  64 -eq $(getconf LONG_BIT) ]; then
    if has_leftover_packages 32bit; then
      echo "dss:stage: System is already 64-bit; continuing conversion of remaining 32-bit packages."
    else
      echo "dss:stage: System is already 64-bit; no 32-bit packages remain."
      exit 0
    fi
  fi
  has_leftover_packages oldpkg && ! "${DR_SKIP_OLD_PACKAGE_CHECK:-false}" && show_leftover_packages && echo "dss:error: Old packages must be removed before crossgrading. Run bash $0 --remove-leftover-packages, or set DR_SKIP_OLD_PACKAGE_CHECK=true to override this check." >&2 && exit 1
  crossgrade_debian
  ret=$?
  [ $ret -ne 0 ] && echo "dss:error: crossgrade failed, see above for any details"
  [ $ret -eq 0 ] && echo "dss:info: To show configuration changes, run: bash $0 --show-changes"
  # [ $ret -eq 0 ] && print_config_state_changes && echo "dss:info: no errors."
  exit $ret
elif [ "--show-changes" = "${DR_ACTION:-$1}" ] ; then
  print_config_state_changes
  exit $?
elif [ "--pause" = "${DR_ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  touch ~/distrorejuve.pause
  echo "dss:info: Touched the pause file at $(realpath ~/distrorejuve.pause)"
  exit 0
elif [ "--resume" = "${DR_ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  rm -f ~/distrorejuve.pause
  echo "dss:info: Removed the pause file at $(realpath ~/distrorejuve.pause)"
  exit 0
else
  print_usage
  exit 1
fi

}

function distrorejuve_run() {
  local argument action LOG_VERBOSE=false LOG_TRACE=false UPGRADE_CROSSGRADE=false
  local DR_UNPRIVILEGED=${DR_UNPRIVILEGED:-false}
  local -a arguments=()
  local -a upgrade_retry_command=(bash "$0" "$@")
  for argument in "$@"; do
    case "$argument" in
      --unprivileged) DR_UNPRIVILEGED=true;;
      --verbose) LOG_VERBOSE=true;;
      --trace) LOG_TRACE=true;;
      --crossgrade) UPGRADE_CROSSGRADE=true;;
      *) arguments+=("$argument");;
    esac
  done
  # An explicit public-report command must not enter an inherited upgrade DR_ACTION.
  if [ "${arguments[0]:-}" = --support-report ]; then
    local DR_ACTION=--support-report
    distrorejuve_main "${arguments[@]}"
    return $?
  fi
  # An explicit read-only check must not inherit an upgrade action.
  if [ "${arguments[0]:-}" = --check-upgrade ]; then local DR_ACTION=--check-upgrade; fi
  environment_validate_settings || return 1
  [ "$(id -u)" = 0 ] || DR_UNPRIVILEGED=true
  action=${DR_ACTION:-${arguments[0]:-}}
  if $DR_UNPRIVILEGED; then
    case "$action" in
      --upgrade|--dist-update|--to-latest|--to-debian-release|--to-next-ubuntu|--to-64bit|--remove-leftover-packages|--remove-deprecated-packages|--show-changes|--list-leftover-packages|--pause|--resume)
        printf 'dss:error: %s is not available in unprivileged mode. Run as root without --unprivileged or DR_UNPRIVILEGED=true; use sudo bash if needed.\n' "$action" >&2
        return 1;;
    esac
  fi
  if $UPGRADE_CROSSGRADE; then
    case "$action" in
      --to-latest|--to-debian-release|--to-next-ubuntu) :;;
      *) echo 'dss:error: --crossgrade modifies a release-upgrade command; use --to-64bit for a standalone crossgrade.' >&2; return 1;;
    esac
  fi
  case "$action" in
    --upgrade|--dist-update|--to-latest|--to-debian-release|--to-next-ubuntu|--to-64bit|--remove-leftover-packages|--remove-deprecated-packages)
      logging_run distrorejuve_main "${arguments[@]}";;
    *)
      if $LOG_VERBOSE || $LOG_TRACE; then
        echo 'dss:error: --verbose and --trace apply to commands that change the system.' >&2
        return 1
      fi
      distrorejuve_main "${arguments[@]}";;
  esac
}

distrorejuve_run "$@"
