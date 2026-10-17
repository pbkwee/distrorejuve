#!/bin/bash

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
APT_GET_INSTALL_OPTIONS=' -y -o DPkg::Lock::Timeout=-1 -o APT::Get::AllowUnauthenticated=yes -o Acquire::Check-Valid-Until=false -o Dpkg::Options::=--force-confnew -o Dpkg::Options::=--force-confmiss '
# export this variable, e.g. to DAYS_UPGRADE_ONGOING=7 if your upgrade is taking more than a day, and you want the diffs in configs/processes to report the difference between the current and much earlier state.
DAYS_UPGRADE_ONGOING="${DAYS_UPGRADE_ONGOING:-7}"
function print_usage() {
  echo "
# distrorejuve

distrorejuve is a utility that helps with upgrading distros. It works on a number of different distros (Ubuntu,
Debian, Centos). It uses apt, yum and repository corrections as appropriate. It can dist upgrade between
multiple versions for Ubuntu and Debian.  It can convert (some) distros from 32bit to 64 bit (a cross grade).

If you are using the script to make changes, please take a full backup first.

Example usage to download the latest version of the script, then dist upgrade to latest Debian or Ubuntu disto.

wget -O distrorejuve.sh --no-check-certificate https://raw.githubusercontent.com/pbkwee/distrorejuve/master/distrorejuve.sh

sudo bash distrorejuve.sh --dist-upgrade

Uses:
- Enable lts archive for Debian squeeze servers and old-releases for Ubuntu
- Dist upgrade Ubuntu distros to the next LTS version.  Then from LTS version to LTS version.
- On completion provides information on config changes (modified config files, changed ports, changed packages, changed running processes)
- Install missing Debian keys
- Designed to run unattended without lots of prompting.
- Burgeoning support to cross grade 32 bit distros to 64 bit
- Show/remove cruft to permit tidy up of packages installed from non-current (old) repositories

Arguments:

Run with --usage to get this message

Run with --check (or no argument) to report disk space, kernel, distro version and configuration changes. Leave REMOVEX11 unset for a read-only check.

Run with --dist-upgrade run an upgrade, followed by dist-upgrading ubuntu distros to the latest lts or debian distros to latest debian.

Run with --upgrade to run a yum upgrade or apt-get upgrade (fixing up repos, etc where we can).  no distro version change.

Run with --dist-update to update packages on the current distro version (no distro version change).

Run with --manifest or --manifest-json to collect a read-only application/service inventory.
Add --no-dns to skip bounded DNS lookups. MANIFEST_MAIL_METRICS=false skips mail size/count probes.

Upgrade commands automatically retain private detailed logs in /root/distrorejuveinfo/runs.
Use --verbose to show command output too, or --trace to write a separate Bash trace.
DISTROREJUVE_LOG_DIR changes the log parent directory. Terminal colours respect NO_COLOR.

Run with --show-changes to report the differences pre/post upgrading (packages installed, config files, ports, etc).

Run with --show-cruft to see packages that do not belong to the current distro.  e.g. leftover packages from older distros.  And to see 32 bit packages installed on 64 bit distros.

Run with --remove-cruft to remove old packages and 32 bit applications on 64 bit distros.

Run with --remove-deprecated-packages to remove old packages

Add --crossgrade to a release-upgrade command to permit i386 to amd64 conversion at the last
release supporting native i386 (Debian 12 or Ubuntu 18.04), then continue to the requested target.
A running x86_64 kernel is required. Ubuntu also requires ENABLE_UBUNTU_CROSSGRADE.

Run with --to-64bit to convert a 32 bit distro to 64 bit.  Works OK with Debian.  May work for Ubuntu < 18.04.

Run with --to-wheezy to get from squeeze to wheezy

Run with --to-jessie to get from an older distro to jessie

Run with --to-latest-debian to get from an older debian distro to the latest stable distro

Run with --to-debian-release [6-13] to get from your current version to the specified version

Run with --to-latest-lts to get from an ubuntu distro to the most recent ubuntu lts version

Run with --to-next-ubuntu to get from an ubuntu distro to the next ubuntu version.  If the current ubuntu is an LTS version then this skips to the next LTS version.

Run with --pause to pause a distro rejuve running process (touch ~/distrorejuve.pause).  Triggers 30s sleeps at key points in the script.

Run with --resume to resume a paused distro rejuve running process (rm -f ~/distrorejuve.pause)

Disk space: upgrades and crossgrades require 5120 MiB free on package/cache/state filesystems.
Set MIN_FREE_DISK_MIB to a positive integer to adjust the floor, or SKIP_DISK_SPACE_CHECK=true to bypass.
--check reports a failed precondition with a nonzero exit status. Help and cleanup commands do not require this floor.
Legacy skip controls (any nonempty value enables them): IGNOREKERNEL, IGNOREX11, IGNOREBACKPORTS,
IGNOREOTHERREPOS (current-release only), IGNORECRUFT, IGNORE_DOVECOT_ERROR (2.4 migration only).
REMOVEX11 enables X11 removal; ENABLE_UBUNTU_CROSSGRADE permits experimental Ubuntu crossgrading.
DAYS_UPGRADE_ONGOING sets the configuration-history lookback (default 7 days).
PURGE_INCOMPATIBLE_PACKAGES=false blocks known config-breaking packages before release upgrades.
Set it to literal true to back them up and purge them; reinstall and configure them manually afterward.

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
   which replace &>/dev/null >/dev/null
   if [ $? -eq 0 ]; then
     # the double quotes are needed else you get:
      # /usr/local/mysql/bin/replace 1 2 3 e f g -- b
      # instead of:
      # /usr/local/mysql/bin/replace '1 2 3' 'e f g' -- b
     $(which replace) "$@"
     return $?
   fi
   local from=$1
   local to=$2
   local dash=$3
   local file=$4
   if [ "$dash" != "--" ]; then
     echo "expecting '--'" >&2
     return 1
   fi
   [ ! -f "$file" ] && echo "No such file as $file" >&2 && return 1
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
  if which lsb_release >/dev/null 2>&1; then
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
  which dpkg-query >/dev/null && dpkg-query -W -f='${Conffiles}\n' '*' | grep -v obsolete  | awk 'OFS="  "{print $2,$1}' | LANG=C md5sum -c 2>/dev/null | awk -F': ' '$2 !~ /OK$/{print $1}' | sort | awk '{print "dss:modifiedconfigs:" $0}'
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
    architectures=""
    if (match(prefix, /arch=[^] \t]+/)) { architectures=substr(prefix,RSTART+5,RLENGTH-5); gsub(/,/," ",architectures); architectures=architectures "||" }
    if (prefix ~ /arch[+-]=/) architectures=prefix
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

function apt_sources_list() {
  local file
  while IFS= read -r file; do
    apt_sources_process list "$file" || return 1
  done < <(apt_sources_files)
}

# Stage every file before activation. Keep originals for manual recovery and rollback.
function apt_sources_rewrite() {
  local mode=$1 family=$2 from=$3 to=$4 stage backup file index=0 changed=false ret=0
  local -a source_files=() activated=()
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
  apt_state_updated=
  apt_state_healthy=
  apt_state_upgraded=
  apt_state_dist_upgraded=
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
      5.*) name=lenny;; 6.*) name=squeeze;; 7.*) name=wheezy;; 8.*) name=jessie;;
      9.*) name=stretch;; 10.*) name=buster;; 11.*) name=bullseye;; 12.*) name=bookworm;; 13.*) name=trixie;; *) return 1;;
    esac
    printf '%s\n' "$name"
    return 0
  fi
  return 1
}

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

# Check official suite consistency/base sources/backports and vendor upgrade blockers.
function apt_sources_check_releases_and_vendors() {
  local target=${1:-${apt_sources_transition_target:-}} current family records file line provider type suite base
  local ret=0 official=0 seen=' ' support status
  records=$(apt_sources_list) || return 1
  if [ -n "$target" ] && { command -v plesk >/dev/null 2>&1 || [ -e /usr/local/cpanel/cpanel ]; }; then
    echo "dss:error: Hosting panel detected; use its documented distro upgrade procedure." >&2
    return 1
  fi
  current=$(distro_output_codename) || current=
  family=debian
  case " $ALL_UBUNTU " in *" $current "*) [ -n "$current" ] && family=ubuntu;; esac
  while IFS=$'\t' read -r file line provider type _ suite _ _; do
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
        if [ -z "$IGNOREBACKPORTS" ]; then
          echo "dss:warn: $file:$line enables backports ($suite); disable before upgrading or export IGNOREBACKPORTS=Y." >&2; ret=1
        fi;;
      esac
      continue
    fi
    [ -z "$target" ] && [ -n "$IGNOREOTHERREPOS" ] && continue
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

# Existing security sources must cover each binary base component and architecture filter.
# Do not add conflicting Signed-By records when only part of a security pocket is configured.
function apt_sources_check_security_coverage() {
  local records=$1 family=$2 current=$3 target=$4 provider type suite components architectures
  local secprovider sectype secsuite seccomponents secarchitectures component covered
  local -a basecomponents=()
  while IFS=$'\t' read -r _ _ provider type _ suite components architectures; do
    if [ "$provider" != "$family" ] || [ "$type" != deb ]; then continue; fi
    [ "$suite" = "$current" ] || [ "$suite" = "$target" ] || continue
    read -r -a basecomponents <<< "$components"
    for component in "${basecomponents[@]}"; do
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
  local skip=${SKIP_DISK_SPACE_CHECK:-false} minimum=${MIN_FREE_DISK_MIB:-5120}
  local path output available
  case "$skip" in
    true|false) :;;
    *) echo "dss:error: SKIP_DISK_SPACE_CHECK must be true or false." >&2; return 1;;
  esac
  $skip && return 0
  case "$minimum" in
    *[!0-9]*|'') echo "dss:error: MIN_FREE_DISK_MIB must be a positive integer (default 5120)." >&2; return 1;;
  esac
  if ! [ "$minimum" -gt 0 ] 2>/dev/null; then
    echo "dss:error: MIN_FREE_DISK_MIB must be a positive integer (default 5120)." >&2
    return 1
  fi
  # Probe package/cache/state paths individually to catch separate mounts and symlinks.
  for path in . / /usr /var /var/cache /var/cache/apt /var/cache/apt/archives /var/cache/yum /var/lib/apt /var/lib/apt/lists /var/lib/dpkg /var/lib/rpm /root /root/distrorejuveinfo; do
    [ -d "$path" ] || continue
    if ! output=$(LC_ALL=C df -Pm -- "$path"); then
      echo "dss:error: Cannot check disk space for $path. Resolve df failure or export SKIP_DISK_SPACE_CHECK=true after review." >&2
      return 1
    fi
    # df -Pm: Filesystem 1048576-blocks Used Available Capacity Mounted-on; field 4 is MiB free.
    # Refuse shifted columns (for example a filesystem name containing whitespace).
    available=$(printf '%s\n' "$output" | awk '
      NR == 2 && NF >= 6 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ &&
        $4 ~ /^-?[0-9]+$/ && $5 ~ /^[0-9]+%$/ { print $4 }
    ')
    if [ "$available" -lt "$minimum" ] 2>/dev/null; then
      echo "dss:error: Insufficient disk space for $path: $available MiB available; require $minimum MiB. Free space or review MIN_FREE_DISK_MIB; export SKIP_DISK_SPACE_CHECK=true to bypass." >&2
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
  check_disk_space || return 1
  local ret=0
  # e.g. 3.12.1
  if uname -r | grep -qai '^[12]'; then
    echo "dss:warn:Running an old kernel.  May not work with the latest packages (e.g. udev).  Please upgrade.  Note RimuHosting customers can set the kernel at https://rimuhosting.com/cp/vps/kernel.jsp.  To skip this check run: export IGNOREKERNEL=Y"
    [ -z "$IGNOREKERNEL" ] && ret=$(($ret+1))
  fi
  # cat /proc/sys/kernel/osrelease => 4.14.264-rh305-20220204224046.xenU.x86_64
  # ERROR: Your kernel version indicates a revision number
  # of 255 or greater.  Glibc has a number of built in
  # assumptions that this revision number is less than 255.
  ver="$([ -f /proc/sys/kernel/osrelease ] && cat /proc/sys/kernel/osrelease | sed 's/[.-]/ /g' | awk '{print $3}')"
  [ ! -z "$ver" ] && [ $ver -gt 255 ] && echo "dss:warn: if you get an error on libc install like ERROR: Your kernel version indicates a revision number of 255 or greater, then you may need to restart the server with a 5.10 kernel, or a kernel with a version smaller than 255.  You are currently on $(uname -r)" >&2
  # ii  dmidecode                       2.9-1.2build1                           Dump Desktop Management Interface data
  local libx11=
  which dpkg >/dev/null 2>&1 && if dpkg -l | grep '^ii' | awk '{print $2}' | egrep -qai 'gnome|desktop|x11-common'; then
    # ignoring some packages since they are 'fine'.  and typically some of them (eg libx11) are required by things like imagemagick and php-gd
    # install ok installed utils zip
    # install ok installed vcs cvs
    # install ok installed vcs patch
    local libx11="$(dpkg-query -W -f='${Status} ${Section} ${Package}\n'  | grep '^install ok installed' | egrep 'x11|gnome' | sort -k 4 | sed 's/install ok installed //' | awk '{print $2}' | egrep -v 'xorg-sgml-doctools|libx11|libx11-data|x11-common|theme-ubuntu-text|xauth|xfonts-encodings|xfonts-utils|msttcorefonts|gnome$|gnome-icon-theme|libsoup|gsettings-desktop|adwaita-icon-th|lib-xkd|mesa-util|xkb-data|icon-the|ubuntu-mono|plymouth|x11proto|xtrans-dev' | tr '\r\n' ' ')"
  fi
  if [  ! -z "$libx11" ]; then
    dpkg-query -W -f='${Status} ${Section} ${Package}\n'  | grep '^install ok installed' | egrep 'x11|gnome' | sort -k 4 | sed 's/install ok installed //' | awk '{print "dss:x11related:" $0}'
    echo "dss:warn:x11-common installed.  You may hit conflicts.  To resolve: apt-get -y remove x11-common $libx11; apt-get -y autoremove.  To skip this check run: export IGNOREX11=Y.  To automatically remove X11 libs use export REMOVEX11=Y"
    if [ ! -z "$REMOVEX11" ]; then
      apt-get -y remove $libx11 || ret=$(($ret+1))
      apt-get -y autoremove
    else
      [ -z "$IGNOREX11" ] && ret=$(($ret+1))
    fi
  fi

  if [ -f /etc/debian_version ]; then
    apt_sources_check_releases_and_vendors "$1" || ret=1
  fi
  [ "$ret" -eq 0 ] && echo "dss:trace:upgrade_precondition_checks completed."
  [ "$ret" -ne 0 ] && echo "dss:error:upgrade precondition checks failed." >&2

  return $ret
}

function add_missing_ubuntu_keys() {
  [ ! -f /etc/debian_version ] && return 0
  [ ! -x /usr/bin/apt-key ] && return 0
  print_distro_info | grep -qai ubuntu || return 0
  # import the lts key

  apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 112695A0E562B32A

  apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 648ACFD622F3D138

  apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 0E98404D386FA1D9

  return 0
}

HAS_INSTALLED_KEYS=
function add_missing_debian_keys() {
  [ ! -f /etc/debian_version ] && return 0
  [ ! -x /usr/bin/apt-key ] && return 0
  print_distro_info | grep -qai debian || return 0
  # only needs doing once
  [ -n "$HAS_INSTALLED_KEYS" ] && return 0
  echo "dss:info: checking debian keys"
  # import the lts key
  # sometimes its like '...AD62 4692 5553' other times its like '...AD6246925553'
  if ! apt-key list | egrep -qai "4692.*5553"; then
    echo "dss:info: installing the deb 7 2020 key"
    if ! gpg --recv-key  8B48AD6246925553 ; then gpg --keyserver pgpkeys.mit.edu --recv-key  8B48AD6246925553; fi
    gpg -a --export 8B48AD6246925553 | apt-key add -
  fi

  if ! apt-key list | egrep -qai "4730.*41FA"; then
    # Debian Archive Automatic Signing Key (6.0/squeeze) <ftpmaster@debian.org>
    echo "dss:info: installing the deb 6 key"
    gpg --recv-key AED4B06F473041FA
    gpg -a --export AED4B06F473041FA | apt-key add -
  fi
  if ! apt-key list | egrep D97A3AE911F63C51; then
    #webmin key
    echo "dss:info: installing webmin key"
    gpg --keyserver pgpkeys.mit.edu --recv-key D97A3AE911F63C51
    gpg -a --export D97A3AE911F63C51 | apt-key add -
  fi
  HAS_INSTALLED_KEYS=Y

  return 0
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
      upgrade_compatibility_config_matches '^[[:space:]]*slapd_conf[[:space:]]*=[[:space:]]*[^[:space:]]|(^|[[:space:]])-[fF][[:space:]]' /etc/default/slapd /etc/systemd/system/slapd.service /etc/systemd/system/slapd.service.d/*.conf
      status=$?
      [ "$status" -eq 1 ] || return 2
      [ ! -f /etc/ldap/slapd.conf ] || queue+=(/etc/ldap/slapd.conf)
      if [ -d /etc/ldap/slapd.d ]; then
        text=$(find /etc/ldap/slapd.d -maxdepth 8 \( -type f -o -type l \) -name '*.ldif' -print) || return 2
        while IFS= read -r file; do [ -z "$file" ] || queue+=("$file"); done <<< "$text"
      fi;;
    bind) queue=(/etc/bind/named.conf);;
    dovecot)
      upgrade_compatibility_config_matches '(^|[=[:space:]])-c[[:space:]]|--config([=[:space:]]|$)' /etc/default/dovecot /etc/systemd/system/dovecot.service /etc/systemd/system/dovecot.service.d/*.conf
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
    text=$(awk -v kind="$kind" '
      /^[[:space:]]*#/ { next }
       kind == "bind" {
        line=$0; sub(/#.*/, "", line); sub(/\/\/.*/, "", line)
        while (match(line, /(^|[;{}[:space:]])include[[:space:]]+"[^"]+"[[:space:]]*;/)) {
          value=substr(line,RSTART,RLENGTH); sub(/^[^"]*"/, "", value); sub(/".*$/, "", value)
          print "required|" value; line=substr(line,RSTART+RLENGTH)
        }
        if (line ~ /(^|[;{}[:space:]])include([[:space:]]|$)/) exit 2
      }
      kind != "bind" && /^[[:space:]]*!?include(_try)?[[:space:]]+/ {
        line=$0; sub(/^[[:space:]]*!?include(_try)?[[:space:]]+/, "", line); sub(/[[:space:]]+#.*/, "", line)
        gsub(/^["\047]|["\047][[:space:]]*$/, "", line); print ($0 ~ /!include_try/ ? "optional|" : "required|") line
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
        upgrade_compatibility_config_matches '^[[:space:]]*(mail_replica[[:space:]]*=[[:space:]]*["\047]?[^[:space:]#"\047]|service[[:space:]]+(replicator|director)[[:space:]]*\{|mail_plugins[[:space:]]*=[[:space:]]*([^#]*[[:space:]])?replication([[:space:]]|$))' "${paths[@]}"
      fi;;
    dovecot-armhf) [ "$arch" = armhf ];;
    crossgrade-rrd|crossgrade-postgresql|crossgrade-ldap)
      [ -n "${crossgrade_release:-}" ] && [ "$arch" = i386 ];;
    sasl-sql)
      upgrade_compatibility_config_matches '^[[:space:]]*auxprop_plugin:[[:space:]]*(mysql|pgsql|sqlite)' /etc/sasl2/*.conf /etc/postfix/sasl/*.conf;;
    xfs-barrier)
      [ -r /etc/fstab ] || return 2
      awk '$0 !~ /^[[:space:]]*#/ && $3 == "xfs" && $4 ~ /(^|,)(no)?barrier(=[^,]+)?(,|$)/ { bad=1 } END { exit !bad }' /etc/fstab;;
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
        END { exit !(all ~ /(^|[;{}[:space:]])masterfile-format[[:space:]]+"?map"?[[:space:]]*;/) }
      ';;
    pam-lastlog)
      upgrade_compatibility_config_matches '^[[:space:]]*-?(auth|account|password|session)[[:space:]]+(required|requisite|\[[^]]*default=(die|bad)[^]]*\])[[:space:]]+[^[:space:]]*pam_lastlog\.so' /etc/pam.d/*;;
    rrd-armhf) [ "$arch" = armhf ];;
    cgroup-v1)
      upgrade_compatibility_config_matches '(^|[[:space:]])(systemd\.unified_cgroup_hierarchy=(0|false|no)|systemd\.legacy_systemd_cgroup_controller(=1|=yes|=true)?)([[:space:]]|$)' /proc/cmdline;;
    ssh-rsa-list)
      upgrade_compatibility_config_matches '^[[:space:]]*(pubkeyacceptedkeytypes|hostbasedacceptedkeytypes)[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf;;
    sysctl-conf) upgrade_compatibility_config_matches '^[[:space:]]*[^[:space:]#;]+[[:space:]]*=' /etc/sysctl.conf;;
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
    [ "$rule" = dovecot-24 ] && [ -n "$IGNORE_DOVECOT_ERROR" ] && continue
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

# Automatic crossgrade planning.
# Legacy foreign applications may remain; native tools and the service manager must be converted.
# Keep the original conversion inventory until every recorded target has been verified.
# APT_CONFIG loads before apt.conf.d and apt.conf: unchanged probes expose defaults.
# Run before package inventory or any i386->amd64 mutation; never override user pins.
function crossgrade_check_apt_architecture_config() {
  (
    local directory probe status
    if [ -n "${APT_CONFIG:-}" ]; then
      printf '%s\n' 'dss:error: Existing APT_CONFIG prevents a reliable crossgrade architecture check; review and unset it first.' >&2
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
      return 0
    fi
    printf '%s\n' 'dss:error: Persistent APT architecture overrides block crossgrade. Remove APT::Architecture pins; explicit APT::Architectures lists must include i386 and amd64, including binary-specific settings.' >&2
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

function crossgrade_bookworm_check_native() {
  local native bits packages
  native=$(dpkg --print-architecture) || return 2
  bits=$(getconf LONG_BIT) || return 2
  [ "$native:$bits" = amd64:64 ] || return 1
  packages=$(dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Essential}\n') || return 2
  printf '%s\n' "$packages" | awk -F '\t' '
    $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ {
      sub(/:.*/, "", $2)
      if ($4 == "yes" || $2 ~ /^(dpkg|apt|apt-utils|bash|coreutils|tar|perl-base|systemd|systemd-sysv|udev|openssh-server|ifupdown)$/) {
        if ($1 !~ / installed$/ || ($3 != "amd64" && $3 != "all")) mixed=1
      }
    }
    END { exit mixed }
  '
}

# shellcheck shell=bash
# Output the release at which an explicitly permitted architecture conversion must run.
# Permission alone does not request conversion while the chosen release supports i386.
function upgrade_output_crossgrade_release() {
  local family=$1 current=$2 target=$3 enabled=${UPGRADE_CROSSGRADE-false}
  local native bits kernel boundary releases state pending=false
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
    crossgrade_bookworm_is_pending
    state=$?
    case "$state" in 0) pending=true;; 1) :;; *) return 1;; esac
  fi
  case "$native:$bits" in
    amd64:64)
      if $pending; then state=1
      else crossgrade_bookworm_check_native; state=$?; fi
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
    echo "dss:error: $family $target requires conversion before leaving $boundary. Add --crossgrade to permit i386 to amd64 conversion." >&2
    return 1
  fi
  if [ "$family" = ubuntu ] && [ -z "${ENABLE_UBUNTU_CROSSGRADE:-}" ]; then
    echo 'dss:error: Ubuntu crossgrading remains experimental. Set ENABLE_UBUNTU_CROSSGRADE only after reviewing that risk, as well as --crossgrade.' >&2
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
  printf '%s\n' "$boundary"
}

function upgrade_check_crossgrade_checkpoint() {
  # Source checks read this dynamically scoped override; no release transition is active here.
  # shellcheck disable=SC2034
  local family=$1 release=$2 current audit plan apt_sources_transition_target=''
  if [ "$family" = debian ]; then debian_check_release_completion "$release"; return $?; fi
  current=$(distro_output_codename) || return 1
  [ "$current" = "$release" ] || return 1
  apt_sources_check_releases_and_vendors || return 1
  audit=$(LC_ALL=C dpkg --audit) || return 1
  if [ -n "$audit" ]; then
    printf '%s\n' "$audit" >&2
    echo 'dss:error: Incomplete package state prevents crossgrading.' >&2
    return 1
  fi
  plan=$(LC_ALL=C apt-get -s dist-upgrade) || return 1
  if printf '%s\n' "$plan" | grep -Eq '^(Inst|Conf|Remv|Purg) '; then
    echo 'dss:error: Pending package changes prevent crossgrading. Finish updating this release first.' >&2
    return 1
  fi
}

# Call before changing repositories at bookworm -> trixie or bionic -> focal.
function upgrade_crossgrade_before_release() {
  local family=$1 old=$2 target=$3 current checkpoint native bits
  current=$(distro_output_codename) || return 1
  [ "$current" = "$old" ] || return 0
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
function upgrade_check_path() {
  echo "dss:stage: Checking complete upgrade path $2 -> $3" >&2
  local family=$1 current=$2 target=$3 issues action rule boundary packages remedy arch crossgrade_release blocked=false
  local purge=${PURGE_INCOMPATIBLE_PACKAGES-false}
  case "$purge" in true|false) :;; *) echo 'dss:error: PURGE_INCOMPATIBLE_PACKAGES must be true or false.' >&2; return 1;; esac
  local releases
  case "$family" in debian) releases=$ALL_DEBIAN;; ubuntu) releases=$ALL_UBUNTU;; *) return 1;; esac
  case " $releases " in *" $current "*) :;; *) echo "dss:error: Unknown $family starting release: $current" >&2; return 1;; esac
  case " $releases " in *" $target "*) :;; *) echo "dss:error: Unknown $family target release: $target" >&2; return 1;; esac
  if crossgrade_release=$(upgrade_output_crossgrade_release "$family" "$current" "$target"); then :; else blocked=true; fi
  if ! is_distro_name_older "$current" "$target"; then $blocked && return 1; return 0; fi
  arch=$(dpkg --print-architecture) || return 1
  if [ "$family" = debian ] && ! is_distro_name_older "$target" trixie; then
    case "$arch" in i386)
      if [ -z "$crossgrade_release" ]; then blocked=true; fi;;
      mipsel|mips64el)
      echo "dss:error: Requested path $current -> $target reaches Debian 13, which cannot upgrade native $arch. Migrate or crossgrade first." >&2
      blocked=true;;
    esac
  fi
  if [ "$family" = ubuntu ] && [ "$arch" = i386 ] && is_distro_name_newer "$target" bionic && [ -z "$crossgrade_release" ]; then
    echo "dss:error: Requested path $current -> $target exceeds Ubuntu 18.04 native i386 support. Migrate or crossgrade first." >&2
    blocked=true
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
        if ! $purge; then blocked=true; fi;;
    esac
  done <<< "$issues"
  if $blocked; then
    echo "dss:error: Requested upgrade path $current -> $target blocked before changes. PURGE_INCOMPATIBLE_PACKAGES=true backs up and purges config-only blockers; manual migrations cannot be bypassed with it." >&2
    return 1
  fi
  upgrade_check_incompatible_packages "$family" "$current" "$target"
}

function upgrade_preflight_action() {
  local action=$1 version=${2:-} family current target next remaining=1000
  current=$(distro_output_codename) || return 1
  case " $ALL_DEBIAN " in *" $current "*) family=debian;; *)
    case " $ALL_UBUNTU " in *" $current "*) family=ubuntu;; *) return 0;; esac;;
  esac
  case "$action:$family" in
    --to-squeeze:ubuntu|--to-wheezy:ubuntu|--to-jessie:ubuntu|--to-debian-release:ubuntu|--to-latest-debian:ubuntu|--to-latest-lts:debian|--to-next-ubuntu:debian)
      echo "dss:error: $action does not apply to $family." >&2; return 1;;
  esac
  case "$action" in
    --to-squeeze) target=squeeze;;
    --to-wheezy) target=wheezy;;
    --to-jessie) target=jessie;;
    --to-debian-release)
      case "$version" in 6) target=squeeze;; 7) target=wheezy;; 8) target=jessie;; 9) target=stretch;; 10) target=buster;; 11) target=bullseye;; 12) target=bookworm;; 13) target=trixie;; *) return 1;; esac;;
    --to-latest-debian) target=trixie;;
    --to-next-ubuntu) remaining=1;;
    --to-latest-lts|--dist-upgrade) :;;
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
  local family=$1 current=$2 target=$3 purge=${PURGE_INCOMPATIBLE_PACKAGES-false}
  local listed baseline backup plan status package
  local -a packages=()
  case "$purge" in
    true|false) :;;
    *) echo "dss:error: PURGE_INCOMPATIBLE_PACKAGES must be true or false." >&2; return 1;;
  esac
  listed=$(upgrade_output_incompatible_packages "$family" "$current" "$target") || return 1
  [ -n "$listed" ] || return 0
  while IFS= read -r package; do packages+=("$package"); done <<< "$listed"
  if ! $purge; then
    case " $listed " in *fail2ban*) print_uninstall_fail2ban;; esac
    if printf '%s\n' "$listed" | grep -q '^dovecot'; then
      if [ "$target" = trixie ] || { [ "$family" = ubuntu ] && ! is_distro_name_older "$target" questing; }; then
        echo "dss:error: Dovecot 2.4 requires config migration. Export IGNORE_DOVECOT_ERROR=Y only after manual migration review." >&2
      else
        print_uninstall_dovecot
      fi
    fi
    echo "dss:error: Upgrade $current to $target blocked by: ${packages[*]}. Set PURGE_INCOMPATIBLE_PACKAGES=true to back up and purge them; services remain removed until manual reinstall." >&2
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
  apt_state_healthy=''
  apt_state_upgraded=''
  apt_state_dist_upgraded=''
  (umask 077; : > "$backup/purge.log") || return 1
  LC_ALL=C apt-get $APT_GET_INSTALL_OPTIONS -o APT::Get::AutomaticRemove=false purge "${packages[@]}" 2>&1 | tee "$backup/purge.log"
  local -a result=("${PIPESTATUS[@]}")
  if [ "${result[0]}" -ne 0 ] || [ "${result[1]}" -ne 0 ]; then
    echo "dss:error: Purge failed; upgrade stopped. Backup: $backup. Review package state before retrying." >&2
    [ "${result[0]}" -ne 0 ] && return "${result[0]}"
    return 1
  fi
  mv -- "$backup/packages.requested" "$backup/packages.purged" || return 1
  echo "dss:warn: Purged incompatible packages: ${packages[*]}. Backup: $backup. Reinstall manually after upgrading: apt-get install ${packages[*]}" >&2
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
  #echo "dss:warn: In the event of a dist-upgrade failure, try things like commenting out the new distro, uncomment the previous distro, try an apt-get -f install, then change the distros back."
  #echo "dss:warn: In the event of dovecot errors, apt-get remove dovecot* unless you need dovecot (e.g. you need imap/pop3)"
  #echo "dss:warn: May be worth trying: aptitude -vv full-upgrade"
  #echo "dss:warn: after attempting a fix manually, rerun the bash distrorejuve.sh  command"
  return 0
}

function dist_upgrade_lenny_to_squeeze() {
export old_distro=lenny
export old_ver="inux 5"
export new_distro=squeeze
export new_ver="inux 6"

dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_squeeze_to_wheezy() {
export old_distro=squeeze
export old_ver="inux 6"
export new_distro=wheezy
export new_ver="inux 7"

dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_wheezy_to_jessie() {
export old_distro=wheezy
export old_ver="inux 7"
export new_distro=jessie
export new_ver="inux 8"
dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_jessie_to_stretch() {
export old_distro=jessie
export old_ver="inux 8"
export new_distro=stretch
export new_ver="inux 9"
dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_stretch_to_buster() {
export old_distro=stretch
export old_ver="inux 9"
export new_distro=buster
export new_ver="inux 10"
dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_buster_to_bullseye() {
export old_distro=buster
export old_ver="inux 10"
export new_distro=bullseye
export new_ver="inux 11"
dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_bullseye_to_bookworm() {
export old_distro=bullseye
export old_ver="inux 11"
export new_distro=bookworm
export new_ver="inux 12"
dist_upgrade_x_to_y
ret=$?
return $ret
}

function dist_upgrade_bookworm_to_trixie() {
export old_distro=bookworm
export old_ver="inux 12"
export new_distro=trixie
export new_ver="inux 13"
dist_upgrade_x_to_y
ret=$?
return $ret
}

  
function check_usrmerge() {
  [ -L /lib ] && return 0
  echo "dss:warn: /usr not merged.  Trying to install usrmerge to resolve."
  [ -e /etc/unsupported-skip-usrmerge-conversion ] && rm /etc/unsupported-skip-usrmerge-conversion
  local duplicatefiles="$(comm -12 \
  <(find /bin -maxdepth 1 -type f -printf '%f\n' | sort) \
  <(find /usr/bin -maxdepth 1 -type f -printf '%f\n' | sort))"
  local info="$(for file in $duplicatefiles; do dpkg -S /bin/$file ; dpkg -S /usr/bin/$file 2>&1 ; done | grep 'no path' | sed 's/.*matching pattern /rm /')"
  [ ! -z "$info" ] && echo "dss:warn:usrmerge will fail due to file collisions.  You may wish to remove the following: $info"
  apt_get_install usrmerge
  local ret=$?
  [ "$ret" -eq 0 ] && echo "dss:trace:check_usrmerge completed."
  [ "$ret" -ne 0 ] && echo "dss:error:check usrmerge failed." >&2
  return  $ret
}

function retain_etc_networking_naming_re_enX0() {
  # test we're a debian/ubuntu system currently using eth0
  [ ! -f /etc/network/interfaces ] && return 0
  ! egrep -i '^ *iface.*eth0.*static' /etc/network/interfaces && return 0
  [ -e /etc/systemd/network/99-default.link ] && return 0
  ! ifconfig eth0 2>/dev/null && return 0

  ln -sf /dev/null /etc/systemd/network/99-default.link && echo "Disabling /etc/systemd/network/99-default.link re enX0"
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

  if egrep -aqi 'mysql_upgrade: [ERROR] .*alter routine command denied to user ' $tmplog; then
    echo "dss:warn: mysql error.  Trying a mysql_upgrade to resolve."
    mysql_upgrade
  fi
  local mysqlerrlogs="$([ -d /var/lib/mysql ] && [ -d /var/log/mysql ] && find /var/lib/mysql /var/log/mysql -type f -mmin -10 | egrep '\.err$|mysql/error.log')"
  if [ -d /var/lib/mysql ] ; then
    mysqlerrlogs="$mysqlerrlog $tmplog"
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
  local i=
  local rmed=0
  for i in $overwrites; do
    case "$i" in /etc/apache2|/etc/apache2/*|/etc/httpd|/etc/httpd/*)
      echo "dss:warn: Preserving Apache configuration after package overwrite failure: $i. Review the package error; no configuration was removed." >&2
      continue;;
    esac
    [  ! -f "$i" ] && echo "dss:warn: expecting $i to be a file in rm_overwrite_files" && continue
    rm -f "$i"
    echo "dss:info: removed a shared overwrite file.  sometimes required when cross grading: $i"
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

# Local checks are cheaper than APT resolution/network work. A failed probe disables reuse.
function apt_state_output_signature() {
(
  [ "${apt_state_cache_disabled:-false}" = false ] || return 1
  [ -z "$APT_CONFIG$DPKG_ADMINDIR$DPKG_ROOT" ] || return 1
  case "$APT_GET_INSTALL_OPTIONS" in *Dir::*|*--admindir*|*--root*|*--simulate*|*--download-only*|*--print-uris*) return 1;; esac
  local kind=$1 config path sources keypaths binary metadata
  set -o pipefail
  config=$(apt-config dump) || return 1
  # Custom roots can move inputs outside the paths inspected below; run normally there.
  printf '%s\n' "$config" | awk -F '"' '
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
    }
    END { exit bad }
  ' || return 1
  sources=$(apt_sources_files) || return 1
  {
    printf '%s\n' "$config" "$APT_GET_INSTALL_OPTIONS"
    dpkg --print-architecture || exit 1
    dpkg --print-foreign-architectures || exit 1
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
          if [[ ! "$metadata" =~ \.[0-9]+[[:space:]][+-][0-9]+$ ]] ||
              [[ "$metadata" =~ \.0+[[:space:]][+-][0-9]+$ ]]; then
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
  apt_state_healthy=
  apt_state_upgraded=
  apt_state_dist_upgraded=
  tmplog=$(mktemp "tmplog.aptgetremove.log.XXXXXX") || return 1
  apt-get $APT_GET_INSTALL_OPTIONS remove $@ | tee "$tmplog"
  local ret=${PIPESTATUS[0]}
  [  $ret -ne 0 ] && rm_overwrite_files "$tmplog" && apt-get $APT_GET_INSTALL_OPTIONS remove $@ && ret=$?
  #if [  $ret -ne 0 ] && echo "$@" | egrep -qai 'gcc-6-base:i386'; then
  #fi
  if [  $ret -ne 0 ] && echo "$@" | egrep -qai 'gcc-6-base:i386'; then
    if egrep -qai 'systemd : Depends: libcap2-bin' "$tmplog"; then
      echo "dss:info: attempting to install libcap2-bin since gcc-6-base remove failed." && apt_get_install libcap2-bin:amd64 && apt-get $APT_GET_INSTALL_OPTIONS remove $@ && ret=$?
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
  apt_state_healthy=
  apt_state_upgraded=
  apt_state_dist_upgraded=
  tmplog=$(mktemp "tmplog.aptgetinstall.log.XXXXXX") || return 1
  apt-get $APT_GET_INSTALL_OPTIONS install $@ | tee "$tmplog"
  local ret=${PIPESTATUS[0]}
  [  $ret -ne 0 ] && rm_overwrite_files "$tmplog" && apt-get $APT_GET_INSTALL_OPTIONS install $@ && ret=$?
  local essentialissuepackages="$(grep --after-context 50 'WARNING: The following essential packages will be removed.' "$tmplog" | grep '^ ' | tr '\n' ' ' | sed  -r 's/\(due to +\S*?\)//g')"
  [ ! -z "$essentialissuepackages" ] && echo "dss:warn: apt_get_install $@ essential package issues for: $essentialissuepackages"

  rm -f "$tmplog"
  if [ "$ret" -eq 0 ]; then apt_state_record_healthy; fi
  return $ret
}

function apt_get_f_install() {
  echo "dss:stage: Checking package repair" >&2
  pause_check
  local tmplog signature
  signature=$(apt_state_output_signature packages 2>/dev/null) || signature=
  if [ -n "$signature" ] && [ "$signature" = "${apt_state_healthy:-}" ]; then
    echo "dss:trace:apt_get_f_install: dependency state already checked."
    return 0
  fi
  apt_state_healthy=
  apt_state_upgraded=
  apt_state_dist_upgraded=
  tmplog=$(mktemp "tmplog.aptgetfinstall.log.XXXXXX") || return 1
  apt-get $APT_GET_INSTALL_OPTIONS -f install | tee "$tmplog"
  local ret=${PIPESTATUS[0]}
  if [  $ret -ne 0 ]; then
    rm_overwrite_files "$tmplog" && apt-get $APT_GET_INSTALL_OPTIONS -f install && ret=$?
  fi
  echo "dss:trace:apt_get_f_install:$1 results $(egrep 'upgraded' "$tmplog")"
  local essentialissuepackages="$(grep --after-context 50 'WARNING: The following essential packages will be removed.' "$tmplog" | grep '^ ' | tr '\n' ' ' | sed  -r 's/\(due to +\S*?\)//g')"
  [ ! -z "$essentialissuepackages" ] && echo "dss:warn: apt_get_f_install $@ essential package issues for: $essentialissuepackages"
  if [ ! -z "$essentialissuepackages" ] && echo "$essentialissuepackages" | grep -qai 'perl-base:amd64'; then
    echo "dss:trying to dpkg -i perl-base:i386"
    if dpkg -l | grep perl-base | grep i386 | grep -qai ii; then
      echo "dss: perl-base:i386 already installed"
    else
      apt-get download perl-base:i386
      dpkg -i perl-base*i386*deb
      apt-get $APT_GET_INSTALL_OPTIONS -f install | tee "$tmplog"
      local ret=${PIPESTATUS[0]}
    fi
  fi

  rm -f "$tmplog"
  if [ $ret -ne 0 ]; then
    echo "dss:warn: dpkg results showing packages with issues."
    dpkg -l  | egrep -v '^ii|^rc|^iU' | awk '{print "dss:warn:apt_get_f_install: " $0}'
    echo "dss:info: as a last resort you can move away the failed dpkg status files at /var/lib/dpkg/info/pkngname*"
  fi
  if [ "$ret" -eq 0 ]; then apt_state_record_healthy; fi
  return $ret
}

function dpkg_install() {
  [  -z "$1" ] && return 0
  local tmplog
  apt_state_healthy=
  apt_state_upgraded=
  apt_state_dist_upgraded=
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
  [  ! -f /etc/debian_version ] && return 0
  [ -x /usr/bin/dpkg ] || return 0
  local psservicemanager=
  local dpkgservicemanager=

  # lsof -p 1 since ps may have an 'init' when its actually systemd
  # root         1  0.0  0.0 204588  6864 ?        Ss   Nov30   0:29 /sbin/init
  #root@pingability:~# ls -l /sbin/init
  #lrwxrwxrwx 1 root root 20 Dec  3  2017 /sbin/init -> /lib/systemd/systemd
  #root@pingability:~# lsof -p 1
  #COMMAND PID USER   FD      TYPE             DEVICE SIZE/OFF       NODE NAME
  #systemd   1 root  cwd       DIR              202,1     4096          2 /
  #systemd   1 root  rtd       DIR              202,1     4096          2 /
  #systemd   1 root  txt       REG              202,1  1141448     238139 /lib/systemd/systemd

  if ps auxf | egrep -qai '^root +1 +.*init'; then
    if ! lsof -p 1 | grep -qai systemd; then
      psservicemanager="${psservicemanager}sysvinit"
    fi
  fi
  ps auxf | egrep -qai '^root +1 +.*systemd' && psservicemanager="${psservicemanager}systemd"
  [ -z "$psservicemanager" ] && lsof -p 1 | grep -qai systemd && psservicemanager="${psservicemanager}systemd"

  # packages will sometimes be
  # systemd:i386
  # or
  # systemd

  dpkg -l | egrep '^.i|^iU' | awk '{print $2}' | grep -v '^lib' | egrep -qai '^sysvinit(:|$)' && dpkgservicemanager="${dpkgservicemanager}sysvinit"
  dpkg -l | egrep '^.i|^iU' | awk '{print $2}' | grep -v '^lib' | egrep -qai '^systemd(:|$)' && dpkgservicemanager="${dpkgservicemanager}systemd"

  [ "$psservicemanager" != "$dpkgservicemanager" ] && echo "dss:warn:sysvinit / systemd conflict (between running init/systemd process, and installed packages).  Reboot (and rerun distrorejuve) required? controlling process is '$psservicemanager' (per lsof -p 1), packages are '$dpkgservicemanager'.  Sometimes running $0 --remove-cruft can remove older sysvinit packages to resolve this issue." 2>&1 && return 1
  return 0

  # sysv wheezy
  # ps auxf | egrep '^root +1 +'
  # root         1  0.0  0.0   2320  1340 ?        Ss   Oct08   2:32 init [2]
  # root         1  0.0  0.0   2320  1340 ?        Ss   Oct08   2:32 init [2]
  # dpkg -l | grep sysv
  # ii  sysv-rc                            2.88dsf-41+deb7u1                all          System-V-like runlevel change mechanism
  # ii  sysvinit                           2.88dsf-41+deb7u1                i386         System-V-like init utilities
  # ii  sysvinit-utils                     2.88dsf-41+deb7u1                i386         System-V-like utilities

  # dpkg -l | grep systemd
  # ii  libsystemd-login0:i386             44-11+deb7u5                     i386         systemd login utility library

  # systemd jessie
  # root@debian:~# ps auxf | egrep '^root +1 +'
  # root         1  0.3  0.4 204580  7176 ?        Ss   01:59   0:09 /lib/systemd/systemd --system --deserialize 22
  # root@debian:~# dpkg -l | grep sysv
  # ii  systemd-sysv                    232-25+deb9u6                amd64        system and service manager - SysV links
  # ii  sysv-rc                         2.88dsf-59.9                 all          System-V-like runlevel change mechanism
  # ii  sysvinit-utils                  2.88dsf-59.9                 amd64        System-V-like utilities
  # root@debian:~# dpkg -l | grep systemd
  # ii  libpam-systemd:amd64            232-25+deb9u6                amd64        system and service manager - PAM module
  # ii  libsystemd0:amd64               232-25+deb9u6                amd64        systemd utility library
  # ii  systemd                         232-25+deb9u6                amd64        system and service manager
  # ii  systemd-sysv                    232-25+deb9u6                amd64        system and service manager - SysV links

}

# shellcheck shell=bash
# shellcheck shell=bash
# Bookworm crossgrade keeps unavailable foreign applications and never autoremoves.
# https://wiki.debian.org/CrossGrading (Bookworm dpkg/tar/apt bootstrap recipe)
function crossgrade_bookworm_output_candidate() {
  local package=$1 version rows policy
  policy=$(LC_ALL=C apt-cache policy "$package:amd64") || return 2
  version=$(printf '%s\n' "$policy" | awk '$1 == "Candidate:" { print $2; exit }')
  [ -n "$version" ] && [ "$version" != '(none)' ] || return 1
  rows=$(LC_ALL=C apt-cache madison "$package:amd64") || return 2
  printf '%s\n' "$rows" | awk -F '|' -v version="$version" '
    { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2) }
    $2 == version && $3 ~ /[[:space:]]amd64[[:space:]]+Packages[[:space:]]*$/ { found=1 }
    END { exit !found }' || return 1
  printf '%s\n' "$version"
}

# Every removal must have its amd64 replacement in this same plan or already installed.
function crossgrade_bookworm_check_plan() {
  local plan=$1 targets=$2 installed=$3
  awk -F '\t' '
    FILENAME == ARGV[1] { wanted[$1]=1; if ($3 == "same") coinstall[$1]=1; next }
    FILENAME == ARGV[2] { if ($1 == "install ok installed" && $3 == "amd64") native[$2]=1; next }
    {
      line=$0; split(line, field, /[[:space:]]+/); name=field[2]; sub(/:.*/, "", name)
      if (field[1] == "Inst") {
        if (field[2] ~ /:i386$/ || line ~ /\[i386\]\)$/) { if (!(name in coinstall)) bad=1 }
        else replaced[name]=1
      }
      if (field[1] == "Remv" || field[1] == "Purg") {
        if (field[1] == "Purg" || field[2] ~ /:amd64$/ || (!(field[2] ~ /:/) && name in native) || !(name in wanted)) bad=1
        removed[name]=1
      }
    }
    END { for (name in removed) if (!(name in replaced) && !(name in native)) bad=1; exit bad }
  ' "$targets" "$installed" "$plan"
}

# Download to an empty private cache, check the simulated removals, then inspect every archive.
function crossgrade_bookworm_download() {
  local directory=$1 targets=$2 installed=$3 phase=$4 file package version arch cache
  local -a apt_options=()
  shift 4
  read -r -a apt_options <<< "$APT_GET_INSTALL_OPTIONS"
  cache=$(mktemp -d "$directory/$phase.XXXXXX") || return 1
  mkdir "$cache/partial" || return 1
  printf '%s\n' "$cache" > "$directory/$phase.cache" || return 1
  LC_ALL=C apt-get "${apt_options[@]}" -o APT::Get::AllowUnauthenticated=false \
    -o APT::Get::AutomaticRemove=false -o APT::Get::Purge=false --allow-remove-essential --fix-broken --simulate install "$@" \
    > "$directory/$phase.plan" 2>&1 || return 1
  crossgrade_bookworm_check_plan "$directory/$phase.plan" "$targets" "$installed" || {
    echo "dss:error: Crossgrade plan would remove a protected package or reverse architecture; inspect $directory/$phase.plan." >&2
    return 1
  }
  LC_ALL=C apt-get "${apt_options[@]}" -o APT::Get::AllowUnauthenticated=false \
    -o APT::Get::AutomaticRemove=false -o APT::Get::Purge=false -o Dir::Cache::archives="$cache" \
    --allow-remove-essential --fix-broken --download-only install "$@" || return 1
  : > "$directory/$phase.archives" || return 1
  for file in "$cache/"*.deb; do
    [ -f "$file" ] || continue
    package=$(dpkg-deb -f "$file" Package) && version=$(dpkg-deb -f "$file" Version) && arch=$(dpkg-deb -f "$file" Architecture) || return 1
    case "$arch" in
      amd64|all) :;;
      i386) awk -F '\t' -v package="$package" '$1 == package && $3 == "same" { found=1 } END { exit !found }' "$targets" || {
        echo "dss:error: Unapproved i386 archive: $file" >&2; return 1;
      };;
      *) echo "dss:error: Unexpected $arch archive: $file" >&2; return 1;;
    esac
    printf '%s\t%s\t%s\t%s\n' "$package" "$version" "$arch" "$file" >> "$directory/$phase.archives" || return 1
  done
}

function crossgrade_bookworm_check_completion() {
  local directory=$1 audit package version status plan
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

function crossgrade_debian_bookworm() {
  local apt_state_cache_disabled=true current native architecture records file line type filters base added removed
  local baseline directory package installed_version essential priority multi_arch candidate status audit version oldmark held cache attempt
  local -a arguments=() bootstrap=() backups=() archives=() apt_options=()
  read -r -a apt_options <<< "$APT_GET_INSTALL_OPTIONS"
  pause_check || return 1
  current=$(distro_output_codename) || return 1
  [ "$current" = bookworm ] || { echo 'dss:error: This crossgrade backend requires Debian 12 bookworm.' >&2; return 1; }
  [ "$(uname -m)" = x86_64 ] || { echo 'dss:error: Boot a verified x86_64 kernel before crossgrading.' >&2; return 1; }
  [ "$(id -u)" = 0 ] || return 1
  check_disk_space || return 1
  native=$(dpkg --print-architecture) || return 1
  case "$native" in i386|amd64) :;; *) return 1;; esac
  if directory=$(crossgrade_bookworm_output_pending_directory); then :
  else
    status=$?
    [ "$status" -eq 1 ] || { echo 'dss:error: Cannot select an unambiguous pending Bookworm crossgrade.' >&2; return 1; }
    if [ "$native" = amd64 ]; then
      crossgrade_bookworm_check_native || { echo 'dss:error: Mixed native packages without an original crossgrade inventory require manual review.' >&2; return 1; }
      echo 'dss:stage: Bookworm native amd64 conversion is already complete.' >&2
      return 0
    fi
  fi
  crossgrade_check_apt_architecture_config || return 1
  check_systemd_install_matches_init || return 1
  apt_sources_check_releases_and_vendors bookworm || return 1
  records=$(apt_sources_list) || return 1
  while IFS=$'\t' read -r file line _ type _ _ _ filters; do
    [ "$type" = deb ] || continue
    [ "$filters" != '*' ] || continue
    IFS='|' read -r base added removed <<< "${filters//,/ }"
    for architecture in i386 amd64; do
      case " $removed " in *" $architecture "*) echo "dss:error: Source $file:$line excludes $architecture; enable both i386 and amd64 first." >&2; return 1;; esac
      if [ -n "$base" ]; then
        case " $base $added " in *" $architecture "*) :;; *) echo "dss:error: Source $file:$line excludes $architecture; enable both i386 and amd64 first." >&2; return 1;; esac
      fi
    done
  done <<< "$records"
  if [ -z "$directory" ]; then
    baseline=$(config_state_output_baseline) || {
      record_config_state || return 1
      baseline=$(config_state_output_baseline) || return 1
    }
    directory="$baseline.crossgrade-bookworm"
  fi
  if [ ! -f "$directory/original.i386" ]; then
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
  : > "$directory/targets.new" || return 1
  : > "$directory/retained-i386.new" || return 1
  while IFS=$'\t' read -r package installed_version essential priority multi_arch; do
    [ -n "$package" ] || continue
    if candidate=$(crossgrade_bookworm_output_candidate "$package"); then status=0; else status=$?; fi
    [ "$status" -ne 2 ] || { echo "dss:error: Cannot inspect APT availability for $package:amd64." >&2; return 1; }
    if [ -n "$candidate" ] && dpkg --compare-versions "$candidate" ge "$installed_version"; then
      printf '%s\t%s\t%s\n' "$package" "$candidate" "${multi_arch:-no}" >> "$directory/targets.new" || return 1
    else
      case "$essential:$priority:$package" in
        yes:*|*:required:*|*:important:*|*:dpkg|*:apt|*:bash|*:coreutils|*:tar|*:systemd|*:udev|*:openssh-server|*:ifupdown|*:iproute2|*:apache2|*:apache2-bin|*:postfix|*:dovecot-core|*:mariadb-server*)
          echo "dss:error: No suitable archive amd64 replacement for critical package $package; manual migration required." >&2; return 1;;
      esac
      printf '%s\t%s\n' "$package" "$installed_version" >> "$directory/retained-i386.new" || return 1
      case "$package" in libapache2-mod-*)
        upgrade_compatibility_apache_module_enabled "$package"; status=$?
        case "$status" in
          0) echo "dss:error: Active unavailable 32-bit Apache module package $package needs manual migration before changing Apache architecture." >&2; return 1;;
          1) :;;
          *) echo "dss:error: Cannot inspect Apache module configuration for $package." >&2; return 1;;
        esac;;
      esac
      echo "dss:warn: Preserving unavailable legacy foreign package $package:i386 ($installed_version); review it manually." >&2
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
  dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\n' > "$directory/installed" || return 1
  while IFS=$'\t' read -r package candidate multi_arch; do
    arguments+=("$package:amd64=$candidate")
    [ "$multi_arch" = same ] || arguments+=("$package:i386-")
  done < "$directory/targets"
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
    # A second pass can satisfy pre-dependencies configured by the first grouped pass.
    if ! dpkg --force-confnew --force-confmiss --install "${archives[@]}"; then
      dpkg --force-confnew --force-confmiss --install "${archives[@]}" || return 1
    fi
    [ "$(/usr/bin/dpkg --print-architecture)" = amd64 ] || return 1
    apt_get_update || return 1
  fi
  dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\n' > "$directory/installed" || return 1
  crossgrade_bookworm_download "$directory" "$directory/targets" "$directory/installed" remaining "${arguments[@]}" || return 1
  # One transaction keeps systemd and udev together and preserves recorded service packages.
  cache=$(cat "$directory/remaining.cache") || return 1
  LC_ALL=C apt-get "${apt_options[@]}" -o APT::Get::AllowUnauthenticated=false \
    -o APT::Get::AutomaticRemove=false -o APT::Get::Purge=false -o Dir::Cache::archives="$cache" \
    --allow-remove-essential --fix-broken install "${arguments[@]}" || return 1
  while IFS= read -r oldmark; do
    package=${oldmark%:i386}
    if awk -F '\t' -v package="$package" '$1 == package { found=1 } END { exit !found }' "$directory/targets"; then
      apt-mark auto "$package:amd64" || return 1
    fi
  done < "$directory/original.auto"
  if [ "$(od -An -tu1 -j4 -N1 /proc/1/exe 2>/dev/null | tr -d ' ')" != 2 ]; then
    systemctl daemon-reexec || return 1
    for attempt in 1 2 3 4 5; do
      [ "$(od -An -tu1 -j4 -N1 /proc/1/exe 2>/dev/null | tr -d ' ')" != 2 ] || break
      [ "$attempt" -eq 5 ] || sleep 1
    done
  fi
  crossgrade_bookworm_check_completion "$directory" || return 1
  (umask 077; : > "$directory/completed") || return 1
  echo 'dss:stage: Bookworm native amd64 packages, package state and 64-bit PID1 verified.' >&2
}


function crossgrade_debian() {
  local apt_state_cache_disabled=true
  [  ! -f /etc/debian_version ] && echo "dss:info: Only debian derived distro crossgrades are supported, but not $(print_distro_info)." && return 0
  check_disk_space || return 1
  # see https://wiki.debian.org/CrossGrading
  ! uname -a | grep -qai x86_64 && echo "dss:error: Not running a 64 bit kernel. Cannot crossgrade." 2>&1 && return 1

  lsb_release -a 2>/dev/null | egrep -qai 'stretch|lenny|squeeze|wheezy|jessie' && echo "dss:error: Older (pre stretch) Debian distros have dependency issues preventing crossgrades.  $0 --dist-upgrade prior to cross grading." 2>&1 && return 1

  [ -z "$ENABLE_UBUNTU_CROSSGRADE" ] && lsb_release -a 2>/dev/null | egrep -qai 'ubuntu' && echo "dss:error: Ubuntu cross grades have not been successful.  To ignore this warning and attempt one at your own peril: export ENABLE_UBUNTU_CROSSGRADE=Y" 2>&1 && return 1

  if ! check_systemd_install_matches_init; then
    echo "dss:error: system needs a reboot prior to cross grading to fully switch to systemd." 2>&1
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
  [  -z "$IGNORECRUFT" ] && has_cruft_packages oldpkg && show_cruft_packages oldpkg && echo "dss:warn:There are some old packages installed.  Best to remove them before proceeding.  Do that by running bash $0 --show-cruft followed by bash $0 --remove-cruft.  Or to ignore that, run export IGNORECRUFT=Y and re-run this command. " && return 1

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
    apt_get_f_install crossgrade
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
  lsb_release -a 2>/dev/null | grep -qai Ubuntu && echo "dss:fiddle to try and have Ubuntu use amd64 packages by default." &&
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
          apt_get_f_install "after-${pkg}-remove"
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
    local fromfile="$(find /root/distrorejuveinfo/ /root/deghostinfo/ -mtime -${DAYS_UPGRADE_ONGOING} 2>/dev/null | grep crossgrade)"
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

  if has_cruft_packages 32bit; then 
    show_cruft_packages
    echo "dss:error:after cross grade, 32 bit packages remain." >&2
    return 1
  else 
    echo "dss:info:no 32 bit packages remain (good)"
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

# e.g. has_cruft_packages && show_cruft_packages && reduce_cruft_packages
function has_cruft_packages() {
   cruft_packages0 has $1
   # returns 0 if cruft packages
   return $?
}
function show_cruft_packages() {
   cruft_packages0 show $1
   return $?
}

function remove_cruft_packages() {
   cruft_packages0 remove  $1
   local ret=$?
   [ "$ret" -eq 0 ] && echo "dss:trace:removed_cruft_packages completed."
   [ "$ret" -ne 0 ] && echo "dss:error:remove cruft packages failed." >&2
   return $ret
}

# Report from existing indexes only; this deliberately does not use the mutating cruft helpers.
function print_installed_packages_without_available_versions() {
(
  [ -f /etc/debian_version ] || return 0
  umask 077
  set -o pipefail
  local directory native architecture package _installed_arch _version query_arch
  native=$(dpkg --print-architecture) || return 1
  directory=$(mktemp -d) || return 1
  trap 'rm -rf -- "$directory"' EXIT
  dpkg-query -W -f='${Status}\t${Package}\t${Architecture}\t${Version}\n' > "$directory/status" || return 1
  # package<TAB>installed architecture<TAB>version<TAB>query architecture; 'all' uses native indexes.
  awk -F '\t' -v OFS='\t' -v native="$native" '
    $1 ~ / installed$/ { print $2, $3, $4, ($3 == "all" ? native : $3) }
  ' "$directory/status" > "$directory/installed" || return 1
  : > "$directory/available" || return 1
  local architectures
  architectures=$(awk -F '\t' '{ print $4 }' "$directory/installed" | sort -u) || return 1
  for architecture in $architectures; do
    : > "$directory/query" || return 1
    while IFS=$'\t' read -r package _installed_arch _version query_arch; do
      [ "$query_arch" = "$architecture" ] || continue
      if [ "$architecture" = "$native" ]; then
        printf '%s\0' "$package"
      else
        printf '%s\0' "$package:$architecture"
      fi
    done < "$directory/installed" > "$directory/query" || return 1
    # Bound argv size; cache files remain untouched. Madison may also print Sources rows.
    if ! LC_ALL=C xargs -0 -r -n 256 apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= madison < "$directory/query" > "$directory/madison"; then
      echo "dss:error: Cannot assess installed package availability from existing APT indexes; no packages were changed." >&2
      return 1
    fi
    # Madison example: package:i386 | version | URI suite/component i386 Packages
    awk -F '|' -v OFS='\t' -v architecture="$architecture" '
      $3 ~ / Packages[ \t]*$/ {
        name=$1; gsub(/^[ \t]+|[ \t]+$/, "", name); sub(/:.*/, "", name)
        if (name != "") print name, architecture
      }
    ' "$directory/madison" >> "$directory/available" || return 1
  done
  # A missing name/architecture is a migration hint, not a support or vulnerability assessment.
  awk -F '\t' '
    FILENAME == ARGV[1] { available[$1 SUBSEP $2]=1; next }
    !(($1 SUBSEP $4) in available) {
      print "dss:warn: Installed package " $1 ":" $2 " (" $3 ") has no versions in active APT indexes. Review manually and migrate if needed; package preserved."
    }
  ' "$directory/available" "$directory/installed"
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

# e.g. cruft_packages0 show 32bit
function cruft_packages0() {
  [  ! -f /etc/debian_version ] && return 0
  [  ! -x /usr/bin/apt-show-versions ] && apt-get $APT_GET_INSTALL_OPTIONS install apt-show-versions
  local cruftlog=$(mktemp "cruftpackages.log.XXXXXX")
  [ "$1" = "show" ] && local show="true"
  [ "$1" = "has" ] && local has="true" && local hasold="yes" && local has32bit="true"
  [ "$1" = "remove" ] || [  -z "$1" ]&& local remove="true"
  local oldpkg=true
  local bit32=true
  [ "$2" = "oldpkg" ] && oldpkg=true && bit32=
  [ "$2" = "32bit" ] && bit32=true && oldpkg=

  local has_cruft=0
  local commandret=0

  # apt-show-versions
  # ruby:i386 not installed
  # openssl-blacklist:all 0.5-3 installed: No available version in archive
  # ruby-did-you-mean:all/stretch 1.0.0-2 uptodate

  #echo "dss:trace: cruft show=$show has=$has remove=$remove oldpkg=$oldpgk 32bit=$bit32"

  ignorablecruft="^lib|webmin|virtualmin|usermin"
  if [  ! -z "$oldpkg" ] && [ -x /usr/bin/apt-show-versions ]  && [  0 -ne $(print_no_available_versions | egrep -v "$ignorablecruft" | wc -l) ]; then
    has_cruft=$((has_cruft+1))
    [  ! -z "$show" ] && echo "dss:warn: Applications from non-current distro versions installed: $(print_no_available_versions |egrep -v "$ignorablecruft" | grep -v '^lib' | awk '{print $1}' | tr '\n' ' ')"
    if [  ! -z "$remove" ]; then
      echo "dss:trace: Working out the old packages to resume."
      local oldpkgstoremove="$(print_no_available_versions | egrep -v "$ignorablecruft" | awk '{print $1}' | tr '\n' ' ')"
      # e.g. oldpkgstoremove has mysql-server-5.0:i386 mysql-server-core-5.0:i386
      [  $? -ne 0 ] && commandret=$((commandret+1))
      # /var/log/mysql/error.log:
      # [Warning] Failed to set up SSL because of the following SSL library error: SSL context is not usable without certificate and private key
      # =>
      # mysql_ssl_rsa_setup

      # may also need to add skip-grant-tables to /etc/mysql/my.cnf [mysqld] section
      echo "$oldpkgstoremove" | grep -qai mysql-ser && apt_get_install mysql-server
      echo "$oldpkgstoremove" | grep -qai mariadb-server && apt_get_install mariadb-server
      apt_get_remove $oldpkgstoremove
      #apt-get $APT_GET_INSTALL_OPTIONS autoremove
    fi
  fi
  if [  ! -z "$oldpkg" ] && [ -x /usr/bin/apt-show-versions ]  && [  0 -ne $(print_no_available_versions | grep '^lib' | wc -l) ]; then
    has_cruft=$((has_cruft+1))
    [  ! -z "$show" ] && echo "dss:warn: Libraries from non-current distro versions installed: $(print_no_available_versions | grep '^lib' | awk '{print $1}' | tr '\n' ' ')"
    if [  ! -z "$remove" ]; then
      apt_get_remove $(print_no_available_versions | grep '^lib' | awk '{print $1}' | tr '\n' ' ')
      [  $? -ne 0 ] && commandret=$((commandret+1))
      #apt-get $APT_GET_INSTALL_OPTIONS autoremove
    fi
  fi
  if [  ! -z "$bit32" ]; then
    if [ $(getconf LONG_BIT) -eq 32 ]; then
      return 0
    fi
    if [ $(getconf LONG_BIT) -eq 64 ]; then
      dpkg -l | grep 'i386' | grep '^ii' | awk '{print $2}' > "$cruftlog"
      if [  $(cat "$cruftlog" | head | wc -l ) -gt 0 ]; then
        has_cruft=$((has_cruft+1))
        [  ! -z "$show" ] && echo "dss:warn: There are some i386 application packages still installed.  They can be removed by running bash $0 --remove-cruft.  They are: $(grep -v '^lib' "$cruftlog" | tr '\n' ' ') $(grep '^lib' "$cruftlog" | tr '\n' ' ')."
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
              dpkg -l | grep 'i386' | grep '^ii' | awk '{print $2}' > "$cruftlog"
            else
              echo "dss:trace: cross grading downloading essential packages (after download+install failed) via download and separate install"
              apt-get $APT_GET_INSTALL_OPTIONS download $essentialpackages
              dpkg_install $(find . -type f |  egrep 'amd64.deb$|all.deb$')
              [  ! -d /root/distrorejuveinfo/$$ ] && mkdir /root/distrorejuveinfo/$$
              mv $(find /var/cache/apt/archives/ -type f  | egrep 'amd64.deb$|all.deb$') /root/distrorejuveinfo/$$
              dpkg -l | grep 'i386' | grep '^ii' | awk '{print $2}' > "$cruftlog"
            fi
          done

          # install 64 versions of the packages if we can.
          local lib64="$(grep -v '^lib' "$cruftlog" | sed 's/:i386/:amd64/g' | tr '\n' ' ')"
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
          apt_get_remove $(grep -v '^lib' "$cruftlog" | sed 's/:i386//' | sed 's/$/:i386/' | tr '\n' ' ' )
          local lib32="$(dpkg -l | grep ':i386' | grep '^ii' | awk '{print $2}' | grep 'lib' )"
          echo "dss:trace: individually removing i386 libraries: $lib32"
          for i in $lib32; do apt_get_remove $i; done
          #apt-get $APT_GET_INSTALL_OPTIONS autoremove
          [  $(dpkg -l | grep ':i386' | grep '^ii' | wc -l) -gt 0 ] && commandret=$((commandret+1))
        fi
      fi
    fi
  fi # if32
  [  -f "$cruftlog" ] && rm -f "$cruftlog"
  # returns 0 if cruft packages
  [  ! -z "$remove" ] && return $commandret
  if [  ! -z "$has" ]; then [ $has_cruft -gt 0 ] && return 0 || return 1; fi
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
    if ! which dpkg >/dev/null 2>&1; then break; fi

    # mysql server of some version is installed.  done
    if dpkg -l | egrep -qai '^ii.*mysql-server|^ii.*mariadb-server'; then break; fi

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

    echo "dss:info: MySQL appears to have been installed, but no longer present.  This can happen between debian 8 and debian 9.  As mysql is replaced by mariadb.  Attempting to install mysql-server which would pull in mariadb."
    dpkg -l | egrep -i 'mysql|mariadb' | awk '{print "dss:mysqlrelatedpackages:pre:" $0}'
    local dbpgk=
    local dbpkgret=0
    if dpkg -l | egrep ii | egrep -qai 'mariadb'; then
      dbpkg=mariadb-server
    elif dpkg -l | egrep ii | egrep -qai 'mysql.*server'; then
      dbpkg=mysql-server
    fi
    if [ ! -z "$dbpkg" ]; then
      apt_get_install $dbpkg
      dbpkgret=$?
      if [ $dbpkgret -ne 0 ]; then
        apt_get_install default-mysql-server
        dbpkgret=$?
      fi
    fi
    dpkg -l | egrep -i 'mysql|mariadb' | awk '{print "dss:mysqlrelatedpackages:post:" $0}'
    break
  done

  #Failed because this line in /etc/mysql/my.cnf.migrated
  #log_slow_queries      = /var/log/mysql/mysql-slow.log
  #needed to change to:
  #slow_query_log                  = 1
  #slow_query_log_file             = /var/log/mysql/mysql-slow.log
  #find /var/log -type f | xargs --no-run-if-empty grep log_slow | grep ERROR
  #/var/log/daemon.log:Apr  6 19:14:44 ititch mysqld_safe[13273]: 2020-04-06 19:14:44 3079187200 [ERROR] /usr/sbin/mysqld: unknown variable 'log_slow_queries=/var/log/mysql/mysql-slow.log'
  if [ -f /var/log/daemon.log ] && grep -qai "unknown variable 'log_slow" /var/log/daemon.log; then
    echo "dss:info: Disabling log_slow settings, they are now slow_query_log"
    [ -d /etc/mysql ] && for file in $(find /etc/mysql/ -type f | xargs --no-run-if-empty grep -l '^log_slow'); do
      sed -i 's/^log_slow/#log_slow/' $file && echo "dss:info: disabled log_slow in $file"
    done
    [ -f /etc/init.d/mysql ] && ps auxf | grep -qai '[m]ysqld_safe' && /etc/init.d/mysql restart && echo "dss:info: issued a mysql restart"
  fi

  for i in $(find /etc/cron.* -type f -name 000loaddelay); do
    #old style ifconfig
    ifconfig | grep -qai 'inet addr' && continue
    # not our script
    grep -qai 'random=.*ifconfig.*sed' $i || continue
    echo '#!/bin/bash
# This is to delay cron jobs by up to 10 minutes to relieve host server load.
# needs to parse inet 174.136.11.74  B174.136.11.79  M255.255.255.248 and
# inet addr:174.136.11.74  Bcast:174.136.11.79  Mask:255.255.255.248
declare -i random=$(expr $(ifconfig | grep -v inet6  | grep  "inet" | head -n 1 | sed -e "s/[^0-9 ]//g" | sed "s/^  *//" |  cut -f 1 -d\ ) % 900)
sleep ${random}
exit 0' > $i
    echo "dss:info: updating load delay script: $i"
  done
  # fix missing udev
  while true; do
    # not debian-ish
    if ! which dpkg >/dev/null 2>&1; then break; fi

    # dpkg -l | grep '/dev'
    # ii  makedev                          2.3.1-93                       all          creates device files in /dev
    # rc  udev                             232-25+deb9u1                  i386         /dev/ and hotplug management daemon
    if dpkg -l | grep -qai '^ii.*udev-'; then break; fi

    apt_get_install udev
    ret=$?
    echo "dss:info: udev install result $ret $(dpkg -l | grep udev)"
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
  # This check must remain read-only: do not run upgrade_precondition_checks (REMOVEX11 can remove packages).
  apt_sources_check_releases_and_vendors || return 1
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
  return 0
}

function dist_upgrade_x_to_y() {
pause_check
[ ! -f /etc/debian_version ] && return 0
echo "dss:trace:dist_upgrade_x_to_y:checking:olddistro=$old_distro:oldver=$old_ver:newdistro=$new_distro"

local current apt_sources_transition_target=$new_distro
current=$(distro_output_codename) || return 1
if [ "$current" != "$old_distro" ]; then
  echo "dss:info: Installed release is $current; skipping $old_distro to $new_distro."
  return 0
fi

echo "dss:stage: Upgrading Debian $old_distro -> $new_distro"
check_disk_space || return 1

upgrade_check_path debian "$old_distro" "$new_distro" || return $?
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

if [ "$old_distro" == "lenny" ]; then
  add_missing_debian_keys
  [ ! -d "/dev/pts" ] && mkdir /dev/pts && echo "dss:info: created /dev/pts"
fi

upgrade_precondition_checks "$new_distro" || return 1
apt_sources_prepare || return 1
if [ "$new_distro" = bookworm ] || [ "$new_distro" = trixie ]; then check_usrmerge || return 1; fi
retain_etc_networking_naming_re_enX0
fix_missing_lsb_release || return 1

echo "dss:trace:dist_upgrade_x_to_y:pre_apt_get_upgrade:old:$old_distro:new:$new_distro"
apt_get_upgrade
local ret=$?
if [ $ret -ne 0 ]; then
  echo "dss:error: apt-get upgrade failed.  exiting dist_upgrade_x_to_y:${old_distro}_to_${new_distro}"
  return 1
fi
apt-get clean
apt-get $APT_GET_INSTALL_OPTIONS autoremove

apt_sources_upgrade debian "$old_distro" "$new_distro" || return 1
apt_get_update || return 1

echo "dss:trace:dist_upgrade_x_to_y:pre_apt_get_dist_upgrade::olddistro=$old_distro:oldver=$old_ver:newdistro=$new_distro"
apt_get_dist_upgrade
ret=$?
if [ $ret -eq 0 ]; then
  apt-get $APT_GET_INSTALL_OPTIONS autoremove
  echo "dss:trace:dist_upgrade_x_to_y:post_apt_get_dist_upgrade::olddistro=$old_distro:oldver=$old_ver:newdistro=$new_distro:ret=$ret"
	if lsb_release -a 2>/dev/null| egrep -qai "${new_distro}|${new_ver:-xxxxx}"; then
	  # dist-upgrade returned ok, and lsb_release thinks we are wheezy
	  echo "dss:info: dist-upgrade from ${old_distro} to ${new_distro} appears to have worked."
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
  local a=$1
  [ ! -f "$a" ] && return 1
  egrep -v '^\s*#|^$' "$a"
  return 0
}
function print_pkg_to_modified_diff() {
[  ! -d "/root/pkgdiff.$$" ] && mkdir /root/pkgdiff.$$
# get a list of config files in packages that have been changed by the user
local modifiedconfigfiles=$(dpkg-query -W -f='${Conffiles}\n' '*' | grep -v obsolete  | awk 'OFS="  "{print $2,$1}' | LANG=C md5sum -c 2>/dev/null | awk -F': ' '$2 !~ /OK$/{print $1}' | sort)
local modifiedconfigfile
cd /root/pkgdiff.$$ || return 1
for modifiedconfigfile in $modifiedconfigfiles; do
  # figure out the package name
  # dpkg -S /etc/apache2/mods-available/ssl.conf
  # apache2: /etc/apache2/mods-available/ssl.conf
  local pkg=$(dpkg -S "$modifiedconfigfile" | awk '{print $1}' | sed 's/://')
  [ -z "$pkg" ] && continue

  #figure out the filename
  #apt-get --print-uris download apache2
  # 'http://http.us.debian.org/debian/pool/main/a/apache2/apache2_2.4.10-10+deb8u7_i386.deb' apache2_2.4.10-10+deb8u7_i386.deb 207220 SHA256:7974cdeed39312fda20165f4ee8bebc10f51062600a7cd95f4c5cba32f7ae12c
  # note will not return a result if the file is already here (hence the 'hidden' stuff below).
  local debfilename=$(apt-get --print-uris download "$pkg" 2>/dev/null| awk '{print $2}')
  [ -z "$debfilename" ] && continue

  # download it if we don't already have it
  if [ ! -f "hidden-${debfilename}" ]; then
    apt-get download "$pkg" &>/dev/null
    # can fail if apt is not up to date
    [ $? -ne 0 ] && apt_get_update &>/dev/null && apt-get download "$pkg" &>/dev/null
    # extract to local dir
    dpkg -x "$debfilename" .
    mv "$debfilename" "hidden-$debfilename"
  fi

  # Apache configuration is managed by its packages; reporting must not create sidecars there.
  case "$modifiedconfigfile" in /etc/apache2|/etc/apache2/*|/etc/httpd|/etc/httpd/*) :;;
    *) [ -f "./${modifiedconfigfile}" ] && [ ! -f "${modifiedconfigfile}.dpkg-dist" ] && cp "./${modifiedconfigfile}" "${modifiedconfigfile}.dpkg-dist";;
  esac
  [ -f "${modifiedconfigfile}.dpkg-dist" ] && echo "dss:modifiedfilereplace:To replace edited file with dist file: [ ! -f $modifiedconfigfile.dpkg-old ] && [ -f /etc/nginx/nginx.conf.dpkg-dist] && mv $modifiedconfigfile $modifiedconfigfile.dpkg-old && mv ${modifiedconfigfile}.dpkg-dist ${modifiedconfigfile}"
  # show a diff
  print_minimal_config_diff "./$modifiedconfigfile" "$modifiedconfigfile" | awk '{print "dss:configdiff:modifiedconfig:'$pkg':'$modifiedconfigfile':" $0}'
done

# cleanup
cd - >/dev/null || return 1
rm -rf /root/pkgdiff.$$
return 0
}

function print_minimal_config_diff() {
  local a=$1
  local b=$2
  [ ! -f "$a" ] && return 1
  [ ! -f "$b" ] && return 1
  ta=$(mktemp "$(basename "${a}").XXXXXX") || return 1
  if ! tb=$(mktemp "$(basename "${b}").XXXXXX"); then
    rm -f "$ta"
    return 1
  fi
  print_minimal_config "$a" > "$ta"
  print_minimal_config "$b" > "$tb"
  diff --ignore-all-space -u "$ta" "$tb"
  ret=$?
  rm -f "$ta" "$tb"
  return $ret
}
function print_config_state_changes() {
  prepare_output_dir
  local availability_ret=0
  print_installed_packages_without_available_versions || availability_ret=$?
  local now=$(date +%s)
  record_config_state "/root/distrorejuveinfo/postupgrade.dpkg.$now"
  # get oldest/first preupgrade file.  e.g. we may have to rerun this script.  so diff from first run
  local fromfile="${1}"
  if [  -z "$fromfile" ]; then
    fromfile=$(config_state_output_baseline) || fromfile=
  fi
  [ -z "$fromfile" ] && fromfile=/root/distrorejuveinfo/preupgrade.dpkg.$$
  # no prior changes just yet.
  [  ! -f  "$fromfile" ] && return "$availability_ret"
  print_incompatible_package_changes "$fromfile"
  # dpkg-new is used on unpack prior to choosing dpkg-dist or overwriting.
  echo "dss:info: Config changes to check.  e.g. different processes after upgrade.  e.g. different ports.  e.g. different apache status output.  e.g. changes to dpkg-old/dpkg-dist files.  dpkg-old = your files that were not used.  dpkg-dist = distro files that were not used."
  print_minimal_config_diff "$fromfile" "/root/distrorejuveinfo/postupgrade.dpkg.$now" | awk '{print "dss:configdiff:statechanges:" $0}'

  # ucf-dist = backup of what was there before dist upgrade
  local files=$(find "/etc" -type f | egrep '.ucf-old|.ucf-diff|.dpkg-new|.dpkg-old|dpkg-dist|\.rpmnew|.rpmsave' | sort)
  [  -z "$files" ] && echo "dss:info: Looks like the server is using all distro-provided config files (no local overrides).  That makes it easy."
  [ ! -z "$files" ] && echo "dss:info:key: How the distro provided config files differ from what is installed.  Consider what is needed to switch back to the distro provided config files?"
  for file in $files; do
    # defer to the new and improved print_pkg_to_modified_diff function (debian/ubuntu only)
    echo $file | grep -q 'dpkg-dist' && continue
    # if not rpmnew file, skip
    echo $file | egrep -qv 'dpkg-dist|rpmnew' && continue
    current=$(echo $file | sed 's/\.dpkg-dist$//')
    current=$(echo $file | sed 's/\.rpmnew$//')

    # modified file exists?
    [ -z "$current" ] || [ ! -f $current ] && continue

    echo "dss:pkgdiff:$current To use the dist file: mv $current $current.dpkg-old; mv $file $current"
    print_minimal_config_diff $file $current | awk '{print "dss:configdiff:pkgconfig:" $0}'
  done
  print_pkg_to_modified_diff

  # non .conf site files
  # IncludeOptional sites-enabled/*.conf
  [ -d /etc/apache2/sites-available ] && [ -f /etc/apache2/apache2.conf ] && grep -qai 'Include.*sites-.*conf' /etc/apache2/apache2.conf && local nonconfsitefiles=$(find /etc/apache2/sites-available -type f | egrep -v '\.conf$|dpkg-')
  for file in $nonconfsitefiles; do
    echo "dss:warn: Apache config file '$file' should have a .conf extension: mv $file $file.conf;a2ensite $(basename $file).conf"
  done
  return "$availability_ret"
}

# Keep purge reminders attached to the same oldest recent baseline used for configuration diffs.
function config_state_output_baseline() {
  local file baseline='' days=${DAYS_UPGRADE_ONGOING:-7}
  case "$days" in *[!0-9]*|'') echo "dss:error: DAYS_UPGRADE_ONGOING must be a positive integer." >&2; return 1;; esac
  [ "$days" -gt 0 ] || return 1
  for file in "/root/distrorejuveinfo/"*preupgrade* "/root/deghostinfo/"*preupgrade*; do
    [ -f "$file" ] || continue
    [ -n "$(find "$file" -maxdepth 0 -mtime "-$days" -print)" ] || continue
    if [ -z "$baseline" ] || [ "$file" -ot "$baseline" ]; then baseline=$file; fi
  done
  [ -n "$baseline" ] || return 1
  printf '%s\n' "$baseline"
}

function print_incompatible_package_changes() {
  local baseline=$1 manifest package backup confirmed
  for manifest in "$baseline.purged-incompatible/"*/packages.purged "$baseline.purged-incompatible/"*/packages.requested; do
    [ -f "$manifest" ] || continue
    backup=${manifest%/*}
    confirmed=false
    case "$manifest" in
      */packages.purged) confirmed=true;;
      *) [ -f "$backup/packages.purged" ] && continue;;
    esac
    while IFS= read -r package; do
      if $confirmed; then
        echo "dss:warn: Package purged before upgrading: $package. Backup: $backup. Reinstall manually if needed: apt-get install $package"
      else
        echo "dss:warn: Purge completion unconfirmed for selected package: $package. Backup/attempt directory: $backup. Review package state before manual reinstall: apt-get install $package"
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
  [ ! -z "$files" ] && ls -lrt $files | awk '{print "configfiles:" $0}' > "$file"
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
  return 0
}

function apt_get_update() {
  echo "dss:stage: Refreshing APT package indexes" >&2
pause_check
local tmplog signature completed inputs current_inputs warning_status
signature=$(apt_state_output_signature repositories 2>/dev/null) || signature=
if [ -n "$signature" ] && [ "$signature" = "${apt_state_updated:-}" ]; then
  ret=0
  echo "dss:trace:apt_get_update: indexes already refreshed for these repositories."
  return 0
fi
inputs=$(apt_state_output_signature inputs 2>/dev/null) || inputs=
apt_state_updated=
apt_state_upgraded=
apt_state_dist_upgraded=
tmplog=$(mktemp "tmplog.aptgetupdate.log.XXXXXX") || return 1
apt-get $APT_GET_INSTALL_OPTIONS update 2>&1 | tee "$tmplog"
ret=${PIPESTATUS[0]}

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
  apt-get -o Acquire::ForceIPv4=true -o APT::Get::AllowUnauthenticated=yes -o Acquire::Check-Valid-Until=false "${release_options[@]}" update 2>&1 | tee -a "$tmplog"
  ret=${PIPESTATUS[0]}
fi

# https://www.debian.org/releases/bookworm/amd64/release-notes/ch-information.html#non-free-split
if egrep -qai "Repository 'Debian bookworm' changed its 'non-free component' value from 'non-free' to 'non-free non-free-firmware'" "$tmplog" && [ -d /etc/apt/apt.conf.d/ ]; then
  echo "dss:info: disabling the warning around non-free/non-free-firmware per /etc/apt/apt.conf.d/no-bookworm-firmware.conf and https://www.debian.org/releases/bookworm/amd64/release-notes/ch-information.html#non-free-split" && echo 'APT::Get::Update::SourceListWarnings::NonFreeFirmware "false";' > /etc/apt/apt.conf.d/no-bookworm-firmware.conf
fi

# A stale APT::Default-Release can break package selection even after a good update.
if [ "$ret" -eq 0 ]; then
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
[ "$ret" -ne 0 ] && echo "dss:error:apt_get_update failed." >&2
return $ret
}

function apt_get_upgrade() {
  echo "dss:stage: Upgrading current packages" >&2
  pause_check
  [ ! -f /etc/debian_version ] && return 0
  [ -e /etc/redhat-release ] && return 0
  upgrade_precondition_checks || return $?
  apt_sources_archive || return 1
  apt_get_update || return 1
  local signature completed current operation_ret cacheable=true
  signature=$(apt_state_output_signature packages 2>/dev/null) || signature=
  if apt_state_repositories_are_current && [ -n "$signature" ] && [ "$signature" = "${apt_state_upgraded:-}" ]; then
    ret=0
    echo "dss:trace:apt_get_upgrade: packages already upgraded for this state."
    return 0
  fi
  apt_state_upgraded=
  apt_state_dist_upgraded=
  echo "dss:trace:apt_get_upgrade"
  record_config_state
  if ! dpkg --configure -a --force-confnew --force-confmiss; then
    cacheable=false; apt_state_healthy=
  fi
  if ! apt-get $APT_GET_INSTALL_OPTIONS autoremove; then cacheable=false; apt_state_healthy=; fi
  apt_get_f_install || cacheable=false
  echo "dss:info: running an apt-get upgrade"
  apt_state_healthy=
  apt-get $APT_GET_INSTALL_OPTIONS upgrade
  operation_ret=$?
  if [ "$operation_ret" -eq 0 ]; then
    completed=$(apt_state_output_signature packages 2>/dev/null) || completed=
    $cacheable && apt_state_healthy=$completed
  else
    cacheable=false
  fi
  if ! apt-get $APT_GET_INSTALL_OPTIONS autoremove; then cacheable=false; apt_state_healthy=; fi
  apt_get_f_install || cacheable=false
  if [ "$operation_ret" -ne 0 ]; then
    echo "dss:info: apt-get upgrade failed. trying a dist-upgrade..."
    apt-get $APT_GET_INSTALL_OPTIONS dist-upgrade
    operation_ret=$?
    if [ "$operation_ret" -eq 0 ]; then
      echo "dss:info: apt-get dist-upgrade succeeded when an upgrade failed."
      ret=0
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
  return "$ret"
}

function plesk_upgrade() {
  which plesk >/dev/null 2>&1 || return 0
  plesk installer --select-release-current --reinstall-patch --upgrade-installed-components
  local ret=$?
  [ "$ret" -ne 0 ] && echo "dss:error:plesk upgrade failed." >&2
  [ "$ret" -eq 0 ] && echo "dss:info:plesk upgrade completed." >&2
  return $ret
}

function apt_get_dist_upgrade() {
  echo "dss:stage: Performing full package upgrade" >&2
  pause_check
  [ ! -f /etc/debian_version ] && return 0
  upgrade_precondition_checks || return $?
  local signature completed current first_ret upgrade_ret cacheable=true
  signature=$(apt_state_output_signature packages 2>/dev/null) || signature=
  if apt_state_repositories_are_current && [ -n "$signature" ] && [ "$signature" = "${apt_state_dist_upgraded:-}" ]; then
    ret=0
    echo "dss:trace:apt_get_dist_upgrade: packages already upgraded for this state."
    return 0
  fi
  apt_state_dist_upgraded=
  echo "dss:trace:apt_get_dist_upgrade:pre_apt_get_upgrade:"
  apt_get_upgrade || return 1
  echo "dss:trace:apt_get_dist_upgrade"
  apt_get_f_install || cacheable=false
  apt_get_install dpkg || cacheable=false
  if ! apt-get $APT_GET_INSTALL_OPTIONS autoremove; then cacheable=false; apt_state_healthy=; fi
  apt-get $APT_GET_INSTALL_OPTIONS dist-upgrade
  first_ret=$?
  # Keep recovery retries unconditional after a failure, including immediate-configuration workarounds.
  if [ "$first_ret" -ne 0 ]; then
    cacheable=false; apt_state_healthy=
    if apt-get $APT_GET_INSTALL_OPTIONS dist-upgrade 2>&1 | grep -qai "Could not perform immediate configuration on "; then
      apt-get -f $APT_GET_INSTALL_OPTIONS install libc6-dev
      apt-get dist-upgrade -f -o APT::Immediate-Configure=0 $APT_GET_INSTALL_OPTIONS
    fi
  fi
  [ -e /var/log/syslog ] && [ -e /etc/my/my.cnf ] && if grep "unknown variable 'lc-messages-dir" /var/log/syslog; then
    echo "dss: info: commenting out the my.cnf lc-messages-dir directive in case it is causing problems"
    sed -i "s@^lc-messages-dir\(.*\)@#lc-messages-dir\1@" /etc/my/my.cnf
  fi
  if ! dpkg --configure -a --force-confnew --force-confmiss; then
    cacheable=false; apt_state_healthy=
  fi
  if ! apt-get $APT_GET_INSTALL_OPTIONS autoremove; then cacheable=false; apt_state_healthy=; fi
  apt-get -y autoclean || cacheable=false
  apt_state_healthy=
  apt-get $APT_GET_INSTALL_OPTIONS dist-upgrade
  ret=$?
  if [ "$ret" -eq 0 ]; then
    completed=$(apt_state_output_signature packages 2>/dev/null) || completed=
    $cacheable && apt_state_healthy=$completed
  else
    cacheable=false
    echo "dss:warn: Got an error after an apt-get dist-upgrade. trying an apt-get -f install"
    apt_get_f_install
    apt-get $APT_GET_INSTALL_OPTIONS dist-upgrade
    ret=$?
    if [ "$ret" -ne 0 ]; then
      check_systemd_install_matches_init
      echo "dss:error: Got an error after an apt-get dist-upgrade"
    fi
  fi
  # Config repairs may change packages or fail after the final successful dist-upgrade.
  upgrade_ret=$ret
  tweak_broken_configs || cacheable=false
  current=$(apt_state_output_signature packages 2>/dev/null) || current=
  if $cacheable && apt_state_repositories_are_current && [ -n "$completed" ] && [ "$completed" = "$current" ] &&
      [ "$completed" = "${apt_state_healthy:-}" ]; then
    apt_state_dist_upgraded=$completed
    apt_state_upgraded=$completed
  fi
  ret=$upgrade_ret
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

# First argument limits the number of release transitions; LTS to LTS counts as one.
function dist_upgrade_ubuntu_to_latest() {
  pause_check
  [ -f /etc/debian_version ] || return 0
  local remaining=${1:-1000} current next arch ret apt_sources_transition_target=
  current=$(distro_output_codename) || return 1
  case " $ALL_UBUNTU " in *" $current "*) :;; *) return 0;; esac
  local planned=$current steps=$remaining
  while [ "$steps" -gt 0 ]; do
    next=$(ubuntu_output_next_release "$planned") || return 1
    [ -n "$next" ] || break
    planned=$next
    steps=$((steps-1))
  done
  upgrade_check_path ubuntu "$current" "$planned" || return $?
  while [ "$remaining" -gt 0 ]; do
    current=$(distro_output_codename) || return 1
    next=$(ubuntu_output_next_release "$current") || return 1
    [ -n "$next" ] || return 0
    check_disk_space || return 1
    upgrade_check_path ubuntu "$current" "$next" || return $?
    if [ "$current" = bionic ]; then
      upgrade_crossgrade_before_release ubuntu "$current" "$next" || return $?
    fi
    arch=$(dpkg --print-architecture) || return 1
    if [ "$arch" = i386 ] && ! is_distro_name_older "$current" bionic; then
      echo "dss:error: Native i386 Ubuntu cannot upgrade past 18.04." >&2
      return 1
    fi
    echo "dss:stage: Upgrading Ubuntu $current -> $next"
    apt_sources_transition_target=$next
    upgrade_precondition_checks "$next" || return 1
    apt_sources_prepare || return 1
    apt_get_upgrade || return 1
    retain_etc_networking_naming_re_enX0
    apt_sources_upgrade ubuntu "$current" "$next" || return 1
    apt_get_update || return 1
    apt_get_dist_upgrade
    ret=$?
    if [ "$ret" -ne 0 ] || [ "$(distro_output_codename)" != "$next" ]; then
      echo "dss:error: Ubuntu upgrade from $current to $next failed." >&2
      return 1
    fi
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
which lsb_release >/dev/null 2>&1 && return 0
! [ -f /etc/debian_version ] && return 0
echo "dss:info: Missing lsb release command.  trying to install it."
apt_get_update
apt_get_install lsb-release
ret=$?
return $ret
}


function yum_upgrade() {
  pause_check
  [ ! -f /etc/redhat-release ] && return 0
  check_disk_space || return 1
  yum_enable_rhel4 || return 0
  if ! which yum >/dev/null 2>&1; then echo "dss:info: yum not found."; return 1; fi
  local QOPT=" -q"
  echo "dss:trace:yum_upgrade"

  yum --version >/dev/null && ! yum -q --version 2>/dev/null >/dev/null && QOPT=
  yum -y install yum rpm > /dev/null 2>&1

  # handy tools to make life better
  yum $QOPT -y install yum-utils yum-verify

  echo "dss:info: running yum upgrade"
  yum $QOPT -y upgrade
  ret=$?
  [ "$ret" -ne 0 ] && echo "dss:error:yum_upgrade failed." >&2
  [ "$ret" -eq 0 ] && echo "dss:info:yum_upgrade completed."
  return $ret
}

function yum_enable_rhel4() {
[ ! -f /etc/redhat-release ] && return 0
! grep -qai 'release.* 4' /etc/redhat-release && return 0
if which yum >/dev/null 2>&1; then echo "dss:info: yum enabled on a rhel4 distro already."; return 0; fi
echo "dss:info: yum not enabled on $(print_distro_info).  Trying to enable it."
{
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/libxml2-2.6.16-12.6.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/libxml2-python-2.6.16-12.6.i386.rpm

rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/readline-4.3-13.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/python-2.3.4-14.7.el4.i386.rpm

# install all together else dependency issues
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/sqlite-3.3.6-2.i386.rpm http://vault.centos.org/4.9/os/i386/CentOS/RPMS/sqlite-devel-3.3.6-2.i386.rpm http://vault.centos.org/4.9/os/i386/CentOS/RPMS/python-sqlite-1.1.7-1.2.1.i386.rpm

rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/python-elementtree-1.2.6-5.el4.centos.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/sqlite-3.3.6-2.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/python-sqlite-1.1.7-1.2.1.i386.rpm

rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/elfutils-libelf-0.97.1-5.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/elfutils-0.97.1-5.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/popt-1.9.1-32_nonptl.i386.rpm

rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/python-urlgrabber-2.9.8-2.noarch.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/yum-metadata-parser-1.0-8.el4.centos.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/centos-release-4-8.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/yum-2.4.3-4.el4.centos.noarch.rpm
prepare_output_dir
if [ ! -e /root/distrorejuveinfo/CentOS-Base.repo ]; then
  echo "dss:info: Running cp /etc/yum.repos.d/CentOS-Base.repo /root/distrorejuveinfo/CentOS-Base.repo"
  cp /etc/yum.repos.d/CentOS-Base.repo /root/distrorejuveinfo/CentOS-Base.repo
fi

wget -nc -O /etc/yum.repos.d/CentOS-Base.repo http://vault.centos.org/4.9/CentOS-Base.repo
}
if which yum >/dev/null 2>&1; then echo "dss:info: yum enabled on a rhel4 distro."; return 0
else echo "dss:info: yum install failed on a rhel4 distro."; return 1 ; fi
return 0
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

if [ ! -f /etc/redhat-release ]; then return 0; fi
if grep -qai 'Shrike' /etc/redhat-release; then
  # RH9
  return 0
elif grep -qai 'release.* 7' /etc/redhat-release; then
  # yum install
  return 0
elif  grep -qai 'release.* 6' /etc/redhat-release; then
  # yum install
  return 0
elif  grep -qai 'release.* 5' /etc/redhat-release; then
  # yum install
  return 0
elif  grep -qai 'release.* 4' /etc/redhat-release; then
  # install prebuilt rpm
  return 0
elif  grep -qai 'release.* 3' /etc/redhat-release; then
  # install prebuilt rpm
  return 0
elif  grep -qai 'release.* 2' /etc/redhat-release; then
  true
elif  grep -qai 'release.* 1' /etc/redhat-release; then
  true
else
  return 0
fi

# cat /etc/redhat-release
#Red Hat Enterprise Linux WS release 4 (Nahant)
echo "dss:warn: There is currently no autopatch option for $(print_distro_info).  The distro is likely out of date and no longer supported."
return 1
}

function improve_yum_setup() {
if ! print_distro_info | egrep -i 'redhat|centos' | egrep -qai 'release.* 5|release.* 6|release.* 7' ; then return 0; fi
if rpm -qa 2>&1 | grep -qai rpmdbnextiter ; then
  # e.g. error: rpmdbNextIterator: skipping h#     489 Header V3 RSA/SHA256 Signature, key ID c105b9de: BAD
  echo "dss:info: rpm database errors.  rebuilding the rpm db"
  rpm --rebuilddb
fi
if [ ! -x /usr/bin/yum ] ; then
  #rpm http://centos5.rimuhosting.com/centos /5 os updates rimuhosting addons extras centosplus
  if [ ! -f /etc/apt/sources.list ]; then
    echo "dss:warn: Cannot do a yum install on this host, yum not installed, no /etc/apt/sources.list either."
    return 1
  fi
  if ! which apt-get >/dev/null 2>&1 ; then
    echo "dss:warn: Cannot do a yum install on this host, yum not installed, no apt-get either."
  fi
  echo "dss:info: Trying to install yum via apt-get"
  apt-get --force-yes -y install yum
fi
if [ ! -x /usr/bin/yum ] ; then
  echo "dss:warn: Cannot do a yum install on this host, yum not installed"
  return 1
fi
if [ ! -x /usr/bin/which ]; then
  echo "dss:warn: Which not installed.  Installing that with yum install which."
  yum install -y which
fi

# this file was added by us, but with wrong name (ending in s).
[ -f /etc/yum.repos.d/CentOS-Base.repos ] && [ -f /etc/yum.repos.d/CentOS-Base.repo ] && rm /etc/yum.repos.d/CentOS-Base.repos
if print_distro_info | egrep -i 'redhat|centos' | egrep -qai 'release.* 5' && [ ! -f /etc/yum.repos.d/CentOS-Base.repo ] && [ -d /etc/yum.repos.d ] ; then
 wget -nc -O /etc/yum.repos.d/CentOS-Base.repo http://downloads.rimuhosting.com/CentOS-Base.repos.v5
fi
return 0
}

function packages_upgrade() {
upgrade_precondition_checks || return $?

apt_sources_prepare || return 1

fix_missing_lsb_release


yum_enable_rhel4 || return $?

improve_yum_setup || return $?

add_missing_debian_keys || return $?

upgrade_precondition_checks || return $?

echo "dss:trace:packages_upgrade:pre_apt_get_upgrade:"
apt_get_upgrade || return $?

yum_upgrade || return $?

return 0
}

function dist_upgrade_to_latest() {
  pause_check
  local debian_target=''
  echo "dss:trace:dist_upgrade_to_latest"
  upgrade_preflight_action --dist-upgrade || return $?

  if [ -f /etc/debian_version ] && lsb_release -a 2>/dev/null | grep -qai debian; then
    debian_target=trixie
    if ! dist_upgrade_lenny_to_squeeze; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_lenny_to_squeeze:failed" && return 1; fi
    if ! dist_upgrade_squeeze_to_wheezy; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_squeeze_to_wheezy:failed" && return 1; fi
    if ! dist_upgrade_wheezy_to_jessie; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_wheezy_to_jessie:failed" && return 1; fi
    if ! dist_upgrade_jessie_to_stretch; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_jessie_to_stretch:failed" && return 1; fi
    if ! dist_upgrade_stretch_to_buster; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_stretch_to_buster:failed" && return 1; fi
    if ! dist_upgrade_buster_to_bullseye; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_buster_to_bullseye:failed" && return 1; fi
    if ! dist_upgrade_bullseye_to_bookworm; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_bullseye_to_bookworm:failed" && return 1; fi
    if ! dist_upgrade_bookworm_to_trixie; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_bookworm_to_trixie:failed" && return 1; fi

  fi
  if [ -f /etc/debian_version ] && lsb_release -a 2>/dev/null | grep -qai ubuntu; then
    if ! dist_upgrade_ubuntu_to_latest; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_ubuntu_to_latest:failed" && return 1; fi
  fi
  if ! packages_upgrade; then echo "dss:error:dist_upgrade_to_latest:packages_upgrade:failed" && return 1; fi
  if ! apt_get_dist_upgrade; then echo "dss:error:dist_upgrade_to_latest:apt_get_dist_upgrade:failed" && return 1; fi
  if [ -n "$debian_target" ]; then debian_check_release_completion "$debian_target" || return 1; fi
  if ! plesk_upgrade; then echo "dss:error:dist_upgrade_to_latest:plesk_upgrade:failed" && return 1; fi
}

function print_php5_advice() {
cat<<EOJ
# recent ubuntus have php7.  If your code does not work with that, install
# php5.x from a ppa repository
apt-get install software-properties-common
add-apt-repository ppa:ondrej/php
apt-get install php5.6
EOJ
}


# Application/service manifest: bounded read-only collection.
# shellcheck shell=bash
# Manifest collection is read-only: parse configuration and application metadata, never run application code.
function manifest_json_string() {
  local value="$1" character escaped i
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
          printf -v escaped '\\u%04x' "'$character"
          printf '%s' "$escaped"
        else
          printf '%s' "$character"
        fi ;;
    esac
  done
  printf '"'
}

function manifest_emit() {
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

function manifest_listeners() {
  local raw source protocol address port program scope application
  if command -v ss >/dev/null 2>&1 && raw=$(ss -lntp 2>/dev/null); then
    source=ss
  elif command -v netstat >/dev/null 2>&1 && raw=$(netstat -lntp 2>/dev/null); then
    source=netstat
  else
    manifest_emit warning area listeners reason 'ss/netstat unavailable or permission denied'
    return
  fi
  # ss: LISTEN 0 128 127.0.0.1:25 *:* users:(("master",pid=12,fd=3))
  # netstat: tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN 12/apache2
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
  done < <(printf '%s\n' "$raw" | awk -v source="$source" '
    source == "ss" && $1 == "LISTEN" {
      endpoint=$4; program="unknown"
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
    }')
}

function manifest_packages() {
  local package version status
  if ! command -v dpkg-query >/dev/null 2>&1; then
    manifest_emit warning area packages reason 'dpkg-query unavailable'
    return
  fi
  while IFS=$'\t' read -r package version status; do
    case "$status" in *' installed') :;; *) continue;; esac
    case "$package" in libapache2-mod-php*) manifest_php_packages+=("$package"); manifest_php_versions+=("$version");; esac
    case "$package" in
      apache2|apache2-bin|libapache2-mod-php*|nginx|nginx-core|nginx-full|nginx-light|caddy|postfix|exim4*|sendmail*|dovecot*|courier*|php[0-9]*|php-fpm|ruby|ruby[0-9]*|python[23]*|nodejs|mysql-server*|mariadb-server*|postgresql-[0-9]*|redis-server|mailman*|fail2ban)
        manifest_emit package name "$package" version "$version" ;;
    esac
  done < <(dpkg-query -W -f='${Package}\t${Version}\t${Status}\n' 2>/dev/null)
}

function manifest_read_metadata() {
  # Configuration/metadata only: cap individual files even when they contain a huge single line.
  [ -f "$1" ] && [ -r "$1" ] || return 1
  head -c 1048576 -- "$1" 2>/dev/null
}

function manifest_config_files() {
  local kind="$1" file count=0
  local -a files=()
  case "$kind" in
    apache) files=("$manifest_root"/etc/apache2/apache2.conf "$manifest_root"/etc/apache2/sites-enabled/* "$manifest_root"/etc/apache2/conf-enabled/* "$manifest_root"/etc/httpd/conf/httpd.conf "$manifest_root"/etc/httpd/conf.d/*.conf) ;;
    apache-modules) files=("$manifest_root"/etc/apache2/apache2.conf "$manifest_root"/etc/apache2/mods-enabled/*.load "$manifest_root"/etc/apache2/conf-enabled/*.conf "$manifest_root"/etc/apache2/sites-enabled/*.conf) ;;
    nginx) files=("$manifest_root"/etc/nginx/nginx.conf "$manifest_root"/etc/nginx/sites-enabled/* "$manifest_root"/etc/nginx/conf.d/*.conf) ;;
    caddy) files=("$manifest_root"/etc/caddy/Caddyfile) ;;
    fpm) files=("$manifest_root"/etc/php/*/fpm/pool.d/*.conf "$manifest_root"/etc/php5/fpm/pool.d/*.conf "$manifest_root"/etc/php-fpm.d/*.conf) ;;
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
  local file module conditional owners owner package version source owner_count i seen='' ambiguous=false count=0
  while IFS= read -r file; do
    while IFS=$'\t' read -r module conditional; do
      [ -n "$module" ] || continue
      case "|$seen|" in *"|$module|"*) continue;; esac
      seen="$seen|$module"
      package=unknown; version=unknown; owner_count=0; source=unknown
      case "$module" in
        /*)
          if [ -f "$manifest_root$module" ] && [ "$conditional" = false ]; then
            owners=$(dpkg-query -S "$module" 2>/dev/null) || owners=''
            # dpkg -S: libapache2-mod-php5: /usr/lib/apache2/modules/libphp5.so
            # Multiarch owner names may also include :amd64 before the final ': path'.
            while IFS= read -r owner; do
              [ "$owner" != "${owner%": $module"}" ] || continue
              owner_count=$((owner_count+1))
              [ "$owner_count" -le 1 ] || ambiguous=true
              owner=${owner%": $module"}; owner=${owner%%:*}
              for ((i=0; i<${#manifest_php_packages[@]}; i++)); do
                [ "$owner" = "${manifest_php_packages[i]}" ] || continue
                if [ "$package" != unknown ]; then ambiguous=true; fi
                package=$owner
                version=${manifest_php_versions[i]#*:}
                if [[ "$version" =~ ^([0-9]+[.][0-9]+([.][0-9]+)?) ]]; then version=${BASH_REMATCH[1]}
                else version=unknown; fi
              done
            done <<< "$owners"
          fi;;
      esac
      count=$((count+1))
      [ "$conditional" = false ] || ambiguous=true
      [ "$version" = unknown ] || source=installed_module_package
      manifest_apache_php_version=$version
      manifest_apache_php_package=$package
      manifest_emit runtime kind apache-mod-php version "$version" package "$package" module "$module" config "${file#"$manifest_root"}" conditional "$conditional" version_source "$source"
    done < <(awk '
      FNR > 20000 { exit }
      /^[ \t]*#/ { next }
      tolower($1) ~ /^<if/ { conditional++ }
      tolower($1) ~ /^<\/if/ && conditional > 0 { conditional-- }
      tolower($1) == "loadmodule" && tolower($2) ~ /^php[0-9.]*_module$/ {
        path=$3; gsub(/[\042\047]/,"",path)
        print path "\t" (conditional ? "true" : "false")
      }' < <(manifest_read_metadata "$file"))
  done < <(manifest_config_files apache-modules)
  if [ "$count" -gt 1 ] || $ambiguous; then
    manifest_apache_php_version=unknown
    manifest_apache_php_package=unknown
  fi
  if [ "$count" -eq 1 ] && ! $ambiguous; then manifest_apache_php_available=true; fi
}

function manifest_has_php_document_root() {
  local root=$1 entry
  for entry in index.php wp-includes/version.php administrator/manifests/files/joomla.xml core/lib/Drupal.php includes/constants.php includes/DefaultSettings.php version.php artisan; do
    [ ! -f "$manifest_root$root/$entry" ] || return 0
  done
  return 1
}

function manifest_fpm_pools() {
  local file pool socket user version
  while IFS= read -r file; do
    version=${file#"$manifest_root"/etc/php/}; version=${version%%/*}
    [ "$version" != "$file" ] || version=unknown
    case "$file" in */etc/php5/*) version=5 ;; */etc/php-fpm.d/*) version=unknown ;; esac
    while IFS=$'\t' read -r pool socket user; do
      manifest_fpm_sockets+=("$socket")
      manifest_fpm_users+=("$user")
      manifest_fpm_versions+=("$version")
      manifest_emit runtime kind php-fpm pool "$pool" listen "$socket" user "$user" version "$version" config "${file#"$manifest_root"}"
    done < <(awk '
      function output() { if (pool != "") print pool "\t" socket "\t" user }
      BEGIN { socket="unknown"; user="unknown" }
      FNR > 20000 { exit }
      /^[ \t]*[;#]/ { next }
      /^[ \t]*\[/ { output(); pool=$0; gsub(/^[ \t]*\[|\][ \t]*$/,"",pool); socket="unknown"; user="unknown"; next }
      /^[ \t]*(listen|user)[ \t]*=/ {
        key=$0; sub(/[ \t]*=.*/,"",key); gsub(/^[ \t]+/,"",key)
        value=$0; sub(/^[^=]*=[ \t]*/,"",value); sub(/[ \t]*;.*/,"",value)
        if (key == "listen") socket=value; else user=value
      }
      END { output() }' < <(manifest_read_metadata "$file"))
  done < <(manifest_config_files fpm)
}

function manifest_dns() {
  local domain="$1" address addresses='' match=false result reason i
  manifest_dns_addresses=unknown
  manifest_dns_result=unknown
  if ! $manifest_dns_enabled; then manifest_dns_reason=disabled; return; fi
  if [[ ! "$domain" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z0-9-]+$ ]]; then
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
  if ! command -v timeout >/dev/null 2>&1 || ! command -v getent >/dev/null 2>&1; then
    manifest_dns_reason=resolver_or_timeout_unavailable; return
  fi
  if addresses=$(timeout 2 getent ahosts "$domain" 2>/dev/null); then
    addresses=$(printf '%s\n' "$addresses" | awk '!seen[$1]++ { if (value != "") value=value ","; value=value $1 } END { print value }')
    if [ -n "$addresses" ]; then
      for address in ${addresses//,/ }; do
        case " $manifest_local_addresses " in *" $address "*) match=true ;; esac
      done
      if [ -z "$manifest_local_addresses" ]; then result=unknown; reason=local_addresses_unavailable
      elif $match; then result=this_host; reason=resolved
      else result=other_address; reason=resolved; fi
    else addresses=unknown; result=unknown; reason=no_addresses; fi
  else addresses=unknown; result=unknown; reason=resolution_failed_or_timed_out; fi
  manifest_dns_names+=("$domain"); manifest_dns_values+=("$addresses")
  manifest_dns_results+=("$result"); manifest_dns_reasons+=("$reason")
  manifest_dns_addresses="$addresses"; manifest_dns_result="$result"; manifest_dns_reason="$reason"
}

function manifest_application() {
  local document_root="$1" file='' application=unknown version=unknown language=unknown language_version=unknown version_source=unknown modified=unknown
  case "$document_root" in /*) ;; *) return ;; esac
  case "$document_root" in *'$'*|*'%'*|*'{'*|*'}'*) return ;; esac
  if [ -f "$manifest_root$document_root/wp-includes/version.php" ]; then
    file="$manifest_root$document_root/wp-includes/version.php"; application=WordPress; language=PHP
    version=$(awk '/^[ \t]*\$wp_version[ \t]*=/ { line=$0; sub(/^[^=]*=[ \t]*[\047\042]/,"",line); sub(/[\047\042].*$/,"",line); print line; exit }' < <(manifest_read_metadata "$file"))
  elif [ -f "$manifest_root$document_root/administrator/manifests/files/joomla.xml" ]; then
    file="$manifest_root$document_root/administrator/manifests/files/joomla.xml"; application=Joomla; language=PHP
    version=$(awk 'match($0,/<version>[^<]+/) { print substr($0,RSTART+9,RLENGTH-9); exit }' < <(manifest_read_metadata "$file"))
  elif [ -f "$manifest_root$document_root/core/lib/Drupal.php" ]; then
    file="$manifest_root$document_root/core/lib/Drupal.php"; application=Drupal; language=PHP
    version=$(awk '/const VERSION[ \t]*=/ { line=$0; sub(/^[^=]*=[ \t]*[\047\042]/,"",line); sub(/[\047\042].*$/,"",line); print line; exit }' < <(manifest_read_metadata "$file"))
  elif [ -f "$manifest_root$document_root/includes/constants.php" ] && grep -q 'PHPBB_VERSION' < <(manifest_read_metadata "$manifest_root$document_root/includes/constants.php"); then
    file="$manifest_root$document_root/includes/constants.php"; application=phpBB; language=PHP
    version=$(awk '/define[ \t]*\([ \t]*[\047\042]PHPBB_VERSION[\047\042]/ { line=$0; sub(/^.*PHPBB_VERSION[\047\042][ \t]*,[ \t]*[\047\042]/,"",line); sub(/[\047\042].*$/,"",line); print line; exit }' < <(manifest_read_metadata "$file"))
  elif [ -f "$manifest_root$document_root/includes/DefaultSettings.php" ] && grep -q "\\\$wgVersion" < <(manifest_read_metadata "$manifest_root$document_root/includes/DefaultSettings.php"); then
    file="$manifest_root$document_root/includes/DefaultSettings.php"; application=MediaWiki; language=PHP
    version=$(awk '/^[ \t]*\$wgVersion[ \t]*=/ { line=$0; sub(/^[^=]*=[ \t]*[\047\042]/,"",line); sub(/[\047\042].*$/,"",line); print line; exit }' < <(manifest_read_metadata "$file"))
  elif [ -f "$manifest_root$document_root/version.php" ] && [ -f "$manifest_root$document_root/lib/moodlelib.php" ]; then
    file="$manifest_root$document_root/version.php"; application=Moodle; language=PHP
    version=$(awk '/^[ \t]*\$release[ \t]*=/ { line=$0; sub(/^[^=]*=[ \t]*[\047\042]/,"",line); sub(/[\047\042].*$/,"",line); print line; exit }' < <(manifest_read_metadata "$file"))
  elif [ -f "$manifest_root$document_root/artisan" ]; then application=Laravel; language=PHP
  elif [ -f "$manifest_root$document_root/config.ru" ] || [ -f "$manifest_root$document_root/Gemfile" ]; then language=Ruby
  elif [ -f "$manifest_root$document_root/package.json" ]; then language=JavaScript
  elif [ -f "$manifest_root$document_root/manage.py" ] || [ -f "$manifest_root$document_root/app.wsgi" ]; then language=Python
  elif [ -f "$manifest_root$document_root/index.php" ]; then language=PHP
  elif [ -f "$manifest_root$document_root/index.pl" ]; then language=Perl
  elif [ -f "$manifest_root$document_root/index.cgi" ]; then
    language=$(awk 'NR == 1 { if ($0 ~ /^#!.*perl/) print "Perl"; else if ($0 ~ /^#!.*python/) print "Python"; else print "unknown"; exit }' < <(manifest_read_metadata "$manifest_root$document_root/index.cgi"))
  fi
  # A version is metadata, never an arbitrary expression or configuration value.
  if [[ ! "$version" =~ ^[0-9][A-Za-z0-9.+_()\ -]{0,100}$ ]]; then version=unknown; fi
  if [ -n "$file" ]; then modified=$(stat -c '%y' -- "$file" 2>/dev/null) || modified=unknown; fi
  case "$language" in
    Ruby) file="$manifest_root$document_root/.ruby-version" ;;
    Python) file="$manifest_root$document_root/.python-version" ;;
    *) file= ;;
  esac
  if [ -n "$file" ] && [ -r "$file" ]; then
    language_version=$(awk 'NR == 1 { print; exit }' < <(manifest_read_metadata "$file"))
    if [[ "$language_version" =~ ^[0-9][0-9A-Za-z.+_-]{0,60}$ ]]; then version_source=project_declared_not_verified_runtime
    else language_version=unknown; fi
  fi
  manifest_emit application document_root "$document_root" application "$application" version "$version" language "$language" language_version "$language_version" language_version_source "$version_source" version_file_modified "$modified" date_basis filesystem_metadata_not_install_date
}

function manifest_website() {
  local server="$1" names="$2" port="$3" tls="$4" document_root="$5" user="$6" runtime="$7" config="$8"
  local name url scheme=http runtime_version=unknown runtime_source=unknown runtime_package=unknown i
  for ((i=0; i<${#manifest_fpm_sockets[@]}; i++)); do
    if [[ "$runtime" == *"${manifest_fpm_sockets[i]}"* ]] && [ "${manifest_fpm_sockets[i]}" != unknown ]; then
      user=${manifest_fpm_users[i]}; runtime_version=${manifest_fpm_versions[i]}; runtime=php-fpm
      runtime_source=fpm_pool_config
      break
    fi
  done
  case "$runtime" in
    php-fpm|php_disabled) :;;
    /*|*fcgi*) runtime=fastcgi_handler_version_unknown;;
    *php*) runtime=php_handler_version_unknown;;
  esac
  if [ "$server" = apache ] && $manifest_apache_php_available; then
    if [ "$runtime" = php_handler_version_unknown ] || { [ "$runtime" = unknown ] && manifest_has_php_document_root "$document_root"; }; then
      runtime=apache-mod-php; runtime_version=$manifest_apache_php_version; runtime_package=$manifest_apache_php_package
      runtime_source=enabled_module_inferred_for_php_site
    fi
  fi
  [ "$tls" != true ] || scheme=https
  # Configs use comma-separated names internally; whitespace and controls are removed by the parsers.
  for name in ${names//,/ }; do
    case "$name" in https://*) scheme=https; name=${name#https://} ;; http://*) scheme=http; name=${name#http://} ;; esac
    if [[ "$name" =~ ^([^:]+|\[[^]]+\]):([0-9]+)$ ]]; then
      port=${BASH_REMATCH[2]}; name=${BASH_REMATCH[1]}
    elif [[ "$name" == *:* ]] && [[ "$name" != \[*\] ]]; then name="[$name]"; fi
    url="$scheme://$name"
    case "$scheme:$port" in http:80|https:443|*:unknown) ;; *) url="$url:$port" ;; esac
    case "$name" in unknown|_) url=unknown;; esac
    manifest_dns "$name"
    manifest_emit website server "$server" name "$name" port "$port" tls "$tls" url "$url" document_root "$document_root" user "$user" runtime "$runtime" runtime_version "$runtime_version" runtime_version_source "$runtime_source" runtime_package "$runtime_package" config "$config" dns "$manifest_dns_result" dns_addresses "$manifest_dns_addresses" dns_reason "$manifest_dns_reason" proxy unknown
  done
  case "|$manifest_seen_roots|" in *"|$document_root|"*) ;; *)
    manifest_seen_roots="$manifest_seen_roots|$document_root"
    manifest_application "$document_root" ;;
  esac
}

function manifest_websites() {
  local server file names port tls document_root user runtime default_user
  for server in apache nginx caddy; do
    default_user=unknown
    case "$server" in
      apache)
        if [ -r "$manifest_root/etc/apache2/envvars" ]; then
          default_user=$(awk '/^[ \t]*(export[ \t]+)?APACHE_RUN_USER=[A-Za-z_][A-Za-z0-9_-]*[ \t]*$/ { sub(/^.*=/, ""); gsub(/[ \t]/, ""); print; exit }' < <(manifest_read_metadata "$manifest_root/etc/apache2/envvars"))
          [ -n "$default_user" ] || default_user=unknown
        fi ;;
      nginx)
        if [ -r "$manifest_root/etc/nginx/nginx.conf" ]; then
          default_user=$(awk '/^[ \t]*user[ \t]+[A-Za-z_][A-Za-z0-9_-]*[; \t]/ { value=$2; gsub(/;/,"",value); print value; exit }' < <(manifest_read_metadata "$manifest_root/etc/nginx/nginx.conf"))
          [ -n "$default_user" ] || default_user=unknown
        fi ;;
    esac
    while IFS= read -r file; do
      while IFS=$'\t' read -r names port tls document_root user runtime; do
        [ -n "$names" ] || continue
        manifest_website "$server" "$names" "$port" "$tls" "$document_root" "$user" "$runtime" "${file#"$manifest_root"}"
      done < <(awk -v server="$server" -v default_user="$default_user" '
        function reset( i) { names="unknown"; port="unknown"; tls="unknown"; root="unknown"; user=default_user; runtime="unknown"; listeners=0; for (i in ports) delete ports[i]; for (i in secure) delete secure[i] }
        function emit( i) {
          if (!active) return
          if (!listeners) print names "\t" port "\t" tls "\t" root "\t" user "\t" runtime
          else for (i=1; i<=listeners; i++) print names "\t" ports[i] "\t" secure[i] "\t" root "\t" user "\t" runtime
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
            key=tolower($1)
            if (key == "<virtualhost") { emit(); reset(); active=1; port=$2; gsub(/[>]/,"",port); sub(/^.*:/,"",port); next }
            if (key == "</virtualhost>") { emit(); active=0; next }
            if (!active) next
            if (key == "servername" || key == "serveralias") append_names(2,NF)
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
              if ($1 == "ssl_certificate") tls="true"
              if ($1 == "root" && depth == 1) { root=$0; sub(/^[ \t]*root[ \t]+/,"",root); sub(/;[ \t]*$/,"",root); gsub(/^[\042\047]|[\042\047]$/,"",root) }
              if ($1 == "user") user=$2
              if ($1 == "fastcgi_pass") { runtime=$2; sub(/^unix:/,"",runtime); gsub(/;/,"",runtime) }
              if ($1 == "proxy_pass") runtime="reverse_proxy"
              if ($1 == "uwsgi_pass") runtime="uwsgi"
              depth += opens-closes
              if (depth <= 0) { emit(); active=0 }
            }
          } else if (server == "caddy") {
            opens=gsub(/\{/,"{",line); closes=gsub(/\}/,"}",line)
            if (!active && opens > 0 && $1 !~ /^\(/ && $1 != "{") { reset(); active=1; depth=0; append_names(1,NF-1); port="443"; tls="true"; if ($1 ~ /^http:\/\//) { port="80"; tls="false" }; sub(/^https?:\/\//,"",names) }
            if (active) {
              if ($1 == "root") { root=$0; sub(/^[ \t]*root[ \t]+(\*[ \t]+)?/,"",root); gsub(/^[\042\047]|[\042\047][ \t]*$/,"",root) }
              if ($1 == "php_fastcgi") { runtime=$2; sub(/^unix\//,"",runtime) }
              if ($1 == "reverse_proxy") runtime="reverse_proxy"
              depth += opens-closes
              if (depth <= 0) { emit(); active=0 }
            }
          }
        }
        END { emit() }' < <(manifest_read_metadata "$file"))
    done < <(manifest_config_files "$server")
  done
}

function manifest_mail_root() {
  local path="$1" source="$2" size=unknown count=unknown reason=not_scanned count_reason=ambiguous_layout actual output inode
  case "$path" in /*) ;; *) return ;; esac
  case "$path" in *'$'*|*'%'*|*'~'*|*'{'*|*'}'*)
    manifest_emit mail_storage path "$path" source "$source" size_mib unknown mailbox_count unknown reason dynamic_path
    return ;;
  esac
  case "|$manifest_mail_seen|" in *"|$path|"*) return ;; esac
  manifest_mail_seen="$manifest_mail_seen|$path"
  actual="$manifest_root$path"
  [ -d "$actual" ] || return
  inode=$(stat -c '%d:%i' -- "$actual" 2>/dev/null) || inode=
  if [ -n "$inode" ]; then
    case "|$manifest_mail_inodes|" in *"|$inode|"*) return ;; esac
    manifest_mail_inodes="$manifest_mail_inodes|$inode"
  fi
  manifest_mail_count=$((manifest_mail_count+1))
  # Only conventional narrow mail roots are scanned; a configured / or /home is never traversed.
  case "$path" in /var/mail|/var/spool/mail|/var/vmail|/var/mail/*|/var/spool/mail/*|/var/vmail/*|/home/*/Maildir|/root/Maildir)
    if $manifest_mail_metrics && [ "$manifest_mail_count" -le 8 ] && command -v timeout >/dev/null 2>&1; then
      if output=$(timeout 3 du -smx -- "$actual" 2>/dev/null); then size=${output%%[[:space:]]*}; reason=measured; else reason=limit_or_permissions; fi
      if [ -d "$actual/cur" ] && [ -d "$actual/new" ] && [ -d "$actual/tmp" ]; then count=1; count_reason=maildir
      elif [ "$path" = /var/mail ] || [ "$path" = /var/spool/mail ]; then
        if output=$(timeout 2 find "$actual" -mindepth 1 -maxdepth 1 -type f -printf '.\n' 2>/dev/null); then
          if [ -n "$output" ]; then count=$(printf '%s\n' "$output" | wc -l); count_reason=top_level_mbox_files; else count=unknown; fi
        fi
      fi
    else reason=disabled_or_limit; fi ;;
    *) reason=nonstandard_path_not_scanned ;;
  esac
  manifest_emit mail_storage path "$path" source "$source" size_mib "$size" mailbox_count "$count" size_basis allocated_disk_mib count_reason "$count_reason" reason "$reason"
}

function manifest_mail() {
  local file path key value home count=0 file_count=0
  for file in "$manifest_root"/etc/postfix/main.cf "$manifest_root"/etc/dovecot/dovecot.conf "$manifest_root"/etc/dovecot/conf.d/*.conf "$manifest_root"/etc/exim4/exim4.conf.template "$manifest_root"/etc/exim4/conf.d/main/* "$manifest_root"/etc/courier/imapd "$manifest_root"/etc/courier/pop3d; do
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then continue; fi
    file_count=$((file_count+1)); [ "$file_count" -le 200 ] || break
    while IFS=$'\t' read -r key value; do
      case "$key" in
        mail_spool_directory|virtual_mailbox_base|mail_path) manifest_mail_root "$value" "${file#"$manifest_root"}:$key" ;;
        mail_location)
          path=${value#*:}; path=${path%%:*}
          manifest_mail_root "$path" "${file#"$manifest_root"}:$key" ;;
      esac
    done < <(awk '
      FNR > 20000 { exit }
      /^[ \t]*[#;]/ { next }
      /^[ \t]*(mail_spool_directory|virtual_mailbox_base|mail_location|mail_path)[ \t]*=/ {
        key=$0; sub(/[ \t]*=.*/,"",key); gsub(/^[ \t]+/,"",key)
        value=$0; sub(/^[^=]*=[ \t]*/,"",value); sub(/[ \t]+#.*/,"",value); gsub(/^[\042\047]|[\042\047][ \t]*$/,"",value)
        print key "\t" value
      }' < <(manifest_read_metadata "$file"))
  done
  manifest_mail_root /var/mail conventional
  manifest_mail_root /var/spool/mail conventional
  manifest_mail_root /var/vmail conventional
  for home in "$manifest_root"/home/*/Maildir "$manifest_root"/root/Maildir; do
    [ -d "$home" ] || continue
    count=$((count+1)); [ "$count" -le 20 ] || break
    manifest_mail_root "${home#"$manifest_root"}" conventional
  done
  if [ "$manifest_mail_count" -eq 0 ]; then
    manifest_emit mail_storage path unknown source unknown size_mib unknown mailbox_count unknown reason no_conventional_mail_store_identified
  fi
}

# FORMAT is text or json; ROOT is used only by isolated fixtures, never a chroot or executable source.
function manifest_output() (
  local manifest_format="${1:-text}" manifest_dns_enabled="${2:-true}" manifest_root="${3:-/}"
  local manifest_separator='' manifest_local_addresses='' manifest_seen_roots='' manifest_mail_seen='' manifest_mail_inodes='' manifest_mail_count=0
  local manifest_dns_limit=20 manifest_mail_metrics="${MANIFEST_MAIL_METRICS:-true}"
  local manifest_dns_addresses manifest_dns_result manifest_dns_reason
  local manifest_apache_php_available=false manifest_apache_php_version=unknown manifest_apache_php_package=unknown
  local -a manifest_php_packages=() manifest_php_versions=()
  local -a manifest_fpm_sockets=() manifest_fpm_users=() manifest_fpm_versions=()
  local -a manifest_dns_names=() manifest_dns_values=() manifest_dns_results=() manifest_dns_reasons=()
  case "$manifest_format:$manifest_dns_enabled:$manifest_mail_metrics" in
    text:true:true|text:true:false|text:false:true|text:false:false|json:true:true|json:true:false|json:false:true|json:false:false) ;;
    *) printf '%s\n' 'dss:error: invalid manifest format or boolean control' >&2; return 1 ;;
  esac
  [ "$manifest_root" = / ] && manifest_root=
  if command -v ip >/dev/null 2>&1; then
    manifest_local_addresses=$(ip -o address show 2>/dev/null | awk '{split($4,a,"/"); printf "%s ",a[1]}')
  fi
  [ "$manifest_format" != json ] || printf '{"schema_version":1,"records":['
  manifest_emit system hostname "$(hostname 2>/dev/null || printf unknown)" generated_utc "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" local_addresses "${manifest_local_addresses:-unknown}"
  manifest_listeners
  manifest_packages
  manifest_apache_php
  manifest_fpm_pools
  manifest_mail
  manifest_websites
  manifest_emit warning area interpretation reason 'Static inventory: conventional config files only (200 files per server, 1 MiB/20000 lines per file); includes, variables and dynamic application settings may be unresolved. Bindings do not prove Internet reachability; DNS may point at a proxy. Application dates are filesystem metadata. No application code was executed.'
  [ "$manifest_format" != json ] || printf ']}\n'
)

# End application/service manifest.

# Detailed logging and console progress.
# Only mutating actions use this wrapper; read-only reports retain normal stdout.
# LOG_VERBOSE and LOG_TRACE are validated booleans set by the main option parser.
function logging_run() (
	local logging_root="${DISTROREJUVE_LOG_DIR:-/root/distrorejuveinfo/runs}"
	local logging_verbose="${LOG_VERBOSE:-false}" logging_trace="${LOG_TRACE:-false}"
	local logging_dir logging_log logging_line logging_status logging_original_umask
	local logging_color=false logging_level
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

	logging_original_umask=$(umask)
	if [ -t 2 ] && [ -z "${NO_COLOR+x}" ] && [ "${TERM:-dumb}" != dumb ]; then logging_color=true; fi
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
	printf 'dss:stage Detailed run log: %s\n' "$logging_log" >&2

	# The subshell contains traps, tracing and callback exits; caller state is intact.
	# Terminal interrupts reach the foreground pipeline, including action children.
	trap 'printf "dss:error Action interrupted; details: %s\n" "$logging_log" >&2; exit 130' INT
	trap 'printf "dss:error Action terminated; details: %s\n" "$logging_log" >&2; exit 143' TERM
	trap 'printf "dss:error Action disconnected; details: %s\n" "$logging_log" >&2; exit 129' HUP
	(
		trap - INT TERM HUP
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
				dss:stage:*|dss:stage\ *) logging_level=36 ;;
				dss:warn:*|dss:warn\ *) logging_level=33 ;;
				dss:error:*|dss:error\ *) logging_level=31 ;;
			esac
			if [ -n "$logging_level" ] && $logging_color; then
				printf '\033[%sm%s\033[0m\n' "$logging_level" "$logging_line" >&2 || exit 1
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
	if [ "$logging_status" -ne 0 ]; then
		printf 'dss:error Action failed (status %s); details: %s\n' "$logging_status" "$logging_log" >&2
	else
		printf 'dss:stage Action complete; details: %s\n' "$logging_log" >&2
	fi
	return "$logging_status"
)

# End detailed logging.

function distrorejuve_main() {
ret=0
[ "${ACTION:-$1}" = --manifest ] || [ "${ACTION:-$1}" = --manifest-json ] || echo "dss:trace:distrorejuve:main:starting:$(date -u '+%Y-%m-%d %H:%M:%S'):args:$@"
if [ "${ACTION:-$1}" = --manifest ] || [ "${ACTION:-$1}" = --manifest-json ]; then
  manifest_dns_enabled=true
  case "${2:-}" in --no-dns) manifest_dns_enabled=false;; '') :;; *) print_usage; exit 1;; esac
  [ -z "${3:-}" ] || { print_usage; exit 1; }
  if [ "${ACTION:-$1}" = --manifest-json ]; then manifest_output json "$manifest_dns_enabled"
  else manifest_output text "$manifest_dns_enabled"; fi
  exit $?
elif [ "--usage" = "${ACTION:-$1}" ] || [ "--help" = "${ACTION:-$1}" ]; then
  print_usage
elif [ "--check" = "${ACTION:-$1}" ] || [ -z "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  print_info
  upgrade_precondition_checks
  ret=$?
  report_unsupported
  [ "$ret" -eq 0 ]
elif [ "--to-wheezy" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  upgrade_preflight_action --to-wheezy "${2:-}" || exit $?
  print_info
  dist_upgrade_lenny_to_squeeze || exit 1
  dist_upgrade_squeeze_to_wheezy || exit 1
  debian_check_release_completion wheezy || exit 1
  if [ $ret -eq 0 ] ; then true ; else print_failed_dist_upgrade_tips; false; fi
elif [ "--to-jessie" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  upgrade_preflight_action --to-jessie "${2:-}" || exit $?
  print_info
  dist_upgrade_lenny_to_squeeze || exit 1
  dist_upgrade_squeeze_to_wheezy || exit 1
  dist_upgrade_wheezy_to_jessie || exit 1
  debian_check_release_completion jessie || exit 1
  if [ $ret -eq 0 ] ; then true ; else print_failed_dist_upgrade_tips; false; fi
elif [ "--to-debian-release" = "${ACTION:-$1}" ] ; then
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
  if [ "$version" -gt 5 ]; then dist_upgrade_lenny_to_squeeze || exit 1; fi
  if [ "$version" -gt 6 ]; then dist_upgrade_squeeze_to_wheezy || exit 1; fi
  if [ "$version" -gt 7 ]; then dist_upgrade_wheezy_to_jessie || exit 1; fi
  if [ "$version" -gt 8 ]; then dist_upgrade_jessie_to_stretch || exit 1; fi
  if [ "$version" -gt 9 ]; then dist_upgrade_stretch_to_buster || exit 1; fi
  if [ "$version" -gt 10 ]; then dist_upgrade_buster_to_bullseye || exit 1; fi
  if [ "$version" -gt 11 ]; then dist_upgrade_bullseye_to_bookworm || exit 1; fi
  if [ "$version" -gt 12 ]; then dist_upgrade_bookworm_to_trixie || exit 1; fi
  debian_check_release_completion "$debian_target" || exit 1

  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --to-latest-debian completed ok.  use $0 --show-changes to see changes"
elif [ "--to-latest-debian" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  upgrade_preflight_action --to-latest-debian "${2:-}" || exit $?
  print_info
  dist_upgrade_lenny_to_squeeze || exit 1
  dist_upgrade_squeeze_to_wheezy || exit 1
  dist_upgrade_wheezy_to_jessie || exit 1
  dist_upgrade_jessie_to_stretch || exit 1
  dist_upgrade_stretch_to_buster || exit 1
  dist_upgrade_buster_to_bullseye || exit 1
  dist_upgrade_bullseye_to_bookworm || exit 1
  dist_upgrade_bookworm_to_trixie || exit 1
  debian_check_release_completion trixie || exit 1

  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --to-latest-debian completed ok.  use $0 --show-changes to see changes"
elif [ "--to-latest-lts" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  upgrade_preflight_action --to-latest-lts "${2:-}" || exit $?
  print_info
  dist_upgrade_ubuntu_to_latest
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info: --to-latest-lts completed ok.  use $0 --show-changes to see changes"
elif [ "--to-next-ubuntu" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  upgrade_preflight_action --to-next-ubuntu "${2:-}" || exit $?
  print_info
  dist_upgrade_ubuntu_to_latest 1
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --to-next-ubuntu completed ok.  use $0 --show-changes to see changes"
elif [ "--to-squeeze" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  upgrade_preflight_action --to-squeeze "${2:-}" || exit $?
  print_info
  dist_upgrade_lenny_to_squeeze || exit 1
  debian_check_release_completion squeeze || exit 1
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --to-squeeze completed ok.  use $0 --show-changes to see changes"
elif [ "--source" = "${ACTION:-$1}" ] ; then
  echo "dss:info:Loaded distrorejuve functions"
elif [ "--upgrade" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  print_info
  IGNOREOTHERREPOS=Y
  packages_upgrade
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --upgrade completed ok.  use $0 --show-changes to see changes"
elif [ "--dist-upgrade" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  upgrade_preflight_action --dist-upgrade "${2:-}" || exit $?
  print_info
  dist_upgrade_to_latest
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --dist-upgrade completed ok.  use $0 --show-changes to see changes"
elif [ "--dist-update" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  print_info
  yum_upgrade || exit 1
  packages_upgrade || exit 1
  apt_get_dist_upgrade
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --dist-update completed ok.  use $0 --show-changes to see changes"
elif [ "--show-cruft" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  ! has_cruft_packages && echo "No cruft packages (all installed packages from the current distro.  No 32 bit packages on a 64 bit install)." && exit 0
  show_cruft_packages
  echo "To remove those packages, re-run with bash $0 --remove-cruft"
  exit 0
elif [ "--remove-cruft" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  ! has_cruft_packages && echo "No cruft packages (all installed packages from the current distro.  No 32 bit packages on a 64 bit install).  Nothing to do.  All good." && exit 0
  remove_cruft_packages
  exit $?
elif [ "--remove-deprecated-packages" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  ! has_cruft_packages oldpkg && echo "No cruft packages (all installed packages from the current distro).  Nothing to do.  All good." && exit 0
  remove_cruft_packages oldpkg
  exit $?
elif [ "--to-64bit" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  check_disk_space || exit 1
  if [ "$(distro_output_codename)" = bookworm ]; then
    crossgrade_debian_bookworm
    exit $?
  fi
  if [  64 -eq $(getconf LONG_BIT) ]; then
    if has_cruft_packages 32bit; then
      echo "This distro is 64 bit already.  But some 32 bit packages are installed.  Re-running crossgrade."
    else
      echo "Distro is already 64 bit.  Cannot locate any 32 bit packages.  All good."
      exit 0
    fi
  fi
  has_cruft_packages oldpkg && [  -z "$IGNORECRUFT" ] && show_cruft_packages && echo "There are some old packages installed.  Best to remove them before proceeding.  Do that by running bash $0 --remove-cruft.  Or to ignore that, run export IGNORECRUFT=Y and re-run this command. " && exit 1
  crossgrade_debian
  ret=$?
  [ $ret -ne 0 ] && echo "dss:error: crossgrade failed, see above for any details"
  [ $ret -eq 0 ] && echo "dss:info to show config changes, run: bash $0 --show-changes"
  # [ $ret -eq 0 ] && print_config_state_changes && echo "dss:info: no errors."
  exit $ret
elif [ "--show-changes" = "${ACTION:-$1}" ] ; then
  print_config_state_changes
  exit $?
elif [ "--pause" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  touch ~/distrorejuve.pause
  echo "dss:info: Touched the pause file at $(realpath ~/distrorejuve.pause)"
  exit 0
elif [ "--resume" = "${ACTION:-$1}" ] ; then
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
  local -a arguments=()
  for argument in "$@"; do
    case "$argument" in
      --verbose) LOG_VERBOSE=true;;
      --trace) LOG_TRACE=true;;
      --crossgrade) UPGRADE_CROSSGRADE=true;;
      *) arguments+=("$argument");;
    esac
  done
  action=${ACTION:-${arguments[0]:-}}
  if $UPGRADE_CROSSGRADE; then
    case "$action" in
      --dist-upgrade|--to-debian-release|--to-latest-debian|--to-latest-lts|--to-next-ubuntu|--to-squeeze|--to-wheezy|--to-jessie) :;;
      *) echo 'dss:error: --crossgrade modifies a release-upgrade command; use --to-64bit for a standalone crossgrade.' >&2; return 1;;
    esac
  fi
  case "$action" in
    --upgrade|--dist-update|--dist-upgrade|--to-squeeze|--to-wheezy|--to-jessie|--to-debian-release|--to-latest-debian|--to-latest-lts|--to-next-ubuntu|--to-64bit|--remove-cruft|--remove-deprecated-packages)
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
