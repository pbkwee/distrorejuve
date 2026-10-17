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

sudo nohup bash -x distrorejuve.sh --dist-upgrade 2>&1 | tee -a distrorejuve.log | egrep -v '^\+'

Uses:
- Enable lts archive for Debian squeeze servers and old-releases for Ubuntu
- Dist upgrade Ubuntu distros to the next LTS version.  Then from LTS version to LTS version.
- On completion provides information on config changes (modified config files, changed ports, changed packages, changed running processes)
- Install missing Debian keys
- Handles a few common Apache config issues after a distro upgrade.
- Designed to run unattended without lots of prompting.
- Burgeoning support to cross grade 32 bit distros to 64 bit
- Show/remove cruft to permit tidy up of packages installed from non-current (old) repositories

Arguments:

Run with --usage to get this message

Run with --check (or no argument) to report disk space, kernel, distro version and configuration changes. Leave REMOVEX11 unset for a read-only check.

Run with --dist-upgrade run an upgrade, followed by dist-upgrading ubuntu distros to the latest lts or debian distros to latest debian.

Run with --upgrade to run a yum upgrade or apt-get upgrade (fixing up repos, etc where we can).  no distro version change.

Run with --dist-update to update packages on the current distro version (no distro version change).

Run with --show-changes to report the differences pre/post upgrading (packages installed, config files, ports, etc).

Run with --show-cruft to see packages that do not belong to the current distro.  e.g. leftover packages from older distros.  And to see 32 bit packages installed on 64 bit distros.

Run with --remove-cruft to remove old packages and 32 bit applications on 64 bit distros.

Run with --remove-deprecated-packages to remove old packages

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

# Output installed/unpacked blockers only; removed packages with residual configs do not block.
function upgrade_output_incompatible_packages() {
  local family=$1 current=$2 target=$3 dovecot=false fail2ban=false packages
  case "$family" in
    debian)
      if is_distro_name_older "$current" wheezy && ! is_distro_name_older "$target" wheezy; then dovecot=true; fi
      if is_distro_name_older "$current" stretch && ! is_distro_name_older "$target" stretch; then fail2ban=true; fi
      [ "$target" = trixie ] && [ -z "$IGNORE_DOVECOT_ERROR" ] && dovecot=true
      ;;
    ubuntu)
      if is_distro_name_older "$current" xenial && ! is_distro_name_older "$target" xenial; then dovecot=true; fi
      if is_distro_name_older "$current" bionic && ! is_distro_name_older "$target" bionic; then fail2ban=true; fi
      if is_distro_name_older "$current" questing && ! is_distro_name_older "$target" questing && [ -z "$IGNORE_DOVECOT_ERROR" ]; then
        dovecot=true
      fi
      ;;
    *) return 1;;
  esac
  $dovecot || $fail2ban || return 0
  packages=$(dpkg-query -W -f='${Status}\t${Package}\n') || return 1
  # Status example: install ok installed<TAB>dovecot-imapd. Include half-configured packages.
  printf '%s\n' "$packages" | awk -F '\t' -v dovecot="$dovecot" -v fail2ban="$fail2ban" '
    $1 ~ / (installed|unpacked|half-configured|half-installed|triggers-awaited|triggers-pending)$/ &&
      ((dovecot == "true" && $2 ~ /^dovecot($|-)/) || (fail2ban == "true" && $2 == "fail2ban")) { print $2 }
  '
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
      apt_get_install "${pgk}"
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
  [ -f /etc/apache2/apache2.conf ] && grep -qai 'Include conf.d'  /etc/apache2/apache2.conf && [ ! -d /etc/apache2/conf.d ] && mkdir /etc/apache2/conf.d
  if [ -x /usr/sbin/apache2ctl ] && [ -f /etc/apache2/apache2.conf ]; then
    if grep -qai '^Include /etc/apache2/conf.d/' /etc/apache2/apache2.conf && [ ! -d /etc/apache2/conf.d ]; then
      replace 'Include /etc/apache2/conf.d/' '#Include /etc/apache2/conf.d/' -- /etc/apache2/apache2.conf
      echo "dss:info: Commenting out Include /etc/apache2/conf.d/ for non-existent directory.  Might be better to use revert to package provided apache config?"
    fi
    if grep -qa '^Include /etc/apache2/httpd.conf' /etc/apache2/apache2.conf && [ ! -f /etc/apache2/httpd.conf ]; then
      replace "Include /etc/apache2/httpd.conf" "#Include /etc/apache2/httpd.conf" -- /etc/apache2/apache2.conf
      echo "dss:info: Commenting out Include /etc/apache2/httpd.conf for non existent file"
    fi
    if grep -qa '^Include httpd.conf' /etc/apache2/apache2.conf && [ ! -f /etc/apache2/httpd.conf ]; then
      replace "Include httpd.conf" "#Include httpd.conf" -- /etc/apache2/apache2.conf
      echo "dss:info: Commenting out Include httpd.conf for non existent file"
    fi
    if ! /usr/sbin/apache2ctl -S &> /dev/null && grep -qa '^LockFile ' /etc/apache2/apache2.conf; then
        replace "LockFile" "#LockFile" -- /etc/apache2/apache2.conf
        echo "dss:info: Commented out Lockfile in /etc/apache2/apache2.conf"
    fi
    if [ -f /etc/apache2/mods-available/ssl.conf ] && /usr/sbin/apache2ctl -S 2>&1 | grep -qai "Invalid command 'SSLMutex'"; then
      replace "SSLMutex" "#SSLMutex" -- /etc/apache2/mods-available/ssl.conf
    fi
    if /usr/sbin/apache2ctl -S 2>&1 | grep -qai 'Ignoring deprecated use of DefaultType'; then
      replace "DefaultType" "#DefaultType" -- /etc/apache2/apache2.conf
      echo "dss:info: Commented out DefaultType in /etc/apache2/apache2.conf"
    fi
  fi
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

check_disk_space || return 1

if [ "$old_distro" == "lenny" ]; then
  add_missing_debian_keys
  [ ! -d "/dev/pts" ] && mkdir /dev/pts && echo "dss:info: created /dev/pts"
fi

if [ "$new_distro" = trixie ]; then
  local arch
  arch=$(dpkg --print-architecture) || return 1
  case "$arch" in i386|mipsel|mips64el)
    echo "dss:error: Debian 13 cannot upgrade native $arch; migrate or crossgrade before proceeding." >&2
    return 1;;
  esac
fi

upgrade_check_incompatible_packages debian "$old_distro" "$new_distro" || return $?
upgrade_precondition_checks "$new_distro" || return 1
apt_sources_prepare || return 1
if [ "$new_distro" = trixie ]; then check_usrmerge || return 1; fi
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

  # pop a copy there so we can replace current file if desired
  [ -f "./${modifiedconfigfile}" ] && [ ! -f "${modifiedconfigfile}.dpkg-dist" ] && cp "./${modifiedconfigfile}" "${modifiedconfigfile}.dpkg-dist"
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
  while [ "$remaining" -gt 0 ]; do
    current=$(distro_output_codename) || return 1
    next=$(ubuntu_output_next_release "$current") || return 1
    [ -n "$next" ] || return 0
    check_disk_space || return 1
    arch=$(dpkg --print-architecture) || return 1
    if [ "$arch" = i386 ] && ! is_distro_name_older "$current" bionic; then
      echo "dss:error: Native i386 Ubuntu cannot upgrade past 18.04." >&2
      return 1
    fi
    upgrade_check_incompatible_packages ubuntu "$current" "$next" || return $?
    apt_sources_transition_target=$next
    upgrade_precondition_checks "$next" || return 1
    apt_sources_prepare || return 1
    apt_get_upgrade || return 1
    retain_etc_networking_naming_re_enX0
    apt_sources_upgrade ubuntu "$current" "$next" || return 1
    apt_get_update || return 1
    [ -d /etc/apache2 ] && [ ! -f /etc/apache2/httpd.conf ] && touch /etc/apache2/httpd.conf
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


ret=0
echo "dss:trace:distrorejuve:main:starting:$(date -u '+%Y-%m-%d %H:%M:%S'):args:$@"
if [ "--usage" = "${ACTION:-$1}" ] || [ "--help" = "${ACTION:-$1}" ]; then
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
  print_info
  dist_upgrade_lenny_to_squeeze || exit 1
  dist_upgrade_squeeze_to_wheezy || exit 1
  debian_check_release_completion wheezy || exit 1
  if [ $ret -eq 0 ] ; then true ; else print_failed_dist_upgrade_tips; false; fi
elif [ "--to-jessie" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
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
  print_info
  if [ $version -gt 5 ]; then dist_upgrade_lenny_to_squeeze || exit 1; fi
  if [ $version -gt 6 ]; then dist_upgrade_squeeze_to_wheezy || exit 1; fi
  if [ $version -gt 7 ]; then dist_upgrade_wheezy_to_jessie || exit 1; fi
  if [ $version -gt 8 ]; then dist_upgrade_jessie_to_stretch || exit 1; fi
  if [ $version -gt 9 ]; then dist_upgrade_stretch_to_buster || exit 1; fi
  if [ $version -gt 10 ]; then dist_upgrade_buster_to_bullseye || exit 1; fi
  if [ $version -gt 11 ]; then dist_upgrade_bullseye_to_bookworm || exit 1; fi
  if [ $version -gt 12 ]; then dist_upgrade_bookworm_to_trixie || exit 1; fi
  debian_check_release_completion "$debian_target" || exit 1

  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --to-latest-debian completed ok.  use $0 --show-changes to see changes"
elif [ "--to-latest-debian" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
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
  print_info
  dist_upgrade_ubuntu_to_latest
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info: --to-latest-lts completed ok.  use $0 --show-changes to see changes"
elif [ "--to-next-ubuntu" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
  print_info
  dist_upgrade_ubuntu_to_latest 1
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --to-next-ubuntu completed ok.  use $0 --show-changes to see changes"
elif [ "--to-squeeze" = "${ACTION:-$1}" ] ; then
  [ ! -z "$2" ] && print_usage && exit 1
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
