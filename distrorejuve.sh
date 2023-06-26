#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

# https://superuser.com/questions/1456989/how-to-configure-apt-in-debian-buster-after-release buster InRelease' changed its 'Version' value from '' to '10.0'  Run 'apt list --upgradable' to see them. apt-get update --allow-releaseinfo-change

# https://wiki.ubuntu.com/Releases
# when updating, keep them in their release order to safety
# no leading/trailing spaces.  one space per word.
LTS_UBUNTU="dapper hardy lucid precise trusty xenial bionic focal jammy"
#ARCHIVE_REPO_UBUNTU="precise trusty vivid wily xenial yakkety" 
OLD_RELEASES_UBUNTU="warty hoary breezy dapper edgy feisty gutsy hardy intrepid jaunty karmic maverick natty oneiric quantal raring saucy lucid utopic vivid wily yakkety zesty  artful cosmic disco eoan"
ALL_UBUNTU="warty hoary breezy dapper edgy feisty gutsy hardy intrepid jaunty karmic lucid maverick natty oneiric precise quantal raring saucy trusty utopic vivid wily xenial yakkety zesty artful bionic cosmic disco eoan focal groovy hirsute impish jammy"
NON_LTS_UBUNTU=$(for i in $ALL_UBUNTU; do echo $LTS_UBUNTU | grep -qai "$i" || echo -n "$i "; done; echo)

ALL_DEBIAN="hamm slink potato woody sarge etch lenny squeeze wheezy jessie stretch buster bullseye bookworm"
# in egrep code be aware of etch/stretch matching
# https://wiki.debian.org/LTS
UNSUPPORTED_DEBIAN="hamm slink potato woody sarge etch lenny squeeze wheezy jessie stretch"
# no archive for wheezy (update 2020-03, there is now)
#DEBIAN_ARCHIVE="$(echo "$UNSUPPORTED_DEBIAN squeeze-lts" | sed 's/wheezy//')"
DEBIAN_ARCHIVE="$(echo "$UNSUPPORTED_DEBIAN squeeze-lts" )"

# wheezy to 31 May 2018, jessie to April 2020, stretch to June 2022
DEBIAN_CURRENT="buster bullseye bookworm"
IS_DEBUG=
# also DEBIAN_FRONTEND=noninteractive ?
APT_GET_INSTALL_OPTIONS=' -y -o APT::Get::AllowUnauthenticated=yes -o Acquire::Check-Valid-Until=false -o Dpkg::Options::=--force-confnew -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confmiss '
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

Run with --check (or no argument) makes no changes.  Reports information like disk space free, kernel, distro version, config files modified from package defaults.

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

Run with --to-latest-debian to get from squeeze or lenny or wheezy or jessie or stretch or buster to bullseye 11

Run with --to-debian-release [6-12] to get from your current version to the specified version

Run with --to-latest-lts to get from an ubuntu distro to the most recent ubuntu lts version

Run with --to-next-ubuntu to get from an ubuntu distro to the next ubuntu version.  If the current ubuntu is an LTS version then this skips to the next LTS version.

Run with --fix-vuln to try and fix your server (doing minimal change e.g. just an apt-get install of the affected package).

Run with --break-eggs will run a --dist-upgrade if the server is vulnerable.

Run with --pause to pause a distro rejuve running process (touch ~/distrorejuve.pause).  Triggers 30s sleeps at key points in the script.

Run with --resume to resume a paused distro rejuve running process (rm -f ~/distrorejuve.pause)

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

function is_fixed() {
  # 0 = vulnerable, 1 = fixed, 2 = dunno
  is_CVE_2015_0235_vulnerable
  ret=$?
  if [ $ret -eq 1 ]; then
    is_CVE_2015_7547_vulnerable
    ret=$? 
    if [ $ret -eq 1 ]; then
      # return 0 if both vulns are fixed
      return 0
    fi
  fi
  return 1
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

function is_vulnerable() {
  is_CVE_2015_0235_vulnerable && return 0
  is_CVE_2015_7547_vulnerable && return 0
  return 1
}

function prep_ghost_output_dir() {
if [ ! -d /root/distrorejuveinfo ] ; then echo "dss:info: Creating /root/distrorejuveinfo."; mkdir /root/distrorejuveinfo; fi
return 0
}

function print_libc_versions() {
# Checking current glibc version
local prefix=${1:-prefix}
[ -x /usr/bin/ldd ] && /usr/bin/ldd --version | grep -i libc | awk '{print "dss:lddver:'$prefix':" $0}'  
[ -x /usr/bin/dpkg ] && /usr/bin/dpkg -l libc6 | grep libc6 | awk '{print "dss:dpkg:'$prefix':" $0}'
[ -x /bin/rpm ] && /bin/rpm -qa glibc | awk '{print "dss:rpmqa:'$prefix':" $0}'
return 0
}

function is_CVE_2015_0235_vulnerable() {
  print_CVE_2015_0235_vulnerable > /dev/null
  return $?
}
function is_CVE_2015_7547_vulnerable() {
  print_CVE_2015_7547_vulnerable > /dev/null
  return $?
}

# 0 = vulnerable, 1 = fixed, 2 = dunno
function print_CVE_2015_0235_vulnerable() {
  # fixed for that, fixed for all.
  print_CVE_2015_7547_vulnerable > /dev/null
  if [ $? -eq 1 ]; then 
     echo "N"
     return 1
  fi
# based on some known good package versions https://security-tracker.debian.org/tracker/CVE-2015-0235
# http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-0235.html
if [ ! -x /usr/rpm ] && [ -x /usr/bin/dpkg ]; then
   if dpkg -l | grep libc6 | egrep -qai '2\.19-13|2\.19-15|2\.13-38\+deb7u7|2\.11\.3-4\+deb6u4|2\.11\.1-0ubuntu7.20|2\.15-0ubuntu10.10|2\.19-10ubuntu2|2\.19-0ubuntu6'; then
     echo "N"
     return 1
   fi
   if dpkg -l | grep libc6 | egrep -qai '2\.11\.3-4|2\.13-38\+deb7u6|2\.7-18lenny7'; then
     echo "Y"
     return 0
   fi
   # some more that are probably also old/vuln
   if dpkg -l | grep libc6 | egrep -qai '2\.4-1ubuntu12\.3|2\.10\.1-0ubuntu19|2\.10\.2-1|2\.11\.1-0ubuntu7|2\.11\.2-5|2\.13-38|2\.2\.5-11\.5|2\.2\.5-11\.8|2\.3\.2\.ds1-22|2\.3\.2\.ds1-22sa|2\.3\.6\.ds1-13|2\.3\.6\.ds1-13et|2\.3\.6\.ds1-13etch10|2\.3\.6\.ds1-13etch10\+b1|2\.3\.6\.ds1-13etch2|2\.3\.6\.ds1-13etch8|2\.3\.6\.ds1-13etch9\+b1|2\.3\.6\.ds1-8|2\.5-0ubuntu14|2\.6\.1-1ubuntu10|2\.7-10ubuntu4|2\.7-10ubuntu8\.3|2\.7-18|2\.7-18lenny2|2\.7-18lenny4|2\.8~20080505-0ubuntu9|2\.9-4ubuntu6\.3'; then
     echo "Y"
     return 0
   fi
   echo "?"
   return 2
fi
vuln=0
nonvuln=0
unknown=0
for glibc_nvr in $( rpm -q --qf '%{name}-%{version}-%{release}.%{arch}\n' glibc ); do
    glibc_ver=$( echo "$glibc_nvr" | awk -F- '{ print $2 }' )
    glibc_maj=$( echo "$glibc_ver" | awk -F. '{ print $1 }')
    glibc_min=$( echo "$glibc_ver" | awk -F. '{ print $2 }')
    if [ -z "$glibc_maj" ] || [ -z "$glibc_maj" ] || [ -z "$glibc_min" ]; then
      unknown=$(($unknown+1))
      continue
    fi
    #echo -n "- $glibc_nvr: "
    if [ "$glibc_maj" -gt 2   -o  \
        \( "$glibc_maj" -eq 2  -a  "$glibc_min" -ge 18 \) ]; then
        # fixed upstream version
        # echo 'not vulnerable'
        nonvuln=$(($nonvuln+1))
    else
        # all RHEL updates include CVE in rpm %changelog
        if rpm -q --changelog "$glibc_nvr" | grep -q 'CVE-2015-0235'; then
            #echo "not vulnerable"
            nonvuln=$(($nonvuln+1))
        else
            #echo "vulnerable"
            vuln=$(($vuln+1))
        fi
    fi
done

if [ $vuln -gt 0 ] ; then echo "Y"; return 0; fi
if [ $unknown -gt 0 ]; then echo "?"; return 2; fi
if [ $nonvuln -gt 0 ] ; then echo "N"; return 1; fi
echo "?"
return 2
}

# 0 = vulnerable, 1 = fixed, 2 = dunno
function print_CVE_2015_7547_vulnerable() {
if [ ! -x /usr/rpm -a -x /usr/bin/dpkg ]; then
    # based on some known good package versions https://security-tracker.debian.org/tracker/CVE-2015-7547
   if dpkg -l | grep libc6 | grep '^i' | egrep -qai '2\.11\.3-4\+deb6u11|2\.13-38\+deb7u10|2\.19-18\+deb8u3|2\.21-8|2\.21-9'; then
     echo "N"
     return 1
   fi
    # http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-7547.html
   if dpkg -l | grep libc6 | grep '^i' | egrep -qai '2\.15-0ubuntu10\.13|2\.19-0ubuntu6\.7|2\.21-0ubuntu4\.0\.1|2\.21-0ubuntu4\.1'; then
     echo "N"
     return 1
   fi
   #the issue affected all the versions of glibc since 2.9 e.g. to match 2.3.6.ds1-13etch10+b1  or 2.6-blah 
   if dpkg -l | grep libc6 | grep '^i' | egrep -qai '2\.[1-8][-.]'; then
     echo "N"
     return 1
   fi
   # some more that are probably also old/vuln
   if dpkg -l | grep libc6 | egrep -qai '2\.4-1ubuntu12\.3|2\.10\.1-0ubuntu19|2\.10\.2-1|2\.11\.1-0ubuntu7|2\.11\.2-5|2\.13-38|2\.2\.5-11\.5|2\.2\.5-11\.8|2\.3\.2\.ds1-22|2\.3\.2\.ds1-22sa|2\.3\.6\.ds1-13|2\.3\.6\.ds1-13et|2\.3\.6\.ds1-13etch10|2\.3\.6\.ds1-13etch10\+b1|2\.3\.6\.ds1-13etch2|2\.3\.6\.ds1-13etch8|2\.3\.6\.ds1-13etch9\+b1|2\.3\.6\.ds1-8|2\.5-0ubuntu14|2\.6\.1-1ubuntu10|2\.7-10ubuntu4|2\.7-10ubuntu8\.3|2\.7-18|2\.7-18lenny2|2\.7-18lenny4|2\.8~20080505-0ubuntu9|2\.9-4ubuntu6\.3'; then
     echo "Y"
     return 0
   fi
   echo "?"
   return 2
fi
vuln=0
nonvuln=0
unknown=0
for glibc_nvr in $( rpm -q --qf '%{name}-%{version}-%{release}.%{arch}\n' glibc ); do
    glibc_ver=$( echo "$glibc_nvr" | awk -F- '{ print $2 }' )
    glibc_maj=$( echo "$glibc_ver" | awk -F. '{ print $1 }')
    glibc_min=$( echo "$glibc_ver" | awk -F. '{ print $2 }')
    if [ -z "$glibc_maj" -o -z "$glibc_maj" -o -z "$glibc_min" ]; then
      unknown=$(($unknown+1))
      continue
    fi
    #echo -n "- $glibc_nvr: "
    if [ "$glibc_maj" -gt 2   -o  \
        \( "$glibc_maj" -eq 2  -a  "$glibc_min" -ge 22 \) -o \
        \( "$glibc_maj" -eq 2  -a  "$glibc_min" -le 8 \) ]; then
        # fixed upstream version
        # echo 'not vulnerable'
        nonvuln=$(($nonvuln+1))
    else
        # all RHEL updates include CVE in rpm %changelog
        if rpm -q --changelog "$glibc_nvr" | grep -q 'CVE-2015-7547'; then
            #echo "not vulnerable"
            nonvuln=$(($nonvuln+1))
        else
            #echo "vulnerable"
            vuln=$(($vuln+1))
        fi
    fi
done

if [ $vuln -gt 0 ] ; then echo "Y"; return 0; fi
if [ $unknown -gt 0 ]; then echo "?"; return 2; fi
if [ $nonvuln -gt 0 ] ; then echo "N"; return 1; fi
echo "?"
return 2
}

# use print_vulnerability_status beforefix and print_vulnerability_status afterfix
function print_vulnerability_status() {
local prefix=${1:-prefix}
echo "dss:isvulnerable:$prefix: CVE_2015_0235$(print_CVE_2015_0235_vulnerable)"
echo "dss:isvulnerable:$prefix: CVE_2015_7547$(print_CVE_2015_7547_vulnerable)"
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
  [ -f /etc/apt/sources.list ] && cat /etc/apt/sources.list | egrep -v '^$|^#' | awk '{print "dss:aptsources:" $0}'
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
    echo "dss:info: DNS not working after fix attempt, check your /etc/resolv.conf and set, say, nameserver 8.8.8.8"
  fi
  return 0
}

function upgrade_precondition_checks() {
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
  if [ -f /etc/debian_version ] && [ -f /etc/apt/sources.list ] && [ "0" == "$(cat /etc/apt/sources.list | egrep -v '^$|^#' | wc -l)" ]; then
    echo "dss:warn:/etc/apt/sources.list is empty and does not have any valid lines in it."
    ret=$(($ret+1))
  fi
  # e.g. set for --upgrade.  other repos probably fine.  Only an issue if dist-upgrading.
  [ ! -z "$IGNOREOTHERREPOS" ] && return $ret
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
   
  # check that there is only a single package repo in use.  else mixing two distro versions is troublesome
  if [ -f /etc/apt/sources.list ]; then
    num=0
    distros=""
    for distro in $ALL_UBUNTU $ALL_DEBIAN; do
      grep -qai "^ *[a-z].* ${distro}[ /-]" /etc/apt/sources.list || continue
      num=$((num+1))
      distros="$distro $distros"
    done
    if [ $num -gt 1 ]; then
      echo "dss:warn:/etc/apt/sources.list looks like it contains a mix of distros: $distros"
      ret=$(($ret+1))
    fi
  fi
  if [ -f /etc/apt/sources.list ]; then
    # ^ *deb *[a-z.:/]+/debian[-a-z]*  matches: 
    # deb http://mirrors.linode.com/xdebian stretch main
    # deb http://mirrors.linode.com/debian stretch-updates main
    local otherrepos=$(egrep -iv '^ *#|^ *$|^ *[a-z].*ubuntu.com|^ *[a-z].*debian.org|^ *[a-z].*debian.net|software.virtualmin.co|^ *deb *[a-z.:/]+/debian[-a-z]* ' /etc/apt/sources.list | egrep -v '^[[:space:]]*$' | head -n 1 )
    if [ ! -z "$otherrepos" ]; then
      echo "dss:warn:/etc/apt/sources.list looks like it contains an unknown repository.  comment out before proceeding?: '$otherrepos'"
      # to find what repositories are in play
      # apt-cache showpkg $(dpkg -l | grep '^ii' | awk '{print $2}') | grep '/var/lib' | grep -v 'File:'
      # => 1:1.2.8.dfsg-2ubuntu5 (/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_yakkety_main_binary-amd64_Packages) (/var/lib/dpkg/status)
      ret=$(($ret+1))
    fi
    local otherrepos=$(egrep -iv '^ *#|^ *$' /etc/apt/sources.list | grep backports | head -n 1)
    if [ ! -z "$otherrepos" ] && [ -z "$IGNOREBACKPORTS" ] ; then
      echo "dss:warn:/etc/apt/sources.list looks like it contains a backports repository.  comment out before proceeding?: $otherrepos.  Else export IGNOREBACKPORTS=Y"
      ret=$(($ret+1))
    fi
    if [ -d /etc/apt/sources.list.d/ ]; then
      local othersources=$(find /etc/apt/sources.list.d/ -type f | grep -v save)
      for othersource in $othersources; do
        # e.g. othersource = /etc/apt/sources.list.d/wheezy-backports.list
        local otherrepos=$(egrep -iv '^ *#|^ *$' "$othersource" | grep -ai deb | grep backport | head -n 1)
        if [ ! -z "$otherrepos" ] && [ ! -z "$IGNOREBACKPORTS" ] ; then continue; fi
        # this version is used even for newer debian versions
        # deb http://download.webmin.com/download/repository sarge contrib
        # deb http://software.virtualmin.com/vm/6/gpl/apt virtualmin-stretch main
        # deb http://software.virtualmin.com/vm/6/gpl/apt virtualmin-universal main
        # note webmin repos name is sarge even on other debian/ubuntu versions
        local otherrepos=$(egrep -iv '^ *#|^ *$' "$othersource" | grep -ai deb | egrep 'download.webmin.com/download/repository.*sarge|deb http://software.virtualmin.com/vm/6/gpl/apt virtualmin' | head -n 1)
        [ ! -z "$otherrepos" ] && continue
        local otherrepos=$(egrep -iv '^ *#|^ *$' "$othersource" | grep -ai deb | head -n 1)
        if [ ! -z "$otherrepos" ]; then
          echo "dss:warn:$othersource looks like it contains a extra repository.  disable file before proceeding?: $otherrepos"
          #echo "dss:warn:packages from extra repositories may include: $(aptitude search '?narrow(?installed, !?origin(Debian))!?obsolete')"
          ret=$(($ret+1))
        fi
      done
      
    fi
    
  fi
  
  return $ret
}
function convert_deb_6_stable_repo_to_squeeze() {
if [ ! -f /etc/debian_version ] ; then return 0; fi

if [ ! -f /etc/apt/sources.list  ]; then echo "dss:warn: Odd.  Debian distro but no apt sources.list"; return 1; fi

# cat /etc/debian_version 
# 6.0.4
if ! grep -qai "^6." /etc/debian_version; then return 0; fi

if ! grep -qai "^ *deb.*stable" /etc/apt/sources.list ; then echo "dss:info: Not using 'stable' repo.  Not converting deb6 stable to squeeze"; return 0; fi

prep_ghost_output_dir
cp /etc/apt/sources.list /root/distrorejuveinfo/sources.list.$(date +%Y%m%d.%s)

convertfile stable squeeze "debian.org" "" /etc/apt/sources.list
convertfile stable squeeze "debian.net" "" /etc/apt/sources.list
return 0
}

# e.g. convertline squeeze foobar '' '' 'deb-src http://archive.debian.org/debian-security squeeze /updates main contrib non-free'
# => deb-src http://archive.debian.org/debian-security foobar /updates main contrib non-free
function convertline() {
local fromname=$1
local toname=$2
local domlike=$3
local prefix=$4
local line=$5
# ^ *deb[-a-zA-Z]*  => match 'deb ' and 'deb-src '
#  +$fromname[ /-] => needs space first (else stretch/etch get mixed up), space / and - needed for squeeze, squeeze-updates and squeeze/updates
echo $line | egrep -qai "^ *deb[-a-zA-Z]* ([a-zA-Z]+)://([-~a-zA-Z0-9./]*)${domlike}([-~a-zA-Z0-9./]*) +${fromname}[ /-]" && echo $line | sed "s@^ *deb\([-a-zA-Z]*\) \([a-zA-Z]*\)://\([-~a-zA-Z0-9./]*\)\(${domlike}\)\([-~a-zA-Z0-9./]*\) *${fromname}\([ /-]\)@${prefix}deb\1 \2://\3\4\5 ${toname}\6@" && return 0
return 0
}

function convertfile() {
local fromname=$1
local toname=$2
local domlike=$3
# typically '#' to comment out a line
local prefix=$4
local file=$5
# repository like deb ftp://a-b.x.com/~home wheezy blah
sed -i "s@^ *deb\([-a-zA-Z]*\) \([a-zA-Z]*\)://\([-~a-zA-Z0-9./]*\)\($domlike\)\([-~a-zA-Z0-9./]*\) *$fromname\([ /-]\)@${prefix}deb\1 \2://\3\4\5 $toname\6@" "$file"
return 0
}

function islinematch() {
local namematch=$1
local domlike=$2
local line=$4
echo $line | egrep -qai "^ *deb[-a-zA-Z]* ([a-zA-Z]+)://([-~a-zA-Z0-9./]*)${domlike}([-~a-zA-Z0-9./]*) +${namematch}[ /-]" && return 0
return 1
}

function convert_old_ubuntu_repo() {
[ ! -f /etc/apt/sources.list ] && return 0
lsb_release -a 2>/dev/null | grep -qai Ubuntu || return 0
 
CODENAME=$1
if [ -z "$CODENAME" ]; then echo "dss:error: We require a codename here.  e.g. convert_old_ubuntu_repo hardy"; return 1; fi

! egrep -qai "^ *deb.*ubuntu/ $CODENAME|^ *deb.*ubuntu $CODENAME" /etc/apt/sources.list && return 0
grep -qai '^ *deb .*old-releases.ubuntu.com' /etc/apt/sources.list && ! grep -qai "^ *deb.*archive.ub*$CODENAME" /etc/apt/sources.list && if ! grep -qai "^ *deb.*security.ub.*$CODENAME" /etc/apt/sources.list; then echo "dss:info: Already running an 'old-releases' $CODENAME repository."; return 0; fi

prep_ghost_output_dir
cp /etc/apt/sources.list /root/distrorejuveinfo/sources.list.$(date +%Y%m%d.%s)

echo "dss:info: Commenting out expired $CODENAME repository"
sed -i "s@^ *deb http://us.archive.ubuntu.com/ubuntu/ $CODENAME@#deb http://us.archive.ubuntu.com/ubuntu/ $CODENAME@" /etc/apt/sources.list
sed -i "s@^ *deb http://security.ubuntu.com/ubuntu $CODENAME@#deb http://security.ubuntu.com/ubuntu $CODENAME@" /etc/apt/sources.list
sed -i "s@^ *deb-src http://security.ubuntu.com/ubuntu $CODENAME@#deb-src http://security.ubuntu.com/ubuntu $CODENAME@" /etc/apt/sources.list
sed -i "s@^ *deb\(.*\)archive\(.*\)$CODENAME@#deb\1archive\2$CODENAME@" /etc/apt/sources.list
if ! grep -ai old-releases /etc/apt/sources.list | grep -qai "$CODENAME" /etc/apt; then
echo "dss: Adding in the 'old-releases' repository for $CODENAME"
echo "
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME-updates main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME-security main restricted universe multiverse" >> /etc/apt/sources.list
fi

return 0

}

function add_missing_ubuntu_keys() {
  [ ! -e /etc/apt/sources.list ] && return 0
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
  [ ! -e /etc/apt/sources.list ] && return 0
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

# e.g. test with diff /etc/apt/sources.list <(disable_debian_repos squeeze)
function disable_debian_repos() {
  [ ! -f /etc/apt/sources.list ] && return 0
  local name=$1
  # disable both squeeze and squeeze lts if squeeze
  [ "$name" == "squeeze" ] && disable_debian_repos squeeze-lts
  [ ! -z "$IS_DEBUG" ] && echo "dss:sources:disable_debian_repos:pre:$name: $(cat /etc/apt/sources.list | egrep -v '^$|^#')"
  {
    local line=
    cat /etc/apt/sources.list | while IFS='' read -r line || [[ -n "$line" ]]; do
      # leave comment lines
      local line0=$line
      echo $line | grep -qai '^ *#' && echo $line && continue
      local line2=
      local line2=$(convertline $name $name debian.org "#" "$line")
      [ -z "$line2" ] && line2=$(convertline $name $name debian.net "#" "$line")
      if [ -z "$line2" ]; then
        # echo 'deb http://mirrors.linode.com/debian stretch-updates main' | egrep '^ *deb *http[s]{0,1}://[a-z.:/]+/debian[-a-z]* .*' | sed -re 's#^ *deb *http[s]{0,1}://([a-z.:/]+)/debian[-a-z]* .*#\1#'
        # => mirrors.linode.com
        local d2="$(echo $line | egrep '^ *deb *http[s]{0,1}://[a-z.:/]+/debian[-a-z]* .*' | sed -re 's#^ *deb *http[s]{0,1}://([a-z.:/]+)/debian[-a-z]* .*#\1#')"
        if [ ! -z "$d2" ]; then
          line2=$(convertline $name $name "$d2" "#" "$line")
        fi 
      fi  
      [ -z "$line2" ] && echo $line
      echo $line2
      # leave non-debian lines.  e.g. keep deb http://packages.prosody.im/debian wheezy main
      #echo $line | grep -q deb && echo "$line" | grep -qaiv --fixed-strings '.debian.' && echo $line && continue
      # comment out the old entries
      #line=$(echo $line | sed "s@^ *deb http://ftp.\(\S*\).debian.org/debian[/] $name\([ /]\)@#deb http://ftp.\1.debian.org/debian $name\2@")
      #line=$(echo $line | sed "s@^ *deb http://security.debian.org/ $name\([ /]\)@#deb http://security.debian.org/ $name\1@")
      #line=$(echo $line | sed "s@^ *deb-src http://ftp.\(\S*\).debian.org/debian[/] $name\([ /]\)@#deb-src http://ftp.\1.debian.org/debian $name\2@")
      # deb http://http.us.debian.org/debian/ wheezy main non-free contrib
      #line=$(echo $line | sed "s@^ *deb http://http.\(\S*\).debian.org/debian[/] $name\([ /]\)@#deb http://http.\1.debian.org/debian $name\2@")
      #line=$(echo $line | sed "s@^ *deb http://non-us.debian.org/debian-non-US $name\([ /]\)@#deb http://non-us.debian.org/debian-non-US $name\1@")
      #line=$(echo $line | sed "s@^ *deb http://security.debian.org[/] $name\([ /]\)@#deb http://security.debian.org $name\1@")
      # deb-src http://ftp.us.debian.org/debian/ wheezy main
      # deb-src http://security.debian.org/ wheezy/updates main
      #line=$(echo $line | sed "s@^ *deb-src http://ftp.\(\S*\).debian.org/debian[/] $name\([ /]\)@#deb-src http://ftp.\1.debian.org/debian $name\2@")
      # deb-src http://security.debian.org/ wheezy/updates main
      # deb-src http://mirrors.coyx.com/debian/ wheezy-updates main
      #line=$(echo $line | sed "s@^ *deb http://http.\(\S*\).debian.org/debian[/] $name\([ /]\)@#deb http://http.\1.debian.org/debian $name\2@")
      #line=$(echo $line | sed "s@^ *deb-src http://\([a-zA-Z0-9./]*\) *$name\([ /]\)@#deb-src http://\1 $name\2@")
      # disable the archive repositories
      #line=$(echo $line | sed "s@^ *deb http://archive.\([a-zA-Z0-9./]*\) *$name\([ /]\)@#deb http://archive.\1 $name\2@")
      #echo $line
    done
  } > /etc/apt/sources.list.$$
  [ ! -z "$IS_DEBUG" ] && cat /etc/apt/sources.list.$$ | awk '{print "dss:trace:sources:createdaptsources:" $0}'
  if diff /etc/apt/sources.list /etc/apt/sources.list.$$ >/dev/null; then
    rm /etc/apt/sources.list.$$ 
    return 0
  fi
  [ ! -z "$IS_DEBUG" ] && echo "dss:sources:disable_debian_repos:post:$name: $(cat /etc/apt/sources.list | egrep -v '^$|^#')" 
  prep_ghost_output_dir
  cp /etc/apt/sources.list /root/distrorejuveinfo/sources.list.$(date +%Y%m%d.%s)
  echo "dss:info: disable_debian_repos $name diff follows:"
  print_minimal_config_diff /etc/apt/sources.list /etc/apt/sources.list.$$ | awk '{print "dss:configdiff: " $0}'
  mv /etc/apt/sources.list.$$ /etc/apt/sources.list
  echo "$name: apt sources now has $(cat /etc/apt/sources.list | egrep -v '^$|^#')" | awk '{print "dss:sources:disable_debian_repos:post:" $0}'
  return 0
}

# e.g. enable_debian_archive squeeze squeeze-lts
function enable_debian_archive() {
  [ ! -f /etc/apt/sources.list ] && return 0
  [ ! -z "$IS_DEBUG" ] && echo "apt sources now has $(cat /etc/apt/sources.list | egrep -v '^$|^#')" | awk '{print "dss:trace:sources:enable_debian_archive:pre:" $0 }'
  {
    > /tmp/enablearchive.$$
    > /tmp/enabledarchive.$$
    # variables in here not seen outside scope.  need to store in a temp file.
    local line=
    cat /etc/apt/sources.list | while IFS='' read -r line || [[ -n "$line" ]]; do
      local name=
      for name in $DEBIAN_ARCHIVE; do
        # comment line.  skip checking other names.  go onto next line
        local line0=$line
        local name0=$name
        echo $line | egrep -qai '^$|^ *#' && echo $line && line="" && break

        echo $line | grep -qai "^deb http://archive.debian.org/debian ${name}[ /-]" && echo " $name " >> /tmp/enabledarchive.$$ && break
        # disable srcs
        echo $line | egrep -qai "^ *deb-src ([a-z]+)://([-~a-zA-Z0-9./]*) * ${name}[ /-]" && echo $line | sed "s@^ *deb-src \([a-zA-Z]*\)://\([a-zA-Z0-9./]*\) *$name@#deb-src \1://\2 $name@" && line="" && break
        echo $line | egrep -qai "^ *deb ([a-z]+)://([-~a-zA-Z0-9./]*) * ${name}[ /-]" && echo " $name " >> /tmp/enablearchive.$$ && echo "#$line" && line="" && break
      done
      [ ! -z "$line" ] && echo $line
    done
    # if one or the other is enable, add both
    enablearchive=$(cat /tmp/enablearchive.$$)
    enabledarchive=$(cat /tmp/enabledarchive.$$)
    rm -f /tmp/enablearchive.$$ /tmp/enabledarchive.$$
    echo $enablearchive | grep -qai " squeeze " && enablearchive="$enablearchive squeeze-lts"
    uniqueenablearchive=$(for i in $enablearchive; do echo $i; done | sort | uniq)
    spaceenablearchive=$(for i in $uniqueenablearchive; do echo -n " $i "; done)
    for name in $spaceenablearchive; do
      # already there
      echo "$enabledarchive" | grep -qai "$name" && continue 
      echo "deb http://archive.debian.org/debian $name main contrib non-free"
    done
  } > /etc/apt/sources.list.$$
  if diff /etc/apt/sources.list /etc/apt/sources.list.$$ >/dev/null; then
    rm /etc/apt/sources.list.$$ 
    return 0
  fi 
  prep_ghost_output_dir
  cp /etc/apt/sources.list /root/distrorejuveinfo/sources.list.$(date +%Y%m%d.%s)
  echo "dss:info: enabling debian archive repos.  diff follows:"
  print_minimal_config_diff /etc/apt/sources.list /etc/apt/sources.list.$$ | awk '{print "dss:configdiff:sources: " $0}'
  mv /etc/apt/sources.list.$$ /etc/apt/sources.list
  [ ! -z "$IS_DEBUG" ] && echo "apt sources now has $(cat /etc/apt/sources.list | egrep -v '^$|^#')" | awk '{print "dss:trace:sources:enable_debian_archive:post:" $0 }'
  return 0
}

function print_uninstall_fail2ban() {
  [ ! -f /etc/apt/sources.list ] && return 0
  ! dpkg -l | grep -qai '^i.*fail2ban' && return 0
  echo "dss:info: Changes to the fail2ban configs mean that this script will likely hit problems when doing the dist upgrade.  so aborting before starting." >&2
  echo "dss:info: Please remove the fail2ban configs.  You may do that with the following commands:"
  echo apt-get -y purge $(dpkg -l | grep fail2ban | egrep -i 'ii|iF|iU' | awk '{print $2}')
}

function print_uninstall_dovecot() {
  [ ! -f /etc/apt/sources.list ] && return 0
  ! dpkg -l | grep -qai '^i.*dovecot' && return 0
  # trusty 2.9, precise 2.0, lucid (=10.4) 1.29 per https://launchpad.net/ubuntu/+source/dovecot
  echo "dss:info: Seeing '$( [ -f /var/log/mail.info ] && grep 'dovecot' /var/log/mail.info* | grep -c 'Login:')' logins via imap recently."
  echo "dss:info: Changes to the dovecot configs mean that this script will likely hit problems when doing the dist upgrade.  so aborting before starting." >&2
  echo "dss:info: Saving the current dovecot config to /root/distrorejuveinfo/doveconf.log.$$"
  echo "dss:info: Please remove dovecot.  You may do that with the following commands:"
  prep_ghost_output_dir
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

function dist_upgrade_bullseye_to_buster() {
export old_distro=bullseye
export old_ver="inux 11"
export new_distro=buster
export new_ver="inux 12"
dist_upgrade_x_to_y
ret=$?
return $ret
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

function apt_get_remove() {
  pause_check
  local tmplog=$(mktemp "tmplog.aptgetremove.log.XXXXXX")
  apt-get $APT_GET_INSTALL_OPTIONS remove $@ | tee $tmplog
  local ret=${PIPESTATUS[0]}
  [  $ret -ne 0 ] && rm_overwrite_files "$tmplog" && apt-get $APT_GET_INSTALL_OPTIONS remove $@ && ret=$?
  #if [  $ret -ne 0 ] && echo "$@" | egrep -qai 'gcc-6-base:i386'; then
  #fi
  if [  $ret -ne 0 ] && echo "$@" | egrep -qai 'gcc-6-base:i386'; then
    if egrep -qai 'systemd : Depends: libcap2-bin' "$tmplog"; then
      echo "dss:info: attempting to install libcap2-bin since gcc-6-base remove failed." && apt_get_install libcap2-bin:amd64 && apt-get $APT_GET_INSTALL_OPTIONS remove $@ && ret=$?
    fi
  fi
  local essentialissuepackages="$(cat $tmplog | grep --after-context 50 'WARNING: The following essential packages will be removed.' | grep '^ ' | tr '\n' ' ' | sed  -r 's/\(due to +\S*?\)//g')"
  [ ! -z "$essentialissuepackages" ] && echo "dss:warn: apt_get_remove $@ essential package issues for: $essentialissuepackages"
  echo "$essentialissuepackages" | egrep -qai 'libgcc-s1:i386' && echo "dss:warn: This issue may be related to this bug report: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=992317"
  rm -rf "$tmplog"
  return $ret
}

function apt_get_install() {
  pause_check
  local tmplog=$(mktemp "tmplog.aptgetinstall.log.XXXXXX")
  apt-get $APT_GET_INSTALL_OPTIONS install $@ | tee $tmplog
  local ret=${PIPESTATUS[0]}
  [  $ret -ne 0 ] && rm_overwrite_files "$tmplog" && apt-get $APT_GET_INSTALL_OPTIONS install $@ && ret=$?
  local essentialissuepackages="$(cat $tmplog | grep --after-context 50 'WARNING: The following essential packages will be removed.' | grep '^ ' | tr '\n' ' ' | sed  -r 's/\(due to +\S*?\)//g')"
  [ ! -z "$essentialissuepackages" ] && echo "dss:warn: apt_get_install $@ essential package issues for: $essentialissuepackages"  
  
  rm -rf "$tmplog"
  return $ret
}

function apt_get_f_install() {
  pause_check
  local tmplog=$(mktemp "tmplog.aptgetfinstall.log.XXXXXX")
  apt-get $APT_GET_INSTALL_OPTIONS -f install | tee $tmplog
  local ret=${PIPESTATUS[0]}
  if [  $ret -ne 0 ]; then 
    rm_overwrite_files "$tmplog" && apt-get $APT_GET_INSTALL_OPTIONS -f install && ret=$?
  fi
  echo "dss:trace:apt_get_f_install:$1 results $(egrep 'upgraded' $tmplog)"
  local essentialissuepackages="$(cat $tmplog | grep --after-context 50 'WARNING: The following essential packages will be removed.' | grep '^ ' | tr '\n' ' ' | sed  -r 's/\(due to +\S*?\)//g')"
  [ ! -z "$essentialissuepackages" ] && echo "dss:warn: apt_get_f_install $@ essential package issues for: $essentialissuepackages"
  if [ ! -z "$essentialissuepackages" ] && echo "$essentialissuepackages" | grep -qai 'perl-base:amd64'; then
    echo "dss:trying to dpkg -i perl-base:i386"
    if dpkg -l | grep perl-base | grep i386 | grep -qai ii; then
      echo "dss: perl-base:i386 already installed"
    else 
      apt-get download perl-base:i386
      dpkg -i perl-base*i386*deb
      apt-get $APT_GET_INSTALL_OPTIONS -f install | tee $tmplog
      local ret=${PIPESTATUS[0]}
    fi
  fi  
  
  rm -rf "$tmplog"
  if [ $ret -ne 0 ]; then
    echo "dss:warn: dpkg results showing packages with issues."
    dpkg -l  | egrep -v '^ii|^rc|^iU' | awk '{print "dss:warn:apt_get_f_install: " $0}'
    echo "dss:info: as a last resort you can move away the failed dpkg status files at /var/lib/dpkg/info/pkngname*"
  fi
  return $ret
}

function dpkg_install() {
  [  -z "$1" ] && return 0
  local tmplog=$(mktemp "tmplog.dpkginstall.log.XXXXXX")
  dpkg --force-confnew --force-confdef --force-confmiss --install $@ 2>&1 | tee "$tmplog"
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
      dpkg --force-confnew --force-confdef --force-confmiss --install $failedinstalls
      ret=$?
      echo "dss:trace:dpkg_install: retry install $([ $ret -eq 0 ] && echo "succeeded" || echo "failed")"
    fi
  fi
  if [ $ret -ne 0 ]; then
    echo "dss:trace:dpkg_install: some .deb packages had issues.  retrying to install all packages." 
    dpkg --force-confnew --force-confdef --force-confmiss --install $@  2>&1 | tee "$tmplog"
    ret=$?
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
  [  ! -f /etc/debian_version ] && echo "dss:info: Only debian crossgrades are supported, but not $(print_distro_info)." && return 0
  
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
  apt_get_update
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
  apt-get $APT_GET_INSTALL_OPTIONS update
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
    requiredlist="$(apt-rdepends apt apt-listchanges| grep -v "^ "|grep -v "libc-dev" | awk '{print $0":amd64"}')"
    echo "dss:trace: cross grading.  doing a 'download only' on $requiredlist."
    for i in $requiredlist; do apt-get --reinstall --download-only  $APT_GET_INSTALL_OPTIONS install $i; done
     dpkg -l | grep ii | grep -v lib | awk '{print $2}' | grep -v "^ "|grep -v "libc-dev" | awk '{print $0":amd64"}'
    
    #E: Unable to locate package libbz2-1.0:amd64
    #E: Couldn't find any package by glob 'libbz2-1.0'
     
    
    echo "dss:trace: cross grading.  installing key amd64 deb packages: dpkg:amd64 tar:amd64 apt:amd64 perl-base:amd64"
    # something about this removes apache2.  figure out why...
    cd /root/distrorejuveinfo/$$
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
      dpkg_install $debs
      if [ $? -ne 0 ]; then 
        [ $? -ne 0 ] && echo "dss:error: dpkg install amd64.deb files failed" 2>&1 && cd - && return 1
      fi
      mv $debs /root/distrorejuveinfo/$$
    fi
    cd -
  fi
  #apt-get $APT_GET_INSTALL_OPTIONS autoremove
  echo "dss:trace: cross grading.  force installing to see what amd64 packages need to be installed/fixed."
  local i=0
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
    local i=;
    mkdir -p distrorejuveinfo/$$/essentialdebs
    cd distrorejuveinfo/$$/essentialdebs
    echo "dss:trace: apt-get -f install had errors.  there may be some essential packages not installed.  trying to install 32 and 64 bit versions of: $essentialtoinstall"
    for i in $essentialtoinstall; do
      i=$(echo $i | sed 's/:i386//')
      i=$(echo $i | sed 's/:amd64//') 
      # had been downloading 64 and 32 bit versions.  but installing both (for say perl-base) resulted in dpkg -l listing just the i386 version. 
      #apt-get download $i
      #apt-get download $i:i386
      apt-get download $i:amd64
    done  
    dpkg_install $(find . -name '*.deb')
    cd -
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
      for i in $(apt-cache show $i386app | grep Pre-Depends  | sed  -r  's/\([^)]+\)//g' | sed 's/,//g' | sed 's/.*://' | sed 's/ | /____/g'); do
        if echo "$i" | grep -qai '____'; then
          local j="$(echo "$i" | sed 's/____/ /g')"
          for k in $j; do 
            if dpkg -l | grep 'ii' | grep -qai " $k"; then
              echo "dss:info:selecting $k as the pre-dependency for $i386app from options of '$j' since that is what is installed"
              i="$k"
            fi
          done
          [ -z "$i" ] && i="$(echo $j | awk '{print $0}')" &&  echo "dss:info:selecting $i as the pre-dependencies for $i386 from options of '$i' since it that is the first one listed and the others were not installed"
        fi        
        addep="$addep $i:amd64" 
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
    cd /root/distrorejuveinfo/$$
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
    cd -
  done
  
  # getting a dependency issue on apt-get remove a few things: libpam-modules : PreDepends: libpam-modules-bin (= 1.1.8-3.6)
  # workaround is:
  apt_get_install libpam-modules-bin:amd64
  
  
  # these seem to be uninstalled by something above.
  # now handled by other code
  # [ ! -z "${vimpkg}${apachepkg}" ] && echo "dss:trace: cross grading and installing vim/apache2." && apt-get $APT_GET_INSTALL_OPTIONS install $apachepkg $vimpkg
  
  local i=0
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
    local pkg=
    local i386toremove="$(dpkg -l | grep 'i386' | grep '^ii' | awk '{print $2}' | grep -v '^lib' | sed 's/:i386//')"
    echo "dss:trace: cross grading and individually installing 64 bit versions of all i386 packages: $i386toremove"
    # => e.g. apache2-utils bc bind9-host
    local i386toremove2=""
    # install them all
    for pkg in $i386toremove ifupdown; do 
      apt_get_install $pkg:amd64
      local lret=$?
      # fwiw apt-get install $alreadyinstalled returns 0
      [  $lret -eq 0 ] && echo $pkg | egrep -qai 'gcc.*base' && echo "dss:info: not apt-get remove-ing $pkg, as has tended to remove lots of necessary things.  e.g. ifupdown."
      [  $lret -eq 0 ] && echo $pkg | egrep -qai 'gcc.*base' || i386toremove2="$i386toremove2 $pkg" 
    done
    echo "dss:trace: removing 32 bit versions of packages where we were able to install the 64bit version: $i386toremove2"
    # then remove the i386 version.  Used to this after installing each amd64 package, but that sometimes led to other things being removed that broke things
    # fwiw when you install $pkg:amd4 it will typically remove the $pkg:i386, so hopefully not will actually happen in this section?
    for pkg in $i386toremove2 ; do 
      local lret=0
      if echo $pkg | egrep -qai 'gcc.*base'; then 
        true 
      else 
        apt_get_remove $pkg:i386
        lret=$? 
        if [  $lret -ne 0 ]; then
          echo "dss:warn: apt-get remove $pkg:i386 failed.  Trying an apt-get -f install.  Will continue irregardless."  
          ret=$(($ret+1))
          apt_get_f_install "after-${pkg}-remove"
        fi
      fi
    done
    echo "dss:trace: completed individual install and removal of i386 packaged.  Ret code of $ret (0 means we are done, otherwise we go for another round)."
    [  $ret -eq 0 ] && break
  done
  
  # try to install 
  while true; do
      mkdir -p distrorejuveinfo/$$/extra64debs
      cd distrorejuveinfo/$$/extra64debs
      for i in $amd64toinstall; do
        pause_check 
        dpkg -l | grep '^ii' | awk '{print $2}' | grep -qai $i || echo "dss:trace: downloading amd64 debian file for $i" && apt-get download $i
      done
      local amdfilestoinstall="$(find . -type f  | egrep 'amd64.deb$|all.deb$')"
      if [ -z "$amdfilestoinstall" ]; then
        echo "dss:trace: not finding any extra amd64 files to install" 
        break; 
      fi
      cd -
      echo "dss:trace: attempting a dpkg install of non-lib packages: $(echo $amd64toinstall)"
      dpkg_install $(find distrorejuveinfo/$$/extra64debs -type f  | egrep 'amd64.deb$|all.deb$')
      local lret=$?
      echo "dss:trace: dpkg install $( [ $lret -eq 0 ] && echo "succeeded" || echo "failed")"
      break
  done  

  while true; do
      mkdir -p distrorejuveinfo/$$/settheory
      cd distrorejuveinfo/$$/settheory
      #[ir] e.g. to find desired = install or remove where status = installed 
      dpkg -l | egrep '^[ir]i.*i386' | awk '{print $2}' | sed 's/:i386//' | sort > pkgs.386.log
      dpkg -l | egrep '^ii.*amd64' | awk '{print $2}' | sed 's/:amd64//' | sort> pkgs.amd64.log
      amd64toinstall="$(for i in $(comm -3  --check-order pkgs.amd64.log pkgs.386.log | grep -v '^[a-z]'); do echo "$i:amd64 "; done)"

      for i in $amd64toinstall; do
        pause_check 
        echo "dss:trace: downloading amd64 debian file for $i"
        apt-get download $i
      done
      cd -
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
    local i=
    local toreinstall=
    local donotreinstallregex="linux-.*-686-pae|anotherpackagehere"
    for i in $uninstalled; do 
      # sometimes packages are removed, but due to being deprecated.  $available will contain only the packages on the current distro
      echo "$available" | egrep -v "$donotreinstallregex" | egrep -qai "^$i\$" && toreinstall="$toreinstall $i"
    done
    # => e.g. toreinstall=apache2 apache2-bin fontconfig-config fonts-dejavu-core 
    [ ! -z "$toreinstall" ] && echo "dss:info: Will reinstall some packages that have been removed during the crossgrade: $(echo $toreinstall)"
    for i in $toreinstall; do
      apt_get_install $i
    done
  done
  
  apt-get $APT_GET_INSTALL_OPTIONS autoremove
  
  has_cruft_packages 32bit && show_cruft_packages
  
  echo "dss:info: Cross grade has complete.  $(has_cruft_packages 32bit && echo 'has some 32 bit packages still (see above)' || echo 'no 32 bit packages remain (good)')"
  
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
  return 0
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
   return $?
}

function print_no_available_versions() {
  [ ! /etc/apt/sources.list ] && return 0
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
    [ -f /etc/init.d/mysql ] && ps auxf | grep -qai '[m]ysqld_safe' && /etc/init.d/mysql restart && "dss:info: issued a mysql restart" 
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
declare -i random=$(expr $(ifconfig eth0 | grep -v inet6  | grep  "inet" | head -n 1 | sed -e "s/[^0-9 ]//g" | sed "s/^  *//" |  cut -f 1 -d\ ) % 900)
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

function dist_upgrade_x_to_y() {
pause_check
[ ! -e /etc/apt/sources.list ] && return 0
echo "dss:trace:dist_upgrade_x_to_y:checking:olddistro=$old_distro:oldver=$old_ver:newdistro=$new_distro"

if ! grep -qai "^ *deb.*$old_distro" -- /etc/apt/sources.list; then
  echo "dss:info: Not finding $old_distro in /etc/apt/sources.list.  Skipping $old_distro to $new_distro"
  return 0
fi
fix_missing_lsb_release
if ! lsb_release -a 2>/dev/null| egrep -qai "$old_distro|$old_ver" ; then
  echo "dss:info: Not finding $old_distro or $old_ver in lsb_release output.  Skipping $old_distro to $new_distro"
  return 0
fi

if is_distro_name_older "$old_distro" "squeeze"; then  
  if dpkg -l | grep -qai '^i.*dovecot'; then
    print_uninstall_dovecot
    return 1
  fi
fi
if [ "$old_distro" == "lenny" ]; then
  add_missing_debian_keys
  [ ! -d "/dev/pts" ] && mkdir /dev/pts && echo "dss:info: created /dev/pts"
fi

if is_distro_name_older "$old_distro" "stretch"; then
  if dpkg -l | grep -qai '^i.*fail2ban'; then
    print_uninstall_fail2ban
    return 1
  fi
fi
  
upgrade_precondition_checks || return $?

echo "dss:trace:dist_upgrade_x_to_y:pre_apt_get_upgrade:old:$old_distro:new:$new_distro"
apt_get_upgrade
local ret=$?
apt-get clean
apt-get $APT_GET_INSTALL_OPTIONS autoremove
if [ $ret -ne 0 ]; then
  echo "dss:error: apt-get upgrade failed.  exiting dist_upgrade_x_to_y:${old_distro}_to_${new_distro}"
  return 1
fi

disable_debian_repos $old_distro

if ! grep -qai "^ *deb.* ${new_distro}[ /-]" /etc/apt/sources.list; then
  echo "deb http://http.us.debian.org/debian/ ${new_distro} main non-free contrib" >> /etc/apt/sources.list

  #Err:3 http://security.debian.org bullseye/updates Release
  #404  Not Found [IP: 199.232.10.132 80]
  if is_distro_name_newer "${new_distro}" "buster"; then
    echo "deb http://security.debian.org/debian-security ${new_distro}-security main" >> /etc/apt/sources.list
  else
    echo "deb http://security.debian.org/ ${new_distro}/updates main" >> /etc/apt/sources.list
  fi
  echo "$old_distro:$new_distro: apt sources now has $(cat /etc/apt/sources.list | egrep -v '^$|^#')" | awk '{print "dss:sources:dist_upgrade_x_to_y:" $0}'
fi


# redo to convert the above to archive where appropriate.  And add lts if appropriate.
enable_debian_archive

echo "dss:trace:dist_upgrade_x_to_y:pre_apt_get_dist_upgrade::olddistro=$old_distro:oldver=$old_ver:newdistro=$new_distro"
apt_get_dist_upgrade
ret=$?
apt-get $APT_GET_INSTALL_OPTIONS  autoremove
if [ $ret -eq 0 ]; then
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
  local b=$2
  [ ! -f $a ] && return 1
  egrep -v '^\s*#|^$' $a
  return 0
}
function print_pkg_to_modified_diff() {
[  ! -d "/root/pkgdiff.$$" ] && mkdir /root/pkgdiff.$$
# get a list of config files in packages that have been changed by the user
local modifiedconfigfiles=$(dpkg-query -W -f='${Conffiles}\n' '*' | grep -v obsolete  | awk 'OFS="  "{print $2,$1}' | LANG=C md5sum -c 2>/dev/null | awk -F': ' '$2 !~ /OK$/{print $1}' | sort)
local modifiedconfigfile
cd /root/pkgdiff.$$
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
cd - >/dev/null
rm -rf /root/pkgdiff.$$
return 0 
}

function print_minimal_config_diff() {
  local a=$1
  local b=$2
  [ ! -f $a ] && return 1
  [ ! -f $b ] && return 1
  ta=$(mktemp "$(basename "${a}").XXXXXX")
  tb=$(mktemp "$(basename "${b}").XXXXXX")
  print_minimal_config $a > $ta
  print_minimal_config $b > $tb
  diff --ignore-all-space -u $ta $tb
  ret=$?
  rm -f $ta $tb
  return $ret
}
function print_config_state_changes() {
  prep_ghost_output_dir
  local now=$(date +%s)
  record_config_state /root/distrorejuveinfo/postupgrade.dpkg.$now
  # get oldest/first preupgrade file.  e.g. we may have to rerun this script.  so diff from first run
  local fromfile="${1}"
  if [  -z "$fromfile" ]; then
    fromfile="$(find /root/distrorejuveinfo/ /root/deghostinfo/ -mtime -${DAYS_UPGRADE_ONGOING} 2>/dev/null | grep preupgrade)"
    [  ! -z "$fromfile" ] && fromfile="$(ls -1rt $fromfile | head -n 1)"
  fi 
  [ -z "$fromfile" ] && fromfile=/root/distrorejuveinfo/preupgrade.dpkg.$$
  # no prior changes just yet.
  [  ! -f  "$fromfile" ] && return 0
  # dpkg-new is used on unpack prior to choosing dpkg-dist or overwriting.
  echo "dss:info: Config changes to check.  e.g. different processes after upgrade.  e.g. different ports.  e.g. different apache status output.  e.g. changes to dpkg-old/dpkg-dist files.  dpkg-old = your files that were not used.  dpkg-dist = distro files that were not used."
  print_minimal_config_diff $fromfile /root/distrorejuveinfo/postupgrade.dpkg.$now | awk '{print "dss:configdiff:statechanges:" $0}'
  
  # ucf-dist = backup of what was there before dist upgrade
  local files=$(find /etc -type f | egrep '.ucf-old|.ucf-diff|.dpkg-new|.dpkg-old|dpkg-dist|\.rpmnew|.rpmsave' | sort)
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
  return 0  
}

function record_config_state() {
  prep_ghost_output_dir
  local file=$1
  if [ -z "$file" ]; then 
    file="/root/distrorejuveinfo/preupgrade.dpkg.$$"
  fi
  # don't overwrite the preupgrade file
  echo $file | grep -qai preupgrade && [ -f $file ] && return 0
  echo "dss:trace:record_config_state:$file"
  local files=$(find /etc -type f | egrep '.ucf-old|.ucf-diff|.dpkg-new|.dpkg-old|dpkg-dist|\.rpmnew|.rpmsave' | sort)
  > $file
  # conf files
  echo "Date: $(date)" >> $file
  [ ! -z "$files" ] && ls -lrt $files | awk '{print "configfiles:" $0}' > $file
  echo "Listening ports:" >> $file
  echo "" >> $file
  # listening ports
  # Listen ports: 0.0.0.0:995 dovecot
  netstat -ntpl | grep LISTEN | awk '{print "Listen ports: " $4 " " $7}' | sed 's/ [0-9]*\// /' | sed 's/0.0.0.0:/:::/' | sort -k 3 | uniq >> $file
  echo "Apache vhosts:" >> $file
  echo "" >> $file
  print_distro_info >> $file
  # vhosts 
  [ -x /usr/sbin/apache2ctl ] && /usr/sbin/apache2ctl -S 2>&1 | awk '{print "ApacheStatus: " $0}' >> $file
  echo "" >> $file
  echo "Running processes:" >> $file
  echo "" >> $file
  ps ax | awk '{print "process: " $5 " " $6 " " $7 " " $8 " " $9}' | egrep -v '^process: \[|COMMAND|init' | sort | uniq >> $file
  
  [  -x /usr/bin/dpkg ] && echo "Installed packages:" >> $file && dpkg -l | grep '^ii' | awk '{print $2}' | sed 's/:.*//' | sort | grep -v '^lib' | awk '{ print "installed: " $0 }' >> $file
  return 0
}

function apt_get_update() {
pause_check
apt-get update
ret=$?
# E: Release file expired, ignoring http://archive.debian.org/debian/dists/squeeze-lts/Release (invalid since 14d 8h 58min 38s)
if [ $ret -ne 0 ]; then apt-get -o Acquire::ForceIPv4=true  -o APT::Get::AllowUnauthenticated=yes -o Acquire::Check-Valid-Until=false  update; ret=$?; fi
return $ret
}

function apt_get_upgrade() {
pause_check
[ ! -e /etc/apt/sources.list ] && return 0
[ -e /etc/redhat-release ] && return 0
upgrade_precondition_checks || return $?
echo "dss:trace:apt_get_upgrade"

enable_debian_archive
apt_get_update
record_config_state
dpkg --configure -a --force-confnew --force-confdef --force-confmiss
apt-get $APT_GET_INSTALL_OPTIONS autoremove
apt_get_f_install
echo "dss:info: running an apt-get upgrade"
apt-get $APT_GET_INSTALL_OPTIONS --allow-downgrades upgrade
ret=$?
apt-get $APT_GET_INSTALL_OPTIONS autoremove
apt_get_f_install
if [ $ret -ne 0 ]; then
  echo "dss:info: apt-get upgrade failed.  trying a dist-ugprade..."
  apt-get  $APT_GET_INSTALL_OPTIONS  dist-upgrade
  ret=$?
  if [ $ret -eq 0 ]; then
    echo "dss:info: apt-get dist-upgrade succeeded when a upgrade failed."
    return 0
  else
    echo "dss:warn: apt-get upgrade/dist-upgrade failed."
    return 1 
  fi
fi
apt-get clean
return $ret
}

function plesk_upgrade() {
  which plesk >/dev/null 2>&1 || return 0
  plesk installer --select-release-current --reinstall-patch --upgrade-installed-components
}

function apt_get_dist_upgrade() {
pause_check
[ ! -e /etc/apt/sources.list ] && return 0
upgrade_precondition_checks || return $?
echo "dss:trace:apt_get_dist_upgrade:pre_apt_get_upgrade:"
apt_get_upgrade || return 1
echo "dss:trace:apt_get_dist_upgrade"
apt_get_f_install
apt_get_install dpkg
apt-get  $APT_GET_INSTALL_OPTIONS  autoremove
apt-get  $APT_GET_INSTALL_OPTIONS  dist-upgrade
# cope with 'one of those random things'
# E: Could not perform immediate configuration on 'python-minimal'.Please see man 5 apt.conf under APT::Immediate-Configure for details. (2)
if [ $? -ne 0 ] && apt-get  $APT_GET_INSTALL_OPTIONS  dist-upgrade 2>&1 | grep -qai "Could not perform immediate configuration on "; then
  apt-get -f $APT_GET_INSTALL_OPTIONS install libc6-dev
  apt-get dist-upgrade -f -o APT::Immediate-Configure=0 $APT_GET_INSTALL_OPTIONS
fi
[ -e /var/log/syslog ] && [ -e /etc/my/my.cnf ] && if grep "unknown variable 'lc-messages-dir" /var/log/syslog; then
  #lc-messages-dir        = /usr/share/mysql...
  echo "dss: info: commenting out the my.cnf lc-messages-dir directive in case it is causing problems" 
  sed -i "s@^lc-messages-dir\(.*\)@#lc-messages-dir\1@" /etc/my/my.cnf
fi

dpkg --configure -a --force-confnew --force-confdef --force-confmiss
apt-get $APT_GET_INSTALL_OPTIONS autoremove
apt-get -y autoclean
apt-get  $APT_GET_INSTALL_OPTIONS  dist-upgrade
ret=$?
if [ $ret -ne 0 ] ; then
  echo "dss:warn: Got an error after an apt-get dist-upgrade.  trying an apt-get -f install"
  apt_get_f_install
  apt-get  $APT_GET_INSTALL_OPTIONS  dist-upgrade
  ret=$?
  if [ $ret -ne 0 ] ; then
    check_systemd_install_matches_init
    echo "dss:error: Got an error after an apt-get dist-upgrade"
  fi 
fi
# report -dist or -old file changes
tweak_broken_configs
echo "dss:trace:apt_get_dist_upgrade completed $(print_distro_info).  ret=$ret"

return $ret
}

# arg1 is the number of distros to upgrade.  default is all/1000.  else you can do 1 to just go up one distro.  lts to lts counts as 1.
function dist_upgrade_ubuntu_to_latest() {
pause_check
[ ! -e /etc/apt/sources.list ] && return 0
lsb_release -a 2>/dev/null | grep -qai Ubuntu || return 0

echo "dss:trace:dist_upgrade_ubuntu_to_latest $(print_distro_info)."

if is_distro_name_older "$old_distro" "xenial"; then
  if dpkg -l | grep -qai '^i.*dovecot'; then
    print_uninstall_dovecot
    return 1
  fi
fi

if is_distro_name_older "$old_distro" "bionic"; then
  if dpkg -l | grep -qai '^i.*fail2ban'; then
    print_uninstall_fail2ban
    return 1
  fi
fi

local NUM_TO_DIST_UPGRADE="${1:-1000}"

upgrade_precondition_checks || return $?
echo "dss:trace:dist_upgrade_ubuntu_to_latest:pre_apt_get_upgrade:"
apt_get_upgrade
local candidates="$ALL_UBUNTU"
for start in $ALL_UBUNTU; do
  [ $NUM_TO_DIST_UPGRADE -lt 1 ] && echo "Stopping after $1 distro version updates as requested" && return 0
  #No LSB modules are available.
  #Distributor ID: Ubuntu
  #Description:  Ubuntu 14.04.4 LTS
  #Release:  14.04
  #Codename: trusty 
  current=$(lsb_release -a 2>/dev/null| grep -i Codename | awk '{print $2}')
  # remove distros prior to us
  candidates="$(echo $candidates | sed "s/$start//")"
  candidates="$(echo $candidates | sed "s/$current//")"
  # keep looping till we find our current distro
  if [ "$current" != "$start" ]; then continue; fi
  # all done
  if [ -z "$candidates" ]; then return 0; fi
  # if we are currently an lts, then we can move from lts to next lts and skip over the non-lts ones
  if echo $LTS_UBUNTU | grep -qai $current; then
    local removed=""
    for remove in $NON_LTS_UBUNTU; do
       removed="$remove $removed"
       candidates="$(echo $candidates | sed "s/$remove//")"
    done
    echo "dss:info: current distro ($current) is an Ubuntu LTS.  Skipping non-LTS versions: $removed; Leaving LTS versions of: $candidates"
  fi 
  # comment out current sources entries
  prep_ghost_output_dir
  local next=$(echo $candidates | awk '{print $1}')
  if [ -z "$next" ]; then
    echo "dss:info: Current Ubuntu distro is $current.  No newer/better distro.  Finished." 
    return 0 
  fi
  cp /etc/apt/sources.list /root/distrorejuveinfo/sources.list.$(date +%Y%m%d.%s)
  # comment out package entries
  sed -i "s@^ *deb \(.*\)ubuntu.com\(.*\)@#deb \1ubuntu.com\2@" /etc/apt/sources.list
  # add in new repo names
  echo "dss:info: attempting a dist-upgrade from $current to $next."
  if echo $OLD_RELEASES_UBUNTU | grep -qai $next; then
    echo "deb http://old-releases.ubuntu.com/ubuntu/ $next main restricted universe multiverse" >> /etc/apt/sources.list
    echo "deb http://old-releases.ubuntu.com/ubuntu/ $next-updates main restricted universe multiverse" >> /etc/apt/sources.list
    echo "deb http://old-releases.ubuntu.com/ubuntu/ $next-security main restricted universe multiverse" >> /etc/apt/sources.list    
  else
    echo "deb http://archive.ubuntu.com/ubuntu/ $next main universe" >> /etc/apt/sources.list
    echo "deb http://security.ubuntu.com/ubuntu/ $next-security main universe" >> /etc/apt/sources.list
    echo "deb http://archive.ubuntu.com/ubuntu/ $next-updates main universe" >> /etc/apt/sources.list 
  fi 
  # Old apache version contains 'Include /etc/apache2/httpd.conf'. Can be 'touch'ed to recreate
  [ -d /etc/apache2 ] && [ ! -f /etc/apache2/httpd.conf ] && touch /etc/apache2/httpd.conf
  echo "dss:trace:dist_upgrade_ubuntu_to_latest:pre_apt_get_upgrade:next:$next"
apt_get_dist_upgrade
ret=$?
NUM_TO_DIST_UPGRADE=$((NUM_TO_DIST_UPGRADE-1))
if [ $ret -eq 0 ]; then
  if lsb_release -a 2>/dev/null| grep -qai $next; then
    # dist-upgrade returned ok, and lsb_release thinks we are wheezy
    echo "dss:info: dist-upgrade from $current to $next appears to have worked." 
    continue; 
  fi
  ret=1
else
  echo "dss:warn: dist-upgrade from $current to $next appears to have failed." 
fi
echo "dss:trace:dist_upgrade_ubuntu_to_latest:completed $(print_distro_info).  ret=$ret"
return $ret
done
}

function convert_old_debian_repo() {
pause_check
# no apt sources nothing to do
[ ! -f /etc/apt/sources.list ] && return 0
lsb_release -a 2>/dev/null | grep -qai Ubuntu && return 0

echo "dss:trace:convert_old_debian_distro"

#deb http://http.us.debian.org/debian sarge main contrib non-free
#deb http://non-us.debian.org/debian-non-US sarge/non-US main contrib non-free
#deb http://security.debian.org sarge/updates main contrib non-free
# ==>
#deb http://non-us.debian.org/debian-non-US sarge/non-US main contrib non-free
#deb http://security.debian.org sarge/updates main contrib non-free
#deb http://archive.debian.org/debian/ sarge main non-free contrib

local name=
for name in $DEBIAN_ARCHIVE; do 
# no lenny stuff, nothing to do
! grep -qai "^ *deb.*debian.* ${name}[ /-]" /etc/apt/sources.list && continue

# already using archives, all good
if grep -qai "^ *deb http://archive.debian.org/debian/ ${name}[ /-]" /etc/apt/sources.list; then
  echo "dss:info: This is a $name distro, and already has archive.debian in the repository."
  continue
fi

prep_ghost_output_dir
cp /etc/apt/sources.list /root/distrorejuveinfo/sources.list.$(date +%Y%m%d.%s)

# comment out the old entries
convertfile $name $name debian.org "#" /etc/apt/sources.list
#sed -i "s@^ *deb http://ftp.\(\S*\).debian.org/debian $name@#deb http://ftp.\1.debian.org/debian $name@" /etc/apt/sources.list
#sed -i "s@^ *deb http://security.debian.org/ $name@#deb http://security.debian.org/ $name@" /etc/apt/sources.list
#sed -i "s@^ *deb-src http://ftp.\(\S*\).debian.org/debian $name main contrib@#deb-src http://ftp.\1.debian.org/debian $name main contrib@" /etc/apt/sources.list
#sed -i "s@^ *deb http://http.\(\S*\).debian.org/debian $name@#deb http://http.\1.debian.org/debian $name@" /etc/apt/sources.list
#sed -i "s@^ *deb http://non-us.debian.org/debian-non-US $name@#deb http://non-us.debian.org/debian-non-US $name@" /etc/apt/sources.list
#sed -i "s@^ *deb http://security.debian.org $name@#deb http://security.debian.org $name@" /etc/apt/sources.list

echo "deb http://archive.debian.org/debian/ ${name} main non-free contrib" >> /etc/apt/sources.list
echo "$name apt sources now has $(cat /etc/apt/sources.list | egrep -v '^$|^#')" | awk '{print "dss:sources:convert_old_debian_repo:" $0}'
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

function fix_via_apt_install() {
is_fixed && return 0 
if ! which dpkg >/dev/null 2>&1; then 
  # echo "dss:info: dpkg not installed.  Skipping apt-get install"; 
  return 0; 
fi
add_missing_debian_keys
add_missing_ubuntu_keys

if print_distro_info | grep Ubuntu | egrep -qai "$(echo $OLD_RELEASES_UBUNTU | sed 's/ /|/')"; then 
  echo "dss:info: Running an EOL Ubuntu.  Not doing an apt-get install -y libc6.  $(print_distro_info)"
  return 0
fi

if dpkg -s libc6 2>/dev/null | grep -q "Status.*installed" ; then 
  echo "dss:info: Attempting to apt-get install libc6"
  apt_get_update
  ret=$?
  if [ $ret -ne 0 ]; then
    echo "dss:warn: There was an error doing an apt-get update"
  fi
  for distro in $DEBIAN_CURRENT; do 
    if grep -qai "^ *deb.* ${distro}[ /-]" /etc/apt/sources.list && ! grep -qai "^ *deb.*security\.deb.* ${distro}[ /-]" /etc/apt/sources.list; then
      echo "dss:info: adding the $distro security repository to the sources.list"
      cp /etc/apt/sources.list /root/distrorejuveinfo/sources.list.$(date +%Y%m%d.%s)
      # https://wiki.debian.org/NewInBullseye
      # The format of the /etc/apt/sources.list line for the security repository has changed. It should look something like this:
      # deb http://security.debian.org/debian-security bullseye-security main
      if is_distro_name_newer "${distro}" "buster"; then
        echo "deb http://security.debian.org/debian-security ${distro}-security main" >> /etc/apt/sources.list
      else
        echo "deb http://security.debian.org/ $distro/updates main" >> /etc/apt/sources.list
      fi
      apt_get_update
    fi
  done
  POLICY=$(apt-cache policy libc6)
  POLICY_INSTALLED=$(echo $POLICY | grep Installed | sed -e   's/.*Installed: \(\S*\).*/\1/')
  POLICY_CANDIDATE=$(echo $POLICY | grep Candidate | sed -e   's/.*Candidate: \(\S*\).*/\1/')
  if [ ! -z "$POLICY_INSTALLED" -a "$POLICY_INSTALLED" == "$POLICY_CANDIDATE" ]; then
    echo "dss:info: apt-cache policy reports the latest libc6 package already installed"
    return 0
  fi
  if [ -d /var/lib/dpkg/updates ] && [ 0 -ne $(find /var/lib/dpkg/updates -type f | wc -l) ]; then
    echo "dss:info: looks like there were some pending updates.  checking if they need configuring before proceeding with the libc6 install"
    dpkg --configure -a --force-confnew --force-confdef --force-confmiss
  fi
  apt_get_install libc6
  ret=$?
  if [ $ret -eq 0 ]; then
  	echo "dss:fixmethod: apt-get install"
  	# if wrong version is installed you can force the version with something like this on squeeze:
  	# apt-get install libc6=2.11.3-4+deb6u4 libc6-i686=2.11.3-4+deb6u4 libc-bin=2.11.3-4+deb6u4 
  	return 0
  fi
  echo "dss:error: Failed doing apt-get -y install libc6"
  prep_ghost_output_dir
  # download isnt an option on some older apts
  apt-get download libc6 2>/dev/null
  ret=$?
  local file=$(find . -name '*.deb' | grep libc6 | head -n 1)
  if [ $ret -ne 0 ] || [ -z "$file" ]; then
  	echo "dss:error: Failed downloading the libc6 package with apt-get download libc6"
  	return 1
  fi
  dpkg -i $file
  ret=$?
  if [ $ret -eq 0 ]; then
  	echo "dss:fixmethod: apt-get download libc6 and dpkg -i"
  	return 0
  fi
  return $ret
fi
echo "dss:warn: libc6 not installed.  Not running apt-get install libc6"
return 0
}

function yum_upgrade() {
  pause_check
  [ ! -f /etc/redhat-release ] && return 0
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
prep_ghost_output_dir
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
  is_fixed && return 0
  
  [ -f /etc/apt/sources.list ] && [ -f /etc/debian_version ] && if print_distro_info | grep Ubuntu | egrep -qai "$(wordlisttoegreparg $OLD_RELEASES_UBUNTU)"; then 
    echo "dss:warn: Running an end-of-life Ubuntu distro ($(print_distro_info)).  No new package updates available.  dist upgrade to the latest lts"
    return 1
  fi
  # DEBIAN 7.4
  # Debian GNU/Linux 7.9 (n/a) Release: 7.9 Codename: n/a
  # Distributor ID: Debian Description: Debian GNU/Linux 7.2 (wheezy) Release: 7.2 Codename: wheezy

  [ -f /etc/apt/sources.list ] && [ -f /etc/debian_version ] && if print_distro_info | grep -i 'Debian GNU' | egrep -qai "$(wordlisttoegreparg $UNSUPPORTED_DEBIAN)"; then
    # due to etch being unsupported and stretch beinc current
    if ! print_distro_info | grep -i 'Debian GNU' | egrep -qai "$(wordlisttoegreparg $DEBIAN_CURRENT)"; then 
      echo "dss:warn: Running an end-of-life Debian distro ($(print_distro_info)).  No new package updates available.  dist upgrade to the latest lts"
    fi
    return 1
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

function fix_via_yum_install() {
  is_fixed && return 0 
  improve_yum_setup || return 1
  if ! print_distro_info | egrep -i 'redhat|centos' | egrep -qai 'release.* 5|release.* 6|release.* 7' ; then return 0; fi
  echo "dss:info: Doing a centos5-7 fix for $(print_distro_info)"
  yum install -y glibc
  ret=$?
  if [ $ret -ne 0 ]; then
    echo "dss:warn:Error running yum install -y glibc"
  fi
  echo "dss:fixmethod: yum install glibc" 
  return $ret
}


function fix_vuln() {
print_vulnerability_status beforefix
print_libc_versions beforefix || return $?
print_info

if is_fixed ; then 
  echo "dss:info: The server appears to not be vulnerable.  Not doing anything."
  return 0
fi

upgrade_precondition_checks || return $?

# improve apt sources
convert_deb_6_stable_repo_to_squeeze  || return $?
convert_old_debian_repo || return $?

# https://wiki.ubuntu.com/Releases
# lucid server still current?
for distro in $OLD_RELEASES_UBUNTU; do 
  convert_old_ubuntu_repo $distro || return $?
done
enable_debian_archive || return $?

fix_missing_lsb_release


fix_via_apt_install #|| return $?

yum_enable_rhel4 || return $?

fix_via_yum_install || return $?

report_unsupported || return $?
return 0
}

function packages_upgrade() {
upgrade_precondition_checks || return $?

# improve apt sources
convert_deb_6_stable_repo_to_squeeze  || return $?
convert_old_debian_repo || return $?

# https://wiki.ubuntu.com/Releases
# lucid server still current?
for distro in $OLD_RELEASES_UBUNTU; do 
  convert_old_ubuntu_repo $distro || return $?
done
enable_debian_archive || return $?

fix_missing_lsb_release

fix_via_apt_install #|| return $?

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
  echo "dss:trace:dist_upgrade_to_latest"

  if ! packages_upgrade; then echo "dss:error:dist_upgrade_to_latest:packages_upgrade:failed" && return 1; fi
  if ! apt_get_dist_upgrade; then echo "dss:error:dist_upgrade_to_latest:apt_get_dist_upgrade:failed" && return 1; fi
  if [ -e /etc/apt/sources.list ] && lsb_release -a 2>/dev/null | grep -qai debian; then
    if ! dist_upgrade_lenny_to_squeeze; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_lenny_to_squeeze:failed" && return 1; fi
    if ! dist_upgrade_squeeze_to_wheezy; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_squeeze_to_wheezy:failed" && return 1; fi
    if ! dist_upgrade_wheezy_to_jessie; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_wheezy_to_jessie:failed" && return 1; fi
    if ! dist_upgrade_jessie_to_stretch; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_jessie_to_stretch:failed" && return 1; fi
    if ! dist_upgrade_stretch_to_buster; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_stretch_to_buster:failed" && return 1; fi
    if ! dist_upgrade_buster_to_bullseye; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_buster_to_bullseye:failed" && return 1; fi
    if ! dist_upgrade_bullseye_to_buster; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_bullseye_to_buster:failed" && return 1; fi
    
    if ! apt_get_dist_upgrade; then echo "dss:error:dist_upgrade_to_latest:apt_get_dist_upgrade:failed" && return 1; fi
  fi
  if [ -e /etc/apt/sources.list ] && lsb_release -a 2>/dev/null | grep -qai ubuntu; then  
    if ! dist_upgrade_ubuntu_to_latest; then echo "dss:error:dist_upgrade_to_latest:dist_upgrade_ubuntu_to_latest:failed" && return 1; fi
    if ! apt_get_dist_upgrade; then echo "dss:error:dist_upgrade_to_latest:apt_get_dist_upgrade:failed" && return 1; fi
  fi
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
if [ "--usage" = "${ACTION:-$1}" ] ; then
  print_usage
elif [ "--check" = "${ACTION:-$1}" ] || [ -z "${ACTION:-$1}" ] ; then
  print_vulnerability_status beforefix
  print_info
  upgrade_precondition_checks
  report_unsupported
  # set return code
  true
elif [ "--to-wheezy" = "${ACTION:-$1}" ] ; then
  print_info
  dist_upgrade_lenny_to_squeeze
  [ $? -ne 0 ] && ret=$(($ret+1))
  dist_upgrade_squeeze_to_wheezy
  [ $? -ne 0 ] && ret=$(($ret+1))
  if [ $ret -eq 0 ] ; then true ; else print_failed_dist_upgrade_tips; false; fi
elif [ "--to-jessie" = "${ACTION:-$1}" ] ; then
  print_info
  dist_upgrade_lenny_to_squeeze
  [ $? -ne 0 ] && ret=$(($ret+1))
  dist_upgrade_squeeze_to_wheezy
  [ $? -ne 0 ] && ret=$(($ret+1))
  dist_upgrade_wheezy_to_jessie
  [ $? -ne 0 ] && ret=$(($ret+1))
  if [ $ret -eq 0 ] ; then true ; else print_failed_dist_upgrade_tips; false; fi
elif [ "--to-debian-release" = "${ACTION:-$1}" ] ; then
  version="$2"
  [ -z "$version" ] && echo "dss:error: Need a version e.g. 11 for --to-debian-release" && exit 1
  case "$version" in
      6|7|8|9|10|11)
      true
      ;;
      *)
      echo "dss:error: Expecting a --to-debian-release versoin of 6 to 11" && exit 1
      ;;
  esac
  print_info
  if [ $version -gt 5 ]; then dist_upgrade_lenny_to_squeeze; [ $? -ne 0 ] && ret=$(($ret+1)); fi
  if [ $version -gt 6 ]; then dist_upgrade_squeeze_to_wheezy; [ $? -ne 0 ] && ret=$(($ret+1)); fi
  if [ $version -gt 7 ]; then dist_upgrade_wheezy_to_jessie; [ $? -ne 0 ] && ret=$(($ret+1)); fi
  if [ $version -gt 8 ]; then dist_upgrade_jessie_to_stretch; [ $? -ne 0 ] && ret=$(($ret+1)); fi
  if [ $version -gt 9 ]; then dist_upgrade_stretch_to_buster; [ $? -ne 0 ] && ret=$(($ret+1)); fi
  if [ $version -gt 10 ]; then dist_upgrade_buster_to_bullseye; [ $? -ne 0 ] && ret=$(($ret+1)); fi
  if [ $version -gt 11 ]; then dist_upgrade_bullseye_to_buster; [ $? -ne 0 ] && ret=$(($ret+1)); fi
  
  
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --to-latest-debian completed ok.  use $0 --show-changes to see changes" 
elif [ "--to-latest-debian" = "${ACTION:-$1}" ] ; then
  print_info
  dist_upgrade_lenny_to_squeeze
  [ $? -ne 0 ] && ret=$(($ret+1))
  dist_upgrade_squeeze_to_wheezy
  [ $? -ne 0 ] && ret=$(($ret+1))
  dist_upgrade_wheezy_to_jessie
  [ $? -ne 0 ] && ret=$(($ret+1))
  dist_upgrade_jessie_to_stretch
  [ $? -ne 0 ] && ret=$(($ret+1))
  dist_upgrade_stretch_to_buster
  [ $? -ne 0 ] && ret=$(($ret+1))
  dist_upgrade_buster_to_bullseye
  [ $? -ne 0 ] && ret=$(($ret+1))
  dist_upgrade_bullseye_to_buster
  [ $? -ne 0 ] && ret=$(($ret+1))
  
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --to-latest-debian completed ok.  use $0 --show-changes to see changes" 
elif [ "--to-latest-lts" = "${ACTION:-$1}" ] ; then
  print_info
  dist_upgrade_ubuntu_to_latest
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info: --to-latest-lts completed ok.  use $0 --show-changes to see changes"
elif [ "--to-next-ubuntu" = "${ACTION:-$1}" ] ; then
  print_info
  dist_upgrade_ubuntu_to_latest 1
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --to-next-ubuntu completed ok.  use $0 --show-changes to see changes" 
elif [ "--to-squeeze" = "${ACTION:-$1}" ] ; then
  print_info
  dist_upgrade_lenny_to_squeeze
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --to-squeeze completed ok.  use $0 --show-changes to see changes" 
elif [ "--source" = "${ACTION:-$1}" ] ; then 
  echo "dss:info:Loaded distrorejuve functions"
elif [ "--upgrade" = "${ACTION:-$1}" ] ; then
  print_info
  IGNOREOTHERREPOS=Y
  packages_upgrade
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --upgrade completed ok.  use $0 --show-changes to see changes" 
elif [ "--dist-upgrade" = "${ACTION:-$1}" ] ; then
  print_info
  dist_upgrade_to_latest
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --dist-upgrade completed ok.  use $0 --show-changes to see changes" 
elif [ "--dist-update" = "${ACTION:-$1}" ] ; then
  print_info
  yum_upgrade
  [ $? -ne 0 ] && ret=$(($ret+1))
  packages_upgrade
  [ $? -ne 0 ] && ret=$(($ret+1))
  apt_get_dist_upgrade
  [ $? -ne 0 ] && ret=$(($ret+1))
  [ $ret -ne 0 ] && echo "dss:error: dist upgrade failed, see above for any details, tips to follow." && print_failed_dist_upgrade_tips && echo "dss:error: dist upgrade failed.  exiting.  use $0 --show-changes to see changes"
  [ $ret -eq 0 ] && echo "dss:info:  --dist-update completed ok.  use $0 --show-changes to see changes" 
elif [ "--break-eggs" = "${ACTION:-$1}" ] ; then 
  fix_vuln
  if ! is_fixed; then
    dist_upgrade_to_latest
  fi
  print_libc_versions afterfix
  print_config_state_changes
  print_vulnerability_status afterfix
  if [ $ret -eq 0 ] ; then true ; else false; fi
elif [ "--fix-vuln" = "${ACTION:-$1}" ] ; then 
  fix_vuln
  ret=$?
  print_libc_versions afterfix
  print_vulnerability_status afterfix
  if [ $ret -eq 0 ] ; then true ; else false; fi
elif [ "--show-cruft" = "${ACTION:-$1}" ] ; then
  ! has_cruft_packages && echo "No cruft packages (all installed packages from the current distro.  No 32 bit packages on a 64 bit install)." && exit 0
  show_cruft_packages
  echo "To remove those packages, re-run with bash $0 --remove-cruft"
  exit 0   
elif [ "--remove-cruft" = "${ACTION:-$1}" ] ; then
  ! has_cruft_packages && echo "No cruft packages (all installed packages from the current distro.  No 32 bit packages on a 64 bit install).  Nothing to do.  All good." && exit 0
  remove_cruft_packages
  exit $?   
elif [ "--remove-deprecated-packages" = "${ACTION:-$1}" ] ; then
  ! has_cruft_packages oldpkg && echo "No cruft packages (all installed packages from the current distro).  Nothing to do.  All good." && exit 0
  remove_cruft_packages oldpkg
  exit $?   
elif [ "--to-64bit" = "${ACTION:-$1}" ] ; then
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
  exit $ret   
elif [ "--pause" = "${ACTION:-$1}" ] ; then
  touch ~/distrorejuve.pause
  echo "dss:info: Touched the pause file at $(realpath ~/distrorejuve.pause)"
  exit 0
elif [ "--resume" = "${ACTION:-$1}" ] ; then
  rm -f ~/distrorejuve.pause
  echo "dss:info: Removed the pause file at $(realpath ~/distrorejuve.pause)"
  exit 0
else
  print_usage
fi
