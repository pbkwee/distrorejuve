#!/bin/bash
grep root /etc/passwd | grep tcsh &&  echo "dss:error: deghost.sh needs to be run as a script, rather than a set of commands on a tsch shell." && exit 1
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=text

# https://wiki.ubuntu.com/Releases
EOL_UBUNTU_DISTROS="breezy dapper edgy feisty gutsy hardy hoary intrepid jaunty karmic maverick natty oneiric quantal raring warty" 
SUPPORTED_UBUNTU_DISTROS="lynx pangolin tahr unicorn"
function print_usage() {
  echo "deghost is a cross-distro script to determine the vulnerability of a libc library to the ghost exploits (CVE-2015-0235) and then patch that where possible.

deghost works on a number of different distros. It uses apt, yum and repository corrections as appropriate.

Attempts to improve the situation if it is.

    - Debian 7 => apt-get install
    - Debian 6 => fix up apt repositories for squeeze-lts and then apt-get install
    - Supported Ubuntus (12.04 LTS, 14.04 LTS, 14.10) => apt-get install
    - Unsupported Ubuntus (others per EOL_UBUNTU_DISTROS variable) => convert to old-releases.ubuntu.com
    - RHEL4, WBEL3, RH9, Lenny (Debian 5) and earlier Debians => nothing
    
Potential improvements to come:

    - Lenny.  Need to patch?  Maybe use squeeze .deb?
  
  Use with --source if you just wish to have the functions available to you for testing
  
  Run with --check if you just wish to check, but not change your server
  
  Run with --usage to get this message
  
  Run without an argument to try and fix your server
  
  Written by Peter Bryant at http://lauchtimevps.com
  
  Latest version (or thereabouts) will be available at https://github.com/pbkwee/deghost
  "
}

function is_fixed() {
  # 0 = vulnerable, 1 = fixed, 2 = dunno
  is_CVE_2015_0235_vulnerable
  ret=$?
  if [ $ret -eq 1 ]; then 
    return 0
  fi
  return 1
}

function is_vulnerable() {
  is_CVE_2015_0235_vulnerable
  return $?
  #return 1
}

function prep_ghost_output_dir() {
if [ ! -d /root/deghostinfo ] ; then echo "dss:info: Creating /root/deghostinfo and cd-ing there."; mkdir /root/deghostinfo; fi
[ -d /root/deghostinfo ] && cd /root/deghostinfo
return 0
}

function print_libc_versions() {
# Checking current glibc version
local prefix=${1:-prefix}
[ -x /usr/bin/ldd ] && /usr/bin/ldd --version | grep -i libc | awk '{print "dss:lddver:'$prefix':" $0}'  
[ -x /usr/bin/dpkg ] && /usr/bin/dpkg -l libc-bin | grep libc-bin | awk '{print "dss:dpkg:'$prefix':" $0}'
[ -x /bin/rpm ] && /bin/rpm -qa glibc | awk '{print "dss:rpmqa:'$prefix':" $0}'
return 0
}

function is_CVE_2015_0235_vulnerable() {
  print_CVE_2015_0235_vulnerable > /dev/null
  return $?
}

# 0 = vulnerable, 1 = fixed, 2 = dunno
function print_CVE_2015_0235_vulnerable() {
# based on some known good package versions https://security-tracker.debian.org/tracker/CVE-2015-0235
# http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-0235.html
if [ ! -x /usr/rpm -a -x /usr/bin/dpkg ]; then
   if dpkg -l | grep libc6 | egrep -qai '2\.13-38\+deb7u7|2\.11\.3-4\+deb6u4|2\.11\.1-0ubuntu7.20|2\.15-0ubuntu10.10|2\.19-10ubuntu2'; then
     echo "N"
     return 1
   fi
   if dpkg -l | grep libc6 | egrep -qai '2\.11\.3-4|2\.13-38\+deb7u6|2\.7-18lenny7'; then
     echo "Y"
     return 0
   fi
   echo "?"
   return 2
fi
rv=1
for glibc_nvr in $( rpm -q --qf '%{name}-%{version}-%{release}.%{arch}\n' glibc ); do
    glibc_ver=$( echo "$glibc_nvr" | awk -F- '{ print $2 }' )
    glibc_maj=$( echo "$glibc_ver" | awk -F. '{ print $1 }')
    glibc_min=$( echo "$glibc_ver" | awk -F. '{ print $2 }')
    if [ -z "$glibc_maj" -o -z "$glibc_maj" -o -z "$glibc_min" ]; then
      rv=2
      continue
    fi
    #echo -n "- $glibc_nvr: "
    if [ "$glibc_maj" -gt 2   -o  \
        \( "$glibc_maj" -eq 2  -a  "$glibc_min" -ge 18 \) ]; then
        # fixed upstream version
        # echo 'not vulnerable'
        true
    else
        # all RHEL updates include CVE in rpm %changelog
        if rpm -q --changelog "$glibc_nvr" | grep -q 'CVE-2015-0235'; then
            #echo "not vulnerable"
            true
        else
            #echo "vulnerable"
            rv=0
        fi
    fi
done

if [ $rv -eq 0 ] ; then echo "Y"; return 0; fi
echo "N"
return 1
}

# use print_vulnerability_status beforefix and print_vulnerability_status afterfix
function print_vulnerability_status() {
local prefix=${1:-prefix}
echo "dss:isvulnerable:$prefix: CVE_2015_0235$(print_CVE_2015_0235_vulnerable)"
}

function print_info() {
echo "dss:hostname: $(hostname)"
echo "dss:date: $(date -u)"
echo "dss:dates: $(date -u +%s)"
echo "dss:uptimes:$(cat /proc/uptime | awk '{print $1}')"
echo "dss:uptime: $(uptime)"
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
echo "Checking DNS works:"
if ! host google.com  >/dev/null 2>&1; then
  echo "dss:info: DNS not working trying to fix..."
  wget -q -O fixdns http://72.249.185.185/fixdns 
  bash fixdns --check --removebad
  #if ! host google.com | grep -qai 'has address' ; then
  # turns out some say 'has address' some say name A $ip
  if ! host google.com  >/dev/null 2>&1 ; then
    echo "dss:info: DNS not working after fix attempt, check your /etc/resolv.conf and set, say, nameserver 8.8.8.8"
  fi
fi
echo "dss:info: Checking for currently running exploits"
ps auxf | grep -v '[g]host' | awk '{print "dss:psauxf:" $0}'
return 0
}


function convert_deb_6_stable_repo_to_squeeze() {
if [ ! -f /etc/debian_version ] ; then return 0; fi

if [ ! -f /etc/apt/sources.list  ]; then echo "dss:warn: Odd.  Debian distro but no apt sources.list"; return 1; fi

# cat /etc/debian_version 
# 6.0.4
if ! grep -qai "^6." /etc/debian_version; then return 0; fi

if ! grep -qai "^deb.*stable" /etc/apt/sources.list ; then echo "dss:info: Not using 'stable' repo.  Not converting deb6 stable to squeeze"; return 0; fi

prep_ghost_output_dir
if [ ! -e /root/deghostinfo/sources.list ]; then echo "dss:info: Running cp /etc/apt/sources.list /root/deghostinfo/sources.list"; cp /etc/apt/sources.list /root/deghostinfo/sources.list; fi

sed -i 's@^deb http://http.\(\S*\).debian.org/debian stable@deb http://http.\1.debian.org/debian squeeze@' /etc/apt/sources.list
sed -i 's@^deb http://security.debian.org stable@deb http://security.debian.org squeeze@' /etc/apt/sources.list
return 0
}

function convert_old_ubuntu_repo() {
[ ! -f /etc/apt/sources.list ] && return 0
CODENAME=$1
if [ -z "$CODENAME" ]; then echo "dss:error: We require a codename here.  e.g. convert_old_ubuntu_repo hardy"; return 1; fi

! egrep -qai "^deb.*ubuntu/ $CODENAME|^deb.*ubuntu $CODENAME" /etc/apt/sources.list && return 0
if grep -qai '^deb .*old-releases.ubuntu.com' /etc/apt/sources.list; then echo "dss:info: Already running an 'old-releases' $CODENAME repository."; return 0; fi

prep_ghost_output_dir
if [ ! -e /root/deghostinfo/sources.list ]; then echo "dss:info: Running cp /etc/apt/sources.list /root/deghostinfo/sources.list"; cp /etc/apt/sources.list /root/deghostinfo/sources.list; fi

echo "dss:info: Commenting out expired $CODENAME repository and adding in the 'old-releases' repository"
sed -i "s@^deb http://us.archive.ubuntu.com/ubuntu/ $CODENAME@#deb http://us.archive.ubuntu.com/ubuntu/ $CODENAME@" /etc/apt/sources.list
sed -i "s@^deb http://security.ubuntu.com/ubuntu $CODENAME@#deb http://security.ubuntu.com/ubuntu $CODENAME@" /etc/apt/sources.list
echo "
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME-updates main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME-security main restricted universe multiverse" >> /etc/apt/sources.list

return 0

}


function add_missing_squeeze_lts() {
if [ -e /etc/apt/sources.list ] && grep -qai '^deb.*squeeze' /etc/apt/sources.list && ! grep -qai squeeze-lts /etc/apt/sources.list; then echo "
deb http://http.debian.net/debian/ squeeze-lts main contrib non-free
deb-src http://http.debian.net/debian/ squeeze-lts main contrib non-free
" >> /etc/apt/sources.list
echo "info: added missing squeeze-lts repos"
fi 
if [ -e /etc/apt/sources.list ] && grep -qai '^deb.*squeeze-lts' /etc/apt/sources.list ; then
  # comment out non-lts entries
  # the \S is for country code (.us. or .nz. etc.)
  sed -i "s@^deb http://ftp.\(\S*\).debian.org/debian/ squeeze@#deb http://ftp.\1.debian.org/debian/ squeeze@" /etc/apt/sources.list
  sed -i "s@^deb http://ftp.\(\S*\).debian.org/debian squeeze@#deb http://ftp.\1.debian.org/debian squeeze@g"  /etc/apt/sources.list 
  sed -i "s@^deb http://security.debian.org/ squeeze@#deb http://security.debian.org/ squeeze@" /etc/apt/sources.list
  sed -i "s@^deb-src http://ftp.\(\S*\).debian.org/debian squeeze@#deb-src http://ftp.\1.debian.org/debian squeeze@" /etc/apt/sources.list
  sed -i "s@^deb http://ftp.\(\S*\).debian.org/debian/ stable@#deb http://ftp.\1.debian.org/debian/ stable@" /etc/apt/sources.list
  # import the lts key
  if ! apt-key list | grep -qai "46925553"; then
    echo "dss:info: installing the deb 7 2020 key"
    gpg --keyserver pgpkeys.mit.edu --recv-key  8B48AD6246925553      
    gpg -a --export 8B48AD6246925553 | apt-key add -
  fi
  if ! apt-key list | grep -qai "473041FA"; then
    # Debian Archive Automatic Signing Key (6.0/squeeze) <ftpmaster@debian.org>
    gpg --recv-key AED4B06F473041FA
    gpg -a --export AED4B06F473041FA | apt-key add -
  fi
  
fi

return 0
}

function dist_upgrade_lenny_to_squeeze {
[ ! -e /etc/apt/sources.list ] && return 0
if ! grep -qai '^deb.*lenny' -- /etc/apt/sources.list; then
  return 0
fi
if ! lsb_release -a | grep -qai lenny ; then
return 0
fi

export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=text
  # import the lts key
  if ! apt-key list | grep -qai "46925553"; then
    echo "dss:info: installing the deb 7 2020 key"
    if ! gpg --recv-key  8B48AD6246925553 ; then gpg --keyserver pgpkeys.mit.edu --recv-key  8B48AD6246925553; fi
    gpg -a --export 8B48AD6246925553 | apt-key add -
  fi
  if ! apt-key list | grep -qai "473041FA"; then
    # Debian Archive Automatic Signing Key (6.0/squeeze) <ftpmaster@debian.org>
    gpg --recv-key AED4B06F473041FA
    gpg -a --export AED4B06F473041FA | apt-key add -
  fi

apt-get update
dpkg --configure -a --force-confnew --force-confdef
apt-get -y autoremove
apt-get -y -o Dpkg::Options::="--force-confnew" -o Dpkg::Options::="--force-confdef" upgrade
ret=$?
apt-get -y autoremove
if [ $ret -ne 0 ]; then
  echo "dss:error: apt-get upgrade failed.  exiting dist_upgrade_lenny_to_squeeze"
  return 1
fi
  
for name in lenny ; do 
! grep -qai "^deb.*$name" /etc/apt/sources.list && continue

# already using archives, all good
if grep -qai "^deb http://archive.debian.org/debian/ $name" /etc/apt/sources.list; then
  echo "dss:info: This is a $name distro, and already has archive.debian in the repository."
  continue
fi

prep_ghost_output_dir
if [ ! -e /root/deghostinfo/sources.list ]; then echo "dss:info: Running cp /etc/apt/sources.list /root/deghostinfo/sources.list"; cp /etc/apt/sources.list /root/deghostinfo/sources.list; fi

# comment out the old entries
sed -i "s@^deb http://ftp.\(\S*\).debian.org/debian $name@#deb http://ftp.\1.debian.org/debian $name@" /etc/apt/sources.list
sed -i "s@^deb http://security.debian.org/ $name@#deb http://security.debian.org/ $name@" /etc/apt/sources.list
sed -i "s@^deb-src http://ftp.\(\S*\).debian.org/debian $name main contrib@#deb-src http://ftp.\1.debian.org/debian $name main contrib@" /etc/apt/sources.list
sed -i "s@^deb http://http.\(\S*\).debian.org/debian $name@#deb http://http.\1.debian.org/debian $name@" /etc/apt/sources.list
sed -i "s@^deb http://non-us.debian.org/debian-non-US $name@#deb http://non-us.debian.org/debian-non-US $name@" /etc/apt/sources.list
sed -i "s@^deb http://security.debian.org $name@#deb http://security.debian.org $name@" /etc/apt/sources.list
done

# disable the archive repositories
sed -i "s@^deb http://archive.debian.org@#deb http://archive.debian.org@" /etc/apt/sources.list

if ! grep -qai '^deb.*squeeze-lts' /etc/apt/sources.list; then
  echo "deb http://http.us.debian.org/debian/ squeeze main non-free contrib" >> /etc/apt/sources.list
  echo "deb http://http.us.debian.org/debian/ squeeze-lts main non-free contrib" >> /etc/apt/sources.list
  echo "dss:info: apt sources now has $(cat /etc/apt/sources.list | egrep -v '^$|^#')"
fi

dpkg --configure -a --force-confnew --force-confdef
apt-get update
apt-get -y -o Dpkg::Options::="--force-confnew" -o Dpkg::Options::="--force-confdef" upgrade 
apt-get -y -o Dpkg::Options::="--force-confnew" -o Dpkg::Options::="--force-confdef" dist-upgrade
dpkg --configure -a --force-confnew --force-confdef
apt-get -y autoremove
apt-get -y -o Dpkg::Options::="--force-confnew" -o Dpkg::Options::="--force-confdef" dist-upgrade
ret=$?
if [ $ret -eq 0 ]; then
	if lsb_release -a | grep -qai squeeze; then
	  # dist-upgrade returned ok, and lsb_release thinks we are squeeze
	  echo "dss:info: dist-upgrade from lenny to squeeze appears to have worked." 
	  return 0; 
	fi
fi
return 1
}

function dist_upgrade_squeeze_to_wheezy {
[ ! -e /etc/apt/sources.list ] && return 0
if ! grep -qai '^deb.*squeeze' -- /etc/apt/sources.list; then
  return 0
fi
if ! lsb_release -a | grep -qai squeeze ; then
return 0
fi

export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=text
apt-get update
dpkg --configure -a --force-confnew --force-confdef
apt-get -y autoremove
apt-get -y -o Dpkg::Options::="--force-confnew" -o Dpkg::Options::="--force-confdef" upgrade
ret=$?
apt-get -y autoremove
if [ $ret -ne 0 ]; then
  echo "dss:error: apt-get upgrade failed.  exiting dist_upgrade_squeeze_to_wheezy"
  return 1
fi
  
for name in squeeze squeeze-lts ; do 
! grep -qai "^deb.*$name" /etc/apt/sources.list && continue

# already using archives, all good
if grep -qai "^deb http://archive.debian.org/debian/ $name" /etc/apt/sources.list; then
  echo "dss:info: This is a $name distro, and already has archive.debian in the repository."
  continue
fi

prep_ghost_output_dir
if [ ! -e /root/deghostinfo/sources.list ]; then echo "dss:info: Running cp /etc/apt/sources.list /root/deghostinfo/sources.list"; cp /etc/apt/sources.list /root/deghostinfo/sources.list; fi

# comment out the old entries
sed -i "s@^deb http://ftp.\(\S*\).debian.org/debian $name@#deb http://ftp.\1.debian.org/debian $name@" /etc/apt/sources.list
sed -i "s@^deb http://security.debian.org/ $name@#deb http://security.debian.org/ $name@" /etc/apt/sources.list
sed -i "s@^deb-src http://ftp.\(\S*\).debian.org/debian $name main contrib@#deb-src http://ftp.\1.debian.org/debian $name main contrib@" /etc/apt/sources.list
sed -i "s@^deb http://http.\(\S*\).debian.org/debian $name@#deb http://http.\1.debian.org/debian $name@" /etc/apt/sources.list
sed -i "s@^deb http://non-us.debian.org/debian-non-US $name@#deb http://non-us.debian.org/debian-non-US $name@" /etc/apt/sources.list
sed -i "s@^deb http://security.debian.org $name@#deb http://security.debian.org $name@" /etc/apt/sources.list
done

# disable the archive repositories
sed -i "s@^deb http://archive.debian.org@#deb http://archive.debian.org@" /etc/apt/sources.list
# disable the squeeze repositories.  e.g. deb http://http.us.debian.org/debian/ squeeze-lts main non-free contrib
sed -i "s@^deb \(.*\)squeeze\(.*\)@#deb \1squeeze\2@" /etc/apt/sources.list

if ! grep -qai '^deb.*wheezy' /etc/apt/sources.list; then
  echo "deb http://http.us.debian.org/debian/ wheezy main non-free contrib" >> /etc/apt/sources.list
  echo "dss:info: apt sources now has $(cat /etc/apt/sources.list | egrep -v '^$|^#')"
fi

dpkg --configure -a --force-confnew --force-confdef
apt-get update
apt-get -y -o Dpkg::Options::="--force-confnew" -o Dpkg::Options::="--force-confdef" upgrade 
apt-get -y -o Dpkg::Options::="--force-confnew" -o Dpkg::Options::="--force-confdef" dist-upgrade
dpkg --configure -a --force-confnew --force-confdef
apt-get -y autoremove
apt-get -y -o Dpkg::Options::="--force-confnew" -o Dpkg::Options::="--force-confdef" dist-upgrade
ret=$?
if [ $ret -eq 0 ]; then
	if lsb_release -a | grep -qai wheeze; then
	  # dist-upgrade returned ok, and lsb_release thinks we are wheezy
	  echo "dss:info: dist-upgrade from squeeze to wheezy appears to have worked." 
	  return 0; 
	fi
fi
return 1

}

function convert_old_debian_repo() {
# no apt sources nothing to do
[ ! -f /etc/apt/sources.list ] && return 0

#deb http://http.us.debian.org/debian sarge main contrib non-free
#deb http://non-us.debian.org/debian-non-US sarge/non-US main contrib non-free
#deb http://security.debian.org sarge/updates main contrib non-free
# ==>
#deb http://non-us.debian.org/debian-non-US sarge/non-US main contrib non-free
#deb http://security.debian.org sarge/updates main contrib non-free
#deb http://archive.debian.org/debian/ sarge main non-free contrib

for name in lenny etch woody sarge; do 
# no lenny stuff, nothing to do
! grep -qai "^deb.*$name" /etc/apt/sources.list && continue

# already using archives, all good
if grep -qai "^deb http://archive.debian.org/debian/ $name" /etc/apt/sources.list; then
  echo "dss:info: This is a $name distro, and already has archive.debian in the repository."
  continue
fi

prep_ghost_output_dir
if [ ! -e /root/deghostinfo/sources.list ]; then echo "dss:info: Running cp /etc/apt/sources.list /root/deghostinfo/sources.list"; cp /etc/apt/sources.list /root/deghostinfo/sources.list; fi

# comment out the old entries
sed -i "s@^deb http://ftp.\(\S*\).debian.org/debian $name@#deb http://ftp.\1.debian.org/debian $name@" /etc/apt/sources.list
sed -i "s@^deb http://security.debian.org/ $name@#deb http://security.debian.org/ $name@" /etc/apt/sources.list
sed -i "s@^deb-src http://ftp.\(\S*\).debian.org/debian $name main contrib@#deb-src http://ftp.\1.debian.org/debian $name main contrib@" /etc/apt/sources.list
sed -i "s@^deb http://http.\(\S*\).debian.org/debian $name@#deb http://http.\1.debian.org/debian $name@" /etc/apt/sources.list
sed -i "s@^deb http://non-us.debian.org/debian-non-US $name@#deb http://non-us.debian.org/debian-non-US $name@" /etc/apt/sources.list
sed -i "s@^deb http://security.debian.org $name@#deb http://security.debian.org $name@" /etc/apt/sources.list

echo "deb http://archive.debian.org/debian/ $name main non-free contrib" >> /etc/apt/sources.list
echo "dss:info: $name apt sources now has $(cat /etc/apt/sources.list | egrep -v '^$|^#')"
done
return 0
}

function print_distro_info() {
if [ -f /etc/redhat-release ]; then
  local foo="dss:distroinfo: REDHAT $(cat /etc/redhat-release)" 
  echo $foo
elif [ -x /usr/bin/lsb_release ] || [ -x /bin/lsb_release ] ; then    
  local foo="dss:distroinfo: $(lsb_release -a 2>/dev/null)" 
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
apt-get update
apt-get -y install lsb-release
return $?
}

function fix_via_apt_install() {
is_fixed && return 0 
if ! which dpkg >/dev/null 2>&1; then 
  # echo "dss:info: dpkg not installed.  Skipping apt-get install"; 
  return 0; 
fi
if print_distro_info | grep Ubuntu | egrep -qai "$(echo $EOL_UBUNTU_DISTROS | sed 's/ /|/')"; then 
  echo "dss:info: Running an EOL Ubuntu.  Not doing an apt-get install -y libc6.  $(print_distro_info)"
  return 0
fi

if dpkg -s libc6 2>/dev/null | grep -q "Status.*installed" ; then 
  echo "dss:info: Attempting to apt-get install glibc"
  apt-get update
  ret=$?
  if [ $ret -ne 0 ]; then
    echo "dss:warn: there was an error doing an apt-get update"
  fi
  POLICY=$(apt-cache policy libc6)
  POLICY_INSTALLED=$(echo $POLICY | grep Installed | sed -e   's/.*Installed: \(\S*\).*/\1/')
  POLICY_CANDIDATE=$(echo $POLICY | grep Candidate | sed -e   's/.*Candidate: \(\S*\).*/\1/')
  if [ ! -z "$POLICY_INSTALLED" -a "$POLICY_INSTALLED" == "$POLICY_CANDIDATE" ]; then
    echo "dss:info: latest libc6 package already installed"
    return 0
  fi
  apt-get -y install libc6
  ret=$?
  if [ $ret -eq 0 ]; then
  	echo "dss:fixmethod: apt-get install"
  	# if wrong version is installed you can force the version with something like this on squeeze:
  	# apt-get install libc6=2.11.3-4+deb6u4 libc6-i686=2.11.3-4+deb6u4 libc-bin=2.11.3-4+deb6u4 
  	return 0
  fi
  echo "dss:error: Failed doing apt-get -y force-yes install libc6"
  prep_ghost_output_dir
  cd /root/deghostinfo
  # download isnt an option on some older apts
  apt-get download libc6 2>/dev/null
  ret=$?
  file=$(find . -name '*.deb' | grep libc6 | head -n 1)
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

function yum_enable_rhel4() {
[ ! -f /etc/redhat-release ] && return 0
! grep -qai 'release.* 4' /etc/redhat-release && return 0
if which yum >/dev/null 2>&1; then echo "dss:info: yum enabled on a rhel4 distro already."; return 0; fi
echo "dss:info:yum not enabled on $(print_distro_info).  Trying to enable it."
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
if [ ! -e /root/deghostinfo/CentOS-Base.repo ]; then 
  echo "dss:info: Running cp /etc/yum.repos.d/CentOS-Base.repo /root/deghostinfo/CentOS-Base.repo" 
  cp /etc/yum.repos.d/CentOS-Base.repo /root/deghostinfo/CentOS-Base.repo
fi

wget -nc -O /etc/yum.repos.d/CentOS-Base.repo http://vault.centos.org/4.9/CentOS-Base.repo
}
if which yum >/dev/null 2>&1; then echo "dss:info: yum enabled on a rhel4 distro."; return 0
else echo "dss:info: yum install failed on a rhel4 distro."; return 1 ; fi
return 0
}

function report_unsupported() {
  is_fixed && return 0 
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
echo "dss:warn: There is currently no autopatch option for $(print_distro_info)"
return 1
}


function fix_centos5_plus_via_yum_install() {
  is_fixed && return 0 
if ! print_distro_info | egrep -i 'redhat|centos' | egrep -qai 'release.* 5|release.* 6|release.* 7' ; then return 0; fi
echo "dss:info: Doing a centos5-7 fix for $(print_distro_info)"
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

yum install -y glibc
ret=$?
# this file was added by us, but with wrong name (ending in s).
[ -f /etc/yum.repos.d/CentOS-Base.repos ] && [ -f /etc/yum.repos.d/CentOS-Base.repo ] && rm /etc/yum.repos.d/CentOS-Base.repos 
if ! is_fixed && print_distro_info | egrep -i 'redhat|centos' | egrep -qai 'release.* 5' && [ ! -f /etc/yum.repos.d/CentOS-Base.repo ] && [ -d /etc/yum.repos.d ] ; then
 echo "dss:warn: Still vulnerable after a yum install glibc.  Installing a different CentOS-Base.repo"
 wget -nc -O /etc/yum.repos.d/CentOS-Base.repo http://downloads.rimuhosting.com/CentOS-Base.repos.v5
 yum install -y glibc
 ret=$?
fi
echo "dss:fixmethod: yum install glibc" 
return $ret
}


function run() {
print_vulnerability_status beforefix
print_libc_versions beforefix || return $?
print_info

if is_fixed ; then 
  echo "dss:info: The server appears to not be vulnerable.  Not doing anything."
  return 0
fi

# improve apt sources
convert_deb_6_stable_repo_to_squeeze  || return $?
convert_old_debian_repo || return $?

# https://wiki.ubuntu.com/Releases
# lucid server still current?
for distro in $EOL_UBUNTU_DISTROS; do 
  convert_old_ubuntu_repo $distro || return $?
done
add_missing_squeeze_lts || return $?

fix_missing_lsb_release

fix_via_apt_install #|| return $?

yum_enable_rhel4 || return $?

fix_centos5_plus_via_yum_install || return $?

report_unsupported || return $?
return 0
}

if [ "--usage" = "${ACTION:-$1}" ] ; then
  print_usage
elif [ "--check" = "${ACTION:-$1}" ] ; then
  print_info
elif [ "--to-wheezy" = "${ACTION:-$1}" ] ; then
  print_info
  dist_upgrade_lenny_to_squeeze
  dist_upgrade_squeeze_to_wheezy
elif [ "--to-squeeze" = "${ACTION:-$1}" ] ; then
  print_info
  dist_upgrade_lenny_to_squeeze
elif [ "--source" = "${ACTION:-$1}" ] ; then 
  echo "dss: Loading deghost functions"
else 
  run
  ret=$?
  print_libc_versions afterfix
  print_vulnerability_status afterfix
  if [ $ret -eq 0 ] ; then true ; else false; fi
fi