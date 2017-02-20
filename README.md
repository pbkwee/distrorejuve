#deghost

deghost is a utility that helps with upgrading distros.  It works on a number of different distros (Ubuntu, Debian, Centos). It uses apt, yum and repository corrections as appropriate.  It can dist upgrade between multiple versions for Ubuntu and Debian.

Example usage to dist upgrade to latest Debian or Ubuntu disto.  First make a backup of your server.  Then run:

wget -O deghost.sh --no-check-certificate https://raw.githubusercontent.com/pbkwee/deghost/master/deghost.sh

sudo bash deghost.sh --dist-upgrade | tee -a deghost.log

Uses:
- Enable archive repositories for older Debian distros
- Enable lts archive for Debian squeeze servers and old-releases for Ubuntu
- Dist upgrade Ubuntu distros to the next LTS version.  Then from LTS version to LTS version.
- On completion provides information on config changes (modified config files, changed ports)
- Install missing Debian keys
- Handles a few common Apache config issues after a distro upgrade.
- Designed to run unattended without lots of prompting.

Arguments:
  
Run with --usage to get this message

Run with --dist-upgrade run an upgrade, followed by dist-upgrading ubuntu distros to the latest lts or debian distros to jessie.

Run with --upgrade to run a yum upgrade or apt-get upgrade (fixing up repos, etc where we can).

Run with --to-wheezy to get from squeeze to wheezy

Run with --to-jessie to get from squeeze or lenny or wheezy to jessie (8)

Run with --to-latest-lts to get from an ubuntu distro to the most recent ubuntu lts version

Use with --source if you just wish to have the functions available to you for testing

Run with --check (or no argument) if you just wish to check, but not change your server

Run with --break-eggs to dist upgrade Debian lenny (unsupported) or squeeze (supported) to wheezy (latest).  Note caveats above.

Run with --break-eggs to dist upgrade any ubuntu to the latest LTS.  Note caveats above.

Run with --fix-vuln to try and fix your server (doing minimal change e.g. just an apt-get install of the affected package).
    
Not supported: RHEL4, WBEL3, RH9, Debian 4.

Written by Peter Bryant at http://launchtimevps.com

Latest version (or thereabouts) will be available at https://github.com/pbkwee/deghost
