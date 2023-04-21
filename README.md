# distrorejuve

## Summary
distrorejuve is a utility that helps with upgrading distros. It works on a number of different distros (Ubuntu, 
Debian, Centos). It uses apt, yum and repository corrections as appropriate. It can dist upgrade between 
multiple versions for Ubuntu and Debian.  It can convert (some) distros from 32bit to 64 bit (a cross grade).

If you are using the script to make changes, please take a full backup first.

Example usage to download the latest version of the script, then dist upgrade to latest Debian or Ubuntu disto. 

```bash
wget -O distrorejuve.sh --no-check-certificate https://raw.githubusercontent.com/pbkwee/distrorejuve/master/distrorejuve.sh

sudo nohup bash -x distrorejuve.sh --dist-upgrade 2>&1 | tee -a distrorejuve.log | egrep -v '^\\+'
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
* `--to-latest-debian` to get from squeeze or lenny or wheezy or jessie or stretch or buster to bullseye 11
* `--to-debian-release [6-11]` to get from your current version to the specified version
* `--to-latest-lts` to get from an ubuntu distro to the most recent ubuntu lts version
* `--to-next-ubuntu` to get from an ubuntu distro to the next ubuntu version.  If the current ubuntu is an LTS version then this skips to the next LTS version.
* `--fix-vuln` to try and fix your server (doing minimal change e.g. just an apt-get install of the affected package).
* `--break-eggs` will run a `--dist-upgrade` if the server is vulnerable.
* `--pause` to pause a distro rejuve running process (`touch ~/distrorejuve.pause`).  Triggers 30s sleeps at key points in the script.
* `--resume` to resume a paused distro rejuve running process (`rm -f ~/distrorejuve.pause`)

Use with `--source` if you just wish to have the distrorejuve functions available to you for testing

## Notes

Written by Peter Bryant at http://launchtimevps.com

Latest version (or thereabouts) will be available at https://github.com/pbkwee/distrorejuve
