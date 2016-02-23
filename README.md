#deghost

deghost is a cross-distro script to determine the vulnerability of a libc library to the ghost exploits (CVE-2015-0235 or CVE-2015-7547) and then patch that where possible.

deghost works on a number of different distros. It uses apt, yum and repository corrections as appropriate.

See also http://rimuhosting.com/maintenance.jsp?server_maint_oid=195331653

Attempts to fix:

    - Debian 7 => apt-get install
    - Debian 6 => fix up apt repositories for squeeze-lts and then apt-get install
    - Supported Ubuntus (12.04 LTS, 14.04 LTS, 14.10) => apt-get install
    - Lenny (Deb 5), or any Ubuntu use the --break-eggs options to dist-upgrade to Wheezy or Trusty LTS.  This will likely 
        not work automatically, may leave you in dependency hell, and will likely change configs in ways you wish it hadn't.
        
Attempts to improve the situation:.
        
    - Unsupported Ubuntus (others per UNSUPPORTED_UBUNTU variable) => convert to old-releases.ubuntu.com
    
No action available for the following (and older) distros:
    
    - RHEL4, WBEL3, RH9, Debian 4 => nothing
        
Arguments:
  
Use with --source if you just wish to have the functions available to you for testing

Run with --check if you just wish to check, but not change your server (default)

Run with --fix_vuln if you want the script to install the patched software

Run with --break-eggs to dist upgrade Debian lenny (unsupported) or squeeze (supported) to wheezy (latest).  Note caveats above.

Run with --break-eggs to dist upgrade any ubuntu to the latest LTS.  Note caveats above.

Run with --usage to get this message

Run with --to-wheezy to get from squeeze to wheezy

Run with --to-jessie to get from squeeze or lenny or wheezy to jessie (8)

Run with --to-latest-lts to get from an ubuntu distro to the most recent ubuntu lts version

Run with --upgrade to run a yum upgrade or apt-get upgrade (fixing up repos, etc where we can).

Run with --dist-upgrade run an upgrade, followed by dist-upgrading ubuntu distros to the latest lts or debian distros to jessie.

Run without an argument to try and fix your server

Written by Peter Bryant at http://launchtimevps.com

Latest version (or thereabouts) will be available at https://github.com/pbkwee/deghost

