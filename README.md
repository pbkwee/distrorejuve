# deghost
deghost is a cross-distro script to determine the vulnerability of a libc library to the ghost exploits (CVE-2015-0235) and then patch that where possible.

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
