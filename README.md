# deghost
deghost is a cross-distro script to determine the vulnerability of a libc library to the ghost exploits (CVE-2015-0235) and then patch that where possible.

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
        
Potential improvements to come:

    - Lenny.  Need to patch?  Maybe use squeeze .deb? (vs. the whole --break-eggs dist upgrade)
  
  Use with --source if you just wish to have the functions available to you for testing
  
  Run with --check if you just wish to check, but not change your server
  
  Run with --break-eggs to dist upgrade Debian lenny (unsupported) or squeeze (supported) to wheezy (latest).  Note caveats above.
  
  Run with --break-eggs to dist upgrade any ubuntu to the latest LTS.  Note caveats above.
  
  Run with --usage to get this message
  
  Run without an argument to try and fix your server
  
  Written by Peter Bryant at http://launchtimevps.com
  
  Latest version (or thereabouts) will be available at https://github.com/pbkwee/deghost
