# Migration inventory

Capture the manifest before planning an upgrade or reinstall:

```sh
bash distrorejuve.sh --manifest
bash distrorejuve.sh --manifest-json > manifest.json
```

To prepare a manifest for public discussion, add `--redact`:

```sh
bash distrorejuve.sh --manifest --redact > manifest-public.txt
bash distrorejuve.sh --manifest-json --redact > manifest-public.json
```

This replaces hostnames, IP addresses, website names and URLs, paths, account names,
FPM pool/socket names, process names and proxy destinations with `[redacted]`.
Website and application records remain, including software versions, service state,
ports, TLS/certificate-file status, DNS results, counts and collection warnings.
Unknown or empty identifier values remain unknown or empty. New fields are redacted
unless explicitly approved as general information. Unmatched website handlers are
redacted because they may contain a path or a customer-defined name.
The same replacement marker is used throughout; it does not identify or link sites.

Review the result before posting. Versions, counts and combinations of configuration
facts can still distinguish a system. Redaction changes output only: it does not
reduce what the collector reads, disable DNS queries, sanitize existing files or
upload anything. Keep normal manifests, upgrade reports and logs private.
Upgrade comparison snapshots retain their full detail.

The manifest can run as a non-privileged user. See [manifest privileges](manifest.md)
for the differences in service checks, listener details, mail measurements and file access.

Upgrade/removal commands, pause/resume, `--show-changes` (which writes a snapshot)
and `--list-leftover-packages` (which can install a helper) require root outside reduced mode.
`--check-upgrade` works in reduced mode. It ignores repair and skip overrides, reports blockers, and never changes packages or configuration.
`--upgrade-report` also permits reduced collection, within its existing APT/dpkg scope.

DNS checks report whether website domains resolve to this server.

The manifest supports Debian/Ubuntu package databases and RPM-based systems such as
CentOS, RHEL, Rocky and AlmaLinux. It preserves distribution package versions,
including RPM epochs/releases and architecture. PHP CLI, FPM, Apache module and
extension packages are listed separately. Common RPM Apache, Remi and SCL PHP
configuration paths are included. Runtime associations are inferred from package
ownership and configuration. Check live processes separately to identify their loaded code.

## Lighttpd workload mapping

Lighttpd is recognized in package, service and listener records. Website mapping
starts at `/etc/lighttpd/lighttpd.conf` and follows only literal includes within
the resolved `/etc/lighttpd` tree, including literal glob patterns. A file in
`conf-enabled` is included only if the inspected configuration references it.
The collector never runs lighttpd, an application or `include_shell` to obtain
generated configuration. Custom active configuration paths, generated includes,
variables, chroot paths, aliases, rewrites and unmodelled modules produce
explicit gaps; their runtime mapping remains unknown.

The supported subset retains nested host, URL and socket conditions, inherited
document roots, users, ports, TLS flags, literal redirects and CGI, FastCGI,
SCGI or reverse-proxy backends. `lighttpd_site` records retain configuration
scope, selector kind and ancestor conditions. Regexes and URL conditions are
routing evidence, not literal hostnames for DNS queries. `website_handler`
records identify configured executable/interpreter paths and backend endpoints;
they omit command arguments, environment settings and authentication values.
Redirect targets omit user information, query strings and fragments.

FastCGI endpoints are matched to known FPM pools. PHP version evidence comes
from the matching pool, rather than the shell's default PHP. Multiple matching
pools leave the version unknown. Other configured launchers can be associated
with a shebang and the installed package owning that interpreter; an `env`
wrapper identifies a language without proving an interpreter version. A handler
record describes configured execution, not a successful request to the app.

`web_frontend` records use process status metadata to find lighttpd, retain only
its literal `-f` path from `/proc/PID/cmdline`, and extract module basenames from
`/proc/PID/maps`. Other arguments and map fields are omitted. A matching process
configuration does not prove that each site is live or that files changed on
disk have been loaded. An unreadable or different active configuration requires
review. Service inventory also distinguishes exited systemd daemon wrappers
with no main PID from observed running processes.

`web_asset_root` records retain document-root paths and resolved symlink targets
needed by public assets. Conventional application markers in the root or its
nearest three ancestors produce `application_context` evidence. Retained Rails,
PHP or Python files do not establish that the associated application is running.
Top-level script filenames are sampled as `web_file` records without reading
their contents. A script served by a complete static-only configuration is a
file download; its extension does not make it an executing backend. Installed
runtime packages likewise do not prove website use.

Website and application activity remain unknown until supported by separate
request/runtime evidence. Preserve live routes and required assets, and keep
inactive applications inactive; see the [migration defaults](upgrade-and-migration.md).
Unknown activity does not authorize disabling a site or deleting retained data.

Lighttpd configuration collection is bounded to 200 files, 16 include levels,
256 KiB per file, 2 MiB total and a five-second token scan; the parser has a
separate ten-second limit. It rejects include cycles and paths escaping the
configuration tree. Asset sampling retains at most 20 top-level script paths
per distinct document root. Handler scripts are inspected only for a bounded
first-line shebang, and are never executed. These reads still require the
job's sensitive-data permission for configuration, selected process metadata
and any script metadata; output redaction does not grant permission to read.

## Other inventory coverage

Mail-storage discovery covers these standard layouts:

| Hosting panel/layout | Mail storage |
| --- | --- |
| Plesk | `/var/qmail/mailnames` and the configured `PLESK_MAILNAMES_D` |
| ISPConfig and CWP | `/var/vmail` |
| CyberPanel | `/home/vmail` |
| aaPanel | `/www/vmail` |
| KeyHelp and other Postfix virtual-mail layouts | `/var/mail`, including `/var/mail/vhosts` |
| Froxlor | `/var/customers/mail` |
| cPanel, HestiaCP and VestaCP | `/home/USER/mail` when the panel installation is present |
| DirectAdmin | `/home/USER/imap` when installed, plus account `Maildir` directories |
| Virtualmin/Webmin | Account `Maildir`/`.Maildir`, legacy `mail` when Virtualmin is present, nested `homes/USER` mailboxes and subserver layouts under `domains/DOMAIN` |
| InterWorx | `/home/USER/var/DOMAIN/mail` when installed |
| Conventional local delivery | `/var/mail`, `/var/spool/mail`, `/root/Maildir` and `/root/.Maildir` |

Account discovery also checks numbered home partitions such as `/home2` and `/home10`.
Literal paths from common Postfix, Dovecot (including `/etc/dovecot.conf` and KeyHelp
fragments), Courier and Plesk configuration are reported too. These follow layouts
such as [DirectAdmin mail storage](https://docs.directadmin.com/other-hosting-services/webmail/),
[InterWorx account storage](https://appendix.interworx.com/current-7/getting_started/introduction_to_interworx/siteworx_101/introduction_to_siteworx.html)
and [KeyHelp storage paths](https://kb.keyhelp.de/print-119.html).

Mail-storage collection never reads message contents or changes mail. Sizes use
bounded metadata scans: at most eight mail stores, three seconds per size probe,
and 20 account mail directories.
Empty conventional roots are omitted and aliases to the same directory are deduplicated.
Both the literal path and resolved symlink target must be recognised narrow mail
locations before measuring. Custom paths can therefore be reported with unknown
size. Keep mailbox size unknown until the missing measurements are completed.

Potential compromise indicators appear as `security_indicator` records in text and JSON.
Process collectors validate the requested numeric columns and names even when
`ps` exits successfully. Empty, header-only, PID-only and malformed snapshots
produce warnings and mark core collection incomplete. The name collector can
fall back to bounded `/proc/PID/status` Name/Pid metadata, without arguments or
environment reads. Partial name coverage can establish an observed process;
absence leaves activity unknown. Indicator collection keeps positive findings
from valid rows while reporting malformed rows as a coverage gap; it never
reports a malformed snapshot as a clean security result.
The process check flags shell redirection or `tee` targeting sudoers, Base64 decoding
piped to a shell, kernel-thread-style names with a nonzero UID or userspace memory,
and executable or interpreter-script paths under `/tmp`, `/var/tmp` or `/dev/shm`.
It also flags download-tool commands piped to a shell, mining protocol URLs and
correlated mining algorithm, pool and user options. Authorized maintenance and
mining can match; endpoints, credentials and command bodies are omitted.
Dot-prefixed listener names also get a review record.
The kernel executable-link check also catches temporary binaries hidden behind altered
process names, executables in hidden system binary/library directories, and deleted
executables in home, application-state or temporary directories. It reports
counts and sample PIDs without executable pathnames; ordinary deleted system binaries
are omitted because package updates commonly replace them. The probe is limited to
five seconds and 20000 links; permissions or process exits can leave gaps.
See the [Linux executable-link documentation](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html).
Groups of at least 20 Webmin workers sharing a parent and UID get a concurrency
review hint. Compare sessions and logs with expected activity to determine the cause.

Website files and scheduled jobs are checked for possible signs of compromise.
Website sampling includes WordPress plugin directories within the shared file and
time limits. Scheduled checks also flag execution from hidden directories under
home, application-state and system binary/library paths, and downloads piped to a shell.
Checks are read-only, and reports omit file contents and raw commands.

Findings need review because legitimate activity can trigger them and some problems
may be missed. Warnings indicate incomplete coverage. A report without findings
means the selected checks found no matches in their scanned scope; assess remaining
security risks separately. These observations are excluded from before/after
configuration comparisons.

Migration hints include local program and service paths, cron files and custom timer
paths, selected local user IDs/groups/homes/shells, and configured mount targets and
filesystem types. Service, cron and timer files whose contents match their installed
package are omitted, including routine systemd links to unchanged vendor units.
Package backup files (`.dpkg-*`, `.ucf-*`, `.rpmnew`, `.rpmsave`, `.rpmorig`, `~`),
cron placeholders and SysV dependency metadata are omitted. Routine boot/console,
legacy OS logging and file-indexing scripts are also omitted unless package checks
confirm local content changes. These filters affect migration hints only; security
indicator scans still examine their existing paths.
Other customer edits, unowned files and unknown ownership remain visible, including
stopped or disabled application services and custom jobs that may need migration.
Nonexecutable periodic cron jobs remain visible because removing execute permission
can disable a package job. Other permission/owner changes are not checked.
Unverifiable files, other symlinks and files over 1 MiB remain for manual review.
Ownership-query failures produce one summary warning with a count; affected paths
retain `ownership=unknown`.

Collection reads conventional paths to depth 2, examines at most 200 file paths per
directory and limits each filesystem scan to five seconds. File metadata is capped
at 1 MiB; user and mount records are capped at 200 each. Warnings describe failures
and limits. Command bodies, environment contents, password fields, mount devices
and mount options are omitted. Literal proxy destinations contain only the authority;
credentials, paths, query strings and fragments are discarded. Named or dynamic
upstreams may still require manual resolution.

Keep normal output private; review redacted output before sharing. It is a planning inventory: websites, database contents,
mail accounts/aliases, backups, certificate validity, remote mounts and application
compatibility still need separate checks. Custom includes, containers and uncommon
layouts can be missed. RPM support here applies to `--manifest` and `--manifest-json`;
`--upgrade-report` and Debian-specific upgrade/crossgrade checks retain their APT/dpkg scope.
