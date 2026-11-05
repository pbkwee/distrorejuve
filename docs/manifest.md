# Manifest privileges

`--manifest` and `--manifest-json` can run as a non-privileged user.
Non-root users automatically get reduced collection. The script never invokes sudo automatically.

| Information | Non-privileged collection | Root collection |
| --- | --- | --- |
| SSH host-key fingerprints | SHA256 hashes of readable conventional public host-key files; omissions remain unknown. | Same public-file-only collection; private keys are never read. |
| Packages, runtimes and websites | Collects installed packages and readable configuration and application metadata. | More configuration and application files may be readable. |
| Listeners | Reports addresses and ports; process ownership is unknown. | Also collects process names where available. |
| Service state | Infers running state from visible process names and enablement from available SysV startup links. | Also uses native service-status and enablement checks where available. |
| Mail storage | Reports discoverable paths; skips size scans and spool counts. | Performs bounded measurements unless disabled. |
| Scheduled jobs and migration paths | Private cron jobs and unreadable paths may be omitted. | Can inspect more private paths, including root's cron files. |

Text and JSON output warn when collection is unprivileged. Missing service and
application results remain unknown until checked with sufficient access and coverage.
Root collection also has scan limits and can return incomplete results.

For fuller visibility, run as root or explicitly use `sudo bash distrorejuve.sh --manifest`.
When already root, use `bash` directly.

Add `--unprivileged` or set `DR_UNPRIVILEGED=true` to force reduced collection,
including when running as root. This restricts collection operations; it does not drop
root privileges or hide files root can read.

## Collection for upgrade assessments

When the operator authorizes full root collection, use normal `--manifest` or
`--manifest-json` with DNS, HTTP status probes and mail metrics enabled. Clear action overrides and
use a reviewed script in a controlled environment as described in
[collection controls](upgrade-and-migration.md#collect-evidence).

Use reduced collection for restricted access or an explicit collection limit.
Assessments should name websites and their vhost/document-root/version-file paths,
service/listener roles and upgrade implications. Investigate relevant missing
service state or application use through bounded metadata checks. Keep private
configuration values and command arguments out of reports.

The first pass also collects root disk/inode capacity, memory/swap counters, fixed
database/mail unit states and bounded interpreter-use hints from process names
and cron. See the [inventory record guide](inventory.md#first-pass-upgrade-information)
for fields, panel-generated config paths and HTTP probe controls.
Resolver records identify `/etc/resolv.conf` as a regular file or symlink and
report numeric nameserver addresses. Full collection also queries bounded
`resolvectl dns` upstream addresses. An observed zero count identifies a resolver
with no configured upstream; failed or partially parsed queries retain their status.
Search domains and TLS server names are omitted.

## Legacy read-only intake and custom JVMs

The read-only collector avoids dense-array append syntax and literal parenthesized
Bash regexes that prevented older Bash 3.0 sources from parsing the complete script.
This compatibility does not extend release-upgrade support to those systems or
install a newer interpreter during collection.

The [inventory guide](inventory.md#first-pass-upgrade-information) describes
Apache inheritance, application marker versions, ProxySQL/Webmin recognition,
process self-correlation and the bounded custom Tomcat/JDK records. Full collection
can read selected Java process arguments, JDK/Tomcat version markers, Host/appBase
fields in the named Catalina server.xml and selected process-library identities.
Agree those metadata categories and output limits before collection; arbitrary
arguments, environment values and resource credentials are omitted.

Focused offline regressions run with:

```sh
python3 tests/test-collector-improvements.py
python3 tests/test-manifest-upgrade-assets.py
python3 tests/test-manifest-processes.py
```

## Website probe priority

The standard manifest collects website mappings across supported web servers
before probing their configured authorities. One representative per vhost and
listener runs before remaining generated aliases, within the same DNS-name,
HTTP-request and network-time budgets. Distinct metadata records are retained
when authorities share a cached result. Application/file inspection has its own
budget and is not charged for deferred DNS/HTTP waits. See
[probe coverage and limits](inventory.md#first-pass-upgrade-information).

Verify primary/alias ordering and skipped coverage with the offline fixture:

```sh
python3 tests/test-website-probe-priority.py
```
