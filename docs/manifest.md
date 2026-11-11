# Manifest privileges

`--manifest` and `--manifest-json` work with an ordinary user account.
Non-root users automatically get reduced collection; sudo is never invoked automatically.
Use this mode for an initial assessment when root access is unavailable or unnecessary.

Root collection provides fuller visibility. Add `--unprivileged` or set
`DR_UNPRIVILEGED=true` to force reduced collection, including when running as root.
The flag limits collection operations but keeps the account's existing permissions.
Files readable by that account may still contain sensitive information; review
the manifest before sharing it.

| Information | Reduced collection | Full root collection |
| --- | --- | --- |
| Software and configuration | Installed packages and readable application/configuration metadata. Protected files may be missing. | Greater access to protected configuration and application metadata. |
| Services and networking | Best-effort status from available metadata, with fewer live checks and process details. | More detailed service, process and resolver checks where supported. |
| Websites | Readable site configuration and application versions; HTTP/HTTPS checks are skipped. | Also checks HTTP/HTTPS responses unless disabled. |
| Storage | Basic capacity information; mail measurements and some directory-size scans are skipped. | More complete, bounded mail and directory measurements unless disabled. |
| Scheduled work | Readable jobs and limited runtime-use information; private schedules may be missing. | Greater access to private jobs and additional cron runtime-use checks. |

Both modes report collection warnings. Treat missing or skipped information as
unknown. Root collection also has limits and can be incomplete. Both modes use
readable public files for SSH host-key fingerprints; private keys are never read.

## Collection for upgrade assessments

Start with the evidence available. Use reduced collection for restricted access
or an explicit collection limit. When fuller visibility is needed and authorised,
run as root without `--unprivileged` or `DR_UNPRIVILEGED=true`.

Follow the [collection controls](upgrade-and-migration.md#collect-evidence) to use
a reviewed script in a controlled environment. For normal full collection, leave
DNS, HTTP status probes and mail metrics enabled unless the agreed scope limits them.

Record collection mode, warnings and gaps in the assessment. Resolve missing
information when it affects the recommendation or execution plan. Keep private
configuration values and command arguments out of reports. See the
[inventory guide](inventory.md) for collected records and individual probe controls.

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

### Listener transport and HTTP probe coverage

Listener records include the TCP or UDP transport and the local bind scope.
A socket bind leaves external reachability unknown. UDP inventory is bounded;
an unavailable query or an inventory limit is reported explicitly.

Website HTTP coverage has its own probe status. If an old curl cannot accept
the required safe request options, the collector reports the client as
unsupported and leaves HTTP results unknown. Site and runtime inventory remains
available. For an installed MariaDB server, the manifest includes a reminder to
review [client TLS compatibility](application-transitions.md#mariadb-client-tls-compatibility)
when planning a target at MariaDB 11.4 or later.
