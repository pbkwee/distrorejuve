# PowerDNS role settings during upgrades

PowerDNS Authoritative introduced `primary` and `secondary` in 4.5. The legacy
`master` and `slave` settings were removed in 4.9. An otherwise healthy package
upgrade can therefore leave DNS unable to start with the old configuration.
See the official [PowerDNS upgrade notes](https://doc.powerdns.com/authoritative/upgrading.html#removed-options).

Distrorejuve checks this boundary through its ordinary compatibility reports and
package flow. Use the normal upgrade commands; no separate role-check command is
required.

## Review and enable the migration

The default is to report relevant legacy settings as a manual blocker. After
reviewing the job's configuration-access and execution scope, set:

```bash
sudo env DR_MIGRATE_PDNS_ROLE_SETTINGS=true bash distrorejuve.sh --to-latest
```

Use the same setting with the approved `--to-debian-release`, Ubuntu transition
or package-upgrade command. The flag permits only these key-token substitutions:

| Existing key | New key |
| --- | --- |
| `master` | `primary` |
| `slave` | `secondary` |

The migrator preserves `yes`/`no` values, indentation, whitespace around the
assignment, comments, unrelated settings and the original final-newline state.
It preserves file owner, group and permissions. For example:

```text
  master = yes # writer
```

becomes:

```text
  primary = yes # writer
```

Bare boolean forms such as `master` without `=yes` remain a manual review case.
So do contradictory/duplicate role definitions, including definitions split
across included files. The flag does not permit dropping another definition or
choosing one value over another.

## Version and release timing

`--check-upgrade`, `--upgrade-report` and release preflight inspect and report the
version/configuration concern without changing files. With the flag selected,
a straightforward supported rename is reported as planned work. Unsafe or
ambiguous layouts remain manual blockers.

Existing APT candidates are preferred when they identify the affected target.
Before target indexes are available, the checker knows conservative affected
release boundaries for Debian trixie and Ubuntu questing/resolute from their
[official Debian package metadata](https://packages.debian.org/trixie/pdns-server)
and [official Ubuntu package metadata](https://packages.ubuntu.com/resolute/pdns-server).
Other unknown future versions remain an explicit warning until a successful
package simulation supplies the exact selection. No indexes are refreshed by
these read-only checks.

For a new package transition, the actual saved APT simulation selects the version
that can trigger a write. Immediately before a normal transaction installs or
configures `pdns-server` 4.9 or newer, the flag-controlled helper repeats the
configuration checks and performs the rename. An earlier PowerDNS selection or
an unrelated package plan leaves role settings untouched. This keeps the original
spellings during earlier release hops. Package epochs are ignored only when
comparing upstream parser capabilities; full versions remain in recovery receipts.

An already-unpacked or partially configured package is another exact selection:
its installed version is already durable in dpkg. Before either ordinary raw
`dpkg --configure -a` pass, the helper checks that actual pending PDNS state and
migrates or blocks it before its postinst can restart DNS. It does not substitute
the archive candidate or forecast a future release. The private selection record
is labelled `pending-dpkg`, distinct from an APT simulation. A denied or unsafe
migration stops that configure pass rather than continuing into postinst.

The currently installed binary must already support the canonical names, meaning
upstream PowerDNS 4.5 or newer. A direct transition from an older binary to 4.9+
stops before changing its settings or executing that package transaction. Complete
a compatible intermediate hop, or arrange a separately supervised binary/config
transition. The tool does not rename early and leave an older daemon unable to
read its configuration.

## Supported configuration scope

The automatic path handles `/etc/powerdns/pdns.conf` and the active `*.conf` files
in its single conventional `include-dir` below `/etc/powerdns`. Backup suffixes
such as `.conf.old` are ignored. Nested include directories, external includes,
symlinks, hardlinked files, unsafe permissions and oversized or malformed input
require manual review. Limits are 100 files, 256 KiB per file and bounded line/
record lengths.

Before an actual rename, a running conventional daemon must also match the
current checksum-verified packaged executable and its inode. Stale/deleted or
custom executables require reconciliation; the executable verifier retains its
explicit 16 MiB bound. Already-canonical settings remain a no-op without this
extra alias-migration binary proof. Unknown upstream version formats stop the
selected migration rather than being treated as an earlier version.

A local service override, nonempty custom startup options, a named configuration
instance or a nonconventional running configuration selector also requires review.
Running daemon arguments are examined only for bounded selector/role metadata;
argument values are not returned. PID start identity must remain stable across
that check. Command-line `--master`/`--slave` and role overrides cannot be repaired
by changing the default configuration file.

Other legacy settings, renamed backend options and custom SQL query settings are
reported for manual migration. The flag never rewrites backend queries, database
schemas, zone contents or API settings. Existing schema/client acceptance remains
necessary where the planned PowerDNS version requires it.

## Recovery and retries

Before any file changes, the helper records/reuses the job's established original
baseline. It saves source-local original files and staged replacements in a
private directory beside that baseline:

```text
<baseline>.pdns-role-migration/attempt.<unique>/
```

The backup can contain sensitive configuration; retain it on the approved source
under the job's access and retention rules. Do not copy its contents into a report
or public repository. A per-baseline lock prevents concurrent migrations.

All replacements are staged and checked before activation. The helper verifies
that source bytes, permissions and the include list still match its observations.
It atomically replaces only files that need a key rename, then checks the written
hashes and role syntax. A write/validation failure restores the files owned by
that attempt from the protected originals. If restoration itself fails, the helper
stops and reports the recovery directory for reconciliation.

Completed attempts retain full old/new versions, the selection hash, selection
context and protected selection record. Each saved file has a recorded original
SHA256 and metadata as well as its expected replacement digest.

Before even a selected-PDNS no-op or a fresh attempt, the helper inspects earlier
attempts under the same baseline lock. Activated files without a completed or
verified rollback remain unresolved and block package configuration. A rollback
marker alone is insufficient: backup digests/metadata and current restored file
digests must agree. Missing or modified evidence requires manual reconciliation;
retrying cannot silently turn mixed files into success.

After a clean rollback is verified, a protected `reconciled-rollback.tsv` receipt
binds that decision to the original manifest and activation hashes. All original
failure records remain. A later successful retry may then leave canonical files
without making the earlier clean rollback appear unresolved again. Subsequent
no-ops validate the preserved evidence without demanding legacy bytes forever.
A failure before activation likewise needs its recorded original/current state
to agree before a new attempt. Older journals without original digests require
manual review.

Already canonical configuration needs no new edit or backup once prior recovery
questions are resolved. Never erase a failed receipt to make a later attempt look
like the first one.

The settings migrator never restarts DNS or changes a database. The approved
package transaction retains its normal service behavior and workload checks.
Afterward, verify DNS roles, listener reachability and the application's actual
acceptance requirements under the recorded plan.

## Offline verification

```bash
python3 tests/test-pdns-migration.py
```

Fixtures mock package selection, process metadata and external operations, and use
disposable configuration/baseline directories. They cover earlier/no target
transitions, flags, multi-hop timing, epochs, active includes, duplicate settings,
custom selectors, unresolved rollback/tampering, clean retry and canonical no-op,
and exact pending-dpkg/normal APT ordering.
No customer service restart, upgrade, backup or persistent database is a test.
