# Approved execution evidence

Use `scripts/execution-evidence.py` with Python 3.7 or later on the explicitly
approved source or observer. It adds no mandatory dependency to the legacy
manifest. These commands implement small checks used by the
[execution checkpoints](execution-checkpoints.md) and
[application transition procedure](application-transitions.md).
They do not grant access, approve a migration or select a recovery action.

Read only the selected input categories. Database clients consume an already
approved defaults file without this helper reading its values. No database rows,
passwords, unrestricted global variables or application query text are returned.
A selected client failure remains unknown; the helper never tries another account.

Inputs must be regular files, including regular proc metadata where applicable;
symlinks, FIFOs and sockets are refused before reading. Commands return bounded JSON. Use `--receipt /absolute/private/new.json` to create
an exclusive operator-owned `u=rw,go=` file. Its canonical parent must exist, be
owned by the executing operator and have no group/other write permission. Receipts
are ASCII JSON written in binary mode, so replacing Python's text codecs during
an upgrade cannot prevent final receipt creation. An existing receipt is never
overwritten. Review files must be single-link, operator-owned regular files with
mode `u=rw,go=`; application-supplied metadata is not an approval.

Exit zero means the requested evidence/check succeeded. Failed checks, unknown
client evidence and observed ProxySQL projection disagreement return nonzero.
The `check` command propagates its child status; input/verification failures
return 2. Keep original failed attempts and give later attempts different names.

## Database engine and ProxySQL metadata

Run only after scope covers the designated client, schema and metadata query:

```bash
python3 scripts/execution-evidence.py database-engines \
  --defaults-file /approved/maintenance.cnf --database application \
  --receipt /protected/job/database-engines.json
python3 scripts/execution-evidence.py proxysql-state \
  --defaults-file /approved/proxy-admin.cnf --database main \
  --receipt /protected/job/proxy-projections.json
python3 scripts/execution-evidence.py client-ready \
  --defaults-file /approved/proxy-admin.cnf --database main \
  --attempts 10 --interval 0.5 --timeout 2 \
  --receipt /protected/job/proxy-ready.json
```

All three accept `--client` to select the approved executable. The defaults file
is the client's first option, the database is explicit, and no root override or
empty init-command is added. No authentication fallback occurs.

`database-engines` aggregates `ENGINE`, table count and data/index bytes for base
tables in `DATABASE()` only. It flags any engine other than InnoDB as
nontransactional or unverified for transaction-only recovery. An unavailable
client or malformed result produces unknown coverage. This check cannot prove
backup consistency or restore success. The timeout is bounded to 30 seconds.

`proxysql-state` compares runtime and disk projections for server hostgroups,
addresses, ports, status, weight and maximum connections; rule IDs, active state,
destination hostgroups, apply flags and timeouts; frontend user routes; and the
allowlisted numeric policies `mysql-default_query_timeout`,
`mysql-connect_timeout_server` and `mysql-monitor_connect_timeout`.
NULL/empty default schemas normalize together. Split runtime frontend/backend
user rows normalize to the frontend route, so representation differences do not
create false drift. Output contains counts and match results, not user names,
server names or raw values. Query-match expressions, credentials and unrestricted
policy settings remain explicitly uninspected. A matching projection does not
claim complete ProxySQL equivalence. Each query timeout is at most 10 seconds.

`client-ready` executes only `SELECT 1`. It retries client error codes 2002, 2003
and 2013; authentication/SQL errors, timeouts and malformed success return
immediately. Attempts are bounded to 20, delay to 5 seconds and each query to
10 seconds. A successful service-manager start does not bypass this readiness
checkpoint.

### Compare database retention settings

When a workload contract checks MariaDB retention, project only the approved
numeric settings to protected JSON such as `{"expire_logs_days":"10.000000"}`.
Use the same keys in the original and observed projections. The
`database-retention --before ORIGINAL --after OBSERVED` evidence action compares
`expire_logs_days` and `binlog_expire_logs_seconds` as exact decimals. It accepts
integer values and decimal strings and returns the names of changed settings.
A change from `10` to `10.000000` passes; `10.25` remains distinct.
Missing or malformed projections require review. If the contract pins this
check, review and update the dependent artifact digests together.

## Size and verify a cold copy

Use a representative sample on the approved copy route, including the actual
storage and intended concurrency. Supply the available copy time after
deducting verification time and the approved recovery lead time:

```bash
python3 scripts/execution-evidence.py cold-copy-budget \
  --size-bytes 5583457485 --sample-bytes 134217728 --sample-seconds 8 \
  --available-seconds 900 --receipt /protected/job/copy-budget.json
```

The helper budgets twice the measured-rate estimate for transfer variability.
If the budget will not fit, revise preparation or use the agreed alternative
before stopping writes. Track the actual outage deadline separately.

After an interrupted regular-file copy, verify the exact existing bytes while
writes remain stopped. Use the protected paths covered by the job:

```bash
python3 scripts/execution-evidence.py verify-copy-prefix \
  --source /approved/database/original-file \
  --destination /approved/recovery/partial-file \
  --receipt /protected/job/copy-prefix.json
```

A matching prefix is evidence for a reviewed continuation, not completion.
For a shorter, verified partial in private recovery staging, the existing copy
procedure can use an installed, reviewed rsync with
[`--append-verify`](https://rsync.samba.org/ftp/rsync/rsync.1) on the exact
original and partial regular file. Apply the plan's metadata-preservation
options. This mode updates the partial in place, so keep it outside the set of
usable recovery points until full verification. Use a new attempt or the agreed
fallback if the same stopped original and exact prefix cannot be established.
After copying, repeat with `--complete` and a new receipt. The check reads both
files, returns only byte counts and status, and makes no writes to either file.
Include this full read in the verification budget. For a directory copy, check
the whole inventory and metadata separately and verify each file reused from a
partial attempt. If a prefix differs or the source changed, reconcile the
attempt before using the planned retry or fallback.

## Process listeners and stale executables

```bash
python3 scripts/execution-evidence.py listeners --pid 1234 \
  --expected /protected/job/expected-listeners.json \
  --receipt /protected/job/listeners.json
python3 scripts/execution-evidence.py stale-process --pid 2345 \
  --installed /usr/lib/systemd/systemd-logind \
  --manager-state /protected/job/user-manager.json \
  --receipt /protected/job/logind-identity.json
```

`expected-listeners.json` is an exact list of approved bindings:

```json
[
  {"protocol":"tcp","address":"127.0.0.1","port":6032},
  {"protocol":"tcp","address":"192.0.2.10","port":6033},
  {"protocol":"unix","path":"/run/proxy-pg-admin.sock"}
]
```

The helper associates socket inodes with the selected PID's descriptors and
reads that process's network namespace tables. TCP listeners, unconnected UDP
bindings and listening UNIX sockets are compared as a complete set. Missing or
unexpected endpoints fail. An unreadable/unrecognized table or changed process
identity prevents an acceptance claim. No unrelated process arguments or socket
payloads are collected. The snapshot is point-in-time; keep the rehearsal bind
guard active and repeat after startup when processes may change their binds.

`user-manager.json` contains the already scoped manager facts, for example
`{"ActiveState":"failed","TasksCurrent":0}`. Compare the selected running
executable's device/inode with the installed file. A stale executable plus an
empty failed manager indicates that a targeted refresh deserves review. The
helper never restarts logind, clears failed units or changes authentication.
Check runtime directories, cgroups, PID 1 and independent SSH/console access
using the existing checkpoint procedure before an approved refresh.

## Supervised outcomes and outage headroom

```bash
python3 scripts/execution-evidence.py check \
  --receipt /protected/job/check-01.json -- /approved/check.sh
python3 scripts/execution-evidence.py check --read-only-check --timeout 10 \
  --receipt /protected/job/check-02.json -- /approved/read-only-check.sh
```

`check` starts one explicit argument vector without a shell, discards child
stdout/stderr and saves its actual exit, signal or timeout result. The command
arguments are not written to evidence; the exclusive `.started` sidecar keeps
a command digest, supervisor PID, observer boot ID and monotonic start time.
A nonzero result is propagated after the final binary receipt is written.
Use a new receipt name after reconciliation, never to conceal a failed attempt.

A timeout is rejected before launch unless `--read-only-check` is supplied.
That flag declares the reviewed command safe to terminate. A timed diagnostic
terminates its process group and returns 124. A mutating or ambiguous schema
operation must have no generic timeout; its existing approved supervisor and
recovery plan determine continuation. Missing final evidence never authorizes a
repeat. The helper can run beneath the already approved service supervisor.

`--application-umask 022`, `027` or `077` applies only in the child. It restores
neither old application modes nor ownership; use the transition procedure below.
The parent and private receipt permissions remain separate.

```bash
python3 scripts/execution-evidence.py deadline \
  --started-monotonic 12345.5 --observer-boot-id 00000000-0000-0000-0000-000000000000 \
  --outage-seconds 1800 --recovery-headroom 300 \
  --receipt /protected/job/deadline-01.json
```

Use the real start and boot ID saved at the first disruptive action, not the
example values. The approved outage budget is at most 24 hours. A status inside
the recovery reserve returns `recovery-decision-needed`; exhausted budget returns
`overrun`; earlier status returns `continue`. This command never stops, retries
or rolls back an action. It is suitable for repeated named checkpoint receipts.

The clock belongs to the same observer and its current boot. A changed boot ID
or a current monotonic time earlier than the start is rejected. Keep the approved
wall-clock window and time zone separately in the durable job record; after an
observer reboot, reconcile that record rather than converting unrelated monotonic
values into downtime. Source reboots do not reset an external observer's clock.

With `--session-lost`, the default policy requires reconciliation. An approved
continuation policy requires both `--session-loss-policy continue` and
`--session-loss-approval <plan-reference>`. Record this policy in the concrete
plan before disruption. Neither an overrun nor loss of the operator session
expands the permitted recovery actions.

## Empty boot values and exact review bindings

```bash
python3 scripts/execution-evidence.py debconf --value-type devices \
  --input /protected/job/debconf-get.txt
python3 scripts/execution-evidence.py fingerprint \
  --input /protected/job/original-kernel.json
python3 scripts/execution-evidence.py kernel \
  --original /protected/job/original-kernel.json \
  --current /protected/job/current-kernel.json \
  --review /protected/job/kernel-review.json
```

`debconf` accepts one bounded `debconf-communicate GET` response. `0 ` followed
by newline is a successful empty value; `0 true` is a boolean success. Nonzero
protocol status remains unavailable and its text is discarded. `devices` permits
only an empty list or conventional `/dev/...` device selections; `boolean`
permits empty/true/false. This parser never changes boot settings.

Kernel evidence has these required string fields:

```json
{"source_id":"source-example","kernel":"5.10.1","machine":"x86_64","root_identity":"uuid:example",
 "boot_mode":"xen-pv","cgroup_mode":"v2"}
```

The original stays immutable. The `fingerprint` subcommand reports the SHA256
of canonical sorted ASCII JSON, used to bind a private review to exact inputs.
A changed kernel requires this review shape:

```json
{"original_sha256":"<original fingerprint>","current_sha256":"<current fingerprint>",
 "kernel":"5.10.2","approval":"<recorded operator decision>",
 "root_checked":true,"boot_mode_checked":true,"cgroups_checked":true,
 "applications_checked":true,"provider_selection_verified":false}
```

The same source ID, root identity, machine, boot mode and cgroups are still required. The kernel string and both
input digests must match exactly; an approval for one build cannot accept another.
Provider selection verification is reported independently. RimuHosting API
identity and staff review remain in Upgrader.

`x11-exception --original FILE --review FILE` checks a single narrow exception.
The original contains `source_id`, `release_path`, 64-character
`default_failure_sha256` and `other_checks_sha256`, plus
`display_server_active:false`, `display_manager_active:false` and
`other_checks_passed:true`. The private review repeats the four identity/digest
fields, includes `original_sha256` and a nonempty `approval`, and has exactly
`"skips":["DR_SKIP_X11_CHECK"]`. Success returns that one environment setting
and `default_readiness_passed:false`. It never edits the original failure or
permits another skip. Run the separately approved exact release path with every
other guard active.

## Isolated checks

```bash
python3 tests/test-execution-evidence.py
python3 tests/test-availability-monitor.py
```

The fixtures mock database clients, process identities and network operations.
File allocation and deployment checks use disposable temporary files only.
They do not validate a customer restore, boot or application transition.
