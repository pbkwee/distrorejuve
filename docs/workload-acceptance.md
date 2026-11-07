# Workload acceptance and database readiness

Package and daemon health do not establish application acceptance. Before the
first planned service change, record the expected workload in a private,
root-owned TSV contract. Keep it with the job's immutable original baseline.
Existing PHP/web and common-service findings continue to run independently.
A failed acceptance check cannot be hidden by a successful package transaction.

## Prepare and run the contract

Prepare the source-local job directory with `chmod u=rwx,go=`. Set its contract
file to `chmod u=rw,go=`. Supply its absolute path as `DR_WORKLOAD_CONTRACT` and
pin `DR_CONFIG_BASELINE` to that job's original. Use `--capture-baseline` before
any separately planned service retirement or manual configuration change.

A normal logged upgrade captures the original if needed, validates and freezes
the contract as `<original>.workload/contract.tsv`, and runs its checks before
invoking the changing action. Existing contracts must match byte for byte.
Retries without the environment setting reuse the frozen contract. Keep it for
all release hops and handoffs; do not replace it with a post-change inventory.

There is no automatic contract discovery or arbitrary configuration execution.
Adding a functional script to this protected contract explicitly approves its
exact bytes for this job's checks. Review scripts for bounded, read-only behavior
and permitted credential use before including them. A supplied credential file
remains a reference consumed by its designated client; never embed credentials
in the contract or print them from a check.

Each line has exactly five nonempty, tab-separated fields. No header or comments
are accepted. IDs are unique ASCII letters/digits with `.`, `_` or `-`.
The limit is 200 lines and 1 MiB. Examples below show tabs as `<TAB>`:

```text
service<TAB>web<TAB>nginx<TAB>active<TAB>-
service<TAB>retired-dns<TAB>bind9<TAB>inactive<TAB>-
socket<TAB>php-socket<TAB>/run/php/php8.4-fpm.sock<TAB>33:33:660<TAB>-
path<TAB>site-directory<TAB>/srv/example<TAB>1001:33:750<TAB>-
account<TAB>site-worker<TAB>example<TAB>1001:33<TAB>-
functional<TAB>site-home<TAB>/root/job/check-site<TAB><script-sha256><TAB>-
```

`service` checks loaded native state. Idle SSH socket activation is accepted only
for a loaded, active, listening `ssh.socket` triggering `ssh.service`, without a
failed service. Legacy init status cannot establish an intentional inactive
state; use an approved functional script where necessary. Runtime accounts use
numeric UID/GID, independent of naming changes. Sockets must exist as Unix sockets. Path and socket rows check ownership and
exact octal mode; linked paths are rejected.

Functional scripts must be executable, root-owned and free of group/world write
permission, including every ancestor directory. Symlinked executable paths are
rejected. Their SHA256 must match before each run. The script receives no
arguments and `DR_ACCEPTANCE_PHASE=before` or `after`. Use that variable where
readiness and final-version assertions differ. A required `timeout` limits each
check to 30 seconds, with forced termination after a further five seconds. Output is discarded; only IDs, states and exit statuses
enter the private run's `workload.before.tsv` and `workload.after.tsv`.

## Separate database dimensions

Include both `database-info` and `database-check` rows for **every** dimension
when any database rows are present:

| Dimension | Record in the information row | Check independently |
| --- | --- | --- |
| `engine` | Original/intended engine and versions | Target daemon/version and authenticated query |
| `topology` | Writer, replicas and intended application stage | Correct writer identity, replication role and synchronization |
| `schema` | Application/schema versions, charset/collation and migration revision | Adapted migration verified in an isolated fixture; correct final schema/version |
| `clients` | Custom client revisions and compatibility requirements | Each application client's authenticated functional operation |
| `maintenance` | Designated maintenance identity/credential reference and allowed scope | Maintenance authentication/privileges independently of application access |
| `tables` | Expected upgrade/maintenance command and completion criterion | Successful table-upgrade/maintenance evidence for the target engine |

```text
database-info<TAB>schema-version<TAB>schema<TAB>example-v3 UTF-8; migration revision abc123<TAB>-
database-check<TAB>schema-ready<TAB>schema<TAB>/root/job/check-schema<TAB><script-sha256>
```

These are examples for one dimension; a usable database contract includes all
six. Information records are metadata, never SQL. Check scripts assert readiness
before and completion afterward. Use approved isolated fixtures to validate
adapted migration SQL for the actual application/schema and custom clients.
Apply reviewed schema changes only at the designated writer/application stage
under job execution approval. This tool never generates or executes migration
SQL. A `SELECT 1`, working WordPress page, or running MariaDB cannot substitute
for the maintenance and table-completion checks. Keep the existing
`DR_DATABASE_DEFAULTS_FILE` client scope; do not retry with a different identity
when its designated authentication fails.

## Completion and exceptions

At final verification, every contract check must pass or have an explicit
exception. Failed, timed-out, changed or unavailable checks fail the action.
No contract leaves workload acceptance unknown and the run marked incomplete;
package/release outcomes remain separately visible. The console does not label
that run fully complete. Absence of a contract preserves the legacy action exit
status, so callers must inspect completion evidence as well as status zero.

For a deliberately accepted limitation, use `DR_WORKLOAD_EXCEPTIONS` pointing
to a private root-owned file in a private root-owned directory. Each exception
has five fields:

```text
exception<TAB>site-home<TAB><original-sha256><TAB><frozen-contract-sha256><TAB>APPROVAL-7: accepted limitation and reason
```

The operator's approval reference and reason are required. The exception applies
only to that check, original and contract, only after changes. It cannot bypass
a failed readiness check or erase existing PHP/service failures. Results retain
`accepted_exception` rather than claiming the check passed. A changed plan needs
new review; do not edit the frozen original to make verification pass.
