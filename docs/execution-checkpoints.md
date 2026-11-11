# Execution checkpoints for varied servers

Apply these checks to the observed workload and approved scope. Missing tools,
custom configurations and older command formats remain explicit evidence gaps.
Do not install dependencies, read credentials or change services merely to fill
an assessment field. Use the [data-access rules](sensitive-data.md) and the
[approved upgrade procedure](upgrade-and-migration.md).

## Retain usable original evidence

Check collection exit status, parseability, source identity, warnings and expected
coverage before the first production action. An exit-zero manifest can be
partial. Preserve the first usable original and failed attempts separately;
a later collection describes the changed server.

For an approved upgrade, prepare a private source-local directory and choose one
original configuration snapshot path. For example:

```bash
install -d -m u=rwx,go= /root/upgrade-evidence/job-original
export DR_CONFIG_BASELINE=/root/upgrade-evidence/job-original/preupgrade.dpkg.original
```

If approved preparation changes services or configuration before package work,
capture the original first using the same reviewed tool:

```bash
bash /root/upgrade-tools/reviewed-distrorejuve.sh --capture-baseline
```

The explicit action requires the selected parent to be a private root-owned
directory. It writes evidence only and preserves a usable existing original.
It refuses incomplete captures; resolve those before preparatory changes.

Pass that same setting to every tool invocation, including supervised stages,
release hops and `--show-changes`. The first upgrade snapshot creates the file;
existing usable originals are retained. Explicit selection ignores the history
window and never searches unrelated global baselines. Current report snapshots
are written beside the selected original. It does not relocate all tool logs,
package backups or recovery artifacts; record their paths separately.

A failed required snapshot leaves `<baseline>.incomplete` and cannot be accepted
on retry. Preserve that attempt and resolve the failure before choosing a fresh
original path. Never remove the marker to imply successful collection. Existing
reviewed originals can be selected, but their provenance and coverage still need
verification. A configuration snapshot is not a recovery backup.

`DR_UPGRADE_MANIFEST=false` skips optional automatic application collection and
comparison when outside scope. Required configuration, process, package, service
and web-runtime checks still have their own inputs. Review those inputs before
execution; the setting does not restrict explicit manifest/report actions.
Provide separately approved workload baselines and acceptance checks for gaps.

## Use designated database maintenance access

When an operator designates a client option file, pass its absolute path through
`DR_DATABASE_DEFAULTS_FILE`. A conventional Debian maintenance file is one
possible selection; do not discover or read it automatically. Approve the file,
its client-side includes/login configuration and intended database endpoint.
The client consumes credentials; the script receives only fixed query results.
Do not replace its selected account or socket with root defaults. A failed
selected authentication check needs review, without trying other credentials.

Omit an empty `--init-command`: some MariaDB versions treat it as an empty SQL
query. Successful `SELECT 1` verifies authenticated query access. It does not
prove replication health, table-upgrade completion or application acceptance.
Check those separately within scope.

## Parse the producer's actual records

Use bounded existing metadata tools and retain command status and coverage.
When `sfdisk` is absent, available `lsblk` metadata can supplement partition
review without installing packages. Missing fields remain unknown; neither
command proves bootability or the provider's selected boot method.

For scoped legacy GRUB review, this menu uses a tab after `title` and an equals
sign after `default`:

```text
title	Previous kernel
default=0
```

Parse the title as `Previous kernel` and the default index as zero. Review that
entry's kernel/initrd paths and provider boot selection. Generated GRUB 2
configuration needs its own parser and checks. Do not infer safe boot defaults
from a partial legacy menu.

For line-delimited debconf output, use horizontal whitespace (`[ \t]`) within
a record. For example, these are two separate records:

```text
grub-pc grub-pc/install_devices multiselect
grub-pc grub-pc/install_devices_empty boolean true
```

The first value is empty; the second is `true`. A whole-input `\s+` expression
can consume the newline and incorrectly assign the next record to the empty
value. Preserve blank fields and add literal producer examples and synthetic
fixtures beside any reusable parser introduced later.

A process name such as truncated `unattended-upgr` can denote a shutdown helper.
Use scoped executable metadata and actual package locks/state; do not infer an
active transaction from the name alone or collect arbitrary argv to classify it.
Recheck locks before execution and let the package manager enforce its locks.

## Reconcile supervised launches before retrying

Use the available supervisor with a unique job/stage identity and a durable
source-local log. For `systemd-run`, prefer `--no-block` when supported so a
`Type=oneshot` launch does not wait for the stage to complete. Verify support on
older systems. Arrange a source-local receipt recording stage identity, start
and finish times and the operation's exit status; write the final receipt only
after the operation ends. A missing receipt means completion is unverified.

A client launch status describes the launch request. It does not prove whether
the source operation started, failed or is still running. After a disconnect or
nonzero launch result, inspect the exact unit, source log/receipt and package
state before retrying. Retain the unit result until reconciliation; do not launch
a duplicate transaction because the caller stopped waiting.

## Check service transitions and availability

For an approved service retirement before package upgrades, keep the original
service snapshot intact. After the exact approved package removal succeeds,
record its package names, one per line, in
`<baseline>.service-retirements/packages.removed`. The receipt directory must be
root-owned with mode `u=rwx,go=`; the regular, single-link file must be root-owned
with mode `u=rw,go=`. Record the approval and removal result in the job log.
Service verification accepts that retirement only when the package is no longer
installed and the original service is confirmed inactive. Active, unknown,
malformed or unsafe observations retain their failure or incomplete status.
This receipt does not authorise a removal and is separate from purge evidence.

Compare failed units before and after package work and after reboot. Selected
service-role gates do not cover every custom or ancillary unit. Verify active
replacement timers/services before recording an old unit as retired. Preserve
the failed-state evidence before an approved targeted restart or reset; avoid
blanket restarts, resets or authentication-policy changes.

At a no-reboot checkpoint, verify a new SSH session alongside the existing
connection. If session creation fails, or a session manager is known to retain
a replaced binary, run the bounded
[stale-process check](execution-evidence.md#process-listeners-and-stale-executables)
as part of that checkpoint. After a targeted refresh covered by the plan,
verify a fresh session, the same boot ID, and the original SSH and workload
processes that the plan requires to remain active.

For PAM/session failures during a version transition, compare installed versions
with the running executable identity of logind, D-Bus and the affected user
manager. Check runtime-directory ownership, cgroups and PID 1 independently.
A replaced binary can explain a stale process, but it does not establish the
cause of every failure. Preserve fresh SSH/console access and dependency evidence
before an approved targeted refresh. Unknown errors remain unresolved.

If the plan needs interruption evidence, begin approved status-only probes before
the first production action. Bound each probe and the sampler's lifetime. Record
probe location/protocol, client availability, timestamps, interval and gaps;
keep response bodies and customer data out of the sampling log.

A missing client or timeout facility is a probe failure, distinct from an actual
response timeout. Sampling that begins during a failure is left-censored;
sampling that ends before recovery is right-censored. Sparse samples bound an
interruption between observed successes/failures; they do not establish exact
downtime. Report the covered window, uncertainty and missed earlier events.

## Durable release-stage resume

Pin `DR_CONFIG_BASELINE` before changes. Its `<original>.stage` record preserves
the exact interrupted target despite an advanced release label. `DR_STAGE_RECORD`
selects another private absolute file. Use `--resume-stage RECORD` to finish that
hop through normal guards; existing `--resume` only removes the pause file.
See [release-stage records](release-stage-records.md).

## Resume after provider rescue

Recover unavailable SSH through the [rescue procedure](rescue-access.md).
Verify normal boot and a fresh installed-system SSH login before using the
[release-stage record](release-stage-records.md#resume-after-rescue-recovery).
RimuHosting rescue keys apply to that rescue boot; they do not establish access
to the installed OS. Treat status 202 as pending and account for the API client's
five-minute inventory cache when reconciling recovery or snapshots.

## Outage deadlines and loss of the operator session

Complete local write/tool readiness, source staging, deployment-permission review,
approved recovery preparation and the first observation cycle before downtime.
Record the approved start/window/time zone, maximum interruption, recovery lead
time and decision owner. Derive the latest recovery-decision time from that budget;
do not silently replace the approved outage limit after an overrun.

Use a named source/observer supervisor and immutable reviewed artifacts. Record
how execution continues, pauses or requests assistance if the operator session is
lost. A package/schema action in an ambiguous state must be reconciled from its
durable stage result, process/lock state and independent workload evidence before
any retry or termination. A launch receipt and a successful supervisor are not
completion evidence. A failing helper must propagate a nonzero exit and preserve
its failure receipt. Use binary receipt writing across interpreter replacement.

For application changes, follow [application transitions](application-transitions.md)
and the [bounded evidence helpers](execution-evidence.md). Validate target-account
access before taking services down, preserve existing/recreated directory modes,
bind the intended database explicitly, allow only documented bundled replacements,
and check every process listener. Keep connection-readiness retries bounded and
fail authentication/SQL errors immediately. Recheck the accepted outage and recovery
boundary after diagnosis, interruption or a material scope change.
