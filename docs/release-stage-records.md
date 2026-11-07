# Original state and interrupted release stages

Capture the original before approved preparation changes, including intentional
service retirements. Keep that same original for the whole job. For example,
after preparing a private root-owned directory using `chmod u=rwx,go=`:

```bash
DR_CONFIG_BASELINE=/root/upgrade-job/original bash distrorejuve.sh --capture-baseline
DR_CONFIG_BASELINE=/root/upgrade-job/original bash distrorejuve.sh --to-debian-release 12
```

The selected original enables a durable release-stage record at
`/root/upgrade-job/original.stage`. `DR_STAGE_RECORD` can select another absolute
file in a private root-owned directory. Both the selected original and record
remain local to the source server; they are private operational evidence.
Unpinned legacy runs retain their existing behavior and have no new durable stage
record. Normal `--check-upgrade` remains non-mutating.

The first exact hop is recorded before path preparation can change prerequisite
packages. Every record binds the source identity, original path and SHA256,
distribution family, starting release, intended adjacent target, release-hop
action and crossgrade choice. It records the last completed milestone, UTC update
time and the outcome. Milestones are original recorded, preflight checked,
sources selected, packages applied and hop complete. Writes use private temporary
files and atomic replacement. The original is never rewritten, and an incomplete
original capture cannot be accepted as a successful baseline.

If a run stops, inspect the private detailed log and current package/service
state, then explicitly resume the recorded hop:

```bash
bash distrorejuve.sh --resume-stage /root/upgrade-job/original.stage
```

The resume command recovers its original path and crossgrade choice from the
record. An inherited `DR_ACTION` cannot change this explicit operation, and a
conflicting selected original or added crossgrade choice is refused. Source
identity and original digest must still match, and the installed release must
be either the recorded source or target. Resume repeats the existing path,
repository, architecture, capacity, package and runtime checks. If `base-files`
already reports the target, resume still finishes that exact hop; it never
selects a later release from that label. A hop already complete only reverifies
its target. The existing `--resume` option still clears the pause file.

## Resume after rescue recovery

Use the [rescue recovery procedure](rescue-access.md) when SSH or normal boot
fails. Keep the original and stage file on the installed source filesystem;
the rescue system is a different environment. Do not capture rescue as the
original or rewrite the record to match rescue identity.

For RimuHosting, the API client supports `vmctl.py rescueboot` with one-off SSH
public keys and optional saved-account keys. Those keys grant rescue access;
they are not automatically installed in the normal system. After the approved
repairs, use the provider's host-controlled `vmctl.py restart`, then verify a
fresh SSH connection, installed host identity and affected services. Only then
run `--resume-stage` on that installed system. See the
[API rescue instructions](rimuhosting.md#recover-access-with-rescue-boot).

Progress streams use HTTP 200 before the terminal result. An API status 202
means accepted, with work potentially pending. Reconcile the terminal operation
result and actual source state before recording recovery or workload acceptance. API status/image inventories may be cached for five minutes; a new client
request time alone does not establish fresh host observation. After a timeout,
reconcile that operation before repeating it. Keep an external availability
observer running through rescue and normal restart; successful rescue SSH does
not establish the original application's recovery.

## Checkpoint completion

`release-packages-verified` means that hop's release/package completion and
cleanup checks passed. It permits the next contiguous hop in the same running
multi-hop operation. It does not claim that the workload is accepted. The final
`verified` outcome requires successful action, release, package, service and
workload checks. Failed, unknown or unaccepted workload checks retain an
`incomplete` outcome. A later release command refuses an unfinished/unverified
record and prints the explicit resume command.

Records contain fixed-key tab-delimited data and are never evaluated as shell
code. Unknown/duplicate/missing fields, invalid target pairs, changed originals,
symlinks, hard links, nonprivate files or directories, and another source identity
are refused. Machine identity uses a hashed machine-id where available; older
hosts use hashed hostname and root filesystem ID. A hostname/filesystem change
on that fallback requires operator review. Matching identity metadata provides
consistency checking; it does not replace host verification or authorization.

Do not edit a checkpoint to claim completion, discard a failed original, select
a new release, or bypass an existing stop. Keep the original, stage file,
validation notes and logs until the job has been accepted. The stage records a
release hop, not individual APT transactions: normal operations may be replayed
under their existing guards after interruption. A stage record does not add
concurrent-writer coordination; retain one writer per source job.

The fixture suite extracts only relevant functions, mocks upgrade operations and
uses temporary originals/records. It covers release labels advancing early,
strict source/target/original binding, malformed records, private atomic writes,
failed captures, completion/workload distinctions and root-only explicit resume.
It performs no package updates or live server operations.
