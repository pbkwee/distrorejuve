# Application transition preparation

Use the approved plan and [execution evidence helper](execution-evidence.md)
before stopping the workload. Inventory and rehearse the exact target build,
metadata, compatibility, listener bindings and recovery boundary. An application
transition is complete only after its functional and database acceptance checks.

## Database consistency and frontend readiness

Use the designated maintenance client and explicitly select its approved
database. `database-engines` returns engine/count/size metadata only. Mixed or
unverified engines need an agreed consistency method; a transaction-only dump
cannot be described as covering MyISAM. Preserve unknown coverage when metadata
access fails. This guidance does not itself authorize a dump, stop or restore.

For ProxySQL, compare the approved runtime/disk projections with `proxysql-state`.
Its limited comparison excludes credentials, application queries, rule-match
expressions and unrestricted global settings. Record those coverage limits and
use workload-specific acceptance for routing behavior. Account for normalized
frontend/backend user rows and NULL/empty schema representation.

`systemctl start` can finish before Admin SQL is ready. Run `client-ready` after
the approved startup and before interpreting client connection failure as a
transition failure. Only recognized connection startup errors receive bounded
retries; authentication and SQL failures stop immediately.

Retain the complete expected listener list and use `listeners` during rehearsal
and after activation. An old configuration may omit protocols introduced by a
new release. ProxySQL PostgreSQL frontend/admin defaults were one example; empty
interface values did not disable those listeners. Verify the target's supported
UNIX-only/private bindings before exposing it. Keep an approved network namespace
or bind guard during rehearsal so acceptance does not itself permit public binds.

## Permissions before an application upgrade

Scope restrictive umasks to private records and recovery artifacts. Select the
reviewed application umask only for deployment children. Before checkout or
replacement, save metadata for the explicitly approved code paths:

```bash
python3 scripts/execution-evidence.py capture-modes --root /srv/application \
  --paths /protected/job/code-paths.json --receipt /protected/job/code-modes.json
```

`code-paths.json` is a list such as `["index.php","lib/component.php"]`.
The helper adds their existing parent directories. It reads metadata only,
without recursively discovering application data or reading file contents.
Symlinks, hardlinked files, escapes, `.git` paths and special objects require
separate handling. Keep configuration and mutable data outside replacement scope.

After replacement, restore the saved modes:

```bash
python3 scripts/execution-evidence.py restore-modes --root /srv/application \
  --snapshot /protected/job/code-modes.json \
  --receipt /protected/job/code-modes-restored.json
```

This includes existing directories removed and recreated by Git. The helper
validates all selected types and owners before applying modes, holds no-follow
descriptors and refuses ownership changes or symlink redirection. It restores
no deleted content. Newly introduced paths need the approved deployment policy;
they have no invented old mode.

Before schema work, run actual application-account read/traversal checks, for
example through the existing approved account-switch mechanism:

```bash
python3 scripts/execution-evidence.py check \
  --receipt /protected/job/application-access.json -- \
  sudo --user=webapp -- test -r /srv/application/index.php
```

Use the real approved account and necessary entry points. Check configured data
write access separately. A mode snapshot alone does not verify ACLs, runtime
configuration or application functionality.

## Supported bundled-component replacements

Compare old and new bounded component/version maps, for example
`{"bundled_v1":"1","custom_plugin":"5"}` and
`{"bundled_v2":"2","custom_plugin":"5"}`. An upstream-supported bundled
replacement may legitimately remove an old version marker. Missing custom
components remain a failure.

```bash
python3 scripts/execution-evidence.py components \
  --before /protected/job/components-before.json \
  --after /protected/job/components-after.json \
  --replacements /protected/job/reviewed-replacements.json \
  --migration-root /srv/reviewed-target \
  --receipt /protected/job/components-result.json
```

The private reviewed replacements file is a list:

```json
[{"old":"bundled_v1","new":"bundled_v2","from_version":"1","to_version":"2",
  "approval":"<reviewed official migration reference>",
  "migration_file":"lib/db/upgrade.php","migration_sha256":"<pinned file SHA256>"}]
```

The helper checks exact old/new versions and the actual bounded migration-file
hash. Review that pinned official code first; a hash or supplied application
claim cannot establish that a migration is supported. Unreviewed custom losses
are not covered by this exception.

## Allocated temporary swap

Choose temporary source preparation in the approved plan. Keep payload files
off the coordination runner. On the selected source with existing Python 3.7+,
the helper can allocate an explicitly named file without installing dependencies:

```bash
python3 scripts/execution-evidence.py prepare-swap \
  --path /root/approved-job/temporary.swap --size-mib 512 \
  --receipt /root/approved-job/swap-prepared.json
```

It uses exclusive zero-filled allocation rather than assuming `fallocate` works
on ext3. It checks parent control, free space with a 64 MiB reserve, exact size,
allocated blocks and private permissions. The maximum requested size is 16 GiB.
No mkswap, swapon, fstab edit or service change occurs. Confirm these results and
perform separately approved formatting/activation. Verify activation again after
each intermediate reboot; this temporary file is deliberately nonpersistent.

If an exact completed allocation already exists, pass
`--existing-receipt /root/approved-job/swap-prepared.json` with a new receipt
output. Device/inode, path, size, permissions and allocated blocks must still
match. Partial or unreceipted files are preserved and refused for explicit
reconciliation. Never truncate an existing swap file as a retry. On older sources
without Python, apply an approved equivalent zero-filled allocation and metadata
checks through the existing source tooling; do not install an interpreter merely
to use this optional helper.
