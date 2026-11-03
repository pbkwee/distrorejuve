# Owner and sysadmin handoff evidence

Use this after approved package, configuration, service or application changes,
including cleanup and reboot. Keep the same immutable job ID, original evidence
and source identity. Follow [sensitive-data scope](sensitive-data.md) and the
[before/after review](upgrade-review.md#beforeafter-review). These commands
collect evidence; successful exit statuses do not establish business acceptance.

## Capture on the verified source

Run through the job's established SSH connection, after verifying hostname,
addresses and host keys. Use the exact reviewed tool artifact recorded for the
job. Replace the example paths with verified source-local paths. Create a fresh
private evidence directory for each checkpoint; never overwrite the original.
The commands below are for Debian/Ubuntu. They write report files and temporary
reporting state, but do not authorize package removal or a new upgrade.

```bash
tool=/root/upgrade-tools/reviewed-distrorejuve.sh
evidence=/root/upgrade-evidence/final-01
run_directory=/root/distrorejuveinfo/runs/recorded-upgrade-run
umask 077
mkdir -- "$evidence"
chmod u=rwx,go= -- "$evidence"

hostname
ip -brief address
sha256sum -- "$tool"

env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin DR_MANIFEST_DNS=false NO_COLOR=1 \
  bash "$tool" --upgrade-report > "$evidence/upgrade-report.private.txt" 2>&1
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin NO_COLOR=1 \
  bash "$tool" --support-report "$run_directory" > "$evidence/support-report.txt" 2>&1
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin DR_UPGRADE_MANIFEST=false \
  DR_MANIFEST_DNS=false DR_MANIFEST_MAIL_METRICS=false NO_COLOR=1 \
  bash "$tool" --show-changes > "$evidence/show-changes.private.txt" 2>&1

dpkg --audit > "$evidence/dpkg-audit.txt" 2>&1
dpkg-query -W -f='${Package}\t${Architecture}\t${Status}\t${Version}\n' \
  > "$evidence/package-states.tsv" 2> "$evidence/package-state-errors.txt"
apt-get -s dist-upgrade > "$evidence/package-plan.private.txt" 2>&1
systemctl --failed --no-pager --plain > "$evidence/failed-units.txt" 2>&1
ss -lntH > "$evidence/listeners.txt" 2>&1
cat /proc/sys/kernel/random/boot_id > "$evidence/boot-id.txt"
```

Inspect and record each command's exit status before continuing; a sequence's
last exit status is not evidence that earlier commands succeeded. Do not use
`--list-leftover-packages` as a read-only substitute: the legacy helper can
install dependencies. Do not use `--check-upgrade` as final acceptance: it is
readiness for a prospective upgrade, with a potentially different target.

Confirm that `--show-changes` selects the recorded original job baseline, using
its path, date and source association. Its default history window can expire or
include unrelated baselines. If the correct baseline is unavailable, disclose
that and compare the recorded job evidence separately. Do not manufacture one
from the changed server. Capture pre-reboot evidence, then repeat relevant
checks after reboot and verify that the boot ID changed.

Where full application collection is approved, also capture the explicit JSON
manifest before and after changes:

```bash
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin DR_MANIFEST_DNS=false \
  DR_MANIFEST_MAIL_METRICS=false NO_COLOR=1 \
  bash "$tool" --manifest-json > "$evidence/manifest.private.json" \
  2> "$evidence/manifest-errors.private.txt"
```

Check its exit status, JSON validity, warnings and `probe_status` records. An
exit-zero inventory can be partial. `DR_UPGRADE_MANIFEST=false` controls automatic collection,
not this explicit command. Permission for metadata alone does not cover every
manifest collector's configuration, scheduled-job and application inputs.

The manifest includes `package_state` records with complete package selection,
current state, architecture and version. On APT systems, `package_review`
records report unavailable/obsolete/transitional or incomplete packages from
existing indexes, with freshness and removal safety unverified. Use the original
and final records to identify removed tools and changed runtimes. An older
collector lacking these records is a coverage gap, not evidence that every
package was added. Keep raw config/state diffs private; extract only the approved
non-secret fields before AI processing. A support report is also subject to review.

Use workload-specific configuration validation and approved application checks
after collecting these facts. Verify the protocol behind changed listeners,
actual daemon state, authenticated maintenance where relevant, useful endpoints,
scheduled work and external dependencies. Port 443 alone is not TLS acceptance;
an active/exited wrapper is not a running authentication daemon.

## Write the two reports

For the **owner report**, explain the resulting service, interruptions, material
behavior/runtime changes, existing faults repaired, remaining risks and specific
acceptance work with owners. State what remains unchanged when it matters, such
as a manually maintained runtime. Use customer-readable effects; leave package
lists and command output in the technical evidence. Do not equate technical
completion with owner acceptance or send the report without communication authority.

For the **sysadmin report**, include source/job identity, original and final
artifact references, tool revision/hash, commands and outcomes, package/runtime
changes, retained unavailable packages, configuration replacements, actual
service/listener state, boot/network verification and recovery references.
Separate proven changes, pre-existing faults, suspected regressions and unknowns.
Record deferred cleanup, reason, dependency/application checks and owner using
the [cleanup guidance](upgrade-review.md#package-cleanup-at-completion).

After any subsequent repair or cleanup, rerun the affected evidence and acceptance
checks, revise both reports where the outcome changes, preserve earlier revisions,
and update `job.md` and the private improvement list. Broad report regeneration
does not grant new data access or permission for a destructive test.
