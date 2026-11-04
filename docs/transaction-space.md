# Package transaction space

The fixed `DR_MIN_FREE_DISK_MIB` floor remains a preliminary check. Ordinary APT
mutations also obtain a fresh simulation with the exact execution arguments
before each attempt. The peak check reads the chosen package versions and
architectures, requires exact `apt-cache show` download and installed sizes, and
matches previously installed versions and sizes with `dpkg-query`. Missing or
unfamiliar plan, package metadata, filesystem identity or free-space evidence
stops the transaction. Every retry obtains new evidence; an earlier successful
check does not authorize a different plan.

The estimate includes the full candidate archive size, positive installed growth,
the largest candidate installed size as an old/new unpack reserve, and a separate
kernel/initramfs reserve on `/boot`. It does not credit package removals or cached
archives: their safe reuse and timing are not established by this evidence. The
package indexes do not describe the destination of every file, so the complete
growth and unpack allowance is conservatively reserved once on each distinct
payload filesystem reached through `/`, `/usr`, `/var`, `/opt`, `/lib`,
`/lib/modules`, and `/var/lib/dpkg`. The cache allowance goes to
`/var/cache/apt/archives`; the kernel/initramfs allowance goes to `/boot`.
Missing directories are resolved to their nearest existing parent. Device IDs
combine allowances for paths on the same filesystem. Free space is measured
separately for every path and the smallest reading for a shared device is used.

Required available bytes on each filesystem equal:

```
retained floor + assigned peak bytes + ceil(assigned peak bytes * safety / 100)
```

`DR_MIN_FREE_DISK_MIB` defaults to 2048, `DR_MIN_FREE_BOOT_MIB` to 128,
`DR_DISK_SAFETY_PERCENT` to 20, and
`DR_KERNEL_INITRAMFS_RESERVE_MIB` to 512. All must be positive integers; safety
is limited to 1000 percent. Increase the kernel/initramfs reserve for hosts with
large images, several kernels, or unusually large initramfs files. A separate `/boot` retains the smaller boot floor. When `/boot` shares a
payload/cache filesystem, that filesystem retains its ordinary floor once. The
retained floor is not consumed as part of the estimated transaction. Review nested/custom
package mounts and maintainer-script/application scratch requirements separately;
package metadata cannot bound arbitrary hooks. The printed estimate identifies
these assumptions and each measured filesystem's required/available bytes.

The existing explicit `DR_SKIP_DISK_SPACE_CHECK=true` escape hatch disables peak
checks too. Review and record any override rather than silently lowering a failed
estimate. Without it, an unknown estimate stops the guarded mutation.

The check uses `apt-config shell` with the execution command's exact `-o`/`-c`
settings to establish effective archive placement. A missing/unreadable setting or
archive directory other than `/var/cache/apt/archives` stops the guarded action;
custom placement requires a reviewed filesystem model. The mutation guard rejects
print, simulation, help and download-only action modes. Before the specialized
PHP download-only step, a matching full install simulation conservatively budgets
space for the subsequent complete transaction before any cache writes.

Coverage includes `apt_get_apply` and fresh checks on the specialized PHP
handoff download/remove/reinstall paths, controlled incompatible-package purge,
and the direct crossgrade upgrade/fix-broken APT paths. The check itself never
executes the selected package transaction. Simulation/help/archive download
commands are not rewritten as mutating APT operations. Legacy raw `dpkg` bootstrap
and crossgrade unpack commands, standalone downloads outside the guarded PHP
handoff, RPM transactions, and raw `dpkg --configure` paths retain their existing
floor checks and operational controls; they do not acquire a metadata-derived
peak guarantee from this change. Native planner reports are not directly parsed
as APT summaries: actual execution needs a fresh successful simulation.

The isolated regression file extracts only function declarations. Synthetic
package plans and mocked APT/dpkg/filesystem commands cover shared/separate
filesystems, retained floor, insufficient cache space, malformed evidence,
version mismatches, plan changes, and preventing execution after a failed guard.
No system package operation is used for these checks.
