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
