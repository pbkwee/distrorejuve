# Manifest privileges

`--manifest` and `--manifest-json` can run as a non-privileged user.
Non-root users automatically get reduced collection. The script never invokes sudo automatically.

| Information | Non-privileged collection | Root collection |
| --- | --- | --- |
| Packages, runtimes and websites | Collects installed packages and readable configuration and application metadata. | More configuration and application files may be readable. |
| Listeners | Reports addresses and ports; process ownership is unknown. | Also collects process names where available. |
| Service state | Infers running state from visible process names and enablement from available SysV startup links. | Also uses native service-status and enablement checks where available. |
| Mail storage | Reports discoverable paths; skips size scans and spool counts. | Performs bounded measurements unless disabled. |
| Scheduled jobs and migration paths | Private cron jobs and unreadable paths may be omitted. | Can inspect more private paths, including root's cron files. |

Text and JSON output warn when collection is unprivileged. Missing results are unknown;
they do not prove that a service or application is absent. Root collection also has scan
limits and can return incomplete results.

For fuller visibility, run as root or explicitly use `sudo bash distrorejuve.sh --manifest`.
When already root, use `bash` directly.

Add `--unprivileged` or set `DR_UNPRIVILEGED=true` to force reduced collection,
including when running as root. This restricts collection operations; it does not drop
root privileges or hide files root can read.
