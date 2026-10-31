# Main options

| Option | Purpose |
| --- | --- |
| `--check-upgrade` (or no argument) | Read-only review of the current distro, intended newer release and known upgrade blockers. RPM major-release upgrades require a reviewed migration procedure. |
| `--upgrade` | Update native APT or DNF/YUM packages. End-of-life CentOS requires an explicit repository/migration choice below. |
| `--dist-update` | Perform a full package upgrade on the current release. |
| `--to-latest` | Upgrade through successive releases to Debian stable or the latest Ubuntu LTS. |
| `--to-debian-release VERSION` | Upgrade Debian to a specific release. |
| `--to-next-ubuntu` | Upgrade Ubuntu to its next release, or next LTS when starting from an LTS. |
| `--crossgrade` | Add to a release upgrade to permit i386 → amd64 conversion at the last native i386 release, then continue. Requires a running x86_64 kernel. |
| `--to-64bit` | Attempt an experimental crossgrade from 32-bit to 64-bit. |
| `--support-report [RUN_DIRECTORY]` | Print a minimal report for a public bug report. Review it before posting. |
| `--upgrade-report` | Collect a read-only developer handover with package, repository, configuration and application facts. |
| `--manifest` / `--manifest-json` | Report applications, service state, websites, mail storage and migration hints as text or JSON (dpkg or RPM). |
| `--redact` | Add to `--manifest` or `--manifest-json` to replace server/website identifiers while retaining general inventory facts. Review before posting; see [inventory privacy](inventory.md). |
| `--show-changes` | Report differences from the pre-upgrade configuration and system state. |
| `--list-leftover-packages` | List packages left over from older releases or architectures. |
| `--remove-leftover-packages` | Remove those leftover packages. |
| `--remove-deprecated-packages` | Remove packages left over from older releases. |
| `--pause` / `--resume` | Pause or resume a running upgrade at its next pause check. |

Run `bash distrorejuve.sh --help` for all options.
Upgrade commands keep private detailed logs in `/root/distrorejuveinfo/runs` and show concise progress.
Add `--verbose` to display command output, or `--trace` to retain a separate Bash trace.
