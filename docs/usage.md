# Main options

| Option | Purpose |
| --- | --- |
| `--check-upgrade` (or no argument) | Read-only review of the current distro, intended newer release and known upgrade blockers. RPM major-release upgrades require a reviewed migration procedure. |
| `--upgrade` | Update native APT or DNF/YUM packages. End-of-life CentOS requires an explicit repository/migration choice below. |
| `--capture-baseline` | Capture the selected private original before preparatory changes; requires root and `DR_CONFIG_BASELINE`. Preserves existing usable originals and refuses incomplete attempts. |
| `--dist-update` | Perform a full package upgrade on the current release. |
| `--to-latest` | Upgrade through successive releases to Debian stable or the latest Ubuntu LTS. |
| `--to-debian-release VERSION` | Upgrade Debian to a specific release. |
| `--to-next-ubuntu` | Upgrade Ubuntu to its next release, or next LTS when starting from an LTS. |
| `--crossgrade` | Add to a release upgrade to permit i386 → amd64 conversion at the last native i386 LTS, then continue. Requires a running x86_64 kernel. |
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

## Release upgrades from i386

Native i386 upgrades stop at **Debian 12 (bookworm)** or **Ubuntu 18.04 LTS
(bionic)**. Upgrades to those releases can remain 32-bit. A later target requires
`--crossgrade`, a running x86_64 kernel and the other preflight checks.
Selecting `--crossgrade` permits conversion when the target needs it; it does not
force conversion for a target that still supports native i386.

For Ubuntu, an approved upgrade from 14.04 follows this sequence:
**14.04 → 16.04 → 18.04 → convert to amd64 on 18.04 → 20.04 → later LTS releases**.
The conversion runs and is verified before 20.04 repositories are selected.
Ubuntu [dropped i386 host support in 19.10](https://documentation.ubuntu.com/release-notes/20.04/#upgrades-on-i386),
so the checkpoint uses the preceding LTS, rather than crossing that boundary
with 32-bit packages. A source already past the checkpoint with native i386
needs a separately reviewed repair or migration path.

Ubuntu crossgrades remain experimental and additionally require
`DR_ENABLE_UBUNTU_CROSSGRADE=true`. After reviewing the plan, backups, recovery
and prerequisites, the combined option is:

```sh
DR_ENABLE_UBUNTU_CROSSGRADE=true bash distrorejuve.sh --to-latest --crossgrade
```

A 32-bit kernel still blocks this command, even if the CPU supports 64-bit.
Arrange and verify the 64-bit boot path first. Failed or incomplete conversion
stops the release upgrade before the next release's repositories are selected.

Run `bash distrorejuve.sh --help` for all options.
Upgrade commands keep private detailed logs in `/root/distrorejuveinfo/runs` and show concise progress.
Add `--verbose` to display command output, or `--trace` to retain a separate Bash trace.
