# Vendor checks within ordinary upgrades

A vendor can publish packages for different distro releases with the same
name, version and architecture. A version-only check cannot identify the installed
build. Review the exact target artifact and at least one package-owned payload
file whose bytes distinguish the accepted build. Preserve the previous artifact
and the failed acceptance evidence for reconciliation.

Use this facility only after the normal vendor/application review and a successful
signed APT refresh. It does not add a publisher-wide exception, change repository
files, install packages or grant permission to read unrelated files. Keep the
approved source/keyring/artifact/payload paths and purpose in the private job.
The standalone script includes every check; it does not need this checkout's
other files or Python on the source.

## Agent-maintained acceptance metadata

The upgrade agent runs covered discovery commands and prepares the necessary
private acceptance metadata from the reviewed signer, signed package metadata
and selected target artifacts. Operators approve the vendor, target and scope;
they do not need to assemble TSV files or run an extra check command. The normal
source/readiness checks validate this evidence before a transition, and normal
current-release/completion checks validate the installed build afterward.

For agent/developer reference, `DR_REVIEWED_VENDOR_CONTRACT` selects an absolute,
root-owned evidence file with mode
`u=rw,go=`. Its directories must be root-owned, unwritable by group/other users
and free of symlink ancestors. Keep it with the protected source-local job record.
The contract is TSV with literal tabs, no header, and no empty fields. It accepts
at most 256 rows and 64 KiB. Do not include credentials or raw configuration.

A `source` row has these 15 fields:

| Field | Meaning |
| --- | --- |
| `source` | Literal row type. |
| ID | Unique simple identifier shared by this source's build rows. |
| URI | Exact reviewed HTTPS repository URI, without credentials or query strings. |
| Suite | Exact active APT suite and expected signed `Codename`. |
| Components | Exact component string and order from the active source. |
| Family | `debian` or `ubuntu`. |
| Target | Exact intended distro codename. |
| Keyring | Absolute path to the sole `Signed-By` keyring. |
| Keyring SHA256 | Lowercase SHA256 of the reviewed keyring bytes. |
| Signer fingerprint | Uppercase 40- or 64-character signing or primary-key fingerprint. |
| Origin | Exact signed Release `Origin`. |
| Label | Exact signed Release `Label`. |
| Series | Exact signed Release `Suite`. |
| Cached InRelease | Absolute path to the signed metadata for this repository after the normal APT refresh. |
| Maximum age days | Reviewed metadata-age bound from 1 to 366 days, without leading zeroes. |

The source checker matches the active URI, suite, components, family and target.
It reads signing options from that exact source record. Only one literal keyring
is supported; inline keys, multiple keyrings, trust overrides and unknown one-line
options remain blocked. Normal architecture filters are retained. The keyring
must match its reviewed digest. `gpgv` must verify one valid signature from the
reviewed fingerprint. Signed Origin, Label, Suite and Codename must match exactly.
Future timestamps, expired signatures/keys, expired `Valid-Until` values and
metadata older than the reviewed age bound fail. A missing `Valid-Until` does not
remove the separate maximum-age requirement.

A `build` row has these 10 fields:

| Field | Meaning |
| --- | --- |
| `build` | Literal row type. |
| Source ID | The matching `source` ID. |
| Package | Exact package name without an architecture suffix. |
| Architecture | Exact target architecture. |
| Version | Exact package version. |
| Archive | Absolute path to the reviewed `.deb` artifact. |
| Archive SHA256 | Lowercase SHA256 from the authenticated, reviewed package metadata. |
| Payload | Absolute path to a discriminating file owned by the installed package. |
| Payload SHA256 | Lowercase SHA256 of that exact path's bytes in the reviewed archive. |
| Target | The matching source row's distro codename. |

Each source needs at least one build row. Add further rows for additional
packages or discriminators. The artifact is bounded to 512 MiB and the installed
payload file to 256 MiB. Files must be regular, single-link, root-owned and
unwritable by group/other users, with root-controlled ancestors. Symlink payloads
need a separate reviewed check and are not accepted here.

The checker verifies the artifact digest and its actual package control fields.
It hashes the selected member directly from the archive stream without extracting
or running package code. At final acceptance, the installed file must have the
same hash, belong to the expected package, and have the expected installed
version/architecture. This verifies the explicitly selected build discriminators;
it is not a full filesystem or all-package-payload audit. Select a file that
actually differs between the old and intended distro builds. Do not choose an
unchanged generic documentation file as build evidence.

## Check before and after the transition

Use the contract during the ordinary reviewed release transition. When a target
is selected, source policy validates its exact identity and approved artifact
before package changes. A current-release/final source-policy check also validates
the installed payload. Removing or disabling the source does not skip the
contract's final assertions: each selected source must still be present.

A same-version wrong-distro build remains an acceptance failure. The agent
prepares the matching-build reinstall through ordinary approved package commands,
checks the exact artifact and dependency/removal plan, and keeps recovery and
future maintenance ownership in the job. Normal readiness/package verification
rechecks the selected evidence; a separate operator check action is unnecessary.

The native source policy still blocks unreviewed vendors. Keep the job's reviewed
evidence selected through final checks and handoff. Disabled or removed sources
cannot conceal failed target-build assertions.

## Dependency replacements in the normal package plan

Ordinary APT simulation and dependency planning select t64 library replacements.
The package wrapper reports verified matching replacements before execution,
using the existing candidate and Provides/Replaces checks. It does not request
another plan file, grant removal authority or weaken an existing no-removal gate.

For a separately controlled application transition whose no-removal rule blocks
an expected dependency replacement, the agent reviews the exact signed native
APT plan, performs that covered dependency change with ordinary package commands,
verifies package health, then records a separately identified application retry.
Preserve the original failed stage and its no-removal protection. The customer
should see the consequential dependency change and any decision needed, rather
than an instruction to run an internal diagnostic helper.

## PowerDNS settings at the relevant version boundary

Use [PowerDNS upgrade handling](pdns-upgrades.md). Ordinary readiness/reporting
detects removed role names and explains the affected version boundary. The
explicit migration setting authorizes the narrow name conversion during the
selected package transition; users do not prepare a role-projection file.

## Offline checks

```bash
python3 tests/test-reviewed-vendors.py
python3 tests/test-package-compatibility.py
```

The vendor suite creates a temporary signing key, signed Release metadata and a
synthetic `.deb`. It tests real signature rejection and equal-version/different-
payload acceptance without network access, package installation or a persistent
database. It skips that integration fixture when existing GnuPG/package tools are
unavailable. Run the focused upgrade, capacity and usrmerge suites as appropriate.
