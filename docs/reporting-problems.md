# Troubleshooting

- [Download errors on old servers](#download-errors-on-old-servers)
- [SSH connection errors](#ssh-connection-errors)
- [Long-running package lock owners](#long-running-package-lock-owners)
- [Reporting upgrade problems](#reporting-upgrade-problems)

## Download errors on old servers

Old `wget`/OpenSSL versions, such as those on Ubuntu 6.06, can fail with
`SSL23_GET_SERVER_HELLO:unknown protocol` or `Unable to establish SSL connection`.
These clients cannot negotiate modern TLS. `--no-check-certificate` does not fix
that protocol failure, and GitHub redirects plain HTTP downloads to HTTPS.

Download on a newer computer, then copy the file to the old server over SSH.
Replace `OLD_SERVER` with the server's address. Run these commands on the newer computer:

```sh
curl --fail --location --output distrorejuve.sh \
  https://raw.githubusercontent.com/pbkwee/distrorejuve/master/distrorejuve.sh &&
scp -O distrorejuve.sh root@OLD_SERVER:/root/distrorejuve.sh
```

## SSH connection errors

For job-specific access, generate and install the public keys using
[SSH setup](ai-assisted-migration.md#arrange-ssh-discovery). Try Ed25519 alone first;
use the RSA fallback if the server cannot accept Ed25519. An RSA public-key line
starts with `ssh-rsa` even when authentication uses SHA-2 signatures. Generating
an RSA key does not itself enable RSA/SHA-1 on the client.

`scp -O` selects the legacy SCP transfer protocol for old SSH servers. If an older SCP
client does not recognize `-O`, omit it. If SSH also reports a negotiation failure,
add only the required option to the connection:

- If the host-key error offers `ssh-rsa`, add `-oHostKeyAlgorithms=+ssh-rsa`.
- If the key-exchange error offers `diffie-hellman-group14-sha1`, add `-oKexAlgorithms=+diffie-hellman-group14-sha1`.
  Use `-oKexAlgorithms=+diffie-hellman-group1-sha1` only if that is the available method.
- If the RSA login key needs SHA-1 signatures, add `-oPubkeyAcceptedAlgorithms=+ssh-rsa`.
- If the cipher error offers only CBC ciphers, add an offered cipher supported by the client, such as `-oCiphers=+aes128-cbc`.
- If the MAC error requires it, add an offered MAC supported by the client, such as `-oMACs=+hmac-sha1`.

Use a Bash array so copying, login and report retrieval use the same job keys
and options. The identities below list Ed25519 first and RSA second. If both are
loaded in an agent, the agent can affect offer order; the linked Ed25519-only test
establishes the preferred working key. On a modern server, omit the RSA identity.
Run on the newer computer; uncomment only exceptions required by this old server:

```bash
SSH_OPTS=(
  -F /dev/null
  -o IdentitiesOnly=yes
  -i "$HOME/.ssh/server-migration-example"
  -i "$HOME/.ssh/server-migration-example-rsa"
  # -o PubkeyAcceptedAlgorithms=+ssh-rsa
  # -o HostKeyAlgorithms=+ssh-rsa
  # -o KexAlgorithms=+diffie-hellman-group14-sha1
  # -o Ciphers=+aes128-cbc
  # -o MACs=+hmac-sha1
)
scp -O "${SSH_OPTS[@]}" distrorejuve.sh root@OLD_SERVER:/root/distrorejuve.sh
ssh "${SSH_OPTS[@]}" root@OLD_SERVER
```

Replace `OLD_SERVER` with the intended address. Use only the options required by
its negotiation errors. Use the same array for downloads and later reconnects;
`-F /dev/null` excludes user/system SSH configuration. Add any agreed bastion or
known-hosts options explicitly; for a custom port add `-o Port=2222` for both tools.
`-O` selects
the older SCP protocol when the server lacks SFTP; it does not fix SSH algorithm
negotiation. Omit it when unnecessary or unsupported by your local scp client.

The `+` appends legacy algorithms to modern defaults. These methods are disabled
by default for security reasons. Keep exceptions on the individual command and
remove them when the server supports current algorithms. Host-key verification
still applies. An older local client may need `PubkeyAcceptedKeyTypes` instead
of `PubkeyAcceptedAlgorithms`; check its manual if it rejects that option.
Changing a key cannot fix an algorithm removed from the client. Check support
with `ssh -Q key`, `ssh -Q kex`, `ssh -Q cipher` and `ssh -Q mac`. For a server
offering only removed methods such as DSA, use an approved isolated compatibility
client or console-assisted SSH repair; do not disable host verification or
generate a new DSA key. Retest Ed25519 and remove legacy exceptions after upgrading.

A shell array affects only commands that explicitly use it. For a tool that calls
SSH internally, use a narrowly scoped entry for the exact source in trusted SSH
configuration, with `IdentitiesOnly yes`, the required `IdentityFile` entries and
only the tested compatibility options. Keep source exceptions off destinations.
This applies to S2I's `mysqlbackup.sh`: it creates its own RSA backup key and calls
SSH/SCP internally; it does not consume `SSH_OPTS`. Install/verify the public key
for the actual sending account and connection direction, or transfer completed
dumps with the tested client yourself. An old initiating client may need an RSA
private key in PEM format; the old remote server alone does not. See
[S2I's legacy SSH guide](https://github.com/pbkwee/s2i/blob/master/docs/legacy-ssh.md).

See the [OpenSSH legacy connection guide](https://www.openssh.org/legacy.html)
and [scp protocol option](https://man.openbsd.org/scp#O).
After copying, inspect `/root/distrorejuve.sh` on the old server and run
`bash /root/distrorejuve.sh --check-upgrade`.

## Reporting upgrade problems

Unexpected upgrade failures save a small `support-report.txt` beside the private detailed log.
The console prints the report path and the project's issue link.
Expected preflight refusals keep their diagnostic and log path without suggesting an issue.
When a supported option addresses a blocker, the console suggests a retry command for review.
Runs with incomplete service verification also produce this report.

Missing upstream sockets in locally managed NGINX configuration are reported for operator review.
These findings do not stop package upgrades when the required services pass their checks.
The final console summary points to a private `configuration-review.txt` in the run directory.
It lists current web service failures, local configuration review items and checks that could not be completed.
Each item includes the installed distribution and release where it was observed, such as `debian/bookworm`.
Repeated checks update the same issue instead of adding duplicate items.
A later complete check removes issues that are no longer present, even after another release transition.
If the later check is incomplete, earlier items stay in the report as **not reverified**, with their original release.
The detailed log keeps earlier observations; resolved findings do not remain on the final checklist.
One private `php-runtime.findings.tsv` holds the latest check state for the run; files are not split by release.
An interrupted check cannot make an older snapshot appear current.
Symlink targets are checked for package ownership; modified package conffiles count as local settings.
Unchanged package configuration failures, unknown ownership and required service failures still stop the upgrade.
Local configuration review alone does not suggest opening an issue.

Review the file before posting it at [distrorejuve issues](https://github.com/pbkwee/distrorejuve/issues/new).
Describe what you expected, what happened and any manual recovery steps.
Paste the report inside a code block. Remove anything you do not want to publish.
Nothing is uploaded automatically.

If no report was created, for example after an interruption or with an older script, generate one yourself.
Use the latest script copy to get current diagnostics, including for an older run:

```sh
umask 077
sudo bash distrorejuve.sh --support-report /root/distrorejuveinfo/runs/run.EXAMPLE > support-report.txt
less support-report.txt
```

Replace `run.EXAMPLE` with the run directory printed by your failed command.
Keep the original run directory intact. The report distinguishes the collector checksum from the original run checksum.
Older logs may lack the exit status, original checksum or operation-level failure status.
Without a run directory, `--support-report` collects current system facts only.
If a collector fails, the report marks the missing fields and returns a nonzero status.

The report contains script checksums, the upgrade action and exit status when recorded,
the crossgrade/target choice, recorded release/package/service checks and the release codenames those checks covered.
Compare the last verified release with the requested target to identify any remaining release hops.
Available APT update failure phase/status and missing web-socket failures are included as fixed labels.
The support report records whether the latest web checks require review or remain incomplete, without copying paths or file contents.
It also contains current distribution/release, architecture, kernel series, Bash/APT/dpkg versions,
package-state counts, free space and exit statuses from read-only APT policy and upgrade simulations.
The plan counts installation (including upgrades), removal, purge and configuration operations.
Simulation counts describe the currently configured indexes; zero planned changes means that simulation found no changes.
Verify the requested release, package completion and service health from their recorded checks.
Current system facts describe collection time; they are not the original pre-upgrade baseline.
Known stage/error messages become fixed category labels. The report does not copy log excerpts.
Bookworm crossgrades distinguish inventory, replacement checks and bootstrap,
remaining-package and cleanup planning. Failed simulations report the phase and
APT exit status separately from current-system probes. Older failures can identify
the phase while leaving the original exit status unknown.
An observed error category can refer to an earlier failed attempt within the run; use the latest matching check to determine the current state.

For a failed crossgrade plan, retain the matching `bootstrap.plan`, `remaining.plan`
or `cleanup.plan` and its `.arguments.new` file from the inventory directory printed
in the log. These files describe that simulation, including the arguments used.
Use the failed phase's plan to explain that failure. Simulation removals are
proposals; check transaction records for executed removals. Keep these files
private and review them before sharing with a maintainer.
If remaining-package planning cannot select another safe native dependency,
a read-only `apt-get check` saves current installed-package diagnostics in
`remaining.installed-check.log` beside that plan. A failed check identifies a
current package-state problem; compare earlier package checks to determine when
it began. No automatic
dependency repair or mail-package removal is attempted.

The report omits hostnames, IP/email addresses, repository URLs, usernames, installed package lists,
application inventories, environment values, arbitrary paths and configuration contents.
It performs no network requests, package changes or service changes.
Software versions and system-state counts are still information about your system, so review them before publication.

For application inventory questions, `--manifest --redact` or `--manifest-json --redact`
creates an inventory with server and website identifiers replaced. Review it before
sharing; see [inventory privacy](inventory.md). General configuration facts remain visible.

**Do not attach detailed logs, Bash traces, unredacted manifests, upgrade reports, configuration comparisons or backup archives to a public issue.**
Those private files can contain credentials, domains, customer information and application data.
The minimal report supports initial diagnosis; a maintainer may need additional carefully reviewed information.

## Long-running package lock owners

Before package-changing actions (including panel updaters and pending recovery),
release-upgrade preflight, index refreshes, ordinary APT transactions and wrapped
dpkg installs, distrorejuve checks kernel write locks on the four standard
APT/dpkg lock paths. An owner running for at least one hour triggers a warning
with its PID, parent PID, process name and runtime. Process arguments are omitted.
Runtime starts when the process starts; lock acquisition time is unavailable.

Check the named process's progress and current lock ownership before using the
suggested `kill -TERM PID` command. Interrupting installation/configuration can
leave packages unfinished. The script never stops the owner or removes a lock
file. Warnings leave operation status unchanged, and APT/dpkg still enforce their
locks. Missing/unreadable lock or process metadata yields no age warning.
