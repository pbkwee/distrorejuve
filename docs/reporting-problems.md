# Reporting an upgrade problem

Unexpected upgrade failures save a small `support-report.txt` beside the private detailed log.
The console prints the report path and the project's issue link.
Expected preflight refusals keep their diagnostic and log path without suggesting an issue.
When a supported option addresses a blocker, the console suggests a retry command for review.
Runs with incomplete service verification also produce this report.

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
A verified intermediate release does not mean that the final requested release was reached.
Available APT update failure phase/status and missing web-socket failures are included as fixed labels.
It also contains current distribution/release, architecture, kernel series, Bash/APT/dpkg versions,
package-state counts, free space and exit statuses from read-only APT policy and upgrade simulations.
The plan counts installation (including upgrades), removal, purge and configuration operations.
Simulation counts describe the currently configured indexes; zero planned changes does not prove the requested upgrade completed.
A current release label or clean package database does not establish successful release, package and service verification.
Current system facts describe collection time; they are not the original pre-upgrade baseline.
Known stage/error messages become fixed category labels. The report does not copy log excerpts.
An observed error category can refer to an earlier failed attempt within the run; it does not prove a current fault.

The report omits hostnames, IP/email addresses, repository URLs, usernames, installed package lists,
application inventories, environment values, arbitrary paths and configuration contents.
It performs no network requests, package changes or service changes.
Software versions and system-state counts are still information about your system, so review them before publication.

**Do not attach detailed logs, Bash traces, manifests, configuration comparisons or backup archives to a public issue.**
Those private files can contain credentials, domains, customer information and application data.
The minimal report supports initial diagnosis; a maintainer may need additional carefully reviewed information.
