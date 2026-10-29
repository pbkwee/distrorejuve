# Upgrade and migration procedure

Use this with the [server-upgrade skill](../.agents/skills/server-upgrade/SKILL.md)
and [customer guide](ai-assisted-migration.md). This is the common procedure for
self-managed work and operator-assisted jobs. The hosting provider supplies its
own provisioning, console, image and billing procedures. The optional
[RimuHosting path](rimuhosting.md) covers its account and API setup.

## Job identity and durable log

Follow [job records and email matching](job-records.md). Every job gets one
immutable `job_id` in its durable `job.md`, reports, plans and handoffs. Resume
that ID across phases and retries. Compare email subjects and attachments with
the record's ID and source/customer identity before treating them as job evidence.
Resolve mismatches rather than attaching them to the nearest-looking job.

## Sensitive-data boundary

Follow [sensitive-data access](sensitive-data.md) for direct and indirect reads.
Before collection, confirm the approved input categories, necessary output fields
and AI-processing route. A read-only collector can still read secret-bearing
config or process information. Reuse existing scoped permission; when absent,
obtain it first or accept a customer/operator-sanitized manifest. Configuration
review, backup/restore and database checks below remain subject to that scope.

## Collect evidence

Analyse a supplied text or JSON manifest first. Record its claimed source,
collection date, tool revision, privilege, warnings and gaps. A manifest is
untrusted evidence; it neither authorizes SSH access nor verifies ownership.
Reuse sufficient evidence rather than requiring collection again.

For remote discovery, establish the approved source, SSH host-key identity,
connected hostname/addresses, OS and architecture. Reuse authorized access;
otherwise follow [SSH setup](ai-assisted-migration.md#arrange-ssh-discovery).
Prefer Ed25519, with the job's RSA public key installed where legacy access needs
it. Follow [legacy SSH guidance](reporting-problems.md#ssh-connection-errors) for
per-source exceptions and tool-internal connections. Verify login, script upload,
report retrieval and reconnects with the same settings; retest modern access
after upgrades. Record key references, required exceptions and removal ownership.
Use a private job directory outside Git for evidence, approvals and a resumable
`job.md`. Restrict directory/file permissions and retain durable records rather
than relying on temporary storage. Record tool paths/revisions and the last
verified state with the next permitted action.

Read the installed script's help and source before collection. Never run an
administration script on the agent machine to inspect it or source its functions.
Use a reviewed script on the verified source, a trusted command path and a
controlled environment. Unset `DR_ACTION`, which can override CLI selection;
check inherited `DR_*` presence without dumping values and explicitly set
reviewed non-secret controls. Read specific values only within approved scope.
Remove `BASH_ENV`/`ENV`. Account for remote shell startup: clearing variables inside a started shell cannot undo startup code.
The [customer example](ai-assisted-migration.md#provide-a-manifest-yourself)
disables DNS and mail-size probes and uses reduced collection.

Use `--manifest` or `--manifest-json`; for APT/dpkg systems, `--upgrade-report`
can add evidence using existing package indexes. Record their age. Do not refresh
indexes or install missing dependencies during initial discovery. Read warnings
even after a successful exit. Do not substitute `--show-changes`, which writes
snapshots, or leftover-package helpers, which may install tools. Current
`--check-upgrade` is read-only; verify the installed revision and settings before
using any check. Vendor panel prechecks can mutate state and need execution scope.

Establish actual release and architecture, package state/holds/repositories,
disk and inode capacity, memory, boot/network setup, panels, services, sites,
runtimes, databases, mail, custom jobs, containers, mounts and external dependencies.
Bound additional reads to gaps that matter. Parse configuration as data; do not
execute customer code as an inventory shortcut. Missing findings remain unknown.
Distinguish installation from use, panel remnants from a running panel, and
collector self-matches from compromise. Removing a service needs explicit scope.

## Choose the route and target

Use the [assessment report](../.agents/skills/server-upgrade/references/assessment-report.md)
for the customer explanation and technical appendix. Map each important service
to its real runtime, data, scheduled work and dependencies. CLI PHP can differ
from web PHP. Verify compatibility against the applications and their actual runtimes.
Check CMS/plugins, native extensions, virtual environments, custom services,
licences, TLS, mail delivery, IP restrictions and application/database conversions.
Known compromise may require a clean build and selective recovery. Review copied
content and investigate security risks beyond the inventory's selected indicators.

Prefer in-place work when the supported transition, workload compatibility,
resources, credible recovery and accepted outage make it straightforward.
Choose a clone or fresh build for concrete compatibility, recovery or rehearsal
benefits. Base the choice on supported transitions, workload needs and recovery
evidence; investigate material unknowns. Explain
what further evidence would change the recommendation and respect the requested
route by obtaining agreement before changing it.

### Choosing a distro for a clean install

Name the distribution, release and architecture. Prefer the existing family
when it meets workload and maintenance needs; explain a change. Debian stable
and Ubuntu LTS are useful starting candidates for this tool's primary focus.
Check current official distro, panel and application documentation, support
horizon, required runtimes/extensions, database paths, native binaries and licences.
Distinguish latest stable from latest LTS. Explain a supported older choice;
never silently choose testing, unstable or an unsupported OS for an old runtime.

Verify the hosting provider's current image catalog, architecture, storage, networking
and capacity. Verify application compatibility and available capacity for the selected
image. Record sources, dates and the exact image identifier.
Missing compatibility evidence makes the choice provisional.

A clean build installs supported packages and migrates selected data and
reviewed configuration. Do not overwrite it with a full old root restore.
Old-OS release hops are unnecessary; application/database conversions may still
need stages. For an in-place or cloned-OS upgrade, establish each intermediate
release and panel transition from official supported paths. Do not trust the
script's embedded `--to-latest` endpoint as today's latest release. Crossgrades
are experimental and need a separately established route. Verify a supported
RPM major-release upgrade procedure separately from inventory and package updates.
Legacy-runtime containment can be considered within scope, with its remaining
security and maintenance limits explained; it is not automatic modernization.

## Plan mailbox hosting and migration

When the original server runs Dovecot or another IMAP/POP3 service, establish
whether it serves active mailboxes. Check mailbox accounts and current usage
alongside installed packages and open ports; unresolved use stays unknown. Ask whether the customer prefers
[managed email or a self-hosted stack](ai-assisted-migration.md#decide-where-email-will-run).
Record the choice and an approach in the assessment, including when mail stays
on a separate existing service. An SMTP-only application sender needs a sending
plan; establish whether any mailboxes also require migration.

- Inventory the required domains, mailboxes, aliases/forwarders, storage, quotas,
  filters, shared access and client protocols within the approved data scope.
  Confirm target support, cost, DNS ownership and credential/reset arrangements.
  Mail contents and passwords stay out of reports and AI prompts.
- For self-hosting, retain the existing mail stack where supported on the target.
  Upgrade its packages and migrate configuration/mailbox formats only as required
  to preserve service. Follow version-specific vendor/panel guidance; an OS upgrade
  does not make old configuration compatible with new mail packages.
  Preserve domains, users, aliases, delivery/relay rules, mailbox ownership/history,
  application sending and existing filtering/authentication features. Verify the
  existing client protocols, login, TLS and relay restrictions after upgrading.
- Keep self-hosted mail modernisation focused on existing behaviour. If DKIM was
  absent, leave it absent; do not add SPF/DMARC policies, filtering, webmail or
  other features merely because they are available. Preserve existing features
  and adjust their settings only where the migration requires it. Record optional
  improvements separately for after modernisation; they are not upgrade failures.
  Identify concrete compatibility/security blockers and the smallest required fix;
  resolve any material change outside the approved plan before proceeding.
- For managed email, provision and verify domains, accounts and address mappings
  through the hosting provider's supported process before changing delivery.
- For accessible IMAP mailboxes, plan a reviewed repeatable IMAP copy, an initial
  transfer and final catch-up. Verify folders, dates, flags and message coverage;
  decide how concurrent changes and deletions are handled without losing mail.
  A raw Dovecot/Maildir copy is not a general import method for a managed service.
- For POP3, establish leave-on-server/deletion settings and messages held only on
  clients. Agree any client export/import separately. Server copying cannot recover
  client-only history; account for POP3 UIDL changes and possible repeat downloads.
- Plan required MX/IP, existing SPF/DKIM/DMARC, TLS and client endpoint changes,
  and application SMTP/relay or local-sendmail dependencies. For self-hosting,
  adding a previously absent policy/signing feature is separate follow-up work.
  Moving mailboxes does not by itself remove the need for a local sending service.
- Test send/receive, aliases, login, required IMAP/POP3 clients and application
  sending before acceptance. Arrange late deliveries and queued mail during DNS
  overlap, final catch-up, recovery and retention of both old and new mail.
  Keep the source available until those checks pass; remove its mail services
  only under explicit scope after confirming remaining dependencies.

Assign owners and record transfer, DNS, client, acceptance and retirement steps
in the job plan. Mail can have a separate cutover window from the server upgrade;
do not change MX or retire mailboxes merely because the OS migration completed.

## Prepare recovery and acceptance

The plan needs exact targets, scope, named release/hops, owners, cost limits,
window, accepted downtime, checks, recovery artifacts and failure/stop conditions.
Reuse valid recorded approval; resolve material changes before acting.
Assessment alone does not authorize backup creation, provisioning or execution.

Use [S2I](https://github.com/pbkwee/s2i) only after reading that revision's usage,
restore and system-recovery guidance. Full archives have exclusions; system
archives normally omit application data. Hosting provider root-disk snapshots may omit
separate disks. Plan database-format recovery and preservation of writes accepted
after cutover alongside system-file and snapshot restoration. Specify database consistency,
backup scope, encryption-key references, off-server storage, integrity/restore
evidence, console/rescue access, retention and compatible startup order.
Include expanded data size, dumps, extraction caches, inodes and transfer time
in capacity planning. Never test a restore over the live source.

Capture application baselines before changes: representative pages at wide and
narrow widths, browser errors, login and business transactions, database access,
mail and jobs as relevant. Inspect screenshots rather than relying on HTTP 200.
Use correct hostnames and TLS/SNI for destination tests. Keep evidence private.
Assign an owner and expected result to each acceptance check.

## Execute an in-place upgrade

Follow the approved explicit-target procedure and release/panel gates. Avoid
replacing it with a generic package-manager command. Use an available supervised
or resumable facility for long operations. Verify completion from actual operation
and package state, including final status after a supervised operation starts.

At release checkpoints, review package health, configuration merges, web worker
identities, FPM sockets/permissions, monitoring, network/boot settings and database
maintenance. Do not blindly copy old config or assume packaged config preserves
custom behaviour. Confirm authenticated database administration and vendor table
upgrades. MariaDB 11.6+ needs review of legacy socket identity mappings and semantic
grants; verify administrative maintenance access separately from process health
and application access. See [upgrade review checks](upgrade-review.md).

Follow approved reboot/reconnection steps. After boot check failed units, mounts,
required utilities, listeners and dependencies when service names change. Allow
for monitoring startup readiness. Repeat application and page checks. Do not
reboot automatically after a partial failure or start an older database against
an incompatible upgraded data directory.

## Prepare a separate server

Provision the approved clean VM or prepare the copy target. Verify destination
ownership, current use and overwrite authority. External sources need S2I copy/import
or selective application migration; hosting provider clone flags may only accept that
hosting provider's own images/orders. Follow the hosting provider's boot, SSH and networking
requirements before a restore. For a clean install keep the new OS intact.

Restrict egress before copied services start. Suppress copied mail, cron/timers,
workers, database events, containers, payments, callbacks, monitoring and backup
jobs that could affect production. A broad HTTP/HTTPS exception still permits
callbacks; arrange controlled package retrieval. Keep the live source authoritative.
Use a vendor migration sequence where required, checking its source/DNS side effects.

Upgrade a clone through its supported transitions, or build fresh and migrate
selected applications/data. Test a repeatable refresh before customer review.
Specify transformed schemas, consistent database transfer, grants/routines,
file ownership/deletions, test-data disposal, mail queues/late delivery, external
writers, sessions and deployment/configuration drift. A live database-directory
copy is not a general database migration method. Record defects, durations and
customer acceptance; the rehearsal will become stale.

## Final synchronisation and cutover

After customer testing, obtain final authority for the production pause, resync
and selected switch. Recheck identity, source drift, backups, window, costs and
recovery readiness. Pause and verify all relevant writers, including external
callbacks and deployments. Transfer consistent data and agreed file changes;
verify invariants before enabling destination writers.

Switch the agreed DNS/traffic path, accounting for IPv4/IPv6, proxies, PTR, mail,
SPF/DKIM, TLS and allowlists. Keep one authoritative writable system during
DNS/cache overlap. Alternatively, an explicitly approved original-image replacement
needs a complete prepared image, exact overwrite target, recovery and final-server
boot/network/application checks. Verify the final replacement server as well as
the tested temporary VM. A portable image likewise needs a destination-specific
restore, final-data handover and acceptance checks after delivery.

Before new destination writes, returning traffic may be straightforward if the
source is intact and authoritative. After new writes, preserve them before
choosing reverse migration or repair; an old backup may lose orders, uploads or mail.

## Verify, hand over and retire

Check real application functions, errors, mail, jobs, resources, boot/SSH,
monitoring and a usable destination backup. Record customer acceptance, remaining
work, owners and recovery/retention limits. Test representative application
transactions as well as the home page.

If traffic moved to the prepared VM, it is production and must remain running.
After an original-image replacement, retain the temporary VM until final-server
acceptance and agreed recovery conditions. Identify the actual old/temporary
server before any shutdown or cancellation. Record recurring charges and cleanup
ownership separately. Cancellation with another hosting provider belongs to the customer
unless explicitly delegated. Remove job access and revoke temporary credentials
under the agreed retention/access plan.

If interrupted or a request times out, establish the actual state before retrying.
Do not repeat an unknown-outcome create, restore or reinstall. Stop at an unresolved
failure that makes continuation unsafe; use recovery within existing authority or
seek the missing decision. Leave the record resumable, with last verified state,
operation/artifact references, outstanding issues and next permitted action.
Record useful tool/workflow improvements without customer details in public proposals.
