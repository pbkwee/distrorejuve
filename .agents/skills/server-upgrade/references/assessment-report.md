# Initial upgrade assessment report

Issue this report only after receiving a usable source-associated manifest or
successfully collecting source inventory. If neither is available, give a short
access/collection status with the blocker and next action, and retain resumable
job notes. General upgrade research, a successful login alone and another
server's configuration are not a substitute. An operator-supplied manifest is
enough to begin without SSH; a source-based report may identify remaining gaps.

Write for two readers: the customer deciding what to do, and the sysadmin or
agent preparing the work. Scale detail to the actual setup. A small, well-understood
upgrade should produce a short report. Do not pad it with irrelevant risks or
copy the raw manifest into the customer explanation.

Put the assigned `job_id` and report revision in the report header. They must
match the durable [job record](../../../../docs/job-records.md). Keep request,
ticket and VM identifiers distinct from the job ID.

Provide a complete customer assessment that the operator can forward. It must
stand alone without raw manifests, runner paths or another chat. Put detailed
commands, access troubleshooting and collector diagnostics in a separate
technical appendix. Link both artifacts from the private job record and keep
their job ID, revision, recommendation and unresolved conditions consistent.
Distinguish the report date from the evidence date when reusing an assessment.

## Customer explanation

Use plain English, short paragraphs and descriptive headings. Explain technical
terms when needed: for example, a runtime is the software that runs the website's
code. Keep useful names and versions, but explain their effect on the customer.
The customer should understand the recommendation without reading commands or
looking up an acronym.

Cover these questions in this order, combining sections for simple cases:

1. **What do we recommend?** Name the source and proposed target, the recommended
   route and its main reason. Name the decision-changing issue near the
   recommendation when one remains.
2. **What is there now, and what would change?** Describe the server's jobs:
   websites, email, stored data, scheduled work and business-critical applications.
   Start with a human-readable bullet list of websites grouped by application,
   mail/database services and other active workloads. Give the upgrade implication
   for each. State current/target distribution and architecture, with an explicit
   crossgrade needed yes/no. Use a small comparison table where useful:

   | Service or component | Current setup | Proposed change | What this means for you |
   | --- | --- | --- | --- |

   Include the OS and relevant application/database/panel versions. Distinguish
   observed, customer-reported and inferred facts; mark missing facts as unknown.
   Say what should continue unchanged and what users may need to do differently.
   List the primary hostname for every configured website, grouped by
   application. Show where DNS points and whether HTTPS is configured on the
   source, with the observed HTTPS result for that hostname. Highlight
   certificate errors and relevant expiry dates. Group aliases with the same
   result and name any with a distinct destination, certificate issue or cutover.
   Distinguish currently live sites from inactive retained applications.
   Describe [mail activity](#assess-mail-activity) for each role found or unknown.
   Name [retirement candidates](#identify-retirement-candidates), the proposed
   treatment and any customer decision needed before leaving them out of scope.
   Default to preserving the live sites and their behaviour while
   leaving inactive sites and applications inactive. File presence, an installed
   runtime or an exited startup wrapper is not proof of live use. Note required
   symlink targets and separate retention decisions; do not infer deletion or
   reactivation authority from inactivity. Keep uncertain activity unknown and
   name the missing check instead of proposing to disable that site.
   Explain relevant support/security changes from current official evidence,
   including application updates needed alongside the OS change. State those
   application tasks directly.
3. **What are the particular risks?** Explain the few material risks supported
   by this source's evidence. For each, connect the observed condition to the
   proposed change, the possible customer impact, the proposed check/remedy,
   and the uncertainty left afterward. Link the technical evidence in the appendix.
   For example, if an old site requires a removed PHP feature, explain that the
   site may fail under the new PHP version and needs compatibility work and tests.
   Identify the application feature or code dependency before describing it as a blocker.
   Separate demonstrated blockers, plausible untested compatibility risks and
   missing evidence. Avoid invented probabilities or generic high/medium labels
   without an explanation. Mention data loss, boot/remote-access failure or mail
   disruption where this server's data, configuration or recovery gaps warrant it.
4. **Why this route?** Compare in-place and separate-server work using the rules
   below. Explain the production outage, opportunity to test, extra work/cost and
   recovery limits. Keep elapsed work time, service interruption and labour separate;
   give assumptions or say an estimate is not yet justified.
5. **What remains and what happens next?** Distinguish the automated OS upgrade
   from application fixes, configuration, data transfers and customer checks.
   Name owners, unresolved scope/costs, prerequisites and the next decision.
   Explain backup coverage and recovery limits in ordinary language. An assessment
   is not permission to make changes, buy resources or send customer messages.

## Follow up on workloads

A source-associated manifest can support a short provisional assessment. For
agent-led work, corroborate the findings in scope. Identify the deployed
application from conventional version markers, package metadata, and narrowly
scoped README or CHANGELOG headings. Treat a document heading as a lead. Trace
the configured handler and runtime. Where needed, check the approved application
configuration for database engine, host and port using the
[sensitive-data scope](../../../../docs/sensitive-data.md).

For sites with aliases, record the configured primary hostname. Choose the main
hostname for the report using the DNS names on the TLS certificate, A/AAAA records,
proxy routes, and configured or observed redirects. Include any website hostname
the customer supplied in those checks. Prefer the confirmed working canonical
destination when aliases redirect there. Shared and wildcard certificates can cover multiple sites.
Report working aliases, names pointing elsewhere, names without DNS and names
still untested. Check the redirect destination's response independently.

Pass up to five known in-scope names in the comma-separated
`DR_MANIFEST_PRIORITY_HOSTS` setting for collection. The manifest prioritizes
matching configured names within its existing budgets. If guest curl cannot
perform the safe probes, run
`scripts/assessment-web.py --manifest PRIVATE_JSON --source-address VERIFIED_IP`
on the runner when the recorded scope covers these probes. Match the address to
the job. This returns bounded source-pinned HEAD results with normal certificate
validation. Record public DNS and proxy results separately. Inspect public
certificate SANs when a hostname's role remains unclear.

Review established connection counts by local IP and port when retiring an IP.
Trace the specific configured service relationship and verify the socket type,
listener and owning roles within scope. For example, compare Postfix's
`smtpd_sasl_type=dovecot` and effective `smtpd_sasl_path` with the Dovecot listener
before moving authentication. Rehearse required dependencies and scheduled
scripts during acceptance.

## Assess mail activity

Start with public MX and relevant host records, running mail daemons and listener
bindings, and the manifest's mailbox and spool measurements. Check conventional
local storage such as mbox and Maildir using counts, sizes and recent file
activity within approved scope. Record which locations were checked. MX records
describe public routing. Listeners show what can accept connections. Stored
messages may predate current use.

Check SMTP bind addresses before assigning its role. Loopback-only SMTP
usually serves local submissions. Look for applications and system jobs that
send mail. Ordinary root and Unix-user spools can hold system notifications.
To identify public mailbox hosting, verify the named mail destination domains,
actual routing or accepted delivery, and user mailbox stores such as Maildir.
Record IMAP/POP3 services and account use where observed. Track public
forwarding, authenticated submission and mailbox delivery independently.

When the role affects migration and the first pass leaves it unclear, use
already approved activity evidence or ask for a bounded summary of recent
mail-log or journal activity. Before a log read, agree the source paths or
journal units, observation window, purpose, output fields and processing scope
under the [sensitive-data rules](../../../../docs/sensitive-data.md). Reuse
existing approval. Where direct access is unavailable, use operator-supplied
counts and outcomes. Aggregate on the source and record only coverage, counts
and delivery roles. Keep raw log lines, addresses, message IDs, headers and
contents out of returned evidence.

Correlate accepted external SMTP with successful local delivery or forwarding
to another server. Count app or system submissions separately from forwarding.
Keep rejected connections, deferred mail and currently queued deliveries
distinct from completed delivery. Report the period actually covered and say
when activity is unknown, including when logs are unavailable or too sparse.
Use the findings to decide whether the migration needs an inbound route,
mailbox data, forwarding rules or an application sending path.

For approved Postfix or Dovecot logs, pipe effective journal records in
short-ISO format or approved syslog records, including decompressed rotations,
into `scripts/assessment-mail.py` on the source. Select effective inputs and
the time period before streaming. Avoid overlapping sources and propagate
file, journal or decompression errors. Keep the raw stream on the source.
Use an operator-provided aggregate when source Python 3 is unavailable.
The helper returns counts and the first and last recognized timestamps in
input order. Record the timezone, year and rotation order for legacy syslog.
Compare available coverage with the requested window and record any gaps.
Use approved role evidence to verify whether accepted SMTP came from outside,
whether relay was forwarding or outbound, and where LMTP delivered.

Carry separate keep, replace or retire decisions for application sending,
public SMTP and auth, inbound delivery and forwarding, IMAP/POP3 and retained
mail. Verify a specific script before attributing a message to it. Before
cutover, test expected notifications and scheduled jobs with an isolated mail
sink. Verify inbound delivery and mailbox access for the agreed domains.

## Identify retirement candidates

During the initial assessment, look for customer-installed packages and services,
local applications, enabled jobs, and custom settings with no current purpose or
consumer. Start with the manifest and supplied evidence. Check references and
observed use before proposing what to leave behind. Include retired-runtime
overrides, stale service units, timers, cron jobs and local scripts when they
affect migration or continued maintenance.

| Candidate | Evidence to compare |
| --- | --- |
| Website, vhost or alias | Match public A/AAAA and CNAME results to the source and verify any CDN, proxy, load balancer or redirect path. Check private access, origin routes and the aliases using the same backend. Check authorized per-host request counts, the newest matching event and the period covered by current and rotated origin or proxy logs. A quiet origin can still serve a cached or privately accessed site. |
| Mail domain, mailbox or alias | Compare MX and backup/fallback routes with accepted SMTP, completed local delivery and forwarding within the covered period. Check authorized mbox/Maildir activity summaries and account dependencies. Consider internal delivery, catch-all routing, clients and application sending. Preserve historical mail according to agreed retention, even when new delivery goes elsewhere. |
| Custom service, package, job or setting | Check package ownership and dependencies, running processes, enabled units and timers, schedules, application references and the customer’s intended use. Consider infrequent jobs and standby functions before treating an inactive component as a retirement candidate. |

Record the actual observation window, coverage gaps and conflicting evidence.
Use periods appropriate to the workload, including infrequent or seasonal use.
Keep activity unknown when proxy or log coverage is insufficient. Use approved
source-side counts or timestamps, or operator-supplied summaries. Scope any
additional log, journal or mailbox metadata access under the
[sensitive-data rules](../../../../docs/sensitive-data.md). Keep request paths,
client addresses, message details and raw records out of returned evidence.

In the customer report, give each supported candidate a name, evidence summary,
proposed disposition and owner for the decision. Say whether to omit it from the
new build, keep it inactive with its data retained, replace it, or remove it
after approval. Include a cost, maintenance or migration implication where
material. In the appendix, record the checks and what would verify the decision.
When evidence is sparse or conflicting, name the missing check and preserve the
component pending review. Get separate approval for disabling or removal and
agree data retention and recovery before acting.

## Write concrete findings

Let observations speak directly. Avoid boilerplate such as “this is not evidence
of”, “absence is not proof of absence”, or “not an upgrade-ready plan”. State an
uncertainty when it changes a decision, a risk or the next check. For example,
“MySQL is masked and inactive; no database daemon was running” is useful when
those states were checked. Installed extensions and an application database's
location belong in their own findings.

The owner report should include a short in-place sequence and the risks to the
actual workloads. Keep routine copy isolation, backup preparation and final sync
in the workflow; avoid presenting them as unusual conditions of this server.

Make the appendix specific: hostname-to-vhost/document-root mapping, exact
application version file, current/target versions, DNS answers and local/proxy
routing where established, listener bind scope, package installation and service
active/enabled/failed/masked states. Identify observed consumers of old runtimes
from bounded process, cron and web-handler metadata. Keep raw arguments, secret
settings and customer content out of reports.

Use available authorized discovery to resolve useful gaps rather than repeating
collection limitations. DNS addresses different from the source call for checking
a proxy or another server before migration decisions. If only reduced input is
available, still produce a useful inventory and describe consequential gaps once.

## Choosing the route

Prefer **in-place** when the supported path is straightforward, relevant workloads
are compatible or need small understood changes, resources and package state are
adequate, recovery is credible, and the customer can accept the production outage.
Explain the simplicity: keep the existing server and normally its IP address,
with no second-server copy, changing-data resync or traffic cutover. State that
production changes happen before the customer can test the upgraded result.

Choose **a separate copy or fresh server** when specific findings justify rehearsal
or rebuilding: hardware incompatible with the target, unsupported panel transitions, substantial
application/database changes, or important behaviour that needs testing before
production changes. Multiple release hops can add risk but do not mandate a copy.
Explain what this route helps test and what it does not solve. Account for copied
production effects, extra hosting, consistent data refresh, final outage and cutover.
Verify backup coverage and restore readiness, and plan how to preserve writes accepted after cutover.
Explain that isolated preparation can leave the live server serving customers,
but the final writer pause, resync and traffic/image switch affect production.
Do not describe the whole service as non-destructive. Public descriptions of
older workflows do not override this job's assessment, supported route or terms.

Do not default to a separate server merely because it sounds safer. Missing
information may call for a targeted check and a conditional in-place recommendation.
Explain why the other route is less suitable and what finding would change the
recommendation. If neither is presently feasible, say so and identify the next check.
For original-server image replacement, explain the overwrite, final verification
and temporary-VM retirement. For a DNS/traffic switch, the prepared VM stays live.

An i386-to-amd64 crossgrade is a candidate in-place stage, rather than an
automatic reason to rebuild. Distrorejuve includes this path; verify its actual
revision, prerequisites and application support for the job. Treat a needed tool
fix as named work with an owner and validation, rather than assuming conversion
will remain unavailable. Distinguish implemented capability, evidence from other
jobs and an untested route on this source. Use the
[crossgrade assessment](../../../../docs/upgrade-and-migration.md#assessing-an-architecture-crossgrade)
to weigh release/package state, workload compatibility, capacity, boot/access,
recovery, outage and customer preferences together. Explain which findings
actually decide the route and which are remediable prerequisites.

Distinguish **clean installation on a new server** from upgrading a clone.
Explain when rebuilding avoids obsolete OS state or unsupported transitions,
and what application/configuration/data migration it adds. Use the
[distro-selection criteria](../../../../docs/upgrade-and-migration.md#choosing-a-distro-for-a-clean-install)
to name and justify the distribution, release and architecture. State its support
horizon and workload/panel constraints, with current official evidence in the
appendix. Release hops for the old OS are unnecessary for a clean build;
application/data conversions still need a supported route. For provider-specific
retained disks or images, verify availability and explain recovery limits without
presenting them as a complete backup or lossless rollback.

## Technical appendix

Make this useful to the next sysadmin or agent without turning unverified
assumptions into executable instructions. Include relevant detail only:

- **Evidence and target:** source identity, collection date, tool revision,
  privileges, warnings and evidence references. Resolve “latest” to a named stable
  release with current official sources and dates. For Ubuntu distinguish the
  latest stable release from the latest LTS. If panel/application support limits
  the target, name the latest release separately and explain the supported
  alternative; never silently substitute it. Record any unresolved target research.
- **Dependency and change map:** actual service-to-runtime/database relationships,
  versions, repositories, held/removed packages, configuration changes, capacity,
  boot/network requirements and required release hops. List what evidence supports
  compatibility and what remains untested, including intermediate transitions.
- **Sizing and price, for a proposed destination:** allocated versus observed
  RAM/disk use, peak-load evidence or gaps, growth/migration headroom, CPU/IO needs
  and budget. Explain the recommended configuration and relevant alternatives.
  For RimuHosting, use [workload-based API quotes](../../../../docs/rimuhosting.md#size-and-quote-the-proposed-vm);
  include query/configuration references, quote date, amount/currency, warnings,
  inclusions and unresolved costs. A quote is separate from purchase approval.
- **Mail, when applicable:** active Dovecot/IMAP/POP3 use or remaining uncertainty,
  managed versus self-hosted preference and proposed approach. Cover mailbox and
  client-only POP3 history, address mappings, application sending, DNS/client
  changes, catch-up, acceptance, retention and owners using the
  [mail procedure](../../../../docs/upgrade-and-migration.md#plan-mailbox-hosting-and-migration).
  For self-hosting, distinguish existing features from necessary compatibility
  changes and optional follow-up. Absent DKIM or another unrequested new feature
  is not an upgrade failure; preserve the existing supported mail behaviour.
- **Risk and verification detail:** bind each material customer-facing risk to
  evidence, an affected service, a mitigation, a check with an expected result,
  an owner and a remaining blocker or uncertainty. Do not claim application
  compatibility from package availability or a successful service start alone.
- **Proposed steps:** ordered preconditions, actions, expected results, stop/recovery
  conditions and approval boundaries. Add reviewed commands only when targets
  and arguments are known; otherwise name the unresolved task. Cover baseline
  checks, release/application work, reboots/reconnection and post-upgrade checks.
  For a separate server include isolation, refresh/schema/test-data handling,
  customer acceptance, final consistent resync and the chosen switch. Use the
  [copy isolation and activation procedure](../../../../docs/upgrade-and-migration.md#copy-isolation-and-activation)
  to plan paused activities, reviewed exceptions, reporting and activation approval.
  Treat omitted private schedules in reduced manifests as unknown.
- **Recovery and handoff:** backup scope/exclusions and restore evidence, database
  consistency, console/rescue access, and recovery after new writes. Record planned
  remaining work with owners/checks and the next permitted action. Unknown windows,
  costs or recovery arrangements remain prerequisites, not invented defaults.

Keep raw customer evidence and the completed report private, outside Git. Link
the report revision and technical appendix from the protected job record. Keep
approvals in the private job record; the report itself does not grant authority.

## Availability, retention and restoration choices

Lead with the observed operational condition and its practical reason. Distinguish
a responding web/authentication service, untested protected content, unavailable
database-backed functions, missing normal configuration and retained files. Old
versions alone do not establish abandonment or maintenance history.

Ask which sites, paths, databases and files are needed and whether inactive
applications should work again before defining recovery scope and cost. Record
working-service migration, application restoration and protected data retention as
separate deliverables, including the retention destination and period. Preserve
source data while the owner decides. Keep material risks visible in a short owner
message; detailed evidence belongs in the technical appendix.

For a custom Java or proxy/database workload, use the manifest's actual running
runtime and endpoint evidence rather than only installed package names. Use
approved engine/count/size metadata to identify nontransactional recovery needs;
leave unauthorized or failed database observations unknown.
