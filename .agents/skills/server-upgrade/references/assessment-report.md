# Initial upgrade assessment report

Write for two readers: the customer deciding what to do, and the sysadmin or
agent preparing the work. Scale detail to the actual setup. A small, well-understood
upgrade should produce a short report. Do not pad it with irrelevant risks or
copy the raw manifest into the customer explanation.

Put the assigned `job_id` and report revision in the report header. They must
match the durable [job record](../../../../docs/job-records.md). Keep request,
ticket and VM identifiers distinct from the job ID.

## Customer explanation

Use plain English, short paragraphs and descriptive headings. Explain technical
terms when needed: for example, a runtime is the software that runs the website's
code. Keep useful names and versions, but explain their effect on the customer.
The customer should understand the recommendation without reading commands or
looking up an acronym.

Cover these questions in this order, combining sections for simple cases:

1. **What do we recommend?** Name the source and proposed target, the recommended
   route, its main reason, and whether this is provisional or ready for approval.
   State the most important unresolved condition near the recommendation.
2. **What is there now, and what would change?** Describe the server's jobs:
   websites, email, stored data, scheduled work and business-critical applications.
   Use a small comparison table where useful:

   | Service or component | Current setup | Proposed change | What this means for you |
   | --- | --- | --- | --- |

   Include the OS and relevant application/database/panel versions. Distinguish
   observed, customer-reported and inferred facts; mark missing facts as unknown.
   Say what should continue unchanged and what users may need to do differently.
   Explain relevant support/security changes from current official evidence,
   including obsolete components that would remain after the upgrade. An OS
   upgrade does not automatically modernize custom applications or containers.
3. **What are the particular risks?** Explain the few material risks supported
   by this source's evidence. For each, connect the observed condition to the
   proposed change, the possible customer impact, the proposed check/remedy,
   and the uncertainty left afterward. Link the technical evidence in the appendix.
   For example, if an old site requires a removed PHP feature, explain that the
   site may fail under the new PHP version and needs compatibility work and tests.
   Do not claim that a detected PHP version proves such a dependency exists.
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

## Choosing the route

Prefer **in-place** when the supported path is straightforward, relevant workloads
are compatible or need small understood changes, resources and package state are
adequate, recovery is credible, and the customer can accept the production outage.
Explain the simplicity: keep the existing server and normally its IP address,
with no second-server copy, changing-data resync or traffic cutover. State that
production changes happen before the customer can test the upgraded result.

Choose **a separate copy or fresh server** when specific findings justify rehearsal
or rebuilding: incompatible architecture, unsupported panel transitions, substantial
application/database changes, or important behaviour that needs testing before
production changes. Multiple release hops can add risk but do not mandate a copy.
Explain what this route helps test and what it does not solve. Account for copied
production effects, extra hosting, consistent data refresh, final outage and cutover.
A copy alone does not establish reliable backups or lossless rollback.
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
  customer acceptance, final consistent resync and the chosen switch.
- **Recovery and handoff:** backup scope/exclusions and restore evidence, database
  consistency, console/rescue access, and recovery after new writes. Record planned
  remaining work with owners/checks and the next permitted action. Unknown windows,
  costs or recovery arrangements remain prerequisites, not invented defaults.

Keep raw customer evidence and the completed report private, outside Git. Link
the report revision and technical appendix from the protected job record. Keep
approvals in the private job record; the report itself does not grant authority.
