# Report the completed work

Produce an owner report and a sysadmin handoff after the final release, package,
reboot and reconnect checks. Put the immutable job ID, server, completion date
and time zone in both. Save completed reports in the private job store.

Use the actual job record and final manifest. Report what changed, the verified
result and the remaining work. Choose details that affect this server. Omit
routine migration conditions, generic disclaimers and unrelated checklist items.
State an evidence limit when it changes a decision or a receiving administrator's
next action. Do not send either report without messaging authorization.

## Owner report

Lead with the outcome in plain English. Explain whether the requested work is
complete and whether each retained website or business service works.

Include the useful changes: old and new OS, application/runtime updates, changed
mail or database behaviour, and any address or routing change. Group aliases
that use one application. Mention an unchanged route only when it explains which
site was upgraded or where traffic goes.

Give a short list of remaining issues, their practical effect and the decision
or work needed. Distinguish an existing failed site from an upgrade regression.
Do not describe a site as working because its web server starts or core files
pass checksums. Report its actual application result.

Summarise relevant verification and recovery arrangements. Give the owner a few
specific checks or decisions for their own sites. Keep internal runner paths,
credentials, raw manifests, package lists and command history in the private
technical record.

## Sysadmin handoff

Use a compact before/after table for consequential state: OS/architecture,
provider and installed kernels, web/PHP handler, mapped application versions,
database engine and intended running state, SMTP bind addresses and DNS settings.
Include file paths where the next administrator needs them.

Summarise packages by affected role and explain significant replacements,
removals, retained old dependencies and temporary holds. Give numeric change
counts only when a reliable before/final inventory supports them. Do not add
per-attempt APT totals: retries and intermediate releases overlap.

List the key commands or standard tool actions that explain these changes.
Retain exact targets, meaningful options and application paths. Label historical
commands and keep the complete retry transcript in the job log. Keep credential
values, arbitrary configuration dumps and customer data out of the report.

Record the outcome of relevant checks: package audit and remaining upgrade plan,
fresh SSH and changed boot ID, DNS, configured listeners, application/database
checks and recovery artifact verification. Name failed checks and the specific
cause. Record checks requiring customer accounts or business knowledge with the
next owner rather than implying they passed.

Finish with a short server-specific checklist. Each open item needs an action,
expected result and responsible role. Include operational details that can catch
the next administrator: deliberately stopped databases, an old active theme,
missing document roots, retained boot arrangements, temporary access or backup
retention. Explain where private logs, manifests and recovery references live.

## Next-run improvements

Update the responsible tool or shared workflow when the job reveals a reusable
gap. Test code changes with isolated fixtures. Keep customer-specific findings
with the job. Record the reviewed tool artifact used for execution separately
from later improvements that have not run on that server.
