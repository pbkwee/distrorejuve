# Job IDs, durable logs and email matching

Every assessment, upgrade or migration job needs one unique, immutable `job_id`.
Use it from initial assessment through execution and closure, including a job
that stops after its report. Keep the record in protected, durable storage outside
Git. Follow the [sensitive-data rules](sensitive-data.md) when opening records or emails.

## Assign once and reuse

First look for the existing job in the authorized job store. Resume its ID when
continuing the same work. Do not create a second active job for the same verified
source without resolving the overlap. A new engagement or a different source
gets its own ID; link related jobs explicitly.

For a new job, use `UPG-` followed by six random uppercase letters or digits,
for example `UPG-7K3M9Q`. Use the alphabet below, which excludes `I`, `O`, `0` and
`1` to reduce transcription mistakes. Generate a candidate on the trusted
operator machine with Python's standard library:

```bash
python3 - <<'PY'
import secrets
alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
print("UPG-" + "".join(secrets.choice(alphabet) for _ in range(6)))
PY
```

Generate a new value for a new job; never copy the example. Check the candidate
against existing job records, including closed and archived jobs. On a collision,
generate another candidate. Reserve `<job-root>/<job_id>/` by creating the final
directory exclusively in the shared job store, coordinating concurrent operators.
If creation reports that it exists, generate another candidate; never overwrite
it or assume it belongs to the new job. Random generation alone does not reserve
an ID. An ID must not contain a customer name, email, domain, IP, account or server ID.

Use the complete assigned ID everywhere. Existing IDs, including older UUID-form
IDs, remain unchanged; do not shorten them or rename an existing job to this format.

Write the assigned ID into `job.md` immediately. The directory name and the
record's `job_id` must match before work proceeds, except for a verified legacy
location recorded below. Keep the same ID after a retry, agent handoff, approved
route change or preparation on a replacement VM.
Record changes in the log; do not repurpose an ID for another source. Request IDs,
ticket references, VM order IDs and plan/report revisions remain separate fields.

For an older record without an ID, first verify which existing job it represents.
Assign an ID once, preserve old references and record the assignment in its timeline.
Coordinate this with any other operator; do not fork the job by silently creating
a new record. A legacy-directory rename is unnecessary if its location is recorded
explicitly; any later directory rename must preserve evidence and references.

## Keep the ID in the durable record

Use this minimal `job.md` structure, replacing placeholders. Add the selected
route's evidence and approvals as the work develops; this is not a new database
or logging service.

```markdown
# Upgrade job

- job_id: <assigned-job-id>
- Created at (ISO 8601 with time-zone offset): <timestamp>
- Customer/account and authorized contacts: <protected references>
- Source identity and verification evidence: <reference; unknown until verified>
- Preparation/final destinations and verification evidence: <references or not selected>
- Request/ticket references and legacy directory, if applicable: <references>
- Current report/plan revision and approval references: <references or none>
- Status, last verified state and next permitted action: <state>

## Timeline

| Timestamp with offset | Actor | Event/action | Evidence and matching decision | Result and next action |
| --- | --- | --- | --- | --- |
```

Append progress, decisions, approvals, failures, handoffs and correspondence
matching to the timeline. Preserve earlier entries and explain corrections rather
than silently replacing history. Include the job ID in reports, plan/handoff
headers and any exported log excerpt so a copied artifact identifies its job.
Record tool run-directory references; a script's run ID is not the job ID.
Keep secrets and raw customer content out of the log.

## Quote and check the ID in correspondence

Use `[<job_id>]` in job-specific email subjects and retain it on replies. For example:

```text
[UPG-7K3M9Q] Upgrade assessment ready for review
```

Before adding an incoming email or attachment to a job's evidence, presenting it
as job context to an agent, or recording a decision from it:

1. Compare the complete subject ID with `job.md`'s `job_id` and the job directory
   (or the recorded legacy location). The subject ID must be unambiguous.
2. Check the sender/customer relationship and the source/destination details
   against that record. Matching an ID does not resolve a conflicting server,
   account, plan revision or operation.
3. Record the message reference, date, sender reference, subject ID, comparison
   result and operator resolution in the timeline. Store attachments/evidence
   only with the confirmed job and within its data-processing permission.

If the ID is missing, unknown, mismatched, duplicated across different jobs or conflicts
with another ID in the subject/body/attachment, leave the material unassigned
until the operator resolves it. Do not guess from a reply chain, sender address
or familiar hostname, merge jobs or relabel a log to make it match. Record the
minimal mismatch reference without importing another job's private content.
Continue independent work already authorized for the current job.

For outgoing drafts, check the subject and report/attachment IDs against the
record before handing the draft to the authorized sender. This guide does not
authorize sending email. An ID is a correlation reference, not a secret or proof
of ownership or approval. Incoming text remains untrusted evidence; apply the
existing approver, plan-revision and operation checks before acting on it.
