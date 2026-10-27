# Sensitive data and agent access

Apply these rules on the source, destination, workstation/runner and restored
copies. They cover direct file reads and tools that read files indirectly.
Read-only access can still disclose secrets or customer data. SSH/root access,
a private directory, Git ignore rules or a general assessment request does not
by itself authorize sensitive-data access or disclosure to an AI service.

## Start with non-secret evidence

Use project source, documentation, synthetic fixtures and intentionally supplied
redacted manifests. Within authorized discovery, prefer package versions,
service names, file existence/permissions and other necessary metadata. Request
only facts that affect the recommendation. File names and paths can also be
sensitive; keep job details private and bound searches to the agreed scope.

Treat files likely to mix settings and secrets as sensitive before opening them.
Examples include `.env` and variants, application configuration such as
`wp-config.php`, database client files such as `.my.cnf`, service environment
files, credentials embedded in repository URLs, `.rimuhosting`, SSH/TLS private
keys, cloud/service-account credentials, kubeconfigs, password stores and shell
history. Logs, process arguments, database dumps, mailboxes, uploads, screenshots,
backups and restored files can contain credentials or private customer content.
Public keys and intentionally sanitized example configuration are usable within
scope; do not read their private counterparts to identify them.

Do not broadly dump configuration, environment variables, process command lines,
container inspection results, service properties or logs. Avoid unrestricted
recursive content searches through customer directories. `printenv`, `nginx -T`,
`docker inspect`, `/proc/*/environ` and full service/config dumps can reveal
secrets. A filtered command can still print a secret on the matching line.
Do not read raw values into tool output and then redact them in the answer.

## Establish permission before sensitive reads

First check the existing job scope and approvals. Permission must cover the
specific files or bounded data categories, purpose, necessary fields, processing
tool and what may be returned to the agent or sent to an AI service. If that
scope is absent or unclear, ask before reading, copying for analysis, or running
a collector that accesses those data. Explain the needed fact and offer a
customer/operator-run check that returns only the required non-secret fields.
Continue analysis from available evidence while permission is pending.

For example: “To check the database migration path, may a local check read the
named application config and return only the database engine setting? It
will omit credentials and other contents. You can run the check and provide
those facts instead.” Name the actual paths and collector before seeking approval.

A reviewed allowlist extractor should emit only approved fields or fixed status
labels. Validate values against expected formats; do not emit full matching lines
or malformed values. Filtering on the source keeps other content out of the
transcript, but the extractor still reads the underlying file and needs permission.
Never source or execute customer `.env`, config or application files to inspect them.
Reuse valid permission for the same purpose/scope; ask again only when it expands,
has been withdrawn or is otherwise no longer valid. Permission to inspect settings
does not authorize printing passwords, tokens, private keys or unrelated records.

Review a collector's inputs as well as its output. distrorejuve manifests and
upgrade reports can read configuration/application files and process metadata.
`--unprivileged` reduces operations; it does not make every readable file
non-sensitive or certify that output is safe for AI processing. Agree the reviewed
collector revision, input categories, output fields and handling before running
it on customer systems. If required exclusions cannot be honoured, use an
operator-supplied sanitized manifest or narrower check and record the gaps.

## Use credentials without exposing them

An approved SSH client, API client or database tool may consume the designated
credential for the agreed operation without returning its value to the agent.
Have the owner provision it through the protected access mechanism. Prefer
credential references and public-key fingerprints. Do not retrieve or display
secret values from credential files, environment variables or existing configs.
Keep secrets out of prompts, command arguments, trace/debug output, screenshots
and job reports.
Review tool output/logging before use. Access to unrelated accounts is outside scope.

S2I backups/restores and data transfers need explicit scope for what is read,
where it is sent/stored and who can access it. Approval to copy a complete archive
for migration does not grant permission to browse its contents or submit them
to an AI. Protect secret-bearing archives, dumps and recovery instructions.
Database checks should return approved status/version facts rather than rows,
password hashes or authentication strings. API responses and logs can contain
private data even when authentication headers are omitted.

## Handle unexpected exposure

If sensitive content appears unexpectedly, stop the exposing command or further
reads where possible. Do not repeat the value, expand the search or copy it into
a report, issue, fixture or repository. Tell the authorized operator what kind
of data was exposed and through which channel, without quoting it. Follow their
incident/retention procedure and obtain a decision about credential rotation or
cleanup when needed. Do not silently delete evidence or rotate production secrets.
Record the permission reference, approved non-secret findings and remaining gaps
in the private job; keep raw secrets out of the record.
