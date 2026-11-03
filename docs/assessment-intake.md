# Initial assessment choices

Collect the missing answers together before discovery. Reuse supplied context
and existing approvals. For a continuation, recover the job record first and ask
only about gaps or changes. Unknown outage/cost details need not block assessment.
Obtain usable source inventory or a source-associated supplied manifest before
issuing the assessment. While collection is blocked, return access/collection
status and the next action, not a generic upgrade assessment or route proposal.

| Topic | Short question and recorded choice |
| --- | --- |
| Job and context | New job or existing ID? Which server, what outcome, and what customer notes or initial findings should inform it? Associate correspondence before importing it. |
| Inventory | Will the operator supply a manifest, or should the agent collect it? Standard/reduced or fuller collection, within which reviewed input categories and AI-processing/output limits? |
| Access | Direct SSH or a named bastion/VPN/firewall route? Use known settings; otherwise default source access to root:22. Identify the designated agent and any different bastion account. |
| Host identity | Use existing verified trust or supplied fingerprints, or permit first-use trust for authorised job endpoints? Record the chosen policy before connecting. |
| Constraints | Critical services, linked replicas/writers, must-keep IPs, known backup/recovery arrangements, target requirements, downtime/window and budget constraints? Unknown answers remain explicit. |
| Working arrangement | Assessment only, or assessment followed by a proposed plan? Which later checkpoints and progress detail does the operator prefer? Execution still needs approval of a concrete plan. |

Keep the initial exchange short. Batch related unanswered choices; do not make
the operator complete the entire execution handoff before collecting evidence.
If the workload already suggests necessary configuration or database metadata,
include those concrete paths/categories and allowed output fields in this exchange.
For a known database workload, identify the approved maintenance-client credential
reference and required metadata privileges early. Do not request credential values
or grant new database privileges during assessment.

## Inventory permission

Explain the reviewed collector's inputs before asking for fuller collection.
The standard manifest can read configuration/application metadata, process
arguments and scheduled jobs, and sample application files for security indicators.
Reduced mode still reads some of these inputs. Use [inventory coverage](inventory.md)
and [sensitive-data rules](sensitive-data.md) to identify the actual categories,
returned fields, exclusions and AI-processing route.

"Full manifest" is a request for coverage; it does not grant unrestricted reads
of credentials, `.env`, logs, zone records, mailboxes or database contents.
Record specific approval once and reuse it for covered reads. If the collector
cannot honour exclusions, collect narrower evidence and report the gaps.

## SSH host-key policy

Choose one policy for explicitly authorised job endpoints, including named
bastions and approved destinations. An address discovered in evidence does not
become an authorised target. Keep authentication/agent access separate from
server identity; a trusted host key does not make an unavailable agent work.

**Verified identity:** reuse trusted `known_hosts` entries, a trusted host CA, or
public keys/fingerprints supplied through a trusted channel and matched to the
job/source. Compare supplied fingerprints with the offered key. Preserve existing
trusted keys/CA configuration or store the matched public key privately, and use
`StrictHostKeyChecking=yes`. Do not ask the
operator to confirm the same pinned key again on reconnects or in a new chat.

**First-use trust, when explicitly permitted:** accept previously unseen keys
for authorised job endpoints without individual fingerprint prompts, and pin
them in the job's private `known_hosts`. Record the endpoint, key/fingerprint,
time and first-use policy as the trust basis. This accepts the risk that the
first connection could reach an impostor. OpenSSH's
[`StrictHostKeyChecking=accept-new`](https://man.openbsd.org/ssh_config#StrictHostKeyChecking)
accepts new keys while rejecting changed keys. Never use `no`/`off` or discard
known-hosts state. If the client lacks `accept-new`, record and pin the first
observed public key under the same explicit policy, then connect with strict
checking; do not weaken the check globally.

If no policy is supplied, retain verified-identity checks and ask once for the
missing policy or trusted evidence. Do not interpret silence as first-use consent.
A changed key requires resolution against the expected host/reinstall/rotation;
never remove the old entry and accept its replacement automatically.

Use the same private SSH configuration and trust store for discovery, uploads,
transfers, tools and reconnects. Apply the policy separately to both the bastion
and source: command-line options for a source do not necessarily configure the
jump host. An existing trusted entry must still be checked before accepting an
endpoint into a new job store; an empty store must not hide a known mismatch.

## Manifest fingerprints

`ssh_host_key` records contain SHA256 fingerprints from conventional
`/etc/ssh/ssh_host_*_key.pub` files. Private keys and comments are not collected.
These files may be stale or not selected by the running sshd; `active=unknown`
is deliberate. Missing files, permissions, unsupported tooling and custom paths
produce warnings or unknown coverage. `--redact` hides fingerprints and paths.

A customer-run manifest received through a trusted, source-associated channel
can provide the expected hashes before SSH. Match the offered key and pin it;
another fingerprint question is unnecessary when that evidence is sufficient.
A manifest collected over an unverified first SSH connection cannot establish
that connection's identity. `ssh-keyscan` alone likewise collects a key without
authenticating its owner. Use the agreed first-use policy or independent evidence
to establish trust; host-key records cannot confer access or execution authority.

## Early access check and reuse

After agreeing discovery and identity scope, use bounded checks for agent
responsiveness, route reachability and host verification before attempting a
large inventory. Record a failed layer accurately and seek only the missing
access detail. Do not install tools or alter production to obtain the manifest.
Test an operator-supplied alternative socket if the configured agent is
unresponsive, returning only public identity metadata. Keep a working socket
scoped to the job's commands. Discovery of other sockets needs an authorised,
bounded scope and account-ownership checks; never search for private keys.

Save the context, collection scope, access route, host-key policy/trust basis,
constraints and checkpoint preferences in `job.md`. Preserve these through
handoffs, retries and later phases. Ask again only when scope changes, evidence
conflicts, authority expires/is withdrawn, or a real new decision is needed.
