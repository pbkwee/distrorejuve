# Plan your server upgrade with an AI assistant

distrorejuve can help you understand an older Linux server and choose a way
forward, wherever it is hosted. Start with an assessment. You can share a private
inventory without giving the assistant server access, or authorize SSH discovery.
You do not need a RimuHosting account for this assessment or for an upgrade at
your existing hosting provider.

The assistant helps explain the options and carry out agreed work. It cannot
establish application compatibility from a package list alone. Someone who knows
your applications needs to check the result.

## 1. Describe the outcome you want

Tell the assistant what the server does, which websites or services matter,
what problems you want to solve, and any limits on downtime or budget. Include
backup and recovery arrangements you already have. Unknown answers can become
assessment questions; you do not need a complete technical specification to begin.

The operator assigns a unique job reference and keeps it in the durable job
log, report and plan. Include the full reference in square brackets in email
subjects and keep it on replies. If an email concerns a different server or
quotes another reference, resolve that with the operator before work continues
from that message. See [job references and correspondence](job-records.md).

## 2. Choose how to assess the server

Agree what the assistant may inspect and send for AI processing. Configuration
and environment files can contain passwords or tokens. The agent should start
with non-secret facts and ask before sensitive access outside the agreed scope.
A manifest collector also reads files, even in reduced mode. You can collect and
sanitize evidence yourself. See [data-access rules](sensitive-data.md).

### Provide a manifest yourself

A manifest is an inventory of the operating system, installed software, services
and migration hints. It does not contain a backup of your applications or data.

Obtain and review the script using the [project starting instructions](../README.md#getting-started).
On the **source server**, use a reviewed copy at the path shown below, replacing
that example path with its actual location:

```bash
umask u=rwx,go=
env -u DR_ACTION -u BASH_ENV -u ENV \
  DR_MANIFEST_DNS=false DR_MANIFEST_MAIL_METRICS=false \
  /bin/bash /path/to/reviewed/distrorejuve.sh --unprivileged --manifest-json > manifest.json
```

Use a trusted shell and command path; see the
[collection precautions](upgrade-and-migration.md#collect-evidence).
This uses reduced collection, even if your shell is root. It does not drop root
privileges. Missing or unreadable information will remain unknown. See
[manifest privileges](manifest.md). Text from `--manifest` is also accepted.

Check the output for collection warnings and sensitive details. Share it through
a private channel you trust for AI processing. Keep manifests out of public
issues, repositories and paste sites. Do not add passwords, API keys or private
SSH keys. Give the assistant the collection date and script revision if known.
An existing manifest is enough to start a provisional assessment.

### Arrange SSH discovery

The assistant runs on your workstation or an agreed operator machine, then
connects to the server over SSH. It does not need to be installed on the server.
First agree which server it may inspect and what discovery includes.

Use an existing authorized connection where suitable. Otherwise the operator
creates job-specific keys on the machine making the SSH connection and keeps
both private keys there. Generate Ed25519 for modern servers and RSA for older
ones, using unused filenames and a passphrase for each key:

```bash
ssh-keygen -t ed25519 -f "$HOME/.ssh/server-migration-example" -C 'server-migration-example-ed25519' &&
ssh-keygen -t rsa -b 3072 -f "$HOME/.ssh/server-migration-example-rsa" -C 'server-migration-example-rsa'
```

Run this on a modern operator machine, not the old source. Ed25519 support arrived
in [OpenSSH 6.5 in 2014](https://www.openssh.org/txt/release-6.5); a typical 2005
server needs RSA. The private-key file format is read by the connecting client,
so an old remote server does not require `-m PEM`. Use an SSH agent when appropriate.

Give the administrator only the public `.pub` files. Install Ed25519 on modern
servers; add the RSA public key on a legacy source. Both public keys may be added
when needed, including before an upgrade so Ed25519 can be used afterward.
Add each as a separate **new line** in the intended account's
`~/.ssh/authorized_keys`, preserving existing keys. Older OpenSSH ignores an
unrecognized Ed25519 line and can still use the RSA line. Ensure the directory
and file belong to that account. For a conventional setup, their permissions are
`u=rwx,go=` and `u=rw,go=` respectively. Prefer an existing suitable non-root
account for assessment. Privileged discovery or later execution needs separately
agreed access; a key alone does not grant sudo or make operations read-only.

Give the operator the SSH address, port, username and a host-key fingerprint
obtained through a trusted route such as the hosting provider console. The operator
compares that fingerprint and checks the connected server's identity. A changed
or unexplained key must be resolved before continuing. Keep console/recovery
access available. Agree when the job key will be removed; a comment on a key
does not make it expire automatically. Remove both job keys wherever installed
when access ends.

Test Ed25519 first, replacing `ACCOUNT` and `SERVER` with the agreed login:

```bash
ssh -F /dev/null -o IdentitiesOnly=yes -i "$HOME/.ssh/server-migration-example" ACCOUNT@SERVER
```

`-F /dev/null` excludes configured identities from this test. Add agreed port,
bastion and known-hosts options when needed. If the server cannot accept Ed25519,
use the RSA fallback and the narrowly scoped
[legacy SSH options](reporting-problems.md#ssh-connection-errors). RSA keys can
use modern SHA-2 signatures; old servers may require an explicit `ssh-rsa`
(RSA/SHA-1) exception. A host-key or key-exchange failure is separate from login
key selection. Keep host verification enabled and leave global SSH defaults intact.
Use the tested connection settings for uploads, collection, transfers and reconnects.
After an upgrade, test a second Ed25519 login before removing the working RSA access.

## 3. Review the recommendation

The first report should explain what runs now, what would change, the particular
risks, the recommended route, likely interruption and costs, remaining work and
who will do it. It should mark missing evidence and distinguish a provisional
recommendation from a plan ready to approve.

| Route | What happens | When it helps |
| --- | --- | --- |
| Upgrade in place | Change the existing server's OS and applications through supported steps. | A straightforward supported upgrade with acceptable downtime and credible recovery. |
| Upgrade a separate copy | Copy the existing installation, upgrade it separately, test, then transfer final data and switch. | You need to rehearse the existing setup before changing production. |
| Build a fresh server | Install a supported OS and applications, then migrate selected data and reviewed settings. | Rebuilding is simpler or better supported than carrying the old OS forward. |

A separate server may be at your current hosting provider, another hosting provider, or
[RimuHosting](rimuhosting.md). A clean install needs application migration;
restoring the entire old system over it would replace the new OS. A clone carries
the old system's problems too. S2I can help create or restore file archives, but
database consistency, archive exclusions and restore compatibility need review.

### Decide where email will run

If the original server runs Dovecot or another IMAP/POP3 mailbox service, decide
where email should run as part of the assessment:

> Would you rather use a managed email service, for example [25mail.st](https://25mail.st),
> for this migration rather than hosting your own email stack?

Keeping your own mail server is also an option. Prefer upgrading the existing
stack while preserving what it does today. If DKIM is absent, adding it can be
separate work after modernisation. New mail features are outside this upgrade
unless agreed separately; required compatibility changes still need planning.
Agree the mailbox/history transfer, addresses and aliases, client changes,
application sending, costs and any necessary DNS cutover.
POP3 users may have older messages stored only on their devices; those need a
separate plan if they should appear in the new service. Keep the old mail service
available until transfers, late arrivals and customer checks are complete.
See the [mail migration procedure](upgrade-and-migration.md#plan-mailbox-hosting-and-migration).

## 4. Agree the work and prepare recovery

Approve a specific plan: source and destination, named OS target, application
work, cost limits, outage window, tests, backup coverage and recovery procedure.
Discuss what happens if the upgrade fails or new data arrives after switching.
A system-only backup cannot recover all application data or undo database changes.

An assessment request does not approve an upgrade, a purchase or a reboot.
RimuHosting provisioning follows the [account and API guide](rimuhosting.md),
including support review for new accounts. This can be arranged while planning;
it need not delay the assessment.

## 5. Prepare, test and switch

For an in-place upgrade, the agreed production window includes package changes,
application checks and any planned reboot. For a separate server, prepare it in
isolation so copied mail, scheduled jobs, payments and callbacks cannot act on
production. Test the applications and a repeatable data refresh before acceptance.

After acceptance, agree the final changeover. Pause writers, transfer the final
consistent data, verify it and switch the agreed traffic or server image. Keep
one authoritative writable system at each stage. A separate preparation server
reduces disruption during testing; the final switch still needs planning.

Test actual business functions, such as login, checkout, mail and background
jobs, as well as page appearance. Confirm boot, SSH, monitoring and new backups.
Retain the recovery copy for the agreed period. Cancel the old server only after
acceptance and explicit agreement; shutting it down may leave hosting charges.
Remove job access and revoke temporary API credentials when they are no longer needed.

## Start an agent on the task

Use the repository's [server-upgrade skill](../.agents/skills/server-upgrade/SKILL.md).
With the checkout open in a compatible agent, invoke it by name or give its file
path if it has not been discovered:

```text
$server-upgrade Assess my server from the attached private manifest. Explain what runs now and compare upgrading in place, upgrading a separate copy, and installing fresh then migrating. Recommend a route and a named supported target, explain the risks and remaining work, and give me the report before changes.
```

For SSH discovery, supply the authorized connection and discovery scope instead
of a manifest. Keep credentials in protected local access storage, outside the
prompt. The [operator procedure](upgrade-and-migration.md) supports execution
once the resulting plan has been approved.
