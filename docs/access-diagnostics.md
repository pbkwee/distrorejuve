# Bounded SSH access diagnostics

Use the operator-designated agent, verified endpoint and recorded host-trust
policy. Keep one command-scoped agent and private SSH configuration for discovery,
transfers and reconnects. Login-key authentication and server host-key identity
are separate checks. Reuse covered answers rather than repeating intake.

1. Check execution permission and the designated socket's existence. A sandbox
   denial is a local access failure; request the required scoped execution access.
2. Query only the approved socket, with a timeout, and compare the expected public
   fingerprint when supplied. Distinguish empty, unavailable and timed-out agents.
3. Check the recorded route and endpoint. Reuse an authorized bastion when needed.
4. Apply established host trust. Reuse pinned keys; changed keys require resolution.
5. Attempt authentication. Offering a key followed by `Permission denied` proves
   authentication denial, but cannot distinguish a key rule, account rule or
   source-address policy. Request a bounded server-side reason for the known
   attempt or the established working route before suggesting replacement keys.

The optional `scripts/access-check.py` runs on the operator machine with Python 3:

```bash
python3 /verified/distrorejuve/scripts/access-check.py agent \
  --socket /operator/designated/socket --timeout 5
python3 /verified/distrorejuve/scripts/access-check.py ssh \
  --status 255 --diagnostic /protected/job/approved-client-excerpt.txt
```

The agent command queries only the supplied socket and returns validated SHA256
fingerprints, excluding comments. The SSH command classifies an explicitly
approved client excerpt of at most 16 KiB; it returns fixed status/next-action
labels, never the original diagnostic. It does not connect to a server. Preserve
the actual SSH exit status before running later commands. Debug excerpts can
contain private metadata; obtain their scope and keep them in protected storage.

No socket search, private-key read, global SSH change or onward agent forwarding
is needed. A partial socket-only reply does not settle missing host trust. An
unfamiliar failure stays unknown; retain the smallest necessary evidence and ask
only for the missing layer. Service-specific staff bastions belong in the service
guide rather than this provider-neutral procedure.
