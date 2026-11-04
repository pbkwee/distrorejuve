# Native init and configuration readiness

Readiness checks stay read-only. Inactive `systemd-resolved` does not invalidate
working static resolver evidence. The resolver collector preserves conventional
client configuration and records the native resolver's state separately.

Common SSH service checks recognize socket activation only when `ssh.service`
is loaded, inactive/dead with a successful result, and its loaded `ssh.socket`
is active/listening, triggers that service and exposes a stream listener.
A failed service, missing socket, different trigger or unknown properties do not
pass this check.

Logrotate configuration review invokes the installed native parser with
`timeout 20 logrotate --debug --state /dev/null /etc/logrotate.conf`. Debug mode
applies that version's includes and taboo rules without rotations, scripts or
state writes. The checker reports duplicate-path and parse failures from the
native result. Missing clients and timeouts leave coverage incomplete. It no
longer treats every file in `/etc/logrotate.d` as an active configuration.
Inspect native debug output locally under the approved configuration scope;
raw configuration diagnostics are not copied into a shareable report.

## Verified usrmerge PID 1 remedy

The precise stale path `/lib~~delete~usrmerge~~/systemd/systemd (deleted)` is
recognized only when `/sbin/init` selects a canonical systemd executable, its
owning `systemd` package is configured, package audit is clean, and its SHA256
matches `/proc/1/exe`. A read-only check explains the remedy and stops.
Unrecognized paths, missing metadata or different binary bytes remain blocked.

During approved execution, use:

```bash
sudo bash distrorejuve.sh --refresh-stale-systemd
```

This separate root-only logged action repeats the identity and package checks,
runs a bounded `systemctl daemon-reexec`, and verifies the canonical running path,
unchanged executable hash and clean package audit afterward. It does not reexec
from a manifest or readiness request. Repeat normal readiness checks before
continuing the recorded release stage. The operation changes PID 1; it requires
the job's execution scope and is never a fixture test on a real server.
