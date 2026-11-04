# Recover SSH access through a rescue system

A provider console or rescue boot can restore access when the installed system
cannot start SSH, accept a key or bring up networking. This can help an
AI-assisted assessment begin, or recover access lost during approved upgrades.
A rescue system boots separately and exposes the installed disks for repair.
Keep a separate backup and rollback plan for package changes and application data.

## Prepare the recovery route

Before disruptive work, identify the provider's console/rescue procedure,
required account access, target server ID and normal-boot procedure. Record the
expected addresses, installed-system host-key fingerprint and approved login
account. Keep the job's private SSH key on the connecting machine; give the
provider only its public key. Check support for that key's algorithm.

Rescue boot interrupts the server. Plan the recovery work and outage with the
operator, using the job's existing recovery arrangements.

For RimuHosting VMs, the optional [API rescue procedure](rimuhosting.md#recover-access-with-rescue-boot)
accepts one-off public keys. Other providers require their own verified procedure.

## Identify the rescue system and installed root

After rescue starts, verify the provider's operation state and target identity.
Rescue normally has different SSH host keys from the installed system. Verify
those keys through a trusted provider/console route and keep their trust record
separate; do not disable host-key checking or discard the installed fingerprint.

Use `lsblk -f` and `findmnt` to inspect disks, filesystems and existing mounts.
Confirm the installed root from filesystem identity and expected OS/configuration
metadata before writing. Account for LVM, RAID, encryption and separate `/usr`,
`/var` or `/home` filesystems. Mount read-only first where practical.
For example, `mount -o ro /dev/xvda1 /mnt` is appropriate only after verifying
that this is the installed root device and `/mnt` is the intended empty mountpoint.
Do not assume that device name or mount over an existing mount.

## Repair the installed system

Back up the specific files being changed to approved recovery storage. Switch
only the verified target filesystem to writable mode when ready. Paths below
refer to the mounted installation, for example `/mnt/root/.ssh/authorized_keys`.
Add the key there when it should remain available after normal boot.

- Append the approved public key as a separate line to the intended account's
  actual `AuthorizedKeysFile`, preserving existing entries and key restrictions.
  For a conventional home-based setup, `.ssh` uses `u=rwx,go=` and
  `authorized_keys` uses `u=rw,go=`. Verify account ownership and parent-directory
  permissions. Do not apply recursive permission changes to the whole home.
- Review the installed SSH configuration, included files and applicable `Match`
  blocks. Check public-key authentication, key-file paths, login/group rules,
  account status and the expected port. Preserve the agreed access policy:
  a non-root login with sudo may be intentional. Do not enable password login
  or globally weaken SSH algorithms merely to recover a key login.
- Check the installed network configuration, interface names, addresses, routes
  and firewall rules against verified provider requirements. Permit the approved
  connection source and SSH port without flushing unrelated firewall policy.
- Validate SSH configuration with the installed system's `sshd -t`; inspect
  effective settings with its supported `sshd -T` options when useful. This may
  require a correctly prepared chroot and its dependencies. Rescue's `sshd`
  validates its own environment and may support different options. Do not start
  the installed SSH daemon alongside rescue's daemon on the same port.
  Use the installed manual for version-specific behavior; the current
  [OpenSSH daemon manual](https://man.openbsd.org/sshd) describes these test modes.

Keep configuration reads and returned evidence within the job's
[sensitive-data scope](sensitive-data.md). Record changed paths and recovery
results privately without exposing credentials or whole configuration files.

## Return to normal boot and verify

Leave any chroot, sync writes, and unmount filesystems and bind mounts you added
in reverse order. Use the provider's normal-boot procedure; a guest `reboot`
may start rescue again. After boot, verify the installed host identity and open
a fresh SSH connection from the actual agent/runner using the intended key,
account and port. Check privilege access, networking and affected services.

If normal boot still fails, preserve evidence and use the agreed recovery route. Resume assessment or upgrade work only from verified
state. Remove temporary keys wherever installed when job access ends.
