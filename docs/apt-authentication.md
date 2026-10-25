# APT authentication on archived releases

Package installs and upgrades require APT authentication by default, including retries.
A missing key, an expired key and expired repository metadata are different problems.
Check the detailed run log and restore the distribution or vendor signing keys from a verified source.
The script does not import keys from arbitrary keyservers.

Some historical Debian and Ubuntu archives have expired signing keys.
If verified keys cannot authenticate that archive, an operator can explicitly set
`DR_ALLOW_UNAUTHENTICATED_ARCHIVES=true` for the invocation. This accepts the risk of
installing packages that APT cannot authenticate.

The exception applies only when every active binary source uses an exact official
`archive.debian.org` or `old-releases.ubuntu.com` archive URI and an archived release.
It does not apply to live mirrors, third-party repositories or an empty source list.
Script-managed source changes revoke the allowance. Index refreshes and shared
package mutation helpers check the sources again. Older crossgrade commands reuse
the last checked options; avoid changing APT configuration concurrently.
Distribution-keyring installation remains authenticated even with this setting.

The exception adds no `AllowInsecureRepositories` override. APT may still refuse
an index refresh, requiring manual trust repair; older APT versions may instead
accept indexes with warnings. Existing `trusted=yes` source settings remain the
administrator's responsibility.

The separate `Acquire::Check-Valid-Until=false` option permits historical metadata;
it does not fix missing or expired signing keys. See the official
[APT authentication documentation](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html).
