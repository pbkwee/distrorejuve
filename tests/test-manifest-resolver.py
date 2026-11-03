#!/usr/bin/env python3
"""Isolated resolver metadata and bounded numeric-address output."""
import pathlib
import re
import shlex
import subprocess
import tempfile
import unittest

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh').read_text()


def run(body):
    declarations = []
    for name in ('manifest_resolver_addresses', 'manifest_resolver'):
        # Functions have a column-one closing brace; nested shell blocks are indented.
        match = re.search(r'^function ' + name + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
        assert match, name
        declarations.append(match.group())
    return subprocess.run(['bash'], input='\n'.join(declarations) + '\n' + body,
                          text=True, capture_output=True)


class Resolver(unittest.TestCase):
    def test_regular_file_only_nameserver_values_and_reduced_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'etc').mkdir()
            (root / 'etc/resolv.conf').write_text('search SECRET.internal\nnameserver 192.0.2.53\nnameserver 2001:DB8::53\nnameserver 192.0.2.53\nnameserver 999.2.3.4\npassword SECRET\n')
            result = run(f'''
manifest_root={directory!r}
manifest_unprivileged=true
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_run_bounded() {{ printf 'CREDENTIAL_READ'; return 99; }}
manifest_resolver
''')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('path /etc/resolv.conf kind regular', result.stdout)
        self.assertIn('source resolv_conf address_count 2 status partial unparsed_count 1', result.stdout)
        self.assertIn('source resolv_conf address 2001:db8::53', result.stdout)
        self.assertIn('status skipped_unprivileged', result.stdout)
        self.assertNotIn('SECRET', result.stdout)
        self.assertNotIn('CREDENTIAL_READ', result.stdout)
        self.assertNotIn('999.2.3.4', result.stdout)

    def test_symlink_and_large_resolv_conf_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'etc').mkdir()
            target = root / 'stub'
            target.write_text('nameserver 127.0.0.53\n')
            (root / 'etc/resolv.conf').symlink_to(target)
            body = f'''
manifest_root={directory!r}
manifest_unprivileged=true
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_resolver
'''
            result = run(body)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('kind symlink', result.stdout)
            self.assertIn('address 127.0.0.53', result.stdout)
            target.write_text('SECRET' * 12000)
            result = run(body)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('reason resolv_conf_read_failed_or_limit', result.stdout)
            self.assertNotIn('SECRET', result.stdout)

    def upstream(self, output, status=0):
        # Head is mocked only for fixed /etc/resolv.conf; collector pipeline still uses real head.
        return run(f'''
manifest_root=
manifest_unprivileged=false
manifest_emit() {{ printf '%s\\n' "$*"; }}
head() {{ case "$*" in *'/etc/resolv.conf') printf 'nameserver 127.0.0.53\\n';; *) command head "$@";; esac; }}
resolvectl() {{ :; }}
manifest_run_bounded() {{
  [ "$1" = 3 ] && [ "$2" = resolvectl ] && [ "$3" = dns ] || return 99
  printf '%s' {shlex.quote(output)}
  return {status}
}}
manifest_resolver
''')

    def test_upstream_dedup_ipv6_tls_suffix_and_zero_upstreams(self):
        result = self.upstream('Global: 192.0.2.53\nLink 2 (eth0): 192.0.2.53 2001:DB8::53 ::1 1:2:3:4:5:6:7:: 192.0.2.54#SECRET.example\npassword SECRET\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('source resolvectl_dns address_count 5 status observed', result.stdout)
        self.assertEqual(result.stdout.count('source resolvectl_dns address 192.0.2.53\n'), 1)
        self.assertNotIn('SECRET', result.stdout)
        result = self.upstream('Global:\nLink 2 (eth0):\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('source resolvectl_dns address_count 0 status observed', result.stdout)

    def test_scoped_ipv6_and_unsupported_tokens(self):
        result = self.upstream('Global: fe80::53%eth0\nLink 2 (eth0): fe80::53%eth0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('source resolvectl_dns address fe80::53', result.stdout)
        self.assertIn('source resolvectl_dns address_count 1 status observed unparsed_count 0', result.stdout)
        self.assertNotIn('%eth0', result.stdout)
        result = self.upstream('Global: SECRET-invalid-address\n')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('source resolvectl_dns address_count 0 status partial unparsed_count 1', result.stdout)
        self.assertNotIn('SECRET', result.stdout)
        result = self.upstream('Global: 192.0.2.53 SECRET-invalid-address\n')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('source resolvectl_dns address_count 1 status partial unparsed_count 1', result.stdout)
        self.assertNotIn('SECRET', result.stdout)

    def test_timeout_malformed_and_output_limits(self):
        result = self.upstream('Global: 192.0.2.53\nSECRET', status=124)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('reason resolvectl_dns_failed_or_limit command_status 124', result.stdout)
        self.assertNotIn('source resolvectl_dns address ', result.stdout)
        self.assertNotIn('SECRET', result.stdout)
        result = self.upstream('password SECRET')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('status malformed_output', result.stdout)
        result = self.upstream('Global: ' + 'SECRET' * 12000)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('status query_failed', result.stdout)
        result = self.upstream('Global: ' + ' '.join('192.0.2.' + str(i) for i in range(1, 80)))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('address_count 32 status partial', result.stdout)
        self.assertEqual(result.stdout.count('source resolvectl_dns address '), 32)


if __name__ == '__main__':
    unittest.main()
