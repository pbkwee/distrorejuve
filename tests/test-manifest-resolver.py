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

    def inactive_service(self, addresses='192.0.2.53', state='inactive', load='loaded', query_status=1, unit_status=0, config_kind='regular'):
        return run(f"""
manifest_root=
manifest_unprivileged=false
manifest_collection_failed=false
# Mock path existence as well as file reads; never depend on the runner resolver.
function [() {{
  case "$1:$2" in
    -L:/etc/resolv.conf) test {shlex.quote(config_kind)} = symlink;;
    -f:/etc/resolv.conf) test {shlex.quote(config_kind)} = regular;;
    *) builtin [ "$@";;
  esac
}}
manifest_emit() {{ printf '%s\\n' "$*"; }}
head() {{ case "$*" in *'/etc/resolv.conf') printf '%s\\n' {shlex.quote(''.join('nameserver ' + address + chr(10) for address in addresses.split()))};; *) command head "$@";; esac; }}
resolvectl() {{ :; }}
systemctl() {{ :; }}
manifest_run_bounded() {{
  case "$1:$2" in
    3:resolvectl) return {query_status};;
    2:systemctl) printf 'LoadState=%s\\nActiveState=%s\\n' {shlex.quote(load)} {shlex.quote(state)}; return {unit_status};;
    *) return 99;;
  esac
}}
manifest_resolver
result=$?
printf 'collection_failed=%s\\n' "$manifest_collection_failed"
exit "$result"
""")

    def test_static_nameservers_with_proven_inactive_optional_service(self):
        result = self.inactive_service('192.0.2.53 2001:db8::53')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('source resolv_conf address_count 2 status observed', result.stdout)
        self.assertIn('source resolvectl_dns status inactive query_status 1 state_source systemctl', result.stdout)
        self.assertIn('collection_failed=false', result.stdout)
        self.assertNotIn('query_failed', result.stdout)

    def test_inactive_exception_preserves_ambiguous_and_failed_queries(self):
        cases = [
            {'config_kind': 'symlink'},
            {'config_kind': 'absent'},
            {'addresses': '127.0.0.53'},
            {'addresses': '192.0.2.53 127.0.0.54'},
            {'addresses': '::1'},
            {'addresses': ''},
            {'addresses': '999.2.3.4'},
            {'state': 'failed'},
            {'state': 'active'},
            {'state': 'activating'},
            {'state': ''},
            {'load': 'not-found'},
            {'unit_status': 1},
            {'query_status': 2},
            {'query_status': 125},
            {'query_status': 126},
            {'query_status': 127},
            {'query_status': 124},
            {'query_status': 137},
        ]
        for case in cases:
            with self.subTest(case=case):
                result = self.inactive_service(**case)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('status query_failed', result.stdout)
                self.assertIn('collection_failed=true', result.stdout)

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
