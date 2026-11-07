#!/usr/bin/env python3
"""Extracted Bash with synthetic status/identity; no service, API or DB operations."""
import hashlib
import pathlib
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh').read_text()


def declaration(name):
    return re.search(r'^function ' + name + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S).group()


def run(names, body):
    return subprocess.run(['bash'], input='\n'.join(map(declaration, names)) + '\n' + body,
                          text=True, capture_output=True)


SYSTEMD = r'''
fixture_pid='/lib~~delete~usrmerge~~/systemd/systemd (deleted)'
fixture_hash=aaa
fixture_refresh=0
readlink() { case "$*" in /proc/1/exe) printf '%s\n' "$fixture_pid";; '-f /sbin/init'|'-f -- /usr/lib/systemd/systemd'|'-f -- /lib/systemd/systemd') echo /usr/lib/systemd/systemd;; *) return 1;; esac; }
dpkg-query() { case "$1" in -W) printf 'install ok installed';; -S) echo 'systemd: /usr/lib/systemd/systemd';; *) return 1;; esac; }
dpkg() { [ "$1" = --audit ]; }
sha256sum() { case "$*" in /proc/1/exe) echo "$fixture_hash  /proc/1/exe";; *) echo 'aaa  /usr/lib/systemd/systemd';; esac; }
timeout() { shift; "$@"; }
systemctl() { [ "$1" = daemon-reexec ] || return 1; echo MUTATED; fixture_pid=/usr/lib/systemd/systemd; return "$fixture_refresh"; }
id() { echo 0; }
'''


@unittest.skipUnless(pathlib.Path('/usr/lib/systemd/systemd').is_file(), 'requires a local executable fixture path')
class StaleInit(unittest.TestCase):
    names = ['systemd_verify_stale_usrmerge_init', 'systemd_refresh_stale_usrmerge_init', 'check_systemd_install_matches_init']

    def test_readiness_explains_verified_remedy_without_mutation(self):
        r = run(self.names, SYSTEMD + '\ncheck_systemd_install_matches_init')
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn('--refresh-stale-systemd', r.stderr)
        self.assertNotIn('MUTATED', r.stdout)

    def test_refresh_rechecks_canonical_path_hash_and_health(self):
        r = run(self.names, SYSTEMD + '\nsystemd_refresh_stale_usrmerge_init')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), 'MUTATED')

    def test_mismatched_or_unknown_binary_never_reexecutes(self):
        for change in ('fixture_hash=bbb', 'fixture_pid=/unknown/deleted', 'dpkg() { echo audit-error; }'):
            with self.subTest(change=change):
                r = run(self.names, SYSTEMD + '\n' + change + '\nsystemd_refresh_stale_usrmerge_init')
                self.assertNotEqual(r.returncode, 0)
                self.assertNotIn('MUTATED', r.stdout)

    def test_package_ownership_before_usrmerge_remains_valid_for_verified_alias(self):
        r = run(self.names, SYSTEMD + r"""
dpkg-query() {
  case "$1" in
    -W) printf 'install ok installed';;
    -S) [ "${@: -1}" = /lib/systemd/systemd ] || return 1; echo 'systemd: /lib/systemd/systemd';;
  esac
}
systemd_refresh_stale_usrmerge_init
""")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_refresh_failure_and_unchanged_path_fail(self):
        for change in ('fixture_refresh=1', 'systemctl() { return 0; }'):
            r = run(self.names, SYSTEMD + '\n' + change + '\nsystemd_refresh_stale_usrmerge_init')
            self.assertNotEqual(r.returncode, 0)


SYSTEM_HOST = r'''
[() { if builtin [ "$*" = '-d /run/systemd/system ]'; then return 0; fi; builtin [ "$@"; }
readlink() { echo /usr/lib/systemd/systemd; }
timeout() { shift; "$@"; }
'''


class NativeSemantics(unittest.TestCase):
    def ssh(self, service, socket, status=0):
        return run(['upgrade_ssh_socket_is_listening'], SYSTEM_HOST + f'''
systemctl() {{ case "${{@: -1}}" in ssh.service) printf '%s\\n' {shlex.quote(service)};; ssh.socket) printf '%s\\n' {shlex.quote(socket)}; return {status};; esac; }}
upgrade_ssh_socket_is_listening
''')

    def test_idle_ssh_socket_is_healthy_but_failures_still_stop(self):
        service = 'LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success'
        socket = 'LoadState=loaded\nActiveState=active\nSubState=listening\nTriggers=ssh.service\nListen=[::]:22 (Stream)'
        self.assertEqual(self.ssh(service, socket).returncode, 0)
        for value in (socket.replace('listening', 'dead'), socket.replace('ssh.service', 'other.service'), socket.replace('LoadState=loaded', 'LoadState=not-found')):
            self.assertNotEqual(self.ssh(service, value).returncode, 0)
        self.assertNotEqual(self.ssh(service.replace('inactive', 'failed'), socket).returncode, 0)
        self.assertEqual(self.ssh(service, socket, 1).returncode, 2)

    def test_autoremove_capability_query_is_read_only(self):
        r = run(['apt_get_autoremove'], r"""
apt-get() { [ "$*" = --help ] || return 99; echo 'autoremove'; }
apt_get_apply() { [ "$*" = 'autoremove' ] || return 99; echo guarded-removal; }
apt_get_autoremove
""")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), 'guarded-removal')

    def test_failed_service_is_not_an_inactive_workload(self):
        for state, expected in [('inactive', 0), ('failed', 1), ('active', 1)]:
            r = run(['upgrade_workload_check_service'], SYSTEM_HOST + f'''
systemctl() {{ printf '%s\\n' LoadState=loaded ActiveState={state} Result=success; }}
upgrade_workload_check_service example inactive
''')
            self.assertEqual(r.returncode, expected, r.stderr)

    def test_logrotate_uses_debug_with_no_persistent_state(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = pathlib.Path(directory) / 'etc/logrotate.conf'
            conf.parent.mkdir(); conf.write_text('include /invented/config/directory\n')
            for output, status in [('', 0), ('error: duplicate log entry for /var/log/example.log', 1), ('syntax error', 1)]:
                r = run(['upgrade_logrotate_review'], f'''
timeout() {{ shift; "$@"; }}
logrotate() {{ printf 'args:%s\\n' "$*"; printf '%s\\n' {shlex.quote(output)}; return {status}; }}
upgrade_logrotate_review {shlex.quote(directory)}
''')
                # stdout is captured by the helper; only the summary is emitted.
                self.assertEqual(r.stdout, '')
                self.assertEqual('duplicate_log_path' in r.stderr, 'duplicate log' in output)
                self.assertEqual('coverage is incomplete' in r.stderr, status != 0)


    @unittest.skipUnless(shutil.which('logrotate'), 'native logrotate is not installed')
    def test_native_logrotate_includes_ignore_taboo_backup_and_find_real_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            includes = root / 'etc/logrotate.d'; includes.mkdir(parents=True)
            log = root / 'example.log'; log.touch()
            stanza = str(log) + ' {\n size 1k\n rotate 1\n missingok\n}\n'
            conf = root / 'etc/logrotate.conf'
            conf.write_text('include ' + str(includes) + '\n')
            (includes / 'active').write_text(stanza)
            (includes / 'ignored.dpkg-old').write_text(stanza)
            first = run(['upgrade_logrotate_review'], 'upgrade_logrotate_review ' + shlex.quote(directory))
            self.assertNotIn('duplicate_log_path', first.stderr)
            (includes / 'duplicate').write_text(stanza)
            second = run(['upgrade_logrotate_review'], 'upgrade_logrotate_review ' + shlex.quote(directory))
            self.assertIn('duplicate_log_path', second.stderr)


class Acceptance(unittest.TestCase):
    names = ['upgrade_workload_validate_contract', 'upgrade_workload_check', 'upgrade_workload_has_exception']

    def check(self, rows, result=0, exception=False, corrupt=False, phase='after'):
        with tempfile.TemporaryDirectory() as directory:
            original = pathlib.Path(directory) / 'original'
            original.write_text('synthetic original\n')
            frozen = pathlib.Path(str(original) + '.workload'); frozen.mkdir()
            contract = frozen / 'contract.tsv'; contract.write_text(rows)
            exception_file = pathlib.Path(directory) / 'exceptions.tsv'
            if exception:
                digest = hashlib.sha256(original.read_bytes()).hexdigest()
                c = hashlib.sha256(contract.read_bytes()).hexdigest()
                exception_file.write_text(f'exception\tapp\t{digest}\t{("a" * 64) if corrupt else c}\tAPPROVAL-7: accepted old limitation\n')
            return run(self.names, f'''
upgrade_workload_private_file() {{ [ -f "$1" ]; }}
upgrade_workload_check_service() {{ return {result}; }}
upgrade_workload_run_script() {{ return {result}; }}
DR_WORKLOAD_EXCEPTIONS={shlex.quote(str(exception_file))}
upgrade_workload_check {shlex.quote(str(original))} {phase}
''')

    def test_success_failure_unknown_and_explicit_exception(self):
        row = 'service\tapp\tnginx\tactive\t-\n'
        self.assertEqual(self.check(row).returncode, 0)
        self.assertNotEqual(self.check(row.rstrip('\n'), 1).returncode, 0)
        for result in (1, 2):
            self.assertNotEqual(self.check(row, result).returncode, 0)
            accepted = self.check(row, result, exception=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertIn('accepted_exception', accepted.stderr)
            self.assertNotEqual(self.check(row, result, exception=True, corrupt=True).returncode, 0)
        self.assertNotEqual(self.check(row, 1, exception=True, phase='before').returncode, 0)

    def test_final_outcome_preserves_workload_gate_and_unknowns(self):
        for gate, expected_status, incomplete in ((0, 0, False), (1, 1, True), (2, 0, True)):
            with self.subTest(gate=gate), tempfile.TemporaryDirectory() as directory:
                r = run(['upgrade_finish_run', 'is_complete_package_plan'], f"""
DR_RUN_DIRECTORY={shlex.quote(directory)}
printf 'release\\tverified\\ttrixie\\npackages\\tverified\\ttrixie\\n' > "$DR_RUN_DIRECTORY/outcome.events"
config_state_output_baseline() {{ echo fixture-original; }}
upgrade_services_check() {{ return 0; }}
upgrade_php_runtime_check() {{ return 0; }}
upgrade_php_runtime_findings_complete() {{ return 0; }}
upgrade_php_runtime_write_review() {{ return 0; }}
upgrade_outcome_output_php_removals() {{ :; }}
manifest_compare_baseline() {{ :; }}
upgrade_workload_check() {{ return {gate}; }}
upgrade_stage_finish() {{ printf 'stage-workload=%s\\n' "$5"; }}
dpkg() {{ [ "$*" = --audit ]; }}
apt-get() {{ echo '0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.'; }}
upgrade_finish_run 0 /fixture/log
""")
                self.assertEqual(r.returncode, expected_status, r.stderr)
                self.assertEqual((pathlib.Path(directory) / 'outcome.incomplete').exists(), incomplete)
                self.assertIn('stage-workload=' + ('verified' if gate == 0 else 'unknown'), r.stdout)

    def test_invalid_contract_never_runs_checks(self):
        for rows in ('', 'service\tx\tnginx\tmaybe\t-\n', 'service\tx\tnginx\tactive\t-\nservice\tx\tssh\tactive\t-\n', 'functional\tx\t/root/script\tbad-hash\t-\n'):
            self.assertNotEqual(self.check(rows).returncode, 0)

    def test_all_database_axes_required_independently(self):
        rows = ''
        for axis in ('engine', 'topology', 'schema', 'clients', 'maintenance', 'tables'):
            rows += f'database-info\ti-{axis}\t{axis}\trecorded version or identity\t-\n'
            rows += f'database-check\tc-{axis}\t{axis}\t/root/job/{axis}\t' + 'a' * 64 + '\n'
        self.assertEqual(self.check(rows).returncode, 0)
        self.assertNotEqual(self.check('\n'.join(rows.splitlines()[:-1]) + '\n').returncode, 0)
        self.assertNotEqual(self.check(rows, 1).returncode, 0)

    def test_script_hash_and_writable_ancestors_block_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            script = pathlib.Path(directory) / 'check'
            script.write_text('#!/bin/sh\nexit 0\n'); script.chmod(0o700)
            digest = hashlib.sha256(script.read_bytes()).hexdigest()
            body = f'''
stat() {{ case "$*" in '-c %u -- '*) echo 0;; '-c %a -- '*) echo 755;; esac; }}
upgrade_workload_run_script {shlex.quote(str(script))} {digest} after
'''
            r = run(['upgrade_workload_run_script'], body)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(run(['upgrade_workload_run_script'], body.replace(digest, 'a' * 64)).returncode, 2)
            self.assertEqual(run(['upgrade_workload_run_script'], body.replace('echo 755', 'echo 777')).returncode, 2)


if __name__ == '__main__':
    unittest.main()
