#!/usr/bin/env python3
"""Offline regressions: extract function declarations; never run script entrypoint."""
import pathlib
import re
import subprocess
import tempfile
import unittest

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh').read_text()


def declaration(name):
    # Producer is the script's top-level `function NAME() {` ... column-one `}`.
    # `function logging_run() (` ... column-one `)` is a subshell declaration.
    # Nested delimiters are indented; do not source initialization or dispatch code.
    match = re.search(r'^function ' + re.escape(name) + r'\(\) (\{\n.*?^\}|\(\n.*?^\))', SOURCE, re.M | re.S)
    assert match, name
    return match.group()


def run(names, body):
    script = '\n'.join(declaration(name) for name in names) + '\n' + body
    return subprocess.run(['bash'], input=script, text=True, capture_output=True)


class UpgradeReview(unittest.TestCase):
    PACKAGE_ERROR = ("dpkg: error processing archive /private/EXAMPLE.deb (--unpack):\n"
                     " trying to overwrite shared '/etc/example.conf', which is different from other instances\n")
    PACKAGE_OUTCOME = ('dss:trace: Package recovery health: verified.\n'
                       'dss:stage: Outcome: release verified (trixie); '
                       'packages verified (trixie); services verified.\n')

    def test_package_error_recovery_requires_later_verified_outcome_and_success(self):
        for log, status, expected in [
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME, 0, 'verified_recovered'),
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME, 1, 'unresolved_or_unverified'),
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME, 'unknown', 'unresolved_or_unverified'),
            (self.PACKAGE_OUTCOME + self.PACKAGE_ERROR, 0, 'unresolved_or_unverified'),
            (self.PACKAGE_ERROR, 0, 'unresolved_or_unverified'),
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME.replace('packages verified (trixie)',
                                                            'packages failed final verification'),
             0, 'unresolved_or_unverified'),
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME.replace('packages verified (trixie)',
                                                            'packages verified (bookworm)'),
             0, 'unresolved_or_unverified'),
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME +
             'dss:stage: Outcome: release not verified; packages not verified; services unknown.\n',
             0, 'unresolved_or_unverified'),
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME.replace(
                'dss:trace: Package recovery health: verified.\n', ''), 0, 'unresolved_or_unverified'),
            (self.PACKAGE_OUTCOME, 0, 'none_observed'),
        ]:
            with self.subTest(log=log, status=status), tempfile.TemporaryDirectory() as directory:
                logfile = pathlib.Path(directory) / 'output.log'
                logfile.write_text(log)
                result = run(['support_output_package_error_recovery'],
                             f'support_output_package_error_recovery {str(logfile)!r} {status!r}')
                self.assertEqual(result.returncode, 0, result.stderr)
                categories = 'none' if expected == 'none_observed' else 'dpkg package_file_conflict'
                self.assertEqual(result.stdout, f'{expected}\t{categories}\n')
                self.assertEqual(logfile.read_text(), log)

    def test_package_recovery_console_keeps_final_health_and_exit_checks(self):
        for health, action_status, expected_status in [('clean', 0, 0), ('held_back', 0, 0),
                                                       ('missing_summary', 0, 0), ('pending', 0, 1),
                                                       ('audit_failed', 0, 1), ('audit_stderr', 0, 1),
                                                       ('service_failed', 0, 1),
                                                       ('clean', 7, 7)]:
            with self.subTest(health=health, action_status=action_status), tempfile.TemporaryDirectory() as directory:
                result = run(['logging_run', 'upgrade_finish_run', 'upgrade_outcome_record',
                              'support_output_package_error_recovery', 'is_complete_package_plan'], f'''
DR_LOG_DIRECTORY={directory!r}
DR_ACTION=--to-latest
config_state_output_baseline() {{ printf 'fixture-baseline\n'; }}
upgrade_services_check() {{ return {1 if health == 'service_failed' else 0}; }}
upgrade_php_runtime_check() {{ return 0; }}
upgrade_php_runtime_findings_complete() {{ return 0; }}
upgrade_php_runtime_write_review() {{ return 0; }}
upgrade_outcome_output_php_removals() {{ :; }}
manifest_compare_baseline() {{ :; }}
support_print_report() {{ printf 'fixture support report\n'; }}
dpkg() {{ [ "$*" = --audit ] || return 99; {'return 2' if health == 'audit_failed' else "printf 'audit diagnostic\\n' >&2" if health == 'audit_stderr' else ':'}; }}
apt-get() {{
  [ "$*" = '-s dist-upgrade' ] || return 99
  {'return 0' if health == 'missing_summary' else ':'}
  printf '%s\n' {'"Inst example [1.0] (2.0 fixture [amd64])"' if health == 'pending' else '"0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded."' if health == 'held_back' else '"0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."'}
}}
distrorejuve_main() {{
  printf '%b' {self.PACKAGE_ERROR!r}
  upgrade_outcome_record release verified trixie || return 99
  upgrade_outcome_record packages verified trixie || return 99
  return {action_status}
}}
logging_run distrorejuve_main --to-latest
''')
                self.assertEqual(result.returncode, expected_status, result.stderr)
                logfile, = pathlib.Path(directory).glob('run.*/output.log')
                self.assertIn('dpkg: error processing archive', logfile.read_text())
                if health == 'clean' and expected_status == 0:
                    self.assertIn('Earlier package errors were recovered', result.stderr)
                    self.assertNotIn('remain unresolved or unverified', result.stderr)
                else:
                    self.assertNotIn('Earlier package errors were recovered', result.stderr)
                    self.assertIn('remain unresolved or unverified', result.stderr)
                if health in ('pending', 'audit_failed', 'audit_stderr'):
                    self.assertIn('packages failed final verification', logfile.read_text())

    def test_support_report_keeps_evidence_and_rechecks_current_package_health(self):
        for health in ('clean', 'pending', 'audit_failed', 'audit_incomplete', 'audit_stderr',
                       'held_back', 'missing_summary', 'partial_summary', 'malformed_summary', 'nonzero_summary',
                       'duplicate_summary', 'inconsistent_summary'):
            with self.subTest(health=health), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                (root / 'support.context').write_text('0\t--to-latest\t' + 'a' * 64 + '\tfalse\tunknown\n')
                (root / 'output.log').write_text(self.PACKAGE_ERROR + self.PACKAGE_OUTCOME)
                result = run(['support_print_report', 'support_output_package_error_recovery',
                              'is_complete_package_plan'], f'''
ALL_DEBIAN='bookworm trixie'
ALL_UBUNTU='noble'
distro_output_codename() {{ printf 'trixie\n'; }}
sha256sum() {{ printf '%s  fixture-script\n' {'a' * 64!r}; }}
dpkg() {{
  case "$*" in
    --print-architecture) printf 'amd64\n';;
    --audit) {'return 2' if health == 'audit_failed' else "printf 'example is unpacked but not configured\\n'" if health == 'audit_incomplete' else "printf 'PRIVATE AUDIT WARNING\\n' >&2" if health == 'audit_stderr' else ':'};;
    *) return 99;;
  esac
}}
dpkg-query() {{
  case "$*" in
    *Version*) printf '1.0\n';;
    *Status*) printf 'install ok installed\n';;
    *) return 99;;
  esac
}}
apt-cache() {{ [ "$*" = policy ]; }}
apt-get() {{
  [ "$*" = '-s dist-upgrade' ] || return 99
  {'return 0' if health == 'missing_summary' else ':'}
  {'printf "0 upgraded, 0 newly installed, 0 to remove\\n"; return 0' if health == 'partial_summary' else ':'}
  {'printf "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded. extra\\n"; return 0' if health == 'malformed_summary' else ':'}
  {'printf "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\\n"' if health == 'duplicate_summary' else ':'}
  {'printf "Inst example [1.0] (2.0 fixture [amd64])\\n"' if health in ('pending', 'inconsistent_summary') else ':'}
  printf '{1 if health in ('pending', 'nonzero_summary') else 0} upgraded, 0 newly installed, 0 to remove and {1 if health == 'held_back' else 0} not upgraded.\n'
}}
df() {{ printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\nfixture 8192000 4096000 4096000 50%% /\n'; }}
uname() {{ [ "$*" = -r ] || return 99; printf '6.12.0-fixture\n'; }}
support_print_report {directory!r}
''')
                self.assertEqual(result.returncode, 1 if health == 'missing_summary' else 0, result.stderr)
                expected = 'verified_recovered' if health == 'clean' else 'unresolved_or_unverified'
                self.assertIn(f'recorded_package_error_recovery: {expected}', result.stdout)
                expected_health = 'verified' if health == 'clean' else 'unverified'
                self.assertIn(f'current_package_health: {expected_health}', result.stdout)
                self.assertIn('observed_package_error_categories: dpkg package_file_conflict', result.stdout)
                observed = re.search(r'^observed_error_categories: (.*)$', result.stdout, re.M).group(1).split()
                self.assertIn('dpkg', observed)
                self.assertIn('package_file_conflict', observed)
                self.assertIn('recorded_completion_verification: verified', result.stdout)
                self.assertNotIn('/private/', result.stdout)
                self.assertNotIn('/etc/example.conf', result.stdout)
                self.assertNotIn('PRIVATE AUDIT WARNING', result.stdout + result.stderr)

    def test_process_snapshot_precedes_parser(self):
        result = run(['manifest_process_indicators'], r'''
manifest_emit() { printf '%s\n' "$*"; }
manifest_run_bounded() {
  # A parser containing our heuristic must not be alive during collection.
  if ps -eww -o args= | grep '^awk ' | grep -q 'mining_command_arguments'; then return 1; fi
  printf '%s\n' '100 1 0 9000 nginx: worker process' \
    '101 100 1000 9000 worker --algo rx/0 --url pool.example.test --user TOKEN' \
    '102 100 1000 9000 /tmp/worker'
}
manifest_process_indicators
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('indicator mining_command_arguments'), 1)
        self.assertIn('sample_pid 101', result.stdout)
        self.assertIn('sample_pid 102', result.stdout)
        self.assertNotIn('sample_pid 100 ', result.stdout)

    def test_process_failure_is_incomplete(self):
        result = run(['manifest_process_indicators'], '''
manifest_emit() { :; }
manifest_run_bounded() { return 124; }
manifest_collection_failed=false
manifest_process_indicators
$manifest_collection_failed
''')
        self.assertEqual(result.returncode, 0)

    def test_virtualmin_remnant_then_installed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = root / 'etc/webmin/virtual-server/config'
            config.parent.mkdir(parents=True)
            config.write_text('private-data-not-read\n')
            names = ['upgrade_panel_output_installed', 'manifest_hosting_panels']
            body = f'manifest_root={directory!r}\nmanifest_emit() {{ printf "%s\\n" "$*"; }}\nmanifest_hosting_panels\n'
            result = run(names, body)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('panel_remnant name virtualmin', result.stdout)
            self.assertNotIn('hosting_panel', result.stdout)
            module = root / 'usr/share/webmin/virtual-server/module.info'
            module.parent.mkdir(parents=True)
            module.write_text('version=8.0.0\n')
            result = run(names, body)
            self.assertIn('hosting_panel name virtualmin version 8.0.0', result.stdout)
            self.assertNotIn('panel_remnant', result.stdout)

    def test_probe_marks_partial_and_unknown(self):
        result = run(['manifest_probe'], """
manifest_warning_count=0
manifest_emit() { printf '%s\n' "$*"; }
probe_partial() { manifest_warning_count=1; }
probe_failure() { return 7; }
manifest_probe sample probe_partial
manifest_probe broken probe_failure
""")
        self.assertEqual(result.returncode, 7)
        self.assertIn('result partial', result.stdout)
        self.assertIn('result unknown command_status 7', result.stdout)

    def test_custom_virtualmin_command_allows_normal_checks(self):
        result = run(['upgrade_panel_refuse_generic', 'upgrade_panel_uses_distro_packages'], """
upgrade_panel_output_installed() { :; }
virtualmin() { :; }
upgrade_panel_refuse_generic
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('blocked', result.stderr)

    def test_distro_panels_pass_generic_guard_but_other_panels_still_block(self):
        for panels, expected in [('virtualmin', 0), ('ispconfig', 0),
                                 ('virtualmin ispconfig', 0), ('virtualmin directadmin', 1),
                                 ('plesk', 1), ('cpanel', 1), ('hestiacp', 1)]:
            with self.subTest(panels=panels):
                result = run(['upgrade_panel_refuse_generic', 'upgrade_panel_uses_distro_packages',
                              'upgrade_panel_output_procedure_url'], f'''
upgrade_panel_output_installed() {{ for panel in {panels}; do printf '%s\\tunknown\\n' "$panel"; done; }}
upgrade_panel_refuse_generic
''')
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_collection_status_is_transient(self):
        result = run(['manifest_output_review_record'], "manifest_output_review_record collection_status warning_count 2")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

    def test_small_disk_floor(self):
        for free, expected in [(2300, 0), (2048, 0), (2047, 1)]:
            result = run(['check_disk_space'], f'''
df() {{ printf 'Filesystem 1048576-blocks Used Available Capacity Mounted-on\\n/dev/test 8000 5000 {free} 70%% /\\n'; }}
check_disk_space
''')
            self.assertEqual(result.returncode, expected, result.stderr)
        result = run(['check_disk_space'], '''
df() { return 1; }
check_disk_space
''')
        self.assertNotEqual(result.returncode, 0)

    def test_configuration_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'etc/network').mkdir(parents=True)
            (root / 'etc/network/interfaces').write_text('iface tun0 inet6 v4tunnel\niface tun0 inet6 v4tunnel\n')
            (root / 'etc/fstab').write_text('/dev/test / ext4 defaults,usrquota 0 1\n')
            (root / 'etc/logrotate.d').mkdir()
            (root / 'etc/logrotate.conf').write_text('/var/log/example.log {\n}\n')
            (root / 'etc/logrotate.d/duplicate').write_text('/var/log/example.log {\n postrotate\n /bin/kill worker\n endscript\n}\n')
            (root / 'etc/monit/conf.d').mkdir(parents=True)
            (root / 'etc/monit/conf.d/example').write_text('if failed port 808080 then restart\nstart program = "service nginx start"\nstop program = "/usr/bin/systemctl stop nginx"\n')
            result = run(['upgrade_configuration_review'], f'upgrade_configuration_review {directory!r}')
            self.assertEqual(result.stderr.count('duplicate_log_path'), 1)
            self.assertEqual(result.stderr.count('invalid_monitor_port'), 1)
            self.assertEqual(result.stderr.count('relative_monitor_program'), 1)
            self.assertIn('duplicate_interface', result.stderr)
            self.assertIn('previous line 1', result.stderr)
            self.assertIn('quota_dependency', result.stderr)

    def test_database_earlier_target_warns(self):
        result = run(['upgrade_database_verify'], """
mariadb() { :; }
manifest_run_bounded() {
  case "$*" in
    *'SELECT 1'*) printf '1\n';;
    *'SELECT @@innodb_buffer_pool_size'*) printf '1\n';;
    *mysql.global_priv*) printf 'socket_identity_requires_review';;
    *) return 99;;
  esac
}
upgrade_database_verify bookworm
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('dss:warn: Root unix_socket', result.stderr)
        self.assertNotIn('dss:error:', result.stderr)

    def test_database_existing_option_file_fallback(self):
        result = run(['upgrade_database_verify'], """
mariadb() { :; }
manifest_run_bounded() {
  case "$*" in
    *'SELECT 1'*)
      case "$*" in *--no-defaults*) return 1;; esac
      printf '1\n';;
    *'SELECT @@innodb_buffer_pool_size'*) printf '1\n';;
    *mysql.global_priv*) :;;
    *) return 99;;
  esac
}
upgrade_database_verify trixie
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('maintenance succeeded', result.stderr)

    def test_database_no_live_commands(self):
        for identity, fail, expected in [('', False, 0), ('socket_identity_requires_review', False, 1), ('', True, 1)]:
            result = run(['upgrade_database_verify'], f'''
mariadb() {{ :; }}
manifest_run_bounded() {{
  case "$*" in
    *'SELECT 1'*) {'return 1' if fail else "printf '1\\n'"};;
    *'SELECT @@innodb_buffer_pool_size'*) printf '1\\n';;
    *mysql.global_priv*) printf '%s' {identity!r};;
    *) return 99;;
  esac
}}
upgrade_database_verify trixie
''')
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertNotIn('legacy-hash', result.stderr)


if __name__ == '__main__':
    unittest.main()
