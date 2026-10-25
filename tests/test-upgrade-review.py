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
    # Nested braces are indented; do not source initialization or dispatch code.
    match = re.search(r'^function ' + re.escape(name) + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
    assert match, name
    return match.group()


def run(names, body):
    script = '\n'.join(declaration(name) for name in names) + '\n' + body
    return subprocess.run(['bash'], input=script, text=True, capture_output=True)


class UpgradeReview(unittest.TestCase):
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

    def test_custom_virtualmin_command_blocks_generic(self):
        result = run(['upgrade_panel_refuse_generic'], """
upgrade_panel_output_installed() { :; }
virtualmin() { :; }
upgrade_panel_refuse_generic
""")
        self.assertEqual(result.returncode, 1)
        self.assertIn('custom installation require review', result.stderr)

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
