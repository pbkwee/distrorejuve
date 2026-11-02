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
    def test_missing_debian_signers_are_pinned_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / 'apt.log'
            log.write_text('NO_PUBKEY 112695A0E562B32A\nNO_PUBKEY 112695A0E562B32A\n'
                           'NO_PUBKEY 648ACFD622F3D138\nNO_PUBKEY 0123456789ABCDEF\n')
            result = run(['apt_repair_debian_signing_keys'], f'''
apt_sources_list() {{ printf '/fixture.list\\t1\\tdebian\\tdeb\\thttps://archive.debian.org/debian\\tstretch\\tmain\\t*\\n'; }}
apt-config() {{ :; }}
apt_config_has_standard_paths() {{ return 0; }}
apt_debian_archive_key_install() {{ printf '%s %s\\n' "$1" "$2"; }}
apt_repair_debian_signing_keys {str(log)!r}
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), [
                'archive-key-10 80D15823B7FD1561F9F7BCDDDC30D7C23CBBABEE',
                'archive-key-10-security 5E61B217265DA9807A23C5FF4DFAB270CAA96DFA'])

    def test_unknown_or_non_debian_signers_do_not_fetch_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / 'apt.log'
            for provider, diagnostic in [('ubuntu', 'NO_PUBKEY 112695A0E562B32A'),
                                         ('debian', 'NO_PUBKEY 0123456789ABCDEF'),
                                         ('debian', 'EXPKEYSIG AA8E81B4331F7F50')]:
                with self.subTest(provider=provider, diagnostic=diagnostic):
                    log.write_text(diagnostic + '\n')
                    result = run(['apt_repair_debian_signing_keys'], f'''
apt_sources_list() {{ printf '/fixture.list\\t1\\t{provider}\\tdeb\\thttps://example.invalid/archive\\told\\tmain\\t*\\n'; }}
apt-config() {{ :; }}
apt_config_has_standard_paths() {{ return 0; }}
apt_debian_archive_key_install() {{ echo unexpected-install; return 99; }}
apt_repair_debian_signing_keys {str(log)!r}
''')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn('unexpected', result.stdout + result.stderr)

    def test_key_repair_refuses_custom_apt_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / 'apt.log'
            log.write_text('NO_PUBKEY 112695A0E562B32A\n')
            result = run(['apt_repair_debian_signing_keys'], f'''
apt_sources_list() {{ printf '/fixture.list\\t1\\tdebian\\tdeb\\thttps://archive.debian.org/debian\\tstretch\\tmain\\t*\\n'; }}
apt-config() {{ :; }}
apt_config_has_standard_paths() {{ return 1; }}
apt_debian_archive_key_install() {{ echo unexpected-install; }}
apt_repair_debian_signing_keys {str(log)!r}
''')
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('unexpected', result.stdout + result.stderr)

    def test_downloaded_key_must_match_pinned_primary_before_activation(self):
        expected = '5E61B217265DA9807A23C5FF4DFAB270CAA96DFA'
        for mode in ['valid', 'wget', 'wrong-primary', 'expired', 'revoked', 'tls-failure']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                target = pathlib.Path(directory) / 'trusted/key.gpg'
                result = run(['apt_debian_archive_key_install'], f'''
curl() {{
  for test_argument in "$@"; do case "$test_argument" in --insecure|-k) echo unexpected-insecure; return 99;; esac; done
  [ {mode!r} != tls-failure ] || return 22
  while [ "$#" -gt 0 ]; do
    if [ "$1" = --output ]; then printf 'fixture-public-key' > "$2"; return 0; fi
    shift
  done
  return 98
}}
command() {{
  if [ {mode!r} = wget ] && [ "$1" = -v ] && [ "$2" = curl ]; then return 1; fi
  builtin command "$@"
}}
wget() {{
  for test_argument in "$@"; do
    case "$test_argument" in
      --no-check-certificate) echo unexpected-insecure; return 99;;
      --output-document=*) printf 'fixture-public-key' > "${{test_argument#--output-document=}}";;
    esac
  done
}}
gpg() {{
  case "$*" in
    *--import*) return 0;;
    *--list-keys*)
      test_validity=-; test_fingerprint={expected}
      [ {mode!r} != wrong-primary ] || test_fingerprint=0000000000000000000000000000000000000000
      [ {mode!r} != expired ] || test_validity=e
      [ {mode!r} != revoked ] || test_validity=r
      printf 'pub:%s:4096:1:4DFAB270CAA96DFA:1:9999999999::::\\nfpr:::::::::%s:\\n' "$test_validity" "$test_fingerprint";;
    *--export*) printf 'verified-public-key-bytes';;
    *) return 97;;
  esac
}}
gpgconf() {{ :; }}
apt_debian_archive_key_install archive-key-10-security {expected} {str(target)!r}
''')
                if mode in ('valid', 'wget'):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(target.read_text(), 'verified-public-key-bytes')
                    self.assertEqual(target.stat().st_mode & 0o777, 0o644)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(target.exists())
                self.assertNotIn('unexpected', result.stdout + result.stderr)

    def test_apt_update_repairs_before_retry_and_stops_if_repair_fails(self):
        for repaired, initial_status, still_bad in [(True, 100, False), (True, 0, False),
                                                   (False, 100, False), (False, 0, False), (True, 0, True)]:
            with self.subTest(repaired=repaired, initial_status=initial_status, still_bad=still_bad), tempfile.TemporaryDirectory() as directory:
                result = run(['apt_get_update'], f'''
cd {directory!r}
apt_package_lock_warn() {{ :; }}
pause_check() {{ :; }}
apt_configure_archive_authentication() {{ :; }}
apt_state_output_signature() {{ printf 'fixture-signature'; }}
apt-get() {{
  printf 'called\\n' >> attempts
  if [ -f repaired ] && [ {str(still_bad).lower()} = false ]; then echo 'Fetched indexes'; return 0; fi
  echo 'NO_PUBKEY 112695A0E562B32A'
  return {initial_status}
}}
apt_repair_debian_signing_keys() {{
  [ {str(repaired).lower()} = true ] || return 1
  touch repaired
}}
apt-cache() {{ return 0; }}
apt_get_update
status=$?
printf 'RESULT=%s ATTEMPTS=%s\\n' "$status" "$(wc -l < attempts)"
exit "$status"
''')
                if repaired and not still_bad:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('RESULT=0 ATTEMPTS=2', result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('ATTEMPTS=' + ('2' if repaired else '1'), result.stdout)

    def test_explicit_readiness_dispatch_cannot_enter_upgrade_or_inventory(self):
        result = run(['distrorejuve_run', 'distrorejuve_main', 'environment_validate_settings'], '''
DR_ACTION=--to-latest
DR_UPGRADE_MANIFEST=false
upgrade_print_check() { printf 'readiness-only\n'; return 7; }
manifest_output() { echo 'unexpected collector'; return 99; }
manifest_capture() { echo 'unexpected capture'; return 99; }
logging_run() { echo 'unexpected mutation'; return 99; }
distrorejuve_run --check-upgrade
''')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn('readiness-only', result.stdout)
        self.assertNotIn('unexpected', result.stdout + result.stderr)

    def test_disabled_upgrade_inventory_never_collects_or_reads_old_baseline(self):
        for name in ['manifest_capture', 'manifest_compare_baseline']:
            with self.subTest(name=name):
                result = run([name], '''
DR_UPGRADE_MANIFEST=false
manifest_output() { echo 'unexpected collector'; return 99; }
mkdir() { echo 'unexpected directory creation'; return 99; }
head() { echo 'unexpected baseline read'; return 99; }
stat() { echo 'unexpected metadata read'; return 99; }
''' + name + ' /does-not-exist\n')
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn('disabled by DR_UPGRADE_MANIFEST=false', result.stderr)

    def test_upgrade_inventory_default_still_publishes_capture(self):
        for setting in ['', 'true']:
            with self.subTest(setting=setting), tempfile.TemporaryDirectory() as directory:
                target = pathlib.Path(directory) / 'inventory'
                result = run(['manifest_capture'], f'''
DR_UPGRADE_MANIFEST={setting!r}
manifest_output() {{
  printf '%s\\n' '{{"schema_version":1,"records":[]}}'
  printf '%s\\n' 'system example' > "$4"
}}
manifest_capture {str(target)!r}
''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((target / 'manifest.review').read_text(),
                                 'manifest-review-v1\nsystem example\n')
                self.assertIn('"records":[]', (target / 'manifest.json').read_text())

    def test_upgrade_inventory_setting_rejects_invalid_before_collection(self):
        for name in ['environment_validate_settings', 'manifest_capture', 'manifest_compare_baseline']:
            with self.subTest(name=name):
                result = run([name], '''
DR_UPGRADE_MANIFEST=invalid
manifest_output() { echo 'unexpected collector'; return 99; }
''' + name + ' /does-not-exist\n')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn('DR_UPGRADE_MANIFEST must be true or false', result.stderr)

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
