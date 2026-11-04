#!/usr/bin/env python3
"""Offline upgrade regressions: extracted declarations, synthetic data, no dispatch."""
import os
import pathlib
import re
import shlex
import subprocess
import tempfile
import unittest

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh').read_text()


def declaration(name):
    # Top-level Bash declarations end at a column-one brace; omit initialization.
    match = re.search(r'^function ' + re.escape(name) + r'\(\) \{\n.*?^\}',
                      SOURCE, re.M | re.S)
    assert match, name
    return match.group()


def run(names, body, source=None):
    script = source or '\n'.join(declaration(name) for name in names)
    return subprocess.run(['bash'], input=script + '\n' + body, text=True,
                          capture_output=True)


class PinnedBaseline(unittest.TestCase):
    def test_explicit_original_survives_history_expiry_without_global_search(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = pathlib.Path(directory) / 'original snapshot'
            baseline.write_text('original\n')
            os.utime(baseline, (1, 1))
            result = run(['config_state_output_baseline'], f'''
DR_CONFIG_BASELINE={shlex.quote(str(baseline))}
DR_CONFIGURATION_HISTORY_DAYS=1
find() {{ echo unexpected-history-search >&2; return 99; }}
config_state_output_baseline
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(baseline))
            self.assertEqual(result.stderr, '')

    def test_unusable_selected_original_never_falls_back(self):
        for kind in ('missing', 'empty', 'symlink', 'directory', 'incomplete'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                baseline = pathlib.Path(directory) / 'original'
                if kind == 'symlink':
                    target = pathlib.Path(directory) / 'other'
                    target.write_text('other job\n')
                    baseline.symlink_to(target)
                elif kind == 'directory':
                    baseline.mkdir()
                elif kind != 'missing':
                    baseline.write_text('original\n' if kind == 'incomplete' else '')
                if kind == 'incomplete':
                    pathlib.Path(str(baseline) + '.incomplete').touch()
                result = run(['config_state_output_baseline'], f'''
DR_CONFIG_BASELINE={shlex.quote(str(baseline))}
find() {{ echo unexpected-history-search >&2; return 99; }}
config_state_output_baseline
''')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('unexpected', result.stderr)

    def test_unset_pin_retains_oldest_recent_legacy_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name in ('current', 'legacy'):
                (root / name).mkdir()
            recent = root / 'current/preupgrade.dpkg.new'
            oldest = root / 'legacy/preupgrade.dpkg.old'
            expired = root / 'current/preupgrade.dpkg.expired'
            for file in (recent, oldest, expired):
                file.write_text('baseline\n')
            os.utime(oldest, (recent.stat().st_mtime - 100, recent.stat().st_mtime - 100))
            os.utime(expired, (1, 1))
            source = declaration('config_state_output_baseline').replace(
                '/root/distrorejuveinfo/', str(root / 'current') + '/').replace(
                '/root/deghostinfo/', str(root / 'legacy') + '/')
            result = run([], 'unset DR_CONFIG_BASELINE\nconfig_state_output_baseline\n', source)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(oldest))

    def test_legacy_history_excludes_incomplete_originals_and_marker_files(self):
        for complete in (False, True):
            with self.subTest(complete=complete), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                for name in ('current', 'legacy'):
                    (root / name).mkdir()
                original = root / 'current/preupgrade.dpkg.failed'
                marker = pathlib.Path(str(original) + '.incomplete')
                orphan = root / 'legacy/preupgrade.dpkg.orphan.incomplete'
                for file in (original, marker, orphan):
                    file.write_text('partial snapshot or marker\n')
                    os.utime(file, (file.stat().st_mtime - 100, file.stat().st_mtime - 100))
                valid = root / 'legacy/preupgrade.dpkg.complete'
                if complete:
                    valid.write_text('complete snapshot\n')
                source = declaration('config_state_output_baseline').replace(
                    '/root/distrorejuveinfo/', str(root / 'current') + '/').replace(
                    '/root/deghostinfo/', str(root / 'legacy') + '/')
                result = run([], 'unset DR_CONFIG_BASELINE\nconfig_state_output_baseline\n', source)
                self.assertEqual(result.returncode, 0 if complete else 1, result.stderr)
                self.assertEqual(result.stdout.strip(), str(valid) if complete else '')

    def test_empty_unmarked_legacy_original_is_neither_selected_nor_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'current').mkdir()
            (root / 'legacy').mkdir()
            empty = root / 'current/preupgrade.dpkg.empty'
            empty.touch()
            source = '\n'.join(declaration(name) for name in
                               ('config_state_output_baseline', 'record_config_state'))
            source = source.replace('/root/distrorejuveinfo/', str(root / 'current') + '/')
            source = source.replace('/root/deghostinfo/', str(root / 'legacy') + '/')
            result = run([], f"""
unset DR_CONFIG_BASELINE
prepare_output_dir() {{ :; }}
config_state_capture() {{ echo unexpected-recollection; return 99; }}
config_state_output_baseline
printf 'SELECT=%s\\n' \"$?\"
record_config_state {shlex.quote(str(empty))}
printf 'REUSE=%s\\n' \"$?\"
""", source)
            self.assertIn('SELECT=1', result.stdout)
            self.assertIn('REUSE=1', result.stdout)
            self.assertNotIn('unexpected', result.stdout + result.stderr)
            self.assertEqual(empty.read_text(), '')

    def capture(self, directory, failure=0, repeated=True, producer_failure='',
                ignored_umask=False, snapshot_name=None):
        argument = shlex.quote(str(pathlib.Path(directory) / snapshot_name)) if snapshot_name else ''
        return run(['config_state_output_baseline', 'config_state_output_listeners',
                    'config_state_capture', 'record_config_state', 'manifest_capture'], f'''
DR_CONFIG_BASELINE={shlex.quote(str(pathlib.Path(directory) / 'original'))}
DR_UPGRADE_MANIFEST=false
fixture_failure={shlex.quote(producer_failure)}
prepare_output_dir() {{ :; }}
find() {{
  [ "$1" = /etc ] && [ "$2" = -type ] && [ "$3" = f ] || return 99
  [ "$fixture_failure" != find ] || return 71
}}
netstat() {{
  [ "$*" = -ntpl ] || return 99
  [ "$fixture_failure" != listeners ] || return 72
  printf 'tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1/sshd\\n'
}}
ss() {{ echo unexpected-listener-fallback >&2; return 99; }}
command() {{
  if [ "$1" = -v ]; then
    case "$2" in netstat) return 0;; ss) return 1;; esac
  fi
  builtin command "$@"
}}
ps() {{
  [ "$fixture_failure" != ps ] || return 73
  printf '1 ? S 0:00 worker\\n'
}}
print_distro_info() {{
  [ "$fixture_failure" != distro ] || return 74
  echo synthetic-distro
}}
dpkg() {{
  [ "$*" = -l ] || return 99
  [ "$fixture_failure" != dpkg ] || return 75
  printf 'ii  fixture-service 1 amd64 Synthetic service\\n'
}}
# Enable only the mocked package command; never execute absolute host tools.
function [() {{
  if builtin [ "$1" = -x ]; then builtin [ "$2" = /usr/bin/dpkg ]; return $?; fi
  builtin [ "$@"
}}
{'umask() { builtin umask 000; }' if ignored_umask else ''}
upgrade_php_runtime_snapshot() {{ echo runtime > "$1/state"; return {failure}; }}
upgrade_services_snapshot() {{ echo service > "$1/state"; }}
record_config_state {argument}
first=$?
printf 'FIRST=%s\\n' "$first"
if {'true' if repeated else 'false'}; then
  find() {{ echo unexpected-recollection >&2; return 99; }}
  record_config_state {argument}
  printf 'SECOND=%s\\n' "$?"
fi
''')

    def test_new_pin_is_private_once_and_respects_disabled_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.capture(directory)
            baseline = pathlib.Path(directory) / 'original'
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('FIRST=0', result.stdout)
            self.assertIn('SECOND=0', result.stdout)
            self.assertEqual(result.stdout.count('record_config_state:'), 1)
            self.assertNotIn('unexpected', result.stdout + result.stderr)
            self.assertEqual(baseline.stat().st_mode & 0o777, 0o600)
            self.assertFalse(pathlib.Path(str(baseline) + '.incomplete').exists())
            self.assertFalse(pathlib.Path(str(baseline) + '.applications').exists())
            self.assertTrue(pathlib.Path(str(baseline) + '.services/state').is_file())

    def test_failed_required_snapshot_remains_incomplete_on_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.capture(directory, failure=17)
            self.assertIn('FIRST=1', result.stdout)
            self.assertIn('SECOND=1', result.stdout)
            self.assertNotIn('unexpected', result.stdout + result.stderr)
            baseline = pathlib.Path(directory) / 'original'
            self.assertTrue(pathlib.Path(str(baseline) + '.incomplete').is_file())

    def test_failed_main_snapshot_producers_remain_incomplete_on_retry(self):
        for producer in ('find', 'listeners', 'ps', 'distro', 'dpkg'):
            with self.subTest(producer=producer), tempfile.TemporaryDirectory() as directory:
                result = self.capture(directory, producer_failure=producer)
                self.assertRegex(result.stdout, r'FIRST=[1-9][0-9]*\n')
                self.assertRegex(result.stdout, r'SECOND=[1-9][0-9]*\n')
                self.assertNotIn('unexpected', result.stdout + result.stderr)
                baseline = pathlib.Path(directory) / 'original'
                self.assertTrue(pathlib.Path(str(baseline) + '.incomplete').is_file())

    def test_legacy_original_capture_keeps_marker_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.capture(directory, producer_failure='ps',
                                  snapshot_name='preupgrade.dpkg.fixture')
            self.assertIn('FIRST=1', result.stdout)
            self.assertIn('SECOND=1', result.stdout)
            marker = pathlib.Path(directory) / 'preupgrade.dpkg.fixture.incomplete'
            self.assertTrue(marker.is_file())
            self.assertNotIn('unexpected', result.stdout + result.stderr)

    def test_snapshot_write_failure_is_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / 'absent-parent/snapshot'
            result = run(['config_state_capture'], f"""
find() {{ :; }}
config_state_capture {shlex.quote(str(target))}
""")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(target.exists())

    def test_reserved_original_and_marker_are_secured_explicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            # Simulate file creation without umask protection, as with an inherited
            # default ACL. Explicit chmod must still secure both reserved files.
            result = self.capture(directory, failure=17, ignored_umask=True)
            self.assertIn('FIRST=1', result.stdout)
            baseline = pathlib.Path(directory) / 'original'
            self.assertEqual(baseline.stat().st_mode & 0o777, 0o600)
            self.assertEqual(pathlib.Path(str(baseline) + '.incomplete').stat().st_mode & 0o777,
                             0o600)

    def test_post_snapshot_is_secured_without_relying_on_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.capture(directory, repeated=False, ignored_umask=True,
                                  snapshot_name='postupgrade.dpkg.fixture')
            self.assertIn('FIRST=0', result.stdout)
            self.assertNotIn('unexpected', result.stdout + result.stderr)
            post = pathlib.Path(directory) / 'postupgrade.dpkg.fixture'
            self.assertEqual(post.stat().st_mode & 0o777, 0o600)

    def test_post_snapshot_stays_in_job_directory_and_missing_pin_fails_report(self):
        for exists in (True, False):
            with self.subTest(exists=exists), tempfile.TemporaryDirectory() as directory:
                baseline = pathlib.Path(directory) / 'original'
                if exists:
                    baseline.write_text('original\n')
                result = run(['config_state_output_baseline', 'print_config_state_changes'], f'''
DR_CONFIG_BASELINE={shlex.quote(str(baseline))}
prepare_output_dir() {{ :; }}
apt_packages_print_review() {{ :; }}
record_config_state() {{ printf 'post:%s\\n' "$1"; }}
print_incompatible_package_changes() {{ :; }}
print_crossgrade_obsolete_package_changes() {{ :; }}
print_minimal_config_diff() {{ printf 'compare:%s:%s\\n' "$1" "$2"; }}
manifest_compare_baseline() {{ return 2; }}
print_pkg_to_modified_diff() {{ :; }}
find() {{ :; }}
print_config_state_changes
''')
                self.assertEqual(result.returncode, 0 if exists else 1, result.stderr)
                self.assertIn(f'post:{directory}/postupgrade.dpkg.', result.stdout)
                self.assertNotIn('/root/distrorejuveinfo/postupgrade', result.stdout)
                self.assertEqual('compare:' in result.stdout, exists)


class DistroSnapshot(unittest.TestCase):
    def test_actual_distro_producer_failures_propagate(self):
        for backend, status, value, expected in [
            ('lsb', 0, 'Description: Debian fixture', 'Description: Debian fixture'),
            ('lsb', 79, 'Description: Debian fixture', None),
            ('lsb', 0, 'Distributor ID: Debian', None),
            ('redhat', 0, 'Example Linux 9', 'REDHAT Example Linux 9'),
            ('redhat', 79, 'Example Linux 9', None),
            ('debian', 0, '12.0', 'DEBIAN 12.0'),
            ('debian', 79, '12.0', None),
            ('debian', 0, '', None),
        ]:
            with self.subTest(backend=backend, status=status, value=value):
                result = run(['print_distro_info'], f"""
function [() {{
  case \"$1:$2\" in
    -f:/etc/redhat-release) {'return 0' if backend == 'redhat' else 'return 1'};;
    -x:/usr/bin/lsb_release|-x:/bin/lsb_release) {'return 0' if backend == 'lsb' else 'return 1'};;
    -f:/etc/debian_version) {'return 0' if backend == 'debian' else 'return 1'};;
  esac
  builtin [ \"$@\"
}}
cat() {{ printf '%s\\n' {shlex.quote(value)}; return {status}; }}
lsb_release() {{ printf '%s\\n' {shlex.quote(value)}; return {status}; }}
print_distro_info
""")
                self.assertEqual(result.returncode, 0 if expected is not None else 1,
                                 result.stderr)
                self.assertEqual(result.stdout.strip(),
                                 'dss:distroinfo: ' + expected if expected is not None else '')


class DesignatedMaintenance(unittest.TestCase):
    def test_designated_file_identity_is_used_for_every_query_without_secret_reads(self):
        for client in ('mariadb', 'mysql'):
            with self.subTest(client=client), tempfile.TemporaryDirectory() as directory:
                defaults = pathlib.Path(directory) / 'maintenance client.cnf'
                defaults.write_text('synthetic-secret-must-not-be-read\n')
                calls = pathlib.Path(directory) / 'calls'
                result = run(['upgrade_database_verify'], f'''
DR_DATABASE_DEFAULTS_FILE={shlex.quote(str(defaults))}
command() {{
  if [ "$1" = -v ] && [ "$2" = mariadb ]; then {'return 0' if client == 'mariadb' else 'return 1'}; fi
  builtin command "$@"
}}
{client}() {{ :; }}
cat() {{ echo unexpected-credential-read >&2; return 99; }}
manifest_run_bounded() {{
  [ "$1" = 10 ] && [ "$2" = {client} ] || return 98
  shift 2
  [ "$1" = "--defaults-file=$DR_DATABASE_DEFAULTS_FILE" ] || return 97
  for argument in "$@"; do
    case "$argument" in --user=*|--no-defaults|--protocol=*|--init-command=*) return 96;; esac
  done
  printf 'query\\n' >> {shlex.quote(str(calls))}
  case "${{@: -1}}" in
    '--execute=SELECT 1') printf '1\\n';;
    '--execute=SELECT @@innodb_buffer_pool_size') printf '1\\n';;
    *mysql.global_priv*) :;;
    *) return 99;;
  esac
}}
upgrade_database_verify trixie
''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls.read_text().count('query'), 3 if client == 'mariadb' else 2)
                self.assertNotIn('synthetic-secret', result.stdout + result.stderr)
                self.assertNotIn('unexpected', result.stdout + result.stderr)

    def test_missing_or_rejected_file_never_tries_other_credentials(self):
        for exists in (True, False):
            with self.subTest(exists=exists), tempfile.TemporaryDirectory() as directory:
                defaults = pathlib.Path(directory) / 'maintenance.cnf'
                calls = pathlib.Path(directory) / 'calls'
                if exists:
                    defaults.touch()
                result = run(['upgrade_database_verify'], f'''
DR_DATABASE_DEFAULTS_FILE={shlex.quote(str(defaults))}
mariadb() {{ :; }}
manifest_run_bounded() {{
  printf '%s\\n' "$3" >> {shlex.quote(str(calls))}
  return 1
}}
upgrade_database_verify trixie
''')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn('maintenance succeeded', result.stderr)
                self.assertIn('Designated database', result.stderr)
                self.assertEqual(calls.read_text().splitlines() if calls.exists() else [],
                                 [f'--defaults-file={defaults}'] if exists else [])

    def test_file_settings_reject_relative_and_directory_paths(self):
        for setting in ('DR_CONFIG_BASELINE', 'DR_DATABASE_DEFAULTS_FILE'):
            for path in ('relative/file', '/', '/absolute/directory/'):
                with self.subTest(setting=setting, path=path):
                    result = run(['environment_validate_settings'],
                                 f'{setting}={shlex.quote(path)}\nenvironment_validate_settings\n')
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn(f'{setting} must be an absolute file path', result.stderr)


class ListenerSnapshots(unittest.TestCase):
    def listeners(self, available, netstat_status=0, ss_status=0, empty=False):
        netstat_output = ('Active Internet connections (only servers)\n'
                          'Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\n')
        ss_output = 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n'
        if not empty:
            netstat_output += 'tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1/sshd\n'
            ss_output += 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
        return run(['config_state_output_listeners'], f'''
command() {{
  if [ "$1" = -v ]; then
    case ' {available} ' in *" $2 "*) return 0;; *) return 1;; esac
  fi
  builtin command "$@"
}}
netstat() {{
  [ "$*" = -ntpl ] || return 99
  printf '%s' {shlex.quote(netstat_output)}
  return {netstat_status}
}}
ss() {{
  [ "$*" = -lntp ] || return 99
  printf '%s' {shlex.quote(ss_output)}
  return {ss_status}
}}
config_state_output_listeners
''')

    def test_netstat_is_preferred_and_ss_is_a_compatible_fallback(self):
        for available in ('netstat ss', 'ss'):
            with self.subTest(available=available):
                result = self.listeners(available, ss_status=97 if 'netstat' in available else 0)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), 'Listen ports: :::22 sshd')

    def test_successful_empty_listener_results_are_valid(self):
        for available in ('netstat', 'ss'):
            with self.subTest(available=available):
                result = self.listeners(available, empty=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, '')

    def test_missing_and_failed_listener_commands_are_not_empty_success(self):
        for available, netstat_status, ss_status in [('', 0, 0), ('netstat ss', 81, 0),
                                                     ('ss', 0, 82)]:
            with self.subTest(available=available):
                result = self.listeners(available, netstat_status, ss_status)
                self.assertNotEqual(result.returncode, 0)


class DiagnosticCapabilities(unittest.TestCase):
    def test_dns_payload_protection_and_unrelated_removals(self):
        for payload, status in [('/usr/bin/dig', 3), ('/usr/bin/host', 3),
                                ('/bin/nslookup', 3), ('/usr/bin/ordinary-tool', 0),
                                ('/usr/share/doc/dnsutils/README', 0)]:
            with self.subTest(payload=payload):
                result = run(['upgrade_cleanup_output_safe_package'], f'''
dpkg-query() {{ [ "$*" = '-L legacy-tools:amd64' ] || return 99; printf '%s\\n' {payload!r}; }}
upgrade_cleanup_output_safe_package legacy-tools:amd64 amd64 true /unused
''')
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(result.stdout.strip(), 'legacy-tools:amd64' if status == 0 else '')
        result = run(['upgrade_cleanup_output_safe_package'], '''
dpkg-query() { return 87; }
upgrade_cleanup_output_safe_package legacy-tools:amd64 amd64 true /unused
''')
        self.assertEqual(result.returncode, 1)

    def test_dns_prerequisites_are_distinct_from_lookup_timeout(self):
        for available, lookup_status, expected in [
            ('timeout', 0, 'resolver_client_unavailable'),
            ('getent', 0, 'timeout_facility_unavailable'),
            ('getent timeout', 124, 'timed_out'),
            ('getent timeout', 142, 'timed_out'),
            ('getent timeout', 2, 'resolution_failed_or_timed_out'),
            ('getent timeout', 0, 'resolved'),
        ]:
            with self.subTest(available=available, lookup_status=lookup_status):
                result = run(['manifest_dns'], f'''
manifest_dns_enabled=true
manifest_dns_limit=20
manifest_local_addresses=192.0.2.1
manifest_dns_names=(); manifest_dns_values=(); manifest_dns_results=(); manifest_dns_reasons=()
command() {{
  if [ "$1" = -v ]; then case ' {available} ' in *" $2 "*) return 0;; *) return 1;; esac; fi
  builtin command "$@"
}}
manifest_run_bounded() {{ printf '192.0.2.1 STREAM example.invalid\\n'; return {lookup_status}; }}
manifest_dns example.invalid
printf '%s:%s\\n' "$manifest_dns_result" "$manifest_dns_reason"
''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), ('this_host:' if expected == 'resolved' else 'unknown:') + expected)


if __name__ == '__main__':
    unittest.main()
