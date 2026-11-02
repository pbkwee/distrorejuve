#!/usr/bin/env python3
"""Offline regressions: extract function declarations; never run script entrypoint."""
import pathlib
import hashlib
import re
import shlex
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
    def test_manifest_preserves_residual_selection_state_without_claiming_a_runtime(self):
        records = ('python\t2.7.12-1~16.04\tinstall ok config-files\ti386\n'
                   'python3\t3.13.5-1\tinstall ok installed\tamd64\n'
                   'example\t1\tpurge ok not-installed\ti386\n')
        result = run(['manifest_packages'], f'''
manifest_package_backend=dpkg
packages_output_inventory() {{ printf '%s' {shlex.quote(records)}; }}
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_service() {{ echo 'unexpected daemon'; }}
manifest_packages
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('package_state name python version 2.7.12-1~16.04 architecture i386 status install ok config-files', result.stdout)
        self.assertNotIn('package name python version', result.stdout)
        self.assertIn('package name python3 version', result.stdout)
        self.assertNotIn('name example', result.stdout)

    def test_manifest_package_review_reports_metadata_without_cleanup_and_preserves_unknowns(self):
        records = ('libold\tamd64\t1.0\tunavailable\torigin unknown\n'
                   'oldmeta\tall\t1\tobsolete\tprevious official release\n'
                   'current\tamd64\t2\tavailable\tbinary exists\n'
                   'python\ti386\t2.7\tresidual-config\tconfiguration only\n')
        for backend, root, query_status in [('dpkg', '', 0), ('dpkg', '', 1),
                                             ('dpkg', '/fixture', 0), ('rpm', '', 0)]:
            with self.subTest(backend=backend, root=root, query_status=query_status):
                result = run(['manifest_package_review'], f'''
manifest_package_backend={backend!r}; manifest_root={root!r}
manifest_emit() {{ printf '%s\\n' "$*"; }}
apt_packages_output_review() {{ printf '%s' {shlex.quote(records)}; return {query_status}; }}
apt_get_update() {{ echo unexpected-update; return 99; }}
apt_get_install() {{ echo unexpected-install; return 99; }}
apt_get_remove() {{ echo unexpected-remove; return 99; }}
manifest_package_review
''')
                expected_unknown = backend == 'dpkg' and (bool(root) or query_status != 0)
                self.assertEqual(result.returncode, int(expected_unknown), result.stderr)
                self.assertNotIn('unexpected-', result.stdout + result.stderr)
                if expected_unknown:
                    self.assertIn('warning area package_review', result.stdout)
                elif backend == 'dpkg':
                    self.assertIn('classification unavailable', result.stdout)
                    self.assertIn('classification obsolete', result.stdout)
                    self.assertIn('freshness unverified removal_safety unverified', result.stdout)
                    self.assertNotIn('name current', result.stdout)
                    self.assertNotIn('name python', result.stdout)

    def test_classifier_treats_install_selected_config_files_as_residual_not_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            inventory = root / 'inventory'
            inventory.write_text('install ok config-files\tpython\ti386\t2.7.12-1~16.04\tno\toptional\told Python\n')
            available = root / 'available'
            available.touch()
            result = run(['apt_packages_output_classifications'],
                         f'apt_packages_output_classifications {str(inventory)!r} amd64 {str(available)!r}\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('\tresidual-config\t', result.stdout)
            self.assertNotIn('\tincomplete\t', result.stdout)

    def test_deprecated_cleanup_reuses_only_current_recorded_transition_and_never_purges(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = pathlib.Path(directory) / 'preupgrade'
            parent = pathlib.Path(str(baseline) + '.obsolete-packages')
            parent.mkdir()
            for transition in ('debian-bookworm-to-trixie', 'debian-bullseye-to-bookworm', 'ubuntu-noble-to-plucky'):
                path = parent / transition
                path.mkdir()
                (path / 'prepared').touch()
            for has_baseline, audit, refresh_status, obsolete_status, source_status in [(True, '', 0, 0, 0), (False, '', 0, 0, 0),
                                                                                       (True, 'pending package', 0, 0, 0),
                                                                                       (True, '', 7, 0, 0), (True, '', 0, 8, 0),
                                                                                       (True, '', 0, 0, 1)]:
                with self.subTest(has_baseline=has_baseline, audit=audit, refresh_status=refresh_status, obsolete_status=obsolete_status, source_status=source_status):
                    result = run(['upgrade_cleanup_deprecated_packages'], f'''
ALL_DEBIAN='bookworm trixie'; ALL_UBUNTU='noble plucky'
distro_output_codename() {{ echo trixie; }}
dpkg() {{ printf '%s' {audit!r}; }}
apt_sources_check_releases_and_vendors() {{ return {source_status}; }}
apt_get_update() {{ echo refresh; return {refresh_status}; }}
config_state_output_baseline() {{ printf '%s' {str(baseline)!r}; return {0 if has_baseline else 1}; }}
upgrade_remove_retired_packages() {{ printf 'obsolete %s\\n' "$*"; return {obsolete_status}; }}
upgrade_autoremove_packages() {{ echo autoremove; }}
apt_packages_print_review() {{ echo availability; }}
apt_get_remove() {{ echo unexpected-legacy-remove; return 99; }}
apt_get_install() {{ echo unexpected-install; return 99; }}
leftover_packages0() {{ echo unexpected-leftover-helper; return 99; }}
upgrade_cleanup_deprecated_packages
''')
                    self.assertEqual(result.returncode, 1 if audit or source_status else refresh_status or obsolete_status, result.stderr)
                    self.assertNotIn('unexpected-', result.stdout + result.stderr)
                    if audit or refresh_status or source_status:
                        self.assertNotIn('autoremove', result.stdout)
                        self.assertNotIn('obsolete ', result.stdout)
                    else:
                        self.assertEqual('obsolete debian bookworm trixie' in result.stdout, has_baseline)
                        self.assertNotIn('obsolete debian bullseye', result.stdout)
                        self.assertEqual('autoremove' in result.stdout, obsolete_status == 0)

    def test_deprecated_cli_dispatch_never_invokes_legacy_selection_or_removal(self):
        result = run(['distrorejuve_main'], '''
unset DR_ACTION
upgrade_panel_handled=false
apt_package_lock_warn() { :; }
upgrade_panel_dispatch() { :; }
upgrade_cleanup_deprecated_packages() { echo guarded-cleanup; return 7; }
has_leftover_packages() { echo unexpected-selection; return 0; }
remove_leftover_packages() { echo unexpected-removal; return 99; }
distrorejuve_main --remove-deprecated-packages
''')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn('guarded-cleanup', result.stdout)
        self.assertNotIn('unexpected-', result.stdout + result.stderr)

    def test_package_review_producer_and_human_report_share_classifications(self):
        inventory = ('install ok installed\tlibold\tamd64\t1\tno\toptional\told library\n'
                     'install ok config-files\tpython\ti386\t2.7\tno\toptional\told Python\n')
        body = f'''
ALL_DEBIAN=trixie; ALL_UBUNTU=''
dpkg() {{ echo amd64; }}
distro_output_codename() {{ echo trixie; }}
apt_packages_output_inventory() {{ printf '%s' {shlex.quote(inventory)}; }}
apt_packages_output_repository_versions() {{ :; }}
apt_packages_output_official_installed_versions() {{ :; }}
apt_sources_list() {{ :; }}
config_state_output_baseline() {{ return 1; }}
apt_get_update() {{ echo unexpected-update; return 99; }}
apt_packages_output_review
apt_packages_print_review
'''
        result = run(['apt_packages_output_classifications', 'apt_packages_output_review', 'apt_packages_print_review'], body)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('libold\tamd64\t1\tunavailable\t', result.stdout)
        self.assertIn('python\ti386\t2.7\tresidual-config\t', result.stdout)
        self.assertIn('Installed package libold:amd64 (1) has no versions', result.stdout)
        self.assertNotIn('Installed package python:', result.stdout)
        self.assertNotIn('unexpected-', result.stdout + result.stderr)

    def test_conffile_reports_ignore_removed_multiarch_digests_and_missing_rc_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            active = root / 'access.conf'
            active.write_text('packaged native configuration\n')
            modified = root / 'custom.conf'
            modified.write_text('retained customization\n')
            (root / 'custom.conf.dpkg-old').write_text('previous customization\n')
            baseline = root / 'baseline'
            baseline.touch()
            digest = hashlib.md5(active.read_bytes()).hexdigest()
            # Literal dpkg-query -W output: removed foreign-arch records can
            # retain the same conffile path with a different packaged digest.
            records = (f'Package: libpam-modules:amd64\tinstall ok installed\n {active} {digest}\n'
                       f'Package: libpam-modules:i386\tdeinstall ok config-files\n {active} {"0" * 32}\n'
                       f' {root / "absent.conf"} {"0" * 32}\n'
                       f'Package: example\thold ok installed\n {modified} {"0" * 32}\n')
            function = declaration('print_pkg_to_modified_diff').replace('/var/lib/ucf/', str(root / 'ucf') + '/')
            for mode in ('', 'summary', 'review'):
                with self.subTest(mode=mode):
                    body = f'''
dpkg-query() {{ printf '%s' {shlex.quote(records)}; }}
print_minimal_config_diff() {{ echo 'fixture difference'; return 1; }}
print_pkg_to_modified_diff {mode!r} {str(baseline)!r}
'''
                    result = subprocess.run(['bash'], input=function + '\n' + body,
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn(str(active), result.stdout + result.stderr)
                    self.assertNotIn('absent.conf', result.stdout + result.stderr)
                    self.assertIn(str(modified), result.stdout)
                    if mode == 'review':
                        self.assertIn('Previous copy:', result.stdout)
                        self.assertNotIn('retained customization', result.stdout)

    def test_completion_reviews_config_replacements_when_application_comparison_is_unavailable(self):
        for comparison in ('disabled', 'missing', 'unchanged', 'changed'):
            with self.subTest(comparison=comparison):
                body = '''
DR_RUN_DIRECTORY=''
config_state_output_baseline() { echo /fixture/preupgrade; }
upgrade_services_check() { return 0; }
upgrade_php_runtime_check() { return 0; }
upgrade_php_runtime_findings_complete() { return 0; }
upgrade_outcome_output_php_removals() { return 0; }
print_pkg_to_modified_diff() { printf 'configuration-review %s %s\\n' "$1" "$2"; }
'''
                if comparison == 'disabled':
                    body += 'DR_UPGRADE_MANIFEST=false\n'
                else:
                    status = {'missing': 2, 'unchanged': 0, 'changed': 1}[comparison]
                    body += f'manifest_compare_baseline() {{ return {status}; }}\n'
                body += 'upgrade_finish_run 0 /fixture/run.log\n'
                result = run(['manifest_compare_baseline', 'upgrade_finish_run'], body)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual('configuration-review review /fixture/preupgrade' in result.stdout,
                                 comparison in ('disabled', 'missing'))

    def test_mysql_server_presence_excludes_rc_clients_and_core_only(self):
        for records, query_status, expected in [
                ('mysql-server-5.0:i386\tdeinstall ok config-files\nlibmariadbclient18\tinstall ok installed', 0, 1),
                ('mariadb-server-core-10.5\tinstall ok installed', 0, 1),
                ('mariadb-server-10.5\tinstall ok half-configured', 0, 0),
                ('mysql-server\thold ok installed', 0, 0), ('', 2, 2)]:
            with self.subTest(records=records, query_status=query_status):
                result = run(['upgrade_database_has_mysql_server'], f'''
dpkg-query() {{ printf '%s\\n' {shlex.quote(records)}; return {query_status}; }}
upgrade_database_has_mysql_server
''')
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_config_repairs_never_revive_removed_database_servers(self):
        for udev_state, query_status, expected_calls, expected_status in [
                ('install ok installed', 0, [], 0), ('hold ok installed', 0, [], 0),
                ('deinstall ok config-files', 0, ['udev'], 0), ('', 2, [], 2)]:
            with self.subTest(udev_state=udev_state, query_status=query_status), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                (root / 'mysql').mkdir()
                (root / 'daemon.log').touch()
                # Isolate this extracted repair function's paths. A regressed
                # RC-based server-install branch must exercise the fixture.
                function = declaration('upgrade_database_has_mysql_server') + '\n' + declaration('tweak_broken_configs')
                function = function.replace('/etc/mysql', str(root / 'mysql'))
                function = function.replace('/var/log/daemon.log', str(root / 'daemon.log'))
                body = f'''
dpkg() {{ printf 'rc  mysql-server-5.0:i386 5.0 i386 old server\\nii  libmariadbclient18:amd64 10.1 amd64 client library\\n'; }}
dpkg-query() {{
  case "$*" in *udev*) printf '%s' {udev_state!r}; return {query_status};; esac
  printf 'mysql-server-5.0:i386\\tdeinstall ok config-files\\nlibmariadbclient18\\tinstall ok installed\\n'
}}
apt_get_install() {{ printf '%s\\n' "$*"; return 0; }}
find() {{ :; }}
grep() {{ return 1; }}
tweak_broken_configs
'''
                result = subprocess.run(['bash'], input=function + '\n' + body, text=True, capture_output=True)
                self.assertEqual(result.returncode, expected_status, result.stderr)
                calls = [line for line in result.stdout.splitlines() if not line.startswith('dss:')]
                self.assertEqual(calls, expected_calls)

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

    def test_explicit_validated_archive_exception_keeps_its_existing_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run(['apt_get_update'], f'''
cd {directory!r}
apt_package_lock_warn() {{ :; }}
pause_check() {{ :; }}
apt_configure_archive_authentication() {{ apt_archive_authentication_enabled=true; }}
apt_state_output_signature() {{ printf fixture; }}
apt-get() {{ echo 'NO_PUBKEY 0123456789ABCDEF'; return 0; }}
apt_repair_debian_signing_keys() {{ echo unexpected-retry; return 99; }}
apt-cache() {{ return 0; }}
apt_get_update
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('unexpected', result.stdout + result.stderr)

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


class PrecompiledLocales(unittest.TestCase):
    def preparation(self, count=100, extra='', plan='Inst locales-all (2.36 Debian [amd64])',
                    install_status=0, available=None, change_selection=False):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            selection = root / 'locale.gen'
            supported = root / 'SUPPORTED'
            entries = [f'xx_{index:03}.UTF-8 UTF-8' for index in range(count)]
            original = '# Preserve this comment and the configured selection.\n' + '\n'.join(entries) + '\n'
            selection.write_text(original)
            supported.write_text('\n'.join(entries) + '\n')
            if available is None:
                available = 'C\nC.utf8\nPOSIX\n' + '\n'.join(entry.split()[0].replace('UTF-8', 'utf8') for entry in entries)
            functions = '\n'.join(declaration(name) for name in (
                'upgrade_locales_output_standard_count', 'upgrade_prepare_debian_locales'))
            for path, replacement in [('/etc/locale.gen', selection),
                                      ('/usr/share/i18n/SUPPORTED', supported),
                                      ('/usr/local/share/i18n/SUPPORTED', root / 'custom')]:
                functions = functions.replace(path, str(replacement))
            body = f'''
unset I18NPATH LOCPATH DR_ALLOW_UNAUTHENTICATED_ARCHIVES DR_PRECOMPILED_LOCALES
ALL_DEBIAN='stretch buster bullseye bookworm trixie'
APT_GET_INSTALL_OPTIONS='-y'
prepared=false
all_state=''
all_query_status=1
locales_state='install ok installed'
locales_query_status=0
after_state='install ok installed'
fixture_custom={str(root / 'custom')!r}
distro_output_codename() {{ printf 'bookworm\\n'; }}
dpkg-query() {{
  case "${{@: -1}}" in
    locales-all*)
      if $prepared; then printf '%s' "$after_state"; return 0; fi
      printf '%s' "$all_state"; return "$all_query_status";;
    locales) printf '%s' "$locales_state"; return "$locales_query_status";;
    *) return 99;;
  esac
}}
dpkg() {{ printf 'amd64\\n'; }}
locale() {{ printf '%s\\n' {shlex.quote(available)}; }}
apt-get() {{ printf 'simulate %s\\n' "$*" >> {str(root / 'calls')!r}; printf '%s\\n' {shlex.quote(plan)}; }}
apt_get_install() {{
  printf 'install %s\\n' "$*" >> {str(root / 'calls')!r}
  prepared=true
  {'printf "# changed\\n" >> ' + shlex.quote(str(selection)) if change_selection else ':'}
  return {install_status}
}}
{extra}
upgrade_prepare_debian_locales
status=$?
if [ "$status" -eq 0 ]; then upgrade_prepare_debian_locales; status=$?; fi
exit "$status"
'''
            result = subprocess.run(['bash'], input=functions + '\n' + body, capture_output=True, text=True)
            calls = (root / 'calls').read_text().splitlines() if (root / 'calls').exists() else []
            if not change_selection:
                self.assertEqual(selection.read_text(), original)
            return result, calls

    def test_bulk_standard_selection_installs_once_with_authenticated_no_removal_policy(self):
        result, calls = self.preparation()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2, calls)
        self.assertTrue(calls[0].startswith('simulate '))
        self.assertTrue(calls[1].startswith('install '))
        for call in calls:
            for argument in ('AllowUnauthenticated=false', 'AutomaticRemove=false', '--no-remove',
                             '--no-install-recommends', 'locales-all:amd64'):
                self.assertIn(argument, call)
        self.assertIn('100 configured locales', result.stderr)

    def test_small_custom_held_existing_and_disabled_cases_do_not_install(self):
        for count, extra, available in [
                (99, '', None), (100, 'DR_PRECOMPILED_LOCALES=false', None),
                (100, "distro_output_codename() { echo noble; }", None),
                (100, "all_state='hold ok not-installed'; all_query_status=0", None),
                (100, "all_state='install ok installed'; all_query_status=0", None),
                (100, "all_state='install ok unpacked'; all_query_status=0", None),
                (100, "locales_state='deinstall ok config-files'", None),
                (100, "locales_state='hold ok installed'", None),
                (100, 'DR_ALLOW_UNAUTHENTICATED_ARCHIVES=true', None),
                (100, 'I18NPATH=/fixture/custom', None),
                (100, 'LOCPATH=/fixture/custom', None),
                (100, 'printf custom > "$fixture_custom"', None),
                (100, '', 'C\ncustom_LOCALE.utf8')]:
            with self.subTest(count=count, extra=extra, available=available):
                result, calls = self.preparation(count=count, extra=extra, available=available)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [])

    def test_codeset_aliases_and_unknown_selections(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            supported = root / 'SUPPORTED'
            selection = root / 'locale.gen'
            supported.write_text('en_US.UTF-8 UTF-8\nde_DE@euro ISO-8859-15\n')
            selection.write_text('# comment\n en_US.UTF-8 UTF-8 # selected\nde_DE@euro ISO-8859-15\n')
            available = 'C\nC.UTF-8\nPOSIX\nen_US.utf8\nde_DE.iso885915@euro'
            result = run(['upgrade_locales_output_standard_count'],
                         f'upgrade_locales_output_standard_count {str(supported)!r} {str(selection)!r} {shlex.quote(available)}')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), '2')
            selection.write_text(selection.read_text() + 'custom_LOCALE UTF-8\n')
            result = run(['upgrade_locales_output_standard_count'],
                         f'upgrade_locales_output_standard_count {str(supported)!r} {str(selection)!r} {shlex.quote(available)}')
            self.assertEqual(result.stdout.strip(), '0')

    def test_unsafe_or_unavailable_plans_keep_normal_generation(self):
        for plan in ('', 'Inst locales-all (2.36 Debian [amd64])\nRemv locales [2.36]',
                     'Inst locales-all (2.36 Debian [amd64])\nInst libc6 (2.36 Debian [amd64])'):
            with self.subTest(plan=plan):
                result, calls = self.preparation(plan=plan)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(all(call.startswith('simulate ') for call in calls))
        result, calls = self.preparation(extra="apt-get() { return 100; }")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])
        result, calls = self.preparation(plan='Inst libc-l10n (2.36 Debian [all])\nInst locales-all (2.36 Debian [amd64])')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)

    def test_install_and_state_failures_stop_preparation(self):
        result, _ = self.preparation(install_status=42)
        self.assertEqual(result.returncode, 42, result.stderr)
        result, _ = self.preparation(extra='all_query_status=2')
        self.assertEqual(result.returncode, 2, result.stderr)
        result, _ = self.preparation(extra='locales_query_status=2')
        self.assertEqual(result.returncode, 2, result.stderr)
        result, _ = self.preparation(extra="after_state='install ok unpacked'")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not fully installed', result.stderr)
        result, _ = self.preparation(change_selection=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Locale selection changed', result.stderr)
        for name in ('environment_validate_settings', 'upgrade_prepare_debian_locales'):
            result = run([name], 'DR_PRECOMPILED_LOCALES=invalid\n' + name)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('must be true or false', result.stderr)

    def test_upgrade_prepares_locales_after_refresh_and_baseline_before_configuration(self):
        for preparation_status, baseline_status in ((0, 0), (42, 0), (0, 17)):
            with self.subTest(preparation_status=preparation_status, baseline_status=baseline_status):
                result = run(['apt_get_upgrade'], f'''
pause_check() {{ :; }}
upgrade_precondition_checks() {{ :; }}
apt_sources_archive() {{ :; }}
apt_get_update() {{ echo refresh; }}
upgrade_php_runtime_prepare() {{ :; }}
apt_state_output_signature() {{ echo signature; }}
apt_state_repositories_are_current() {{ return 1; }}
record_config_state() {{ echo baseline; return {baseline_status}; }}
upgrade_prepare_debian_locales() {{ echo preparation; return {preparation_status}; }}
dpkg() {{ echo configure; }}
apt_get_autoremove() {{ :; }}
apt_get_f_install() {{ :; }}
apt_get_apply() {{ echo upgrade; }}
apt-get() {{ :; }}
upgrade_php_runtime_verify() {{ :; }}
apt_get_upgrade
''')
                self.assertEqual(result.returncode, baseline_status or preparation_status, result.stderr)
                events = [line for line in result.stdout.splitlines() if line in
                          ('refresh', 'baseline', 'preparation', 'configure', 'upgrade')]
                self.assertEqual(events[:3], ['refresh', 'baseline'] if baseline_status else ['refresh', 'baseline', 'preparation'])
                self.assertEqual('configure' in events, preparation_status == 0 and baseline_status == 0)


if __name__ == '__main__':
    unittest.main()
