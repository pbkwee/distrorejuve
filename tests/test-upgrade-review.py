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


def crossgrade_fixture(current='trusty', native='i386', bits=32, kernel='x86_64',
                      selected=True, ubuntu_enabled=True, conversion='success'):
    # Script assignment LTS_UBUNTU="trusty xenial bionic" supplies that literal
    # declaration; use the real release order without sourcing initialization.
    releases = '\n'.join(re.search(r'^' + name + r'="[^"]*"$', SOURCE, re.M).group()
                         for name in ('ALL_DEBIAN', 'ALL_UBUNTU', 'LTS_UBUNTU'))
    settings = f'''
fixture_release={current!r}
fixture_native={native!r}
fixture_bits={bits}
fixture_kernel={kernel!r}
fixture_conversion={conversion!r}
UPGRADE_CROSSGRADE={'true' if selected else 'false'}
DR_ENABLE_UBUNTU_CROSSGRADE={'true' if ubuntu_enabled else 'false'}
upgrade_retry_command=()
'''
    mocks = r'''
# Fix the distro marker for the simulated source; other tests use Bash's test.
function [() {
  if builtin [ "$#" = 3 ] && builtin [ "$1" = -f ]; then
    case "$2" in /etc/debian_version) return 0;; /etc/redhat-release) return 1;; esac
  fi
  # The caller already supplies the closing ] as the final argument.
  builtin [ "$@"
}
distro_output_codename() { printf '%s\n' "$fixture_release"; }
dpkg() { builtin [ "$*" = --print-architecture ] || return 99; printf '%s\n' "$fixture_native"; }
getconf() { builtin [ "$*" = LONG_BIT ] || return 99; printf '%s\n' "$fixture_bits"; }
uname() { builtin [ "$*" = -m ] || return 99; printf '%s\n' "$fixture_kernel"; }
crossgrade_output_core_package_issues() { :; }
crossgrade_output_foreign_packages() {
  if builtin [ "$fixture_native" = i386 ]; then printf 'bash:i386\n'; fi
}
crossgrade_bookworm_output_pending_directory() { return 1; }
crossgrade_check_apt_architecture_config() { :; }
crossgrade_check_source_architectures() { :; }
upgrade_panel_refuse_generic() { :; }
usrmerge_check_upgrade_path() { :; }
usrmerge_recover_pending() { :; }
upgrade_check_crossgrade_package_blockers() { :; }
upgrade_output_crossgrade_obsolete_packages() { :; }
upgrade_output_compatibility_issues() { :; }
upgrade_check_incompatible_packages() { :; }
apt_sources_check_releases_and_vendors() { :; }
apt_package_lock_warn() { :; }
pause_check() { :; }
check_disk_space() { :; }
upgrade_check_crossgrade_checkpoint() {
  builtin [ "$fixture_release" = "$2" ] || return 98
  printf 'event:checkpoint:%s:%s:%s\n' "$2" "$fixture_native" "$fixture_bits"
}
crossgrade_debian() {
  printf 'event:crossgrade:%s\n' "$fixture_release"
  case "$fixture_conversion" in
    fail) return 7;;
    unchanged) return 0;;
    native_only) fixture_native=amd64;;
    success) fixture_native=amd64; fixture_bits=64;;
    *) return 99;;
  esac
}
upgrade_prepare_nss_lookup() { :; }
upgrade_precondition_checks() { :; }
apt_sources_prepare() { :; }
check_usrmerge() { :; }
upgrade_prepare_php_source_retry() { :; }
apt_get_upgrade() { printf 'event:package-update:%s\n' "$fixture_release"; }
retain_etc_networking_naming_re_enX0() { :; }
upgrade_record_package_origins() { :; }
apt_sources_upgrade() {
  printf 'event:sources:%s:%s:%s:%s\n' "$2" "$3" "$fixture_native" "$fixture_bits"
  fixture_next=$3
}
apt_get_update() { :; }
apt_get_install() { :; }
upgrade_migrate_php_packages() { :; }
apt_get_dist_upgrade() { fixture_release=$fixture_next; }
upgrade_remove_retired_packages() { :; }
upgrade_autoremove_packages() { :; }
upgrade_outcome_record() { :; }
upgrade_php_runtime_verify() { :; }
'''
    return releases + '\n' + settings + mocks


class CrossgradeUpgrade(unittest.TestCase):
    planning_functions = ['is_distro_name_older', 'is_distro_name_newer',
                          'upgrade_output_crossgrade_release']
    upgrade_functions = planning_functions + [
        'ubuntu_output_next_release', 'ubuntu_output_latest_lts',
        'upgrade_check_path', 'upgrade_preflight_action',
        'upgrade_crossgrade_before_release', 'dist_upgrade_ubuntu_to_latest']

    def test_i386_release_boundaries_and_crossgrade_permission(self):
        cases = [
            # Native upgrades remain possible up to the last i386 LTS.
            ('ubuntu', 'trusty', 'bionic', False, False, 'i686', 0, ''),
            ('ubuntu', 'trusty', 'bionic', True, False, 'i686', 0, ''),
            ('ubuntu', 'trusty', 'resolute', False, True, 'x86_64', 1, '--crossgrade'),
            ('ubuntu', 'bionic', 'focal', True, False, 'x86_64', 1, 'DR_ENABLE_UBUNTU_CROSSGRADE'),
            ('ubuntu', 'trusty', 'resolute', True, True, 'i686', 1, 'running x86_64 kernel'),
            ('ubuntu', 'trusty', 'resolute', True, True, 'x86_64', 0, 'bionic'),
            ('ubuntu', 'bionic', 'focal', True, True, 'x86_64', 0, 'bionic'),
            ('ubuntu', 'bionic', 'eoan', False, True, 'x86_64', 1, '--crossgrade'),
            ('ubuntu', 'cosmic', 'focal', True, True, 'x86_64', 1, 'before later release sources'),
            ('debian', 'bullseye', 'bookworm', False, False, 'i686', 0, ''),
            ('debian', 'bullseye', 'trixie', False, False, 'x86_64', 1, '--crossgrade'),
            ('debian', 'bullseye', 'trixie', True, False, 'x86_64', 0, 'bookworm'),
        ]
        for family, current, target, selected, enabled, kernel, status, message in cases:
            with self.subTest(family=family, current=current, target=target,
                              selected=selected, enabled=enabled, kernel=kernel):
                result = run(self.planning_functions,
                             crossgrade_fixture(current=current, selected=selected,
                                                ubuntu_enabled=enabled, kernel=kernel)
                             + f'\nupgrade_output_crossgrade_release {family} {current} {target}\n')
                self.assertEqual(result.returncode, status, result.stderr)
                if status == 0:
                    self.assertEqual(result.stdout.strip(), message)
                else:
                    self.assertIn(message, result.stderr)

    def test_native_amd64_needs_no_crossgrade(self):
        result = run(self.upgrade_functions,
                     crossgrade_fixture(native='amd64', bits=64, selected=False,
                                        ubuntu_enabled=False)
                     + '\ndist_upgrade_ubuntu_to_latest\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('event:crossgrade:', result.stdout)
        self.assertIn('event:sources:bionic:focal:amd64:64', result.stdout)

    def test_supported_i386_step_needs_no_64bit_kernel_or_opt_in(self):
        for selected in (False, True):
            with self.subTest(selected=selected):
                result = run(self.upgrade_functions,
                             crossgrade_fixture(current='xenial', kernel='i686',
                                                selected=selected, ubuntu_enabled=False)
                             + '\ndist_upgrade_ubuntu_to_latest 1\n')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('event:crossgrade:', result.stdout)
                self.assertIn('event:sources:xenial:bionic:i386:32', result.stdout)

    def test_ubuntu_crossgrades_on_bionic_before_focal_sources(self):
        result = run(self.upgrade_functions,
                     crossgrade_fixture() + '\ndist_upgrade_ubuntu_to_latest\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        events = [line for line in result.stdout.splitlines() if line.startswith('event:')]
        switches = [line for line in events if line.startswith('event:sources:')]
        self.assertEqual(switches, [
            'event:sources:trusty:xenial:i386:32',
            'event:sources:xenial:bionic:i386:32',
            'event:sources:bionic:focal:amd64:64',
            'event:sources:focal:jammy:amd64:64',
            'event:sources:jammy:noble:amd64:64',
            'event:sources:noble:resolute:amd64:64'])
        self.assertEqual(events.count('event:crossgrade:bionic'), 1)
        conversion = events.index('event:crossgrade:bionic')
        self.assertEqual(events[conversion - 1], 'event:checkpoint:bionic:i386:32')
        self.assertEqual(events[conversion + 1], 'event:checkpoint:bionic:amd64:64')
        self.assertLess(conversion, events.index('event:sources:bionic:focal:amd64:64'))

    def test_blocked_full_path_does_not_start_package_or_source_changes(self):
        for settings in ({'selected': False}, {'ubuntu_enabled': False}, {'kernel': 'i686'}):
            with self.subTest(settings=settings):
                result = run(self.upgrade_functions,
                             crossgrade_fixture(**settings)
                             + '\nupgrade_preflight_action --to-latest\n')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('blocked before changes', result.stderr)
                self.assertNotIn('event:', result.stdout)

    def test_failed_or_incomplete_conversion_stops_before_source_changes(self):
        for conversion, status in [('fail', 7), ('unchanged', 1), ('native_only', 1)]:
            with self.subTest(conversion=conversion):
                result = run(self.upgrade_functions,
                             crossgrade_fixture(current='bionic', conversion=conversion)
                             + '\ndist_upgrade_ubuntu_to_latest\n')
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertIn('event:crossgrade:bionic', result.stdout)
                self.assertNotIn('event:sources:', result.stdout)
                self.assertNotIn('event:package-update:', result.stdout)


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
