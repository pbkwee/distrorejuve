#!/usr/bin/env python3
"""Normal package/report actions keep internal checks out of the public CLI."""

from pathlib import Path
import runpy
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
declaration = runpy.run_path(str(ROOT / 'tests/test-upgrade-review.py'))['declaration']
PLAN = ('0 upgraded, 1 newly installed, 1 to remove and 0 not upgraded.\n'
        'Remv libcurl4 [7.88-1]\n'
        'Inst libcurl4t64 (8.14-1 Debian:stable [amd64])\n'
        'Conf libcurl4t64 (8.14-1 Debian:stable [amd64])\n')


def run(names, body):
    return subprocess.run(['bash'], input='\n'.join(declaration(name) for name in names) + '\n' + body,
                          capture_output=True, text=True, timeout=10)


class NormalWorkflowChecks(unittest.TestCase):
    def report(self, plan=PLAN, metadata_version='8.14-1', query_failure=False):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'plan'
            source.write_text(plan)
            return run(['apt_print_t64_replacements', 'upgrade_php_output_t64_replacement'], f'''
dpkg() {{ [ "$*" = --print-architecture ] || return 99; echo amd64; }}
upgrade_php_has_candidate() {{ return {2 if query_failure else 0}; }}
apt-cache() {{
 case "$1" in
  policy) printf '  Candidate: {metadata_version}\\n';;
  show) printf 'Package: libcurl4t64\\nVersion: {metadata_version}\\nArchitecture: amd64\\nProvides: libcurl4 (= {metadata_version})\\nReplaces: libcurl4\\n';;
  *) return 99;;
 esac
}}
apt_print_t64_replacements {shlex.quote(str(source))}
''')

    def test_selected_plan_reports_verified_native_replacement(self):
        result = self.report()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertIn('libcurl4:amd64 with libcurl4t64:amd64=8.14-1', result.stderr)

    def test_wrong_candidate_or_foreign_architecture_is_not_called_verified(self):
        for result in [self.report(metadata_version='8.15-1'), self.report(plan=PLAN.replace('[amd64]', '[arm64]'))]:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('Selected APT plan replaces', result.stderr)

    def test_metadata_failure_stays_explicit_without_new_approval_gate(self):
        result = self.report(query_failure=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('metadata is unavailable', result.stderr)
        self.assertNotIn('Selected APT plan replaces', result.stderr)

    def test_ordinary_package_action_reports_plan_without_changing_arguments_or_status(self):
        result = run(['apt_get_apply', 'apt_print_t64_replacements'], f'''
apt_package_lock_warn() {{ :; }}
upgrade_php_runtime_prepare() {{ :; }}
upgrade_pdns_prepare_plan() {{ :; }}
dpkg-query() {{ printf 'install ok installed\\tlibcurl4\\n'; }}
dpkg() {{ echo amd64; }}
upgrade_php_output_t64_replacement() {{ printf 'libcurl4t64:amd64=8.14-1\\n'; }}
apt_space_check_plan() {{ :; }}
upgrade_php_output_new_apache_packages() {{ :; }}
apt-get() {{
 case "$*" in
  *--simulate*) printf %s {shlex.quote(PLAN)};;
  *) printf 'selected-action:%s\\n' "$*"; return 67;;
 esac
}}
apt_get_apply --no-remove install example
''')
        self.assertEqual(result.returncode, 67, result.stderr)
        self.assertIn('selected-action:--no-remove install example', result.stdout)
        self.assertIn('normal dependency transaction', result.stderr)

    def test_removed_checks_cannot_inherit_a_package_action(self):
        for action in ('--check-t64-replacement', '--check-vendor-builds', '--check-pdns-roles'):
            with self.subTest(action=action):
                result = run(['distrorejuve_run'], f'''
DR_ACTION=--upgrade
environment_validate_settings() {{ printf 'UNEXPECTED-VALIDATION\\n'; return 99; }}
distrorejuve_main() {{ printf 'UNEXPECTED-MUTATION\\n'; return 99; }}
distrorejuve_run {action}
''')
                self.assertEqual(result.returncode, 1)
                self.assertNotIn('UNEXPECTED', result.stdout)
                self.assertIn('Use --check-upgrade', result.stderr)

    def test_help_has_only_supported_workflow_actions(self):
        result = run(['print_usage'], 'print_usage')
        self.assertEqual(result.returncode, 0, result.stderr)
        for action in ('--check-t64-replacement', '--check-vendor-builds', '--check-pdns-roles'):
            self.assertNotIn(action, result.stdout)
        self.assertIn('--check-upgrade', result.stdout)

    def test_dist_update_rejects_a_second_action_before_dispatch(self):
        result = run(['distrorejuve_main'], '''
upgrade_panel_dispatch() { echo unexpected-panel-dispatch; return 77; }
packages_upgrade() { echo unexpected-package-upgrade; return 78; }
distrorejuve_main --dist-update --to-latest
''')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn('unexpected-', result.stdout)
        self.assertIn('--dist-update takes no arguments.', result.stderr)
        self.assertIn('Use --to-latest to upgrade', result.stderr)


class PackageActionStatus(unittest.TestCase):
    def action(self, action, package_status=0, full_status=0, finish_status=0):
        with tempfile.TemporaryDirectory() as folder:
            names = ['distrorejuve_main', 'logging_run', 'support_print_report',
                     'support_output_package_error_recovery', 'is_complete_package_plan']
            result = run(names, f'''
unset DR_ACTION DR_REVIEWED_VENDOR_CONTRACT
DR_LOG_DIRECTORY={shlex.quote(folder)}
ALL_DEBIAN='buster bookworm trixie'; ALL_UBUNTU='noble'
LOG_VERBOSE=false; LOG_TRACE=false
apt_package_lock_warn() {{ :; }}
upgrade_panel_dispatch() {{ upgrade_panel_handled=false; }}
upgrade_workload_prepare() {{ :; }}
upgrade_outcome_record() {{ :; }}
upgrade_finish_run() {{
  : > "$DR_RUN_DIRECTORY/outcome.incomplete"
  printf 'fixture:finish-status:%s\\n' "$1"
  return {finish_status}
}}
print_info() {{ :; }}
# Real diagnostics and package helpers share ret; the dispatch must retain its
# own failure even if the diagnostic succeeds and resets that shared variable.
print_failed_dist_upgrade_tips() {{ ret=0; return 0; }}
packages_upgrade() {{
  printf 'fixture:packages\\n'
  if [ {package_status} -ne 0 ]; then
    printf 'dss:error: APT could not download all package indexes.\\n' >&2
    printf 'dss:error:apt_get_update failed (phase indexes, status 100).\\n' >&2
  fi
  return {package_status}
}}
apt_get_dist_upgrade() {{ printf 'fixture:full-upgrade\\n'; return {full_status}; }}
# Model the selected OS without depending on the runner's own marker files.
function [() {{
  if builtin [ "$#" = 3 ] && builtin [ "$1" = -f ]; then
    case "$2" in /etc/debian_version) return 0;; /etc/redhat-release) return 1;; esac
  fi
  builtin [ "$@"
}}
distro_output_codename() {{ echo buster; }}
sha256sum() {{ printf '%s  fixture-script\\n' {'a' * 64}; }}
uname() {{ echo 6.1.0-fixture; }}
dpkg() {{ case "$*" in --print-architecture) echo amd64;; --audit) :;; *) return 99;; esac; }}
dpkg-query() {{ case "$*" in *Version*) echo 1.0;; *Status*) echo 'install ok installed';; *) return 99;; esac; }}
apt-cache() {{ [ "$*" = policy ]; }}
apt-get() {{
  [ "$*" = '-s dist-upgrade' ] || {{ echo UNEXPECTED-PACKAGE-OPERATION >&2; return 99; }}
  printf '0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\\n'
}}
df() {{ printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\nfixture 8192000 4096000 4096000 50%% /\\n'; }}
logging_run distrorejuve_main {action}
''')
            run_directory, = Path(folder).glob('run.*')
            return (result, (run_directory / 'support.context').read_text(),
                    (run_directory / 'support-report.txt').read_text(),
                    (run_directory / 'output.log').read_text())

    def test_package_failures_reach_process_context_and_real_support_report(self):
        for action, package_status, full_status, expected in [
            ('--upgrade', 67, 0, 67),
            ('--dist-update', 1, 0, 1),
            ('--dist-update', 0, 68, 68),
        ]:
            with self.subTest(action=action, package_status=package_status):
                result, context, report, log = self.action(action, package_status, full_status)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(context.split('\t')[0], str(expected))
                self.assertIn(f'exit_status: {expected}\n', report)
                self.assertIn(f'fixture:finish-status:{expected}\n', log)
                self.assertNotIn('completed ok', log)
                self.assertIn(f'Action failed (status {expected})', result.stderr)
                if package_status:
                    self.assertIn('last_recorded_apt_update_exit_status: 100', report)
                    self.assertNotIn('fixture:full-upgrade', log)
                self.assertNotIn('UNEXPECTED-', log)

    def test_success_and_completion_failure_keep_their_status(self):
        for action in ('--upgrade', '--dist-update'):
            for finish_status in (0, 73):
                with self.subTest(action=action, finish_status=finish_status):
                    result, context, report, log = self.action(action, finish_status=finish_status)
                    self.assertEqual(result.returncode, finish_status, result.stderr)
                    self.assertEqual(context.split('\t')[0], str(finish_status))
                    self.assertIn(f'exit_status: {finish_status}\n', report)
                    self.assertIn('fixture:finish-status:0\n', log)
                    self.assertIn(f'{action} completed ok', log)
                    self.assertNotIn('UNEXPECTED-', log)


class RepositoryPreflight(unittest.TestCase):
    def upgrade(self, release='buster', provider='sury', override=None, disk_status=0):
        records = (f'/fixture/sources.list\t1\tdebian\tdeb\thttps://deb.debian.org/debian\t{release}\tmain\t*\n'
                   f'/fixture/php.list\t1\t{provider}\tdeb\thttps://packages.sury.org/php/\t{release}\tmain\t*\n')
        names = ['distrorejuve_main', 'packages_upgrade', 'upgrade_precondition_checks',
                 'apt_sources_check_releases_and_vendors', 'apt_repo_sury_support']
        return run(names, f'''
unset DR_ACTION DR_SKIP_CURRENT_RELEASE_REPOSITORY_CHECK DR_REVIEWED_VENDOR_CONTRACT
{'' if override is None else 'DR_SKIP_CURRENT_RELEASE_REPOSITORY_CHECK=' + override}
DR_UNPRIVILEGED=true
ALL_DEBIAN='buster bookworm trixie'; ALL_UBUNTU='jammy noble'
apt_package_lock_warn() {{ :; }}
upgrade_panel_dispatch() {{ upgrade_panel_handled=false; }}
upgrade_panel_refuse_generic() {{ :; }}
print_info() {{ :; }}
print_failed_dist_upgrade_tips() {{ :; }}
packages_output_backend() {{ echo dpkg; }}
crossgrade_bookworm_recover_bootstrap() {{ :; }}
usrmerge_recover_pending() {{ :; }}
upgrade_prepare_nss_lookup() {{ :; }}
check_disk_space() {{ return {disk_status}; }}
upgrade_configuration_review() {{ :; }}
distro_output_codename() {{ echo {release}; }}
apt_sources_list() {{ printf %s {shlex.quote(records)}; }}
apt_sources_prepare() {{ echo event:sources; }}
fix_missing_lsb_release() {{ echo event:lsb-helper; }}
add_missing_debian_keys() {{ echo event:keys-helper; }}
is_distro_name_older() {{ return 1; }}
apt_get_update() {{ echo event:indexes; }}
record_config_state() {{ :; }}
upgrade_check_target_init_plan() {{ :; }}
apt_get_install() {{ echo event:install; }}
upgrade_migrate_php_packages() {{ echo event:php-migration; }}
apt_get_upgrade() {{ echo event:packages; }}
uname() {{ echo 6.1.0-fixture; }}
cat() {{ [ "$*" = /proc/sys/kernel/osrelease ] || return 99; echo 6.1.0-fixture; }}
dpkg() {{ [ "$*" = -l ] || return 99; }}
function [() {{
  if builtin [ "$#" = 3 ] && builtin [ "$1" = -f ]; then
    case "$2" in /etc/debian_version) return 0;; /etc/redhat-release) return 1;; esac
  fi
  builtin [ "$@"
}}
distrorejuve_main --upgrade
''')

    def test_unsupported_sury_stops_after_source_repair_before_indexes_and_packages(self):
        for override in (None, 'false'):
            with self.subTest(override=override):
                result = self.upgrade(override=override)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('dss:error: Unsupported sury repository', result.stderr)
                self.assertIn('/fixture/php.list:1', result.stderr)
                self.assertIn('debian buster', result.stderr)
                self.assertIn('application dependencies', result.stderr)
                self.assertEqual([line for line in result.stdout.splitlines() if line.startswith('event:')],
                                 ['event:sources'])

    def test_supported_sury_can_reach_the_mocked_package_update(self):
        result = self.upgrade(release='bookworm')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('event:indexes', result.stdout)
        self.assertIn('event:packages', result.stdout)

    def test_unreviewed_unknown_repository_is_still_blocked(self):
        result = self.upgrade(provider='unknown')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Review or disable unknown source', result.stderr)
        self.assertEqual([line for line in result.stdout.splitlines() if line.startswith('event:')],
                         ['event:sources'])

    def test_archive_rewrite_keeps_sury_unchanged_before_vendor_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'sources.list'
            vendor = 'deb https://packages.sury.org/php/ buster main\n'
            source.write_text('deb http://deb.debian.org/debian buster main contrib\n'
                              'deb http://security.debian.org buster/updates main contrib\n'
                              'deb http://ftp.debian.org/debian buster-updates main contrib\n' + vendor)
            result = run(['apt_sources_process', 'apt_sources_list',
                          'apt_sources_check_releases_and_vendors', 'apt_repo_sury_support'], f'''
unset DR_SKIP_CURRENT_RELEASE_REPOSITORY_CHECK DR_REVIEWED_VENDOR_CONTRACT
ALL_DEBIAN='buster'; ALL_UBUNTU=''; DEBIAN_ARCHIVE='buster'; OLD_RELEASES_UBUNTU=''
fixture_sources={shlex.quote(str(source))}
distro_output_codename() {{ echo buster; }}
apt_sources_files() {{ printf '%s\\n' "$fixture_sources"; }}
apt_sources_process archive "$fixture_sources" debian buster buster > "$fixture_sources.staged" || exit 99
mv -- "$fixture_sources.staged" "$fixture_sources" || exit 99
apt_sources_check_releases_and_vendors
''')
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('Unsupported sury repository', result.stderr)
            self.assertEqual(source.read_text(),
                             'deb https://archive.debian.org/debian buster main contrib\n'
                             'deb https://archive.debian.org/debian-security buster/updates main contrib\n'
                             'deb https://archive.debian.org/debian buster-updates main contrib\n' + vendor)

    def test_failed_general_precondition_stops_before_source_repair(self):
        result = self.upgrade(disk_status=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('event:', result.stdout)

    def test_explicit_operator_override_retains_existing_scope(self):
        result = self.upgrade(override='true')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('event:indexes', result.stdout)
        self.assertIn('event:packages', result.stdout)


if __name__ == '__main__':
    unittest.main()
