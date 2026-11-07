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


if __name__ == '__main__':
    unittest.main()
