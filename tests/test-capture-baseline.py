#!/usr/bin/env python3
"""Offline dispatch and path gates for explicit original capture."""
import pathlib
import re
import shlex
import subprocess
import tempfile
import unittest

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh').read_text()


def run(names, body):
    declarations = []
    for name in names:
        # Column-one function braces delimit declarations; never execute script startup.
        match = re.search(r'^function ' + re.escape(name) + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
        assert match, name
        declarations.append(match.group())
    return subprocess.run(['bash'], input='\n'.join(declarations) + '\n' + body,
                          text=True, capture_output=True)


class CaptureBaseline(unittest.TestCase):
    def capture(self, selected, extra='', stat='0:700', record_status=0):
        return run(['config_state_capture_original'], f'''
DR_CONFIG_BASELINE={shlex.quote(str(selected))}
stat() {{ printf '%s\\n' {shlex.quote(stat)}; }}
record_config_state() {{ printf 'capture=%s\\n' "$1"; return {record_status}; }}
config_state_capture_original {extra}
''')

    def test_selected_private_parent_delegates_and_preserves_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            original = pathlib.Path(directory) / 'original with spaces'
            result = self.capture(original)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'capture=' + str(original) + '\n')
            result = self.capture(original, record_status=7)
            self.assertEqual(result.returncode, 7)
            self.assertFalse(original.exists())

    def test_rejects_missing_relative_directory_and_extra_arguments(self):
        for selected in ('', 'relative-original', '/no-such-upgrade-parent/original', '/tmp/'):
            with self.subTest(selected=selected):
                result = self.capture(selected)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('capture=', result.stdout)
        with tempfile.TemporaryDirectory() as directory:
            result = self.capture(pathlib.Path(directory) / 'original', extra='unexpected')
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('capture=', result.stdout)

    def test_rejects_nonprivate_nonroot_and_linked_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            original = pathlib.Path(directory) / 'original'
            for mode in ('0:755', '1000:700', ''):
                with self.subTest(mode=mode):
                    result = self.capture(original, stat=mode)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn('capture=', result.stdout)
            link = pathlib.Path(directory) / 'linked-parent'
            link.symlink_to(directory, target_is_directory=True)
            result = self.capture(link / 'original')
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('capture=', result.stdout)

    def dispatch(self, uid='0', arguments='--capture-baseline'):
        return run(['distrorejuve_run'], f'''
DR_ACTION=--upgrade
environment_validate_settings() {{ return 0; }}
id() {{ printf '%s\\n' {shlex.quote(uid)}; }}
logging_run() {{ echo UNEXPECTED_MUTATION; return 99; }}
distrorejuve_main() {{ printf 'action=%s argument=%s\\n' "$DR_ACTION" "$1"; }}
distrorejuve_run {arguments}
''')

    def test_explicit_capture_cannot_inherit_a_mutation(self):
        result = self.dispatch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'action=--capture-baseline argument=--capture-baseline\n')
        self.assertNotIn('UNEXPECTED', result.stdout)

    def test_reduced_mode_never_dispatches_capture(self):
        for uid, arguments in [('1000', '--capture-baseline'), ('0', '--unprivileged --capture-baseline')]:
            with self.subTest(uid=uid, arguments=arguments):
                result = self.dispatch(uid, arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertIn('not available in unprivileged mode', result.stderr)

    def test_main_routes_capture_without_package_preflight(self):
        result = run(['distrorejuve_main'], '''
config_state_capture_original() { printf 'capture-arguments=%s\\n' "$#"; return 6; }
apt_package_lock_warn() { echo UNEXPECTED_APT; return 99; }
unset DR_ACTION
distrorejuve_main --capture-baseline
''')
        self.assertEqual(result.returncode, 6)
        self.assertEqual(result.stdout, 'capture-arguments=0\n')


class ServiceRetirement(unittest.TestCase):
    def check(self, receipt='bind9\n', package_state='deinstall ok config-files',
              query_status=0, service_status=1, directory_mode='0:700',
              file_mode='0:600:1', roles='', linked=False):
        with tempfile.TemporaryDirectory() as directory:
            baseline = pathlib.Path(directory) / 'original'
            services = pathlib.Path(str(baseline) + '.services')
            services.mkdir()
            (services / 'services.before').write_text('bind9\tbind9\tbind9\tactive\n')
            retired = pathlib.Path(str(baseline) + '.service-retirements')
            retired.mkdir()
            if receipt is not None:
                path = retired / 'packages.removed'
                if linked:
                    target = retired / 'other'
                    target.write_text(receipt)
                    path.symlink_to(target)
                else:
                    path.write_text(receipt)
            result = run(['upgrade_services_package_was_retired', 'upgrade_services_check'], f'''
stat() {{
  case "$*" in
    *'%u:%a:%h'*) printf '%s\\n' {shlex.quote(file_mode)};;
    *) printf '%s\\n' {shlex.quote(directory_mode)};;
  esac
}}
dpkg-query() {{ printf '%s' {shlex.quote(package_state)}; return {query_status}; }}
upgrade_services_output_roles() {{ printf '%s' {shlex.quote(roles)}; }}
upgrade_services_package_was_purged() {{ return 1; }}
upgrade_services_is_active() {{ return {service_status}; }}
upgrade_services_check {shlex.quote(str(services))} {shlex.quote(str(baseline))}
''')
        return result

    def test_approved_removed_inactive_service_is_accepted(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Approved retired service bind9', result.stderr)
        result = self.check(package_state='', query_status=1)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_running_or_unknown_retired_service_is_not_accepted(self):
        for service_status in (0, 2):
            with self.subTest(service_status=service_status):
                result = self.check(service_status=service_status)
                self.assertNotEqual(result.returncode, 0)

    def test_receipt_cannot_hide_installed_or_partly_installed_package(self):
        for state in ('install ok installed', 'install ok unpacked', 'install ok half-configured'):
            with self.subTest(state=state):
                result = self.check(package_state=state, service_status=0,
                                    roles='bind9\tbind9\tbind9\n')
                self.assertNotEqual(result.returncode, 0)

    def test_missing_unrelated_malformed_or_unsafe_receipt_is_not_exempted(self):
        cases = [
            {'receipt': None}, {'receipt': 'postfix\n'},
            {'receipt': 'bind9 extra\n'}, {'receipt': '# bind9\n'},
            {'directory_mode': '1000:700'}, {'directory_mode': '0:755'},
            {'file_mode': '1000:600:1'}, {'file_mode': '0:644:1'},
            {'file_mode': '0:600:2'}, {'linked': True},
            {'package_state': '', 'query_status': 2},
        ]
        for case in cases:
            with self.subTest(case=case):
                result = self.check(**case)
                self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
