#!/usr/bin/env python3
"""Offline capacity regressions; extracted functions and mocked package/filesystem commands."""
import os
import pathlib
import re
import shlex
import subprocess
import tempfile
import unittest

SOURCE = pathlib.Path(os.environ.get('DR_TEST_SOURCE', pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh')).read_text()
FUNCTIONS = ('apt_space_check_options', 'apt_space_output_plan_records', 'apt_space_output_package_sizes', 'apt_space_check_plan')
PLAN = '1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst sample [1.0] (2.0 Debian:stable [amd64])\nConf sample (2.0 Debian:stable [amd64])\n'


def declaration(name):
    match = re.search(r'^function ' + re.escape(name) + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
    assert match, name
    return match.group()


def run(body, names=FUNCTIONS):
    return subprocess.run(['bash'], input='\n'.join(declaration(n) for n in names) + '\n' + body,
                          text=True, capture_output=True)


def mocks(separate=False, available=100000, metadata_extra='', installed=200, archive=4096):
    return f'''
DR_MIN_FREE_DISK_MIB=1
DR_MIN_FREE_BOOT_MIB=1
DR_DISK_SAFETY_PERCENT=20
DR_KERNEL_INITRAMFS_RESERVE_MIB=1
apt-config() {{ printf "APT_ARCHIVE_DIR='/var/cache/apt/archives/'\\n"; }}
apt-cache() {{
  [ "$*" = 'show sample:amd64=2.0' ] || return 92
  printf 'Package: sample\\nVersion: 2.0\\nArchitecture: amd64\\nSize: {archive}\\nInstalled-Size: {installed}\\n{metadata_extra}\\n'
}}
dpkg-query() {{ printf 'install ok installed\\t1.0\\t100\\n'; }}
stat() {{
  case "${{!#}}" in
    /usr) echo {4 if separate else 1};;
    /var/cache/apt/archives|/var/cache/apt|/var/cache) echo {2 if separate else 1};;
    /boot) echo {3 if separate else 1};;
    *) echo 1;;
  esac
}}
df() {{ printf 'Filesystem 1024-blocks Used Available Capacity Mounted-on\\n/dev/test 1000000 1 {available} 1%% /\\n'; }}
'''


class TransactionSpace(unittest.TestCase):
    def evaluate(self, body='', plan=PLAN, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            file = pathlib.Path(directory) / 'selected.plan'
            file.write_text(plan)
            return run(mocks(**kwargs) + f'plan={shlex.quote(str(file))}\n' + body + '\napt_space_check_plan "$plan"\n')

    def test_shared_filesystem_aggregates_download_payload_and_boot_once(self):
        result = self.evaluate()
        self.assertEqual(result.returncode, 0, result.stderr)
        peak = 4096 + 100 * 1024 + 200 * 1024 + 1048576
        required = 1048576 + peak + (peak * 20 + 99) // 100
        self.assertIn(f'required {required} bytes', result.stderr)
        self.assertEqual(result.stderr.count('Peak-space filesystem'), 1)

    def test_separate_cache_boot_and_usr_get_their_own_budgets(self):
        result = self.evaluate(separate=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr.count('Peak-space filesystem'), 4)
        self.assertIn('filesystem /var/cache/apt/archives (device 2)', result.stderr)
        self.assertIn('filesystem /boot (device 3)', result.stderr)
        self.assertIn('filesystem /usr (device 4)', result.stderr)
        cache_required = 1048576 + 4096 + (4096 * 20 + 99) // 100
        self.assertIn(f'required {cache_required} bytes', result.stderr)

    def test_insufficient_cache_filesystem_stops_before_transaction(self):
        result = self.evaluate(separate=True, body='''
df() {
  case "${!#}" in /var/cache*) free=1024;; *) free=100000;; esac
  printf 'Filesystem 1024-blocks Used Available Capacity Mounted-on\n/dev/test 1000000 1 %s 1%% /\n' "$free"
}
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Insufficient peak transaction space on /var/cache/apt/archives', result.stderr)

    def test_unknown_df_is_rejected(self):
        for output in ('', 'header\n/dev/test x y unknown 1% /\n',
                       'header\n/dev/test 100 50 -1 50% /\n',
                       'header\n/dev/test 100 50 50 50% /\n/dev/test 100 50 50 50% /\n'):
            with self.subTest(output=output):
                result = self.evaluate(body=f'df() {{ printf %s {shlex.quote(output)}; }}')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Cannot parse disk space', result.stderr)

    def test_unknown_and_inconsistent_plans_are_rejected(self):
        plans = ('', PLAN.replace('1 upgraded', '2 upgraded'),
                 PLAN + PLAN, PLAN.replace('[amd64])', '[amd64]'),
                 PLAN.replace('Inst sample', 'Inst sample:arm64'))
        for plan in plans:
            with self.subTest(plan=plan):
                result = self.evaluate(plan=plan)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Cannot establish a complete selected APT plan', result.stderr)

    def test_metadata_must_be_complete_exact_and_consistent(self):
        for extra in ('Size: 9', 'Version: 9', 'Architecture: arm64'):
            with self.subTest(extra=extra):
                result = self.evaluate(metadata_extra=extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Cannot establish exact download/installed sizes', result.stderr)
        result = self.evaluate(body="apt-cache() { printf 'Package: sample\\nVersion: 2.0\\nArchitecture: amd64\\nInstalled-Size: 100\\n'; }")
        self.assertNotEqual(result.returncode, 0)

    def test_old_package_state_must_match_plan(self):
        result = self.evaluate(body="dpkg-query() { printf 'install ok installed\\tother-version\\t100\\n'; }")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Selected and installed package states disagree', result.stderr)

    def test_removals_and_decreases_do_not_fund_the_peak(self):
        plan = PLAN.replace('0 to remove', '1 to remove') + 'Remv another [1.0]\n'
        result = self.evaluate(plan=plan, installed=50)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('positive installed growth 0 bytes; unpack reserve 51200 bytes', result.stderr)

    def test_configuration_only_plan_keeps_kernel_reserve_and_floor(self):
        result = self.evaluate(plan='0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nConf sample (1.0 Debian:stable [amd64])\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('0 packages; downloads/cache 0 bytes', result.stderr)
        self.assertIn('kernel/initramfs reserve 1 MiB', result.stderr)

    def test_changed_plan_sizes_are_recomputed_without_state_cache(self):
        result = self.evaluate(body='''
apt_space_check_plan "$plan" || exit
apt-cache() { printf 'Package: sample\nVersion: 2.0\nArchitecture: amd64\nSize: 8192\nInstalled-Size: 500\n'; }
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('downloads/cache 4096 bytes; positive installed growth 102400 bytes', result.stderr)
        self.assertIn('downloads/cache 8192 bytes; positive installed growth 409600 bytes', result.stderr)

    def test_floor_and_safety_are_configurable_and_invalid_values_stop(self):
        for setting in ('DR_MIN_FREE_DISK_MIB=bogus', 'DR_DISK_SAFETY_PERCENT=0',
                        'DR_KERNEL_INITRAMFS_RESERVE_MIB=0', 'DR_DISK_SAFETY_PERCENT=1001'):
            with self.subTest(setting=setting):
                self.assertNotEqual(self.evaluate(body=setting).returncode, 0)

    def test_existing_reviewed_skip_is_preserved(self):
        result = self.evaluate(plan='', body='DR_SKIP_DISK_SPACE_CHECK=true\napt-cache() { return 99; }\ndf() { return 99; }')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_separate_boot_has_its_own_floor_and_shared_boot_keeps_root_floor(self):
        shared = self.evaluate(body='DR_MIN_FREE_DISK_MIB=2\nDR_MIN_FREE_BOOT_MIB=128')
        self.assertEqual(shared.returncode, 0, shared.stderr)
        # Root payload+cache+boot reserve, retaining root floor rather than boot floor.
        peak = 4096 + 100 * 1024 + 200 * 1024 + 1048576
        self.assertIn(f'required {2 * 1048576 + peak + (peak * 20 + 99) // 100} bytes', shared.stderr)
        separate = self.evaluate(separate=True, available=300000,
                                 body='DR_MIN_FREE_DISK_MIB=2\nDR_MIN_FREE_BOOT_MIB=128')
        self.assertEqual(separate.returncode, 0, separate.stderr)
        boot_required = 128 * 1048576 + 1048576 + (1048576 * 20 + 99) // 100
        self.assertIn(f'required {boot_required} bytes', separate.stderr)

    def test_effective_cache_options_are_checked_without_evaluating_output(self):
        result = self.evaluate(body="apt-config() { printf \"APT_ARCHIVE_DIR='/custom/cache/'\\n\"; }")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cache placement is unknown or nonstandard', result.stderr)
        result = self.evaluate(body="apt-config() { return 91; }")
        self.assertNotEqual(result.returncode, 0)
        result = run("""
apt-config() { printf '%s\\n' "$*" >&2; printf "APT_ARCHIVE_DIR='/var/cache/apt/archives/'\\n"; }
apt_space_check_options -o Acquire::Retries=2 --option=Quiet=1 -c /tmp/synthetic.conf -y install sample
""", names=('apt_space_check_options',))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('-o Acquire::Retries=2 --option=Quiet=1 -c /tmp/synthetic.conf shell', result.stderr)

    def test_print_simulate_download_and_help_modes_cannot_enter_mutation_guard(self):
        for option in ('--print-uris', '--simulate', '--download-only', '-d', '-s', '-yd', '--help'):
            with self.subTest(option=option):
                result = run(f'apt_space_check_options {option} install sample', names=('apt_space_check_options',))
                self.assertNotEqual(result.returncode, 0)

    def test_guard_failure_prevents_actual_apt_and_uses_exact_arguments(self):
        body = '''
apt_package_lock_warn() { :; }
upgrade_php_runtime_prepare() { :; }
dpkg-query() { printf 'install ok installed\\tapache2\\n'; }
apt-get() {
  case " $* " in *' --simulate '*) printf 'plan from %s\\n' "$*";;
    *) echo mutation-attempted >&2; return 90;;
  esac
}
apt_space_check_plan() { cat "$1"; return 19; }
apt_get_apply -o APT::Immediate-Configure=0 -f install sample=2.0
'''
        result = run(body, names=('apt_get_apply',))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('-o APT::Immediate-Configure=0 -f install sample=2.0 --simulate', result.stdout)
        self.assertNotIn('mutation-attempted', result.stderr)


if __name__ == '__main__':
    unittest.main()
