#!/usr/bin/env python3
"""Offline release checkpoints: extracted Bash functions, private fixtures, mocked operations."""
import os
import pathlib
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_PATH = pathlib.Path(os.environ.get('DR_TEST_SOURCE', ROOT / 'distrorejuve.sh'))
if not SOURCE_PATH.is_file():
    SOURCE_PATH = pathlib.Path(__file__).with_name('candidate.sh')
SOURCE = SOURCE_PATH.read_text()
STAGE_FUNCTIONS = re.findall(r'^function (upgrade_stage_[a-z_]+)\(\)', SOURCE, re.M)


def run(body, extra=()):
    names = STAGE_FUNCTIONS + ['config_state_output_baseline', 'ubuntu_output_next_release'] + list(extra)
    declarations = []
    for name in dict.fromkeys(names):
        match = re.search(r'^function ' + re.escape(name) + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
        assert match, name
        declaration = match.group()
        if name == 'dist_upgrade_x_to_y':
            # Only replace the OS-family sentinel, never source or run script startup.
            declaration = declaration.replace('/etc/debian_version', '"$DR_CONFIG_BASELINE"')
        declarations.append(declaration)
    prelude = r'''
ALL_DEBIAN='etch lenny squeeze wheezy jessie stretch buster bullseye bookworm trixie'
ALL_UBUNTU='bionic cosmic disco eoan focal groovy hirsute impish jammy kinetic lunar mantic noble'
LTS_UBUNTU='bionic focal jammy noble'
# Fixtures belong to the test runner; spoof only ownership, retaining real mode,
# link count and size so path/permission failures exercise actual filesystem state.
stat() {
  local result
  result=$(command stat "$@") || return $?
  case "$2" in '%u:%a'|'%u:%a:%h') printf '0:%s\n' "${result#*:}";; *) printf '%s\n' "$result";; esac
}
upgrade_stage_output_source() { printf '%064d\n' 1; }
record_config_state() { config_state_output_baseline >/dev/null; }
upgrade_panel_refuse_generic() { return 0; }
is_distro_name_older() {
  local release seen=false
  for release in $ALL_DEBIAN $ALL_UBUNTU; do
    [ "$release" != "$2" ] || { $seen; return $?; }
    [ "$release" != "$1" ] || seen=true
  done
  return 1
}
'''
    return subprocess.run(['bash'], input='\n'.join(declarations) + '\n' + prelude + body,
                          text=True, capture_output=True)


class StageRecords(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.root.chmod(0o700)
        self.original = self.root / 'original state'
        self.original.write_text('original untouched\n')
        self.original.chmod(0o600)
        self.record = pathlib.Path(str(self.original) + '.stage')
        self.setup = f'DR_CONFIG_BASELINE={shlex.quote(str(self.original))}\n'

    def call(self, body, extra=()):
        return run(self.setup + body, extra)

    def begin(self):
        result = self.call('upgrade_stage_begin debian bullseye bookworm\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.record.read_text()

    def test_stage_path_cannot_be_the_original_failure_marker(self):
        result = self.call('DR_STAGE_RECORD="$DR_CONFIG_BASELINE.incomplete"\nupgrade_stage_begin debian bullseye bookworm\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(pathlib.Path(str(self.original) + '.incomplete').exists())
        self.assertEqual(self.original.read_text(), 'original untouched\n')

    def test_initial_record_selects_original_target_and_private_atomic_file(self):
        text = self.begin()
        for expected in ('family\tdebian\n', 'from\tbullseye\n', 'target\tbookworm\n',
                         'action\trelease-hop\n', 'last_step\toriginal-recorded\n',
                         'outcome\tpending\n', 'baseline\t' + str(self.original) + '\n'):
            self.assertIn(expected, text)
        self.assertEqual(self.record.stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.root.glob('.distrorejuve-stage.*')))
        self.assertEqual(self.original.read_text(), 'original untouched\n')

    def test_requires_separate_final_workload_verification(self):
        result = self.call('''
upgrade_stage_begin debian bullseye bookworm || exit
upgrade_stage_record_step hop-complete release-packages-verified || exit
upgrade_stage_finish 0 'verified (bookworm)' 'verified (bookworm)' verified unknown || exit
upgrade_stage_load "$DR_CONFIG_BASELINE.stage" || exit
printf 'unknown=%s\n' "$upgrade_stage_outcome"
upgrade_stage_finish 0 'verified (bookworm)' 'verified (bookworm)' verified verified || exit
upgrade_stage_load "$DR_CONFIG_BASELINE.stage" || exit
printf 'accepted=%s\n' "$upgrade_stage_outcome"
upgrade_stage_finish 1 'verified (bookworm)' 'verified (bookworm)' verified verified || exit
upgrade_stage_load "$DR_CONFIG_BASELINE.stage" || exit
printf 'failed=%s\n' "$upgrade_stage_outcome"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'unknown=incomplete\naccepted=verified\nfailed=incomplete\n')

    def test_pending_record_blocks_implicit_new_release_and_other_hops(self):
        self.begin()
        result = self.call('upgrade_stage_guard_command\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--resume-stage', result.stderr)
        before = self.record.read_bytes()
        result = self.call('upgrade_stage_begin debian bookworm trixie\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.record.read_bytes(), before)

    def test_contiguous_hop_can_follow_a_completed_hop_within_one_run(self):
        result = self.call('''
upgrade_stage_begin debian bullseye bookworm || exit
upgrade_stage_record_step hop-complete release-packages-verified || exit
upgrade_stage_begin debian bookworm trixie || exit
upgrade_stage_load "$DR_CONFIG_BASELINE.stage" || exit
printf '%s:%s:%s\n' "$upgrade_stage_from" "$upgrade_stage_target" "$upgrade_stage_outcome"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'bookworm:trixie:pending\n')

    def test_rejects_failed_capture_and_changed_original(self):
        marker = pathlib.Path(str(self.original) + '.incomplete')
        marker.touch()
        result = self.call('upgrade_stage_begin debian bullseye bookworm\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.record.exists())
        marker.unlink()
        self.begin()
        self.original.write_text('changed original\n')
        result = self.call('upgrade_stage_load "$DR_CONFIG_BASELINE.stage"\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('original baseline has changed', result.stderr)

    def test_rejects_wrong_source_baseline_crossgrade_or_target(self):
        text = self.begin()
        original_text = text
        cases = [text.replace('source\t' + '0' * 63 + '1', 'source\t' + '0' * 63 + '2'),
                 text.replace('target\tbookworm', 'target\ttrixie'),
                 text.replace('action\trelease-hop', 'action\t--to-latest'),
                 text.replace('family\tdebian', 'family\tubuntu')]
        for text in cases:
            self.record.write_text(text)
            result = self.call('upgrade_stage_load "$DR_CONFIG_BASELINE.stage"\n')
            self.assertNotEqual(result.returncode, 0)
        self.record.write_text(original_text)
        result = self.call('UPGRADE_CROSSGRADE=true\nupgrade_stage_begin debian bullseye bookworm\n')
        self.assertNotEqual(result.returncode, 0)
        other = self.root / 'other'
        other.write_text('original untouched\n')
        result = run(f'DR_CONFIG_BASELINE={shlex.quote(str(other))}\nupgrade_stage_load {shlex.quote(str(self.record))}\n')
        self.assertNotEqual(result.returncode, 0)

    def test_rejects_malformed_records_without_evaluating_values(self):
        text = self.begin()
        marker = self.root / 'must-not-be-created'
        for altered in (text + 'target\tbookworm\n', text + 'unknown\tvalue\n',
                        text.replace('target\tbookworm', 'target\t'),
                        text.replace('target\tbookworm', 'target\tbookworm\textra'),
                        text.replace('target\tbookworm', 'target\t$(touch ' + str(marker) + ')'),
                        text.replace('target\tbookworm', 'target\tbookworm\r'),
                        text.replace('format\t1\n', ''), text + 'x' * 17000):
            with self.subTest(value=altered[:70]):
                self.record.write_text(altered)
                result = self.call('upgrade_stage_load "$DR_CONFIG_BASELINE.stage"\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())

    def test_refuses_linked_nonprivate_or_hardlinked_records(self):
        self.begin()
        self.record.chmod(0o644)
        self.assertNotEqual(self.call('upgrade_stage_load "$DR_CONFIG_BASELINE.stage"\n').returncode, 0)
        self.record.chmod(0o600)
        link = self.root / 'hardlink'
        os.link(self.record, link)
        self.assertNotEqual(self.call('upgrade_stage_load "$DR_CONFIG_BASELINE.stage"\n').returncode, 0)
        link.unlink()
        saved = self.root / 'saved'
        self.record.rename(saved)
        self.record.symlink_to(saved)
        self.assertNotEqual(self.call('upgrade_stage_load "$DR_CONFIG_BASELINE.stage"\n').returncode, 0)
        self.record.unlink()
        saved.rename(self.record)
        self.root.chmod(0o755)
        self.assertNotEqual(self.call('upgrade_stage_load "$DR_CONFIG_BASELINE.stage"\n').returncode, 0)

    def test_resume_replays_recorded_hop_even_after_base_files_reports_target(self):
        self.begin()
        result = self.call('''
distro_output_codename() { printf 'bookworm\n'; }
dist_upgrade_x_to_y() { printf 'hop=%s:%s baseline=%s\n' "$old_distro" "$new_distro" "$DR_CONFIG_BASELINE"; return 17; }
upgrade_stage_resume "$DR_CONFIG_BASELINE.stage"
''')
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertIn('hop=bullseye:bookworm baseline=' + str(self.original), result.stdout)
        self.assertNotIn('trixie', result.stdout)
        self.assertEqual(self.original.read_text(), 'original untouched\n')

    def test_resume_rejects_release_outside_recorded_pair_without_operations(self):
        self.begin()
        result = self.call('''
distro_output_codename() { printf 'trixie\n'; }
dist_upgrade_x_to_y() { echo UNEXPECTED_OPERATION; }
upgrade_stage_resume "$DR_CONFIG_BASELINE.stage"
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('UNEXPECTED', result.stdout)

    def test_completed_resume_reverifies_exact_target_without_advancing(self):
        result = self.call('''
upgrade_stage_begin debian bullseye bookworm || exit
upgrade_stage_record_step hop-complete release-packages-verified || exit
distro_output_codename() { printf 'bookworm\n'; }
debian_check_release_completion() { printf 'verify=%s\n' "$1"; return 19; }
dist_upgrade_x_to_y() { echo UNEXPECTED_OPERATION; }
upgrade_stage_resume "$DR_CONFIG_BASELINE.stage"
''')
        self.assertEqual(result.returncode, 19, result.stderr)
        self.assertEqual(result.stdout, 'verify=bookworm\n')

    def test_debian_target_label_without_origins_checkpoint_still_runs_guards(self):
        self.begin()
        result = self.call('''
distro_output_codename() { printf 'bookworm\n'; }
pause_check() { return 0; }
check_disk_space() { return 0; }
upgrade_prepare_nss_lookup() { return 0; }
upgrade_check_path() { printf 'guard=%s:%s:%s\n' "$1" "$2" "$3"; return 37; }
upgrade_stage_resume "$DR_CONFIG_BASELINE.stage"
''', ['dist_upgrade_x_to_y'])
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertIn('guard=debian:bullseye:bookworm', result.stdout)
        self.assertNotIn('skipping bullseye', result.stdout)

    def test_ubuntu_target_label_keeps_the_recorded_pair(self):
        result = self.call('''
upgrade_stage_begin ubuntu focal jammy || exit
distro_output_codename() { printf 'jammy\n'; }
pause_check() { return 0; }
upgrade_check_path() { printf 'guard=%s:%s:%s\n' "$1" "$2" "$3"; return 37; }
upgrade_stage_resume "$DR_CONFIG_BASELINE.stage"
''', ['dist_upgrade_ubuntu_to_latest'])
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertEqual(result.stdout, 'guard=ubuntu:focal:jammy\n')

    def test_resume_dispatch_context_exists_before_logging_hooks(self):
        self.begin()
        result = self.call('''
DR_ACTION=--to-latest
unset DR_CONFIG_BASELINE
id() { printf '0\n'; }
environment_validate_settings() { return 0; }
logging_run() { printf 'context=%s action=%s original=%s\n' "$DR_STAGE_RECORD" "$DR_ACTION" "$DR_CONFIG_BASELINE"; }
distrorejuve_run --resume-stage ''' + shlex.quote(str(self.record)) + '\n', ['distrorejuve_run'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f'context={self.record} action=--resume-stage original={self.original}\n')

    def test_first_hop_is_recorded_before_preflight_can_change_base_files(self):
        result = self.call('''
apt_package_lock_warn() { return 0; }
distro_output_codename() { printf 'bullseye\\n'; }
crossgrade_bookworm_recover_bootstrap() {
  upgrade_stage_load "$DR_CONFIG_BASELINE.stage" || return 99
  printf 'before-repair=%s:%s:%s\\n' "$upgrade_stage_from" "$upgrade_stage_target" "$upgrade_stage_last_step"
}
upgrade_check_path() { return 37; }
upgrade_preflight_action --to-debian-release 12
''', ['upgrade_preflight_action'])
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertEqual(result.stdout, 'before-repair=bullseye:bookworm:original-recorded\n')

    def test_unprivileged_resume_cannot_dispatch(self):
        self.begin()
        result = self.call('''
id() { printf '1000\n'; }
environment_validate_settings() { return 0; }
logging_run() { echo UNEXPECTED_OPERATION; }
distrorejuve_run --resume-stage "$DR_CONFIG_BASELINE.stage"
''', ['distrorejuve_run'])
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('UNEXPECTED', result.stdout)
        self.assertIn('not available in unprivileged mode', result.stderr)


if __name__ == '__main__':
    unittest.main()
