#!/usr/bin/env python3
"""Offline process-collection regressions; never execute script initialization."""
import pathlib
import re
import subprocess
import tempfile
import unittest

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh').read_text()


def declaration(name):
    # Top-level producer: function NAME() { ... column-one }. Nested braces indent.
    match = re.search(r'^function ' + re.escape(name) + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
    assert match, name
    return match.group()


def run(names, body):
    script = '\n'.join(declaration(name) for name in names) + '\n' + body
    return subprocess.run(['bash'], input=script, text=True, capture_output=True, timeout=15)


class ManifestProcesses(unittest.TestCase):
    def indicators(self, snapshot, status=0):
        return run(['manifest_process_indicators'], f'''
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_run_bounded() {{ cat <<'SNAPSHOT'
{snapshot}
SNAPSHOT
return {status}
}}
manifest_collection_failed=false
manifest_process_indicators
printf 'failed=%s\\n' "$manifest_collection_failed"
''')

    def test_complete_process_snapshot_enables_shared_service_counts(self):
        result = run(['manifest_process_names'], """
manifest_run_bounded() { printf '101 lighttpd\\n102 mysqld\\n'; }
manifest_process_names
printf 'available=%s\\n' "$manifest_processes_available"
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertIn('available=true', result.stdout)

    def test_zero_exit_does_not_validate_malformed_snapshots(self):
        for snapshot in ['', ',ppid=,uid=,vsz=,args=\n                1\n                2\n              521',
                         'PID PPID UID VSZ COMMAND', '0 1 0 9000 nginx', '101 1 0 9000']:
            with self.subTest(snapshot=snapshot):
                result = self.indicators(snapshot)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('failed=true', result.stdout)
                self.assertIn('argument-indicator coverage is incomplete', result.stdout)
                self.assertNotIn('security_indicator', result.stdout)

    def test_mixed_snapshot_keeps_positive_indicators_and_unknown_coverage(self):
        result = self.indicators('101 1 1000 9000 miner --algo rx/0 --url pool.invalid --user PRIVATE_TOKEN\n'
                                 'BROKEN PRIVATE_COMMAND\n'
                                 '102 1 1000 4000 /tmp/worker SECRET_ARGUMENT')
        self.assertIn('indicator mining_command_arguments', result.stdout)
        self.assertIn('indicator temporary_executable', result.stdout)
        self.assertIn('failed=true', result.stdout)
        for value in ['PRIVATE_TOKEN', 'PRIVATE_COMMAND', 'SECRET_ARGUMENT', 'pool.invalid', 'BROKEN']:
            self.assertNotIn(value, result.stdout)
            self.assertNotIn(value, result.stderr)

    def test_valid_clean_snapshot_and_positive_rules_remain(self):
        result = self.indicators('100 1 0 9000 nginx: worker process\n'
                                 '101 1 1000 9000 tee -a /etc/sudoers\n'
                                 '102 1 1000 9000 python3 -u /tmp/example.py\n'
                                 '103 2 0 0 [kswapd0]')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('failed=false', result.stdout)
        self.assertIn('indicator sudoers_write_command', result.stdout)
        self.assertIn('indicator temporary_script', result.stdout)
        self.assertNotIn('indicator userspace_kernel_name', result.stdout)
        self.assertNotIn('warning', result.stdout)

    def test_command_failure_does_not_process_unreliable_stdout(self):
        result = self.indicators('101 1 0 9000 /tmp/worker', 124)
        self.assertIn('failed=true', result.stdout)
        self.assertNotIn('security_indicator', result.stdout)

    def names(self, root, snapshot, status=0, service=False):
        names = ['manifest_output_proc_process_names', 'manifest_process_names']
        if service:
            names.append('manifest_service')
        return run(names, f'''
manifest_root={str(root)!r}
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_run_bounded() {{ cat <<'SNAPSHOT'
{snapshot}
SNAPSHOT
return {status}
}}
manifest_collection_failed=false
manifest_package_backend=unknown
manifest_unprivileged=true
manifest_process_names
printf 'failed=%s\\n' "$manifest_collection_failed"
printf 'names=%s\\n' "$manifest_processes"
{'manifest_service lighttpd lighttpd 1.4' if service else ''}
''')

    def make_status(self, root, pid, name='lighttpd', recorded_pid=None):
        directory = pathlib.Path(root) / 'proc' / str(pid)
        directory.mkdir(parents=True)
        (directory / 'status').write_text(f'Name:\t{name}\nState:\tS (sleeping)\nPid:\t{recorded_pid or pid}\n')
        return directory

    def test_validated_names_support_service_inference(self):
        with tempfile.TemporaryDirectory() as root:
            result = self.names(root, '  1 init\n553 lighttpd', service=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('names=init\nlighttpd', result.stdout)
        self.assertIn('failed=false', result.stdout)
        self.assertIn('running yes', result.stdout)
        self.assertNotIn('warning', result.stdout)

    def test_malformed_success_uses_kernel_metadata_but_retains_warning(self):
        with tempfile.TemporaryDirectory() as root:
            process = self.make_status(root, 553)
            # The fallback must never inspect cmdline or environ.
            (process / 'cmdline').write_text('PRIVATE_ARGUMENT')
            (process / 'environ').write_text('PRIVATE_ENV')
            result = self.names(root, ',comm=\n                1\n              553', service=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('names=lighttpd', result.stdout)
        self.assertIn('failed=true', result.stdout)
        self.assertIn('malformed despite successful ps exit status', result.stdout)
        self.assertIn('running yes', result.stdout)
        self.assertNotIn('fallback was unavailable', result.stdout)
        self.assertNotIn('PRIVATE_', result.stdout + result.stderr)

    def test_name_failure_falls_back_without_using_unreliable_stdout(self):
        with tempfile.TemporaryDirectory() as root:
            self.make_status(root, 553)
            result = self.names(root, '1 nginx', status=124)
        self.assertIn('names=lighttpd', result.stdout)
        self.assertIn('failed=true', result.stdout)
        self.assertIn('snapshot failed or timed out', result.stdout)
        self.assertNotIn('names=nginx', result.stdout)

    def test_unavailable_proc_cannot_read_runner_proc_or_infer_stopped(self):
        with tempfile.TemporaryDirectory() as root:
            result = self.names(root, '', service=True)
        self.assertIn('names=\n', result.stdout)
        self.assertIn('fallback was unavailable or incomplete', result.stdout)
        self.assertIn('running unknown', result.stdout)
        self.assertNotIn('running no ', result.stdout)

    def test_proc_status_pid_must_match_directory(self):
        with tempfile.TemporaryDirectory() as root:
            self.make_status(root, 553)
            self.make_status(root, 554, name='nginx', recorded_pid=999)
            result = self.names(root, 'PID COMMAND')
        self.assertIn('names=lighttpd', result.stdout)
        self.assertNotIn('nginx', result.stdout)
        self.assertIn('fallback was unavailable or incomplete', result.stdout)

    def test_proc_fallback_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            self.make_status(outside, 553)
            (pathlib.Path(root) / 'proc').symlink_to(pathlib.Path(outside) / 'proc')
            result = self.names(root, 'PID COMMAND')
            self.assertNotIn('names=lighttpd', result.stdout)
            self.assertIn('fallback was unavailable or incomplete', result.stdout)

    def test_proc_fallback_rejects_symlinked_process_and_status(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            outside_process = self.make_status(outside, 553)
            proc = pathlib.Path(root) / 'proc'
            proc.mkdir()
            (proc / '553').symlink_to(outside_process)
            other = proc / '554'
            other.mkdir()
            (other / 'status').symlink_to(outside_process / 'status')
            result = self.names(root, 'PID COMMAND')
            self.assertNotIn('names=lighttpd', result.stdout)
            self.assertIn('fallback was unavailable or incomplete', result.stdout)

    def test_names_reject_numeric_only_empty_and_oversized_rows(self):
        for snapshot in ['553', '', '553 ' + 'x' * 65, '0 lighttpd']:
            with self.subTest(snapshot=snapshot), tempfile.TemporaryDirectory() as root:
                result = self.names(root, snapshot)
                self.assertIn('failed=true', result.stdout)
                self.assertIn('names=\n', result.stdout)

    def test_proc_fallback_bounded_by_process_count(self):
        # More than 20000 synthetic process entries cannot produce complete coverage.
        with tempfile.TemporaryDirectory() as root:
            proc = pathlib.Path(root) / 'proc'
            proc.mkdir()
            for pid in range(1, 20002):
                (proc / str(pid)).mkdir()
            result = self.names(root, '')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('fallback was unavailable or incomplete', result.stdout)


if __name__ == '__main__':
    unittest.main()
