#!/usr/bin/env python3
"""Offline upgrade-asset metadata: fixed tools and bounded directory sizes."""
import pathlib
import re
import subprocess
import tempfile
import unittest

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh').read_text()


def run(body):
    # Script declaration boundaries: `function NAME() {` to a column-one `}`.
    match = re.search(r'^function manifest_upgrade_assets\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
    assert match, 'manifest_upgrade_assets'
    return subprocess.run(['bash'], input=match.group() + '\n' + body,
                          text=True, capture_output=True)


class UpgradeAssets(unittest.TestCase):
    def test_fixed_tools_sizes_failure_and_no_raw_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for relative in ('var/www', 'usr', 'root', 'boot', 'var/cache/apt/archives', 'var/log/journal'):
                (root / relative).mkdir(parents=True)
            result = run(f'''
manifest_root={directory!r}
manifest_unprivileged=false
manifest_emit() {{ printf '%s\\n' "$*"; }}
type() {{ case "$*" in '-P php') printf '/usr/bin/php\\n';; *) return 1;; esac; }}
manifest_run_bounded() {{
  [ "$1" = 10 ] && [ "$2" = du ] && [ "$3" = -skxH ] && [ "$4" = -- ] || return 99
  case "${{@: -1}}" in
    */var/www) printf '12345\\tSECRET-private-path\\n';;
    */var/cache/apt/archives) printf '10\\tPRIVATE-cache-path\\n';;
    */var/cache/apt) printf '20\\tPRIVATE-cache-parent-path\\n';;
    */var/log/journal) printf '800000\\tPRIVATE-journal-path\\n';;
    */usr) printf 'SECRET-invalid-size\\n';;
    */root) printf '999 SECRET-output\\n'; return 124;;
    */boot) printf '1 SECRET-path\\n2 SECRET-other-path\\n';;
    *) return 99;;
  esac
}}
manifest_upgrade_assets
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('name php available yes path /usr/bin/php', result.stdout)
        self.assertIn('name wp available no path unknown', result.stdout)
        self.assertIn('path /var/www status observed allocated_kib 12345', result.stdout)
        self.assertIn('path /usr status malformed_output', result.stdout)
        self.assertIn('path /root status timeout', result.stdout)
        self.assertIn('path /boot status malformed_output', result.stdout)
        self.assertIn('path /backup status absent', result.stdout)
        self.assertIn('path /backups status absent', result.stdout)
        self.assertIn('path /var/cache/apt/archives status observed allocated_kib 10', result.stdout)
        self.assertIn('path /var/cache/apt status observed allocated_kib 20', result.stdout)
        self.assertIn('path /var/log/journal status observed allocated_kib 800000', result.stdout)
        self.assertEqual(result.stdout.count('upgrade_directory path '), 13)
        self.assertNotIn('PRIVATE', result.stdout)
        self.assertNotIn('SECRET', result.stdout)
        self.assertNotIn('999', result.stdout)

    def test_command_line_directory_symlink_measures_target_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'var').mkdir()
            (root / 'target').mkdir()
            (root / 'target/payload').write_bytes(b'x' * 1048576)
            (root / 'unrelated').mkdir()
            (root / 'unrelated/payload').write_bytes(b'x' * 2097152)
            (root / 'target/nested-link').symlink_to(root / 'unrelated')
            (root / 'var/www').symlink_to(root / 'target')
            expected = subprocess.check_output(['du', '-skxH', '--', str(root / 'target')], text=True).split()[0]
            result = run(f'''
manifest_root={directory!r}
manifest_unprivileged=false
manifest_emit() {{ printf '%s\\n' "$*"; }}
type() {{ return 1; }}
manifest_run_bounded() {{ shift; "$@"; }}
manifest_upgrade_assets
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(int(expected), 1024)
        self.assertLess(int(expected), 2048)
        self.assertIn('path /var/www status observed allocated_kib ' + expected, result.stdout)

    def test_reduced_mode_skips_protected_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'root').mkdir()
            (root / 'var/lib/mysql').mkdir(parents=True)
            (root / 'usr').mkdir()
            result = run(f'''
manifest_root={directory!r}
manifest_unprivileged=true
manifest_emit() {{ printf '%s\\n' "$*"; }}
type() {{ return 1; }}
manifest_run_bounded() {{
  case "${{@: -1}}" in */usr) printf '1024\\t/usr\\n';; *) printf 'PROTECTED_READ'; return 99;; esac
}}
manifest_upgrade_assets
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('path /root status skipped_unprivileged', result.stdout)
        self.assertIn('path /var/lib/mysql status skipped_unprivileged', result.stdout)
        self.assertIn('path /usr status observed allocated_kib 1024', result.stdout)
        self.assertNotIn('PROTECTED_READ', result.stdout)


if __name__ == '__main__':
    unittest.main()
