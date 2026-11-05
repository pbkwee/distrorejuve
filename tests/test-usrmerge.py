#!/usr/bin/env python3
"""Exercise usrmerge recovery only on private fixtures; never invoke host APT/dpkg."""
import hashlib
import pathlib
import runpy
import shlex
import subprocess
import tarfile
import tempfile
import unittest

declaration = runpy.run_path(str(pathlib.Path(__file__).with_name('test-upgrade-review.py')))['declaration']


class Usrmerge(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.source = self.root / 'bin/replace'
        self.target = self.root / 'usr/bin/replace'
        self.events = self.root / 'events'
        for file, content in ((self.source, b'legacy executable\n'), (self.target, b'packaged executable\n')):
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(content)
            file.chmod(0o755)
        info = self.root / 'var/lib/dpkg/info'
        info.mkdir(parents=True)
        digest = hashlib.md5(self.target.read_bytes()).hexdigest()
        (info / 'example-package.md5sums').write_text(digest + '  usr/bin/replace\n')
        baseline = self.root / 'baseline/preupgrade.dpkg.1'
        baseline.parent.mkdir()
        baseline.touch()
        self.converter = self.root / 'usr/lib/usrmerge/convert-usrmerge'
        self.converter.parent.mkdir(parents=True)
        self.converter.write_text('#!/bin/bash\nprintf "convert\\n" >> ' + shlex.quote(str(self.events)) +
                                  '\ntouch ' + shlex.quote(str(self.root / 'merged')) + '\n')
        self.converter.chmod(0o700)

    def run_fixture(self, action='check_usrmerge', extra=''):
        names = ['usrmerge_output_executable_origin', 'usrmerge_collision_is_repairable', 'usrmerge_output_collisions',
                 'usrmerge_check_collisions', 'usrmerge_archive_collisions', 'check_usrmerge',
                 'upgrade_print_check']
        functions = '\n'.join(declaration(name) for name in names)
        functions = functions.replace('directory="/$name"', 'directory="$fixture_root/$name"')
        functions = functions.replace('target="/usr/$name/', 'target="$fixture_root/usr/$name/')
        functions = functions.replace('/usr/lib/usrmerge/convert-usrmerge', str(self.converter))
        functions = functions.replace('/etc/unsupported-skip-usrmerge-conversion', str(self.root / 'skip-conversion'))
        # Use the real digest verifier with fixture-root metadata and logical dpkg paths.
        origin = declaration('packages_output_file_origin').replace(
            'function packages_output_file_origin()', 'function fixture_file_origin()')
        body = f'''
fixture_root={str(self.root)!r}
fixture_uid=0
fixture_left_status=1; fixture_left_owner=''; fixture_right_status=0; fixture_right_owner=example-package
unset DR_PREFER_PACKAGED_USRMERGE_FILES
packages_output_file_owner() {{
  case "$1" in
    "$fixture_root/bin/replace"|/bin/replace) printf '%s' "$fixture_left_owner"; return "$fixture_left_status";;
    "$fixture_root/usr/bin/replace"|/usr/bin/replace) printf '%s' "$fixture_right_owner"; return "$fixture_right_status";;
    *) return 1;;
  esac
}}
packages_output_file_origin() {{ fixture_file_origin "$1" "$2" "$fixture_root" "${{4:-1048576}}"; }}
stat() {{
  if [ "$1:$2" = '-c:%u %a' ]; then shift 2; command stat -c "$fixture_uid %a" "$@"
  else command stat "$@"; fi
}}
record_config_state() {{ echo baseline >> "$fixture_root/events"; }}
config_state_output_baseline() {{ printf '%s/baseline/preupgrade.dpkg.1\\n' "$fixture_root"; }}
dpkg-query() {{
  case "${{@: -1}}" in
    usrmerge) case "$*" in
      *-L*) echo {str(self.converter)!r};;
      *) if [ -f "$fixture_root/configured" ]; then printf 'install ok installed'; else printf 'install ok unpacked'; fi;;
    esac;;
    example-package) :;;
    *) printf 'example-package\\tamd64\\tinstall ok installed\\t1.0\\n';;
  esac
}}
dpkg() {{
  printf 'configure\\n' >> "$fixture_root/events"
  test -f "$fixture_root/merged" && touch "$fixture_root/configured"
}}
usrmerge_is_complete() {{ test -f "$fixture_root/merged"; }}
pause_check() {{ :; }}
apt_get_update() {{ echo unexpected-apt-update >> "$fixture_root/events"; return 99; }}
apt_get_install() {{ echo unexpected-apt-install >> "$fixture_root/events"; return 99; }}
apt-get() {{ echo unexpected-apt >> "$fixture_root/events"; return 99; }}
{extra}
{action}
'''
        return subprocess.run(['bash'], input=origin + '\n' + functions + '\n' + body,
                              capture_output=True, text=True)

    def event_lines(self):
        return self.events.read_text().splitlines() if self.events.exists() else []

    def test_default_recovery_preserves_both_copies_before_converter_and_configuration(self):
        original = self.source.read_bytes()
        packaged = self.target.read_bytes()
        result = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.source.exists())
        self.assertEqual(self.target.read_bytes(), packaged)
        self.assertEqual(self.event_lines(), ['baseline', 'convert', 'configure'])
        archives = list(self.root.glob('baseline/*.usrmerge/files.*/files.tar'))
        self.assertEqual(len(archives), 1)
        with tarfile.open(archives[0]) as archive:
            self.assertEqual(archive.extractfile(str(self.source).lstrip('/')).read(), original)
            self.assertEqual(archive.extractfile(str(self.target).lstrip('/')).read(), packaged)
        moved = archives[0].parent / 'originals' / str(self.source).lstrip('/')
        self.assertEqual(moved.read_bytes(), original)
        self.assertEqual(archives[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(archives[0].parent.stat().st_mode & 0o777, 0o700)
        # A completed merge is idempotent and never repeats backup/configuration.
        result = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.event_lines(), ['baseline', 'convert', 'configure'])

    def test_large_packaged_executable_uses_separate_bound_and_rejects_modification(self):
        payload = b"packaged executable\n" * 200000
        self.target.write_bytes(payload)
        digest = hashlib.md5(payload).hexdigest()
        (self.root / 'var/lib/dpkg/info/example-package.md5sums').write_text(digest + '  usr/bin/replace\n')
        result = self.run_fixture(action='usrmerge_collision_is_repairable "$fixture_root/bin/replace" "$fixture_root/usr/bin/replace" example-package')
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_fixture(action='packages_output_file_origin "$fixture_root/usr/bin/replace" dpkg')
        self.assertEqual(result.stdout, 'unknown\tunknown\n')
        self.target.write_bytes(payload + b"modified")
        result = self.run_fixture(action='usrmerge_collision_is_repairable "$fixture_root/bin/replace" "$fixture_root/usr/bin/replace" example-package')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.event_lines(), [])

    def test_executable_specific_verifier_keeps_size_and_executable_bounds(self):
        self.target.chmod(0o644)
        result = self.run_fixture(action='usrmerge_collision_is_repairable "$fixture_root/bin/replace" "$fixture_root/usr/bin/replace" example-package')
        self.assertNotEqual(result.returncode, 0)
        self.target.chmod(0o755)
        with self.target.open('wb') as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
        result = self.run_fixture(action='usrmerge_collision_is_repairable "$fixture_root/bin/replace" "$fixture_root/usr/bin/replace" example-package')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.event_lines(), [])

    def test_reverse_ownership_preserves_the_packaged_legacy_path(self):
        digest = hashlib.md5(self.source.read_bytes()).hexdigest()
        (self.root / 'var/lib/dpkg/info/example-package.md5sums').write_text(digest + '  bin/replace\n')
        result = self.run_fixture(extra="fixture_left_status=0; fixture_left_owner=example-package; fixture_right_status=1; fixture_right_owner=''")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.source.exists())
        self.assertFalse(self.target.exists())

    def test_explicit_false_and_read_only_review_never_move_files(self):
        result = self.run_fixture(extra='DR_PREFER_PACKAGED_USRMERGE_FILES=false')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.source.exists())
        self.assertEqual(self.event_lines(), [])
        result = self.run_fixture(action='upgrade_print_check', extra='''
DR_PREFER_PACKAGED_USRMERGE_FILES=true
ALL_DEBIAN='bullseye bookworm trixie'
packages_output_backend() { echo dpkg; }
distro_output_codename() { echo bullseye; }
report_unsupported() { :; }
upgrade_precondition_checks() { :; }
upgrade_check_path() { usrmerge_check_collisions; }
dpkg() { case "$*" in --print-architecture) echo amd64;; --audit) :;; *) return 99;; esac; }
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.source.exists())
        self.assertEqual(self.event_lines(), [])
        self.assertIn('Read-only review', result.stdout)

    def test_modified_or_ambiguous_files_never_reach_backup_or_converter(self):
        for extra in ("fixture_right_status=2", "fixture_left_status=0; fixture_left_owner=other-package",
                      "fixture_right_status=1; fixture_right_owner=''", 'fixture_uid=1000',
                      'printf modified > "$fixture_root/usr/bin/replace"',
                      'chmod g+w "$fixture_root/usr/bin/replace"'):
            with self.subTest(extra=extra):
                self.target.write_bytes(b'packaged executable\n')
                self.target.chmod(0o755)
                result = self.run_fixture(extra=extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.source.exists())
                self.assertEqual(self.event_lines(), [])

    def test_backup_failure_or_changed_files_prevent_all_moves(self):
        for extra in ('tar() { return 21; }',
                      'tar() { case "$*" in *--compare*) return 22;; *) command tar "$@";; esac; }',
                      'tar() { command tar "$@" || return; case "$*" in *--compare*) printf changed > "$fixture_root/bin/replace";; esac; }',
                      'tar() { command tar "$@" || return; case "$*" in *--compare*) fixture_right_status=2;; esac; }'):
            with self.subTest(extra=extra):
                result = self.run_fixture(extra=extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.source.exists())
                self.assertNotIn('convert', self.event_lines())
                self.assertNotIn('configure', self.event_lines())

    def test_new_collision_after_backup_stops_before_converter(self):
        result = self.run_fixture(extra='''
mv() {
  command mv "$@" || return
  printf another > "$fixture_root/bin/another"
  printf different > "$fixture_root/usr/bin/another"
}
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('New usrmerge collisions', result.stderr)
        self.assertEqual(self.event_lines(), ['baseline'])

    def test_unrelated_symlink_collision_requires_manual_resolution(self):
        self.target.unlink()
        self.target.symlink_to(self.root / 'missing')
        result = self.run_fixture()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.source.exists())
        self.assertEqual(self.event_lines(), [])

    def test_converter_failure_never_configures_or_runs_apt(self):
        self.converter.write_text('#!/bin/bash\nexit 23\n')
        result = self.run_fixture()
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(self.event_lines(), ['baseline'])
        self.assertTrue(list(self.root.glob('baseline/*.usrmerge/files.*/files.tar')))


if __name__ == '__main__':
    unittest.main()
