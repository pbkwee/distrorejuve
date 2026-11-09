#!/usr/bin/env python3
"""Offline legacy APT/source/workload cases; never source dispatch or run host APT."""
import pathlib
import runpy
import shlex
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
declaration = runpy.run_path(str(ROOT / 'tests/test-upgrade-review.py'))['declaration']


def run(names, body):
    return subprocess.run(['bash'], input='\n'.join(declaration(n) for n in names) + '\n' + body,
                          text=True, capture_output=True)


class PackageCompatibility(unittest.TestCase):
    def test_apt_annotations_are_bounded_package_lists(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = pathlib.Path(directory) / 'plan'
            for suffix, allowed in [('', True), (' []', True), (' [perl:amd64 ]', True),
                                    (' [perl:amd64 libc6:amd64 ]', True),
                                    (' [perl:amd64 on perlapi-5.36.0:amd64] [perl:amd64 ]', True),
                                    (' [perl:amd64 on perlapi-5.36.0:amd64]', True),
                                    (' [perl:amd64 on perlapi-5.36.0:amd64] []', True),
                                    (' [perl:amd64 on perlapi-5.36.0:amd64] [python3:amd64 on python3-minimal:amd64] []', True),
                                    (' [perl:amd64 on ]', False), (' [on perl:amd64]', False),
                                    (' [perl:amd64 on lib;run] []', False),
                                    (' [perl:amd64 on libc6:amd64] [] junk', False),
                                    (' [perl:amd64 on libc6:amd64] [[perl]]', False),
                                    (' [perl:amd64] [libc6:amd64]', False),
                                    (' [perl:amd64] junk', False),
                                    (' [perl;run]', False), (' [[perl]]', False), (' [perl', False)]:
                with self.subTest(suffix=suffix):
                    plan.write_text('1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n'
                                    'Inst sample [1.0] (2.0 Debian:stable [amd64])' + suffix + '\n')
                    result = run(['apt_space_output_plan_records'], 'apt_space_output_plan_records ' + shlex.quote(str(plan)))
                    self.assertEqual(result.returncode == 0, allowed, result.stderr)
                    if allowed:
                        self.assertEqual(result.stdout, 'sample\t2.0\tamd64\t1.0\n')

    def test_installed_payload_all_native_label_changes_in_both_directions(self):
        for target, installed in [('amd64', 'all'), ('all', 'amd64')]:
            with self.subTest(target=target):
                result = run(['apt_space_output_installed_size'], f'''
dpkg() {{ [ "$*" = --print-architecture ] || return 99; echo amd64; }}
dpkg-query() {{
  case "${{!#}}" in sample:{target}) return 1;; sample) printf 'install ok installed\\t1.0\\t24\\t{installed}\\n';; *) return 99;; esac
}}
apt_space_output_installed_size sample:{target} 1.0 {target}
''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, '24576\n')

    def test_foreign_ambiguous_and_wrong_version_installed_payloads_fail(self):
        for row in ['install ok installed\t1.0\t24\tarm64\n',
                    'install ok installed\tother\t24\tall\n',
                    'install ok installed\t1.0\t24\tall\ninstall ok installed\t1.0\t24\tamd64\n']:
            with self.subTest(row=row):
                result = run(['apt_space_output_installed_size'], f'''
dpkg() {{ echo amd64; }}
dpkg-query() {{ printf '%s' {shlex.quote(row)}; }}
apt_space_output_installed_size sample:amd64 1.0 amd64
''')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')

    def test_debian_transformation_uses_https_for_active_and_archived_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / 'fixture.list'
            for target, endpoint in [('bookworm', 'deb.debian.org'), ('bullseye', 'archive.debian.org')]:
                source.write_text('deb http://deb.debian.org/debian buster main\n'
                                  'deb https://repo.example.invalid/vendor stable main\n')
                result = run(['apt_sources_process'], f'''
DEBIAN_ARCHIVE='buster bullseye'
OLD_RELEASES_UBUNTU=''
apt_sources_process upgrade {shlex.quote(str(source))} debian buster {target}
''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'deb https://{endpoint}/debian {target} main', result.stdout)
                self.assertIn('deb https://repo.example.invalid/vendor stable main', result.stdout)

if __name__ == '__main__':
    unittest.main()
