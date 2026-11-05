#!/usr/bin/env python3
"""Hermetic vendor acceptance: temporary signed metadata and synthetic .deb files."""
import datetime as dt
import email.utils
import hashlib
import pathlib
import runpy
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
declaration = runpy.run_path(str(ROOT / 'tests/test-upgrade-review.py'))['declaration']
NAMES = ('apt_review_is_root_file', 'apt_review_validate_contract', 'apt_sources_output_signed_by',
         'apt_review_matches_digest', 'apt_review_check_source_identity', 'apt_review_check_build',
         'apt_sources_check_reviewed_vendor', 'apt_review_check_installed_builds',
         'apt_sources_check_releases_and_vendors')


def run(body, real_permissions=False):
    # The fixtures run unprivileged under /tmp. Model root ownership only for
    # acceptance-protocol tests; real permission rejection has its own case.
    permission = '' if real_permissions else '''
apt_review_is_root_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %s -- "$1")" -gt 0 ] && [ "$(stat -c %s -- "$1")" -le "$2" ]; }
'''
    return subprocess.run(['bash'], input='\n'.join(declaration(n) for n in NAMES) + '\n' + permission + body,
                          text=True, capture_output=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(all(shutil.which(command) for command in ('gpg', 'gpgv', 'dpkg-deb', 'tar')),
                     'isolated signed-metadata fixture needs existing gpg/gpgv/dpkg-deb/tar')
class ReviewedVendors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = pathlib.Path(cls.directory.name)
        cls.gnupg = cls.root / 'gnupg'
        cls.gnupg.mkdir(mode=0o700)
        base = ['gpg', '--homedir', str(cls.gnupg), '--batch', '--no-tty', '--pinentry-mode', 'loopback', '--passphrase', '']
        subprocess.run(base + ['--quick-generate-key', 'Fixture Vendor <fixture@example.invalid>', 'rsa2048', 'sign', '0'],
                       check=True, capture_output=True)
        result = subprocess.run(base + ['--with-colons', '--list-keys'], check=True, capture_output=True, text=True)
        cls.fingerprint = next(line.split(':')[9] for line in result.stdout.splitlines() if line.startswith('fpr:'))
        cls.keyring = cls.root / 'vendor.gpg'
        cls.keyring.write_bytes(subprocess.run(base + ['--export', cls.fingerprint], check=True, capture_output=True).stdout)
        cls.release_text = cls.root / 'Release'
        cls.release = cls.root / 'InRelease'
        now = dt.datetime.now(dt.timezone.utc)
        cls.release_text.write_text('Origin: Fixture Vendor\nLabel: Fixture Vendor\nSuite: stable\nCodename: trixie\n'
                                    'Date: ' + email.utils.format_datetime(now) + '\nValid-Until: ' +
                                    email.utils.format_datetime(now + dt.timedelta(days=1)) + '\n')
        subprocess.run(base + ['--output', str(cls.release), '--clearsign', str(cls.release_text)],
                       check=True, capture_output=True)
        cls.installed = cls.root / 'installed/vendor-demo'
        cls.installed.parent.mkdir()
        cls.installed.write_bytes(b'new-target-distro-build\n')
        cls.archive = cls.root / 'vendor-demo.deb'
        package_root = cls.root / 'package'
        (package_root / 'DEBIAN').mkdir(parents=True)
        (package_root / 'DEBIAN/control').write_text('Package: vendor-demo\nVersion: 3.0\nArchitecture: amd64\n'
                                                   'Maintainer: Fixture <fixture@example.invalid>\nDescription: fixture only\n')
        payload = package_root / str(cls.installed).lstrip('/')
        payload.parent.mkdir(parents=True)
        payload.write_bytes(cls.installed.read_bytes())
        subprocess.run(['dpkg-deb', '--build', '--root-owner-group', str(package_root), str(cls.archive)],
                       check=True, capture_output=True)
        cls.source = cls.root / 'vendor.list'
        cls.source.write_text(f'deb [arch=amd64 signed-by={cls.keyring}] https://repo.example.invalid/debian trixie main\n')

    @classmethod
    def tearDownClass(cls):
        if shutil.which('gpgconf'):
            subprocess.run(['gpgconf', '--homedir', str(cls.gnupg), '--kill', 'gpg-agent'], capture_output=True)
        cls.directory.cleanup()

    def setUp(self):
        self.installed.write_bytes(b'new-target-distro-build\n')
        self.contract = self.root / 'review.tsv'
        self.contract.write_text(self.contract_text())

    def contract_text(self):
        return '\t'.join(['source', 'vendor-a', 'https://repo.example.invalid/debian', 'trixie', 'main', 'debian', 'trixie',
                          str(self.keyring), digest(self.keyring), self.fingerprint, 'Fixture Vendor', 'Fixture Vendor',
                          'stable', str(self.release), '7']) + '\n' + '\t'.join([
                              'build', 'vendor-a', 'vendor-demo', 'amd64', '3.0', str(self.archive), digest(self.archive),
                              str(self.installed), hashlib.sha256(b'new-target-distro-build\n').hexdigest(), 'trixie']) + '\n'

    def mocks(self):
        records = ('/fixture/official.list\t1\tdebian\tdeb\thttps://deb.debian.org/debian\ttrixie\tmain\t*\n' +
                   f'{self.source}\t1\tunknown\tdeb\thttps://repo.example.invalid/debian\ttrixie\tmain\t*\n')
        return f'''
DR_REVIEWED_VENDOR_CONTRACT={shlex.quote(str(self.contract))}
ALL_DEBIAN='bullseye bookworm trixie'; ALL_UBUNTU='jammy noble'
distro_output_codename() {{ echo trixie; }}
apt_sources_list() {{ printf %s {shlex.quote(records)}; }}
upgrade_panel_refuse_generic() {{ :; }}
packages_output_file_owner() {{ printf 'vendor-demo:amd64\\n'; }}
dpkg-query() {{ printf 'install ok installed\\t3.0\\tamd64\\n'; }}
'''

    def identity(self, **overrides):
        args = dict(keyring=str(self.keyring), keyring_digest=digest(self.keyring), fingerprint=self.fingerprint,
                    origin='Fixture Vendor', label='Fixture Vendor', series='stable', codename='trixie', release=str(self.release), maximum_age='7')
        args.update(overrides)
        return run('apt_review_check_source_identity ' + ' '.join(shlex.quote(str(v)) for v in args.values()))

    def test_real_signature_and_exact_release_identity_pass(self):
        result = self.identity()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')

    def test_changed_signer_keyring_origin_series_and_suite_fail(self):
        cases = [dict(fingerprint='A' * 40), dict(keyring_digest='0' * 64), dict(origin='Other Vendor'),
                 dict(label='Other Vendor'), dict(series='oldstable'), dict(codename='bookworm')]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                result = self.identity(**overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')

    def test_unsigned_or_modified_release_is_rejected(self):
        unsigned = self.root / 'unsigned'
        unsigned.write_bytes(self.release_text.read_bytes())
        changed = self.root / 'changed'
        changed.write_bytes(self.release.read_bytes().replace(b'Origin: Fixture Vendor', b'Origin: Another Vendor'))
        for path in (unsigned, changed):
            self.assertNotEqual(self.identity(release=path).returncode, 0)

    def test_unsigned_prefix_or_trailer_cannot_supply_missing_signed_origin(self):
        payload = self.root / 'missing-origin'
        signed = self.root / 'missing-origin.asc'
        payload.write_bytes(self.release_text.read_bytes().replace(b'Origin: Fixture Vendor\n', b''))
        subprocess.run(['gpg', '--homedir', str(self.gnupg), '--batch', '--no-tty',
                        '--pinentry-mode', 'loopback', '--passphrase', '', '--output', str(signed),
                        '--clearsign', str(payload)], check=True, capture_output=True)
        for position, data in [('prefix', b'Origin: Fixture Vendor\n' + signed.read_bytes()),
                               ('trailer', signed.read_bytes() + b'\nOrigin: Fixture Vendor\n')]:
            with self.subTest(position=position):
                artifact = self.root / ('unsigned-' + position)
                artifact.write_bytes(data)
                # GnuPG verifies the embedded packet, ignoring the outside text.
                verified = subprocess.run(['gpgv', '--keyring', str(self.keyring), str(artifact)],
                                          capture_output=True)
                self.assertEqual(verified.returncode, 0)
                result = self.identity(release=artifact)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')

    def test_verified_cleartext_directory_is_removed_on_success_and_failure(self):
        scratch = self.root / 'cleartext-scratch'
        scratch.mkdir()
        args = [self.keyring, digest(self.keyring), self.fingerprint, 'Fixture Vendor',
                'Fixture Vendor', 'stable', 'trixie', self.release, '7']
        for expected_fingerprint, allowed in [(self.fingerprint, True), ('A' * 40, False)]:
            args[2] = expected_fingerprint
            body = 'TMPDIR=' + shlex.quote(str(scratch)) + '\napt_review_check_source_identity ' + ' '.join(shlex.quote(str(v)) for v in args)
            result = run(body)
            self.assertEqual(result.returncode == 0, allowed, result.stderr)
            self.assertEqual(list(scratch.iterdir()), [])

    def test_expired_release_and_future_dates_are_rejected_after_signature_validation(self):
        # Only time is mocked; gpgv still verifies the real fixture signature.
        for epoch in ('4102444800', '1'):
            body = f'''
date() {{ if [ "$*" = '-u +%s' ]; then echo {epoch}; else command date "$@"; fi; }}
apt_review_check_source_identity {' '.join(shlex.quote(str(v)) for v in [self.keyring, digest(self.keyring), self.fingerprint, 'Fixture Vendor', 'Fixture Vendor', 'stable', 'trixie', self.release, '7'])}
'''
            self.assertNotEqual(run(body).returncode, 0)

    def test_exact_contract_is_accepted_and_unbound_or_unsafe_records_fail(self):
        valid = self.contract_text()
        cases = [(valid, True), (valid.replace('https://repo.example.invalid', 'http://repo.example.invalid'), False),
                 (valid.replace('\t7\n', '\t0\n'), False), (valid.replace('build\tvendor-a', 'build\tunrelated'), False),
                 (valid.splitlines()[0] + '\n', False), (valid.replace('\tamd64\t', '\t../unsafe\t'), False),
                 (valid + valid, False)]
        for text, allowed in cases:
            with self.subTest(text=text[:80], allowed=allowed):
                self.contract.write_text(text)
                result = run('apt_review_validate_contract ' + shlex.quote(str(self.contract)))
                self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_signing_options_require_one_keyring_without_trust_overrides(self):
        for index, (text, allowed) in enumerate([
            (f'deb [arch=amd64 signed-by={self.keyring}] https://repo.example.invalid trixie main\n', True),
            (f'deb [trusted=yes signed-by={self.keyring}] https://repo.example.invalid trixie main\n', False),
            ('deb https://repo.example.invalid trixie main\n', False),
            (f'deb [signed-by={self.keyring} signed-by=/other] https://repo.example.invalid trixie main\n', False),
        ]):
            path = self.root / f'options{index}.list'
            path.write_text(text)
            result = run('apt_sources_output_signed_by ' + shlex.quote(str(path)) + ' 1')
            self.assertEqual(result.returncode == 0, allowed, result.stderr)
            if allowed:
                self.assertEqual(result.stdout.strip(), str(self.keyring))
        path = self.root / 'vendor.sources'
        for trusted, allowed in [('no', True), ('yes', False)]:
            path.write_text(f'Types: deb\nURIs: https://repo.example.invalid\nSuites: trixie\nComponents: main\nSigned-By: {self.keyring}\nTrusted: {trusted}\n')
            self.assertEqual(run('apt_sources_output_signed_by ' + shlex.quote(str(path)) + ' 1').returncode == 0, allowed)

    def test_current_matching_vendor_and_target_payload_pass_full_policy(self):
        result = run(self.mocks() + '\napt_sources_check_releases_and_vendors\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('exact signer, release identity and after build assertions', result.stderr)

    def test_same_version_wrong_distro_payload_fails_final_acceptance(self):
        self.installed.write_bytes(b'old-distro-build-same-version\n')
        result = run(self.mocks() + '\napt_sources_check_releases_and_vendors\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('build assertion failed', result.stderr)
        # Before transition the selected new archive is valid although activation is pending.
        result = run(self.mocks() + '\napt_sources_check_releases_and_vendors trixie\n')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_archive_hash_and_installed_owner_are_rejected(self):
        self.contract.write_text(self.contract_text().replace(digest(self.archive), '0' * 64))
        result = run(self.mocks() + '\napt_sources_check_releases_and_vendors\n')
        self.assertNotEqual(result.returncode, 0)
        self.contract.write_text(self.contract_text())
        result = run(self.mocks() + '\npackages_output_file_owner() { echo unrelated; }\napt_sources_check_releases_and_vendors\n')
        self.assertNotEqual(result.returncode, 0)

    def test_unreviewed_source_remains_blocked(self):
        result = run(self.mocks() + '\nunset DR_REVIEWED_VENDOR_CONTRACT\napt_sources_check_releases_and_vendors\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Review or disable unknown source', result.stderr)

    def test_normal_source_validation_requires_active_vendor_and_exact_target(self):
        result = run(self.mocks() + '\napt_sources_check_releases_and_vendors\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        result = run(self.mocks() + '\napt_sources_list() { :; }\napt_sources_check_releases_and_vendors\n')
        self.assertNotEqual(result.returncode, 0)
        result = run(self.mocks() + '\ndistro_output_codename() { echo bookworm; }\napt_sources_check_releases_and_vendors\n')
        self.assertNotEqual(result.returncode, 0)

    def test_real_permissions_reject_unprivileged_or_writable_contract(self):
        self.contract.chmod(0o666)
        result = run('apt_review_validate_contract ' + shlex.quote(str(self.contract)), real_permissions=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
