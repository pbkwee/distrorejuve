#!/usr/bin/env python3
"""Offline packaged WordPress discovery without reading database configuration."""
import pathlib
import re
import subprocess
import tempfile
import unittest

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh').read_text()


def run(names, body):
    declarations = []
    for name in names:
        # Function declarations end at a column-one brace; nested bodies are indented.
        match = re.search(r'^function ' + re.escape(name) + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
        assert match, name
        declarations.append(match.group())
    return subprocess.run(['bash'], input='\n'.join(declarations) + '\n' + body,
                          text=True, capture_output=True)


class PackagedWordpress(unittest.TestCase):
    def collect(self, root, seen='', version='5.8.3'):
        version_file = root / 'usr/share/wordpress/wp-includes/version.php'
        version_file.parent.mkdir(parents=True)
        version_file.write_text('$wp_version = "' + version + '";\n')
        (root / 'etc/wordpress').mkdir(parents=True)
        (root / 'etc/wordpress/config-default.php').write_text('DB_PASSWORD=SECRET\n')
        (root / 'usr/share/wordpress/wp-config.php').symlink_to('/missing/protected-config')
        return run(['manifest_packaged_wordpress', 'manifest_application'], f'''
manifest_root={str(root)!r}
manifest_seen_roots={seen!r}
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_read_metadata() {{
  case "$1" in */wp-includes/version.php) head -c 1048576 -- "$1";; *) printf 'CREDENTIAL_READ'; return 99;; esac
}}
manifest_packaged_wordpress
''')

    def test_packaged_copy_version_and_presence_without_credential_read(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.collect(pathlib.Path(directory), seen='|/var/www/manual|')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('application discovery conventional_package_path site_mapping unknown document_root /usr/share/wordpress application WordPress version 5.8.3', result.stdout)
        self.assertIn('version_file /usr/share/wordpress/wp-includes/version.php', result.stdout)
        self.assertIn('path /etc/wordpress/config-default.php present true', result.stdout)
        self.assertIn('path /usr/share/wordpress/wp-config.php present true', result.stdout)
        self.assertIn('path /etc/wordpress/htaccess present false', result.stdout)
        self.assertEqual(len(result.stdout.splitlines()), 5)
        self.assertNotIn('SECRET', result.stdout)
        self.assertNotIn('CREDENTIAL_READ', result.stdout)
        self.assertNotIn('website ', result.stdout)

    def test_mapped_copy_not_duplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.collect(pathlib.Path(directory), seen='|/usr/share/wordpress|')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('application discovery', result.stdout)
        self.assertEqual(len(result.stdout.splitlines()), 4)

    def test_malformed_version_and_absent_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.collect(pathlib.Path(directory), version='TOKEN:invalid')
        self.assertIn('application WordPress version unknown', result.stdout)
        self.assertNotIn('TOKEN', result.stdout)
        with tempfile.TemporaryDirectory() as directory:
            result = run(['manifest_packaged_wordpress'], f'''
manifest_root={directory!r}
manifest_emit() {{ printf 'UNEXPECTED'; }}
manifest_application() {{ printf 'UNEXPECTED'; }}
manifest_packaged_wordpress
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')

    def test_installed_wordpress_packages_are_in_inventory(self):
        result = run(['manifest_packages'], r'''
manifest_package_backend=dpkg
manifest_emit() { printf '%s\n' "$*"; }
packages_output_inventory() {
  printf '%s\n' $'wordpress\t5.8.3+dfsg1-1\tinstall ok installed\tall' \
    $'wordpress-l10n\t5.8.3+dfsg1-1\tinstall ok installed\tall' \
    $'wordpress-old\t4.9\tdeinstall ok config-files\tall'
}
manifest_packages
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('package name wordpress version 5.8.3+dfsg1-1', result.stdout)
        self.assertIn('package name wordpress-l10n version 5.8.3+dfsg1-1', result.stdout)
        self.assertNotIn('package name wordpress-old', result.stdout)
        self.assertIn('package_state name wordpress-old version 4.9 architecture all status deinstall ok config-files', result.stdout)


if __name__ == '__main__':
    unittest.main()
