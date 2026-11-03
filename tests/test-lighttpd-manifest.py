#!/usr/bin/env python3
"""Offline manifest integration: synthetic roots and extracted declarations only."""
import json
import pathlib
import re
import shlex
import subprocess
import tempfile
import unittest


SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh').read_text()
NAMES = [
    'manifest_json_string', 'manifest_emit', 'manifest_read_metadata', 'manifest_run_bounded',
    'manifest_lighttpd_tokens', 'manifest_lighttpd_output_configuration',
    'manifest_lighttpd_handler', 'manifest_lighttpd_frontends', 'manifest_lighttpd_websites',
    'manifest_website', 'manifest_website_assets', 'manifest_application', 'manifest_dns',
    'manifest_packages', 'manifest_service', 'manifest_listeners',
]


def declaration(name):
    # Producer: distrorejuve.sh top-level function NAME() { ... column-one }.
    # Extract declarations, never source initialization or administration dispatch.
    match = re.search(r'^function ' + re.escape(name) + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
    assert match, name
    return match.group()


class LighttpdManifest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.write('/etc/lighttpd/lighttpd.conf', '''server.port = 80
server.name = "example.invalid"
server.document-root = "/srv/www"
server.modules = ( "mod_accesslog", "mod_dirlisting" )
''')
        self.write('/srv/www/index.html', '<html>fixture</html>\n')

    def write(self, path, text):
        target = self.root / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            target.write_bytes(text)
        else:
            target.write_text(text)
        return target

    def frontend(self, config='/etc/lighttpd/lighttpd.conf', modules=('mod_staticfile',)):
        self.write('/proc/101/status', 'Name:\tlighttpd\nPid:\t101\n')
        self.write('/proc/101/cmdline', b'lighttpd\0-f\0' + config.encode() + b'\0--token\0ARG_SECRET\0')
        self.write('/proc/101/maps', ''.join(
            '1000-2000 r-xp 0 00:00 1 /usr/lib/lighttpd/' + module + '.so\n'
            for module in modules))

    def collect(self, setup='', redact=False, body='manifest_lighttpd_websites'):
        script = '\n'.join(declaration(name) for name in NAMES)
        script += '\n' + f'''
manifest_root={shlex.quote(str(self.root))}
manifest_format=json
manifest_separator=
manifest_warning_count=0
manifest_collection_failed=false
manifest_redact={'true' if redact else 'false'}
manifest_dns_enabled=false
manifest_seen_roots=
manifest_package_backend=dpkg
manifest_fpm_sockets=()
manifest_fpm_versions=()
manifest_fpm_packages=()
manifest_fpm_users=()
manifest_web_indicators() {{ :; }}
packages_output_file_owner() {{ return 1; }}
packages_output_inventory() {{ return 1; }}
{setup}
printf '{{"records":['
{body}
printf '],"core_failed":%s}}\\n' "$manifest_collection_failed"
'''
        result = subprocess.run(['bash'], input=script, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_static_sites_frontend_and_unreferenced_fragment(self):
        self.frontend()
        self.write('/etc/lighttpd/conf-enabled/10-unused.conf',
                   'server.document-root = "/UNUSED_SECRET"\n')
        self.write('/srv/www/tool.py', 'raise RuntimeError("MUST_NOT_EXECUTE")\n')
        data = self.collect()
        self.assertFalse(data['core_failed'])
        sites = [r for r in data['records'] if r['type'] == 'website']
        self.assertEqual(sites[0]['name'], 'example.invalid')
        self.assertEqual(sites[0]['runtime'], 'static_files')
        self.assertEqual(sites[0]['execution'], 'static_file_only')
        frontend = next(r for r in data['records'] if r['type'] == 'web_frontend')
        self.assertEqual(frontend['config'], '/etc/lighttpd/lighttpd.conf')
        self.assertEqual(frontend['modules'], 'mod_staticfile')
        sample = next(r for r in data['records'] if r['type'] == 'web_file')
        self.assertEqual(sample['language'], 'Python')
        self.assertEqual(sample['execution'], 'static_file_only')
        self.assertNotIn('ARG_SECRET', json.dumps(data))
        self.assertNotIn('UNUSED_SECRET', json.dumps(data))
        self.assertNotIn('MUST_NOT_EXECUTE', json.dumps(data))

    def test_shared_symlink_assets_retain_ancestor_without_activation(self):
        public = self.write('/legacy/blog/public/files/downloads/tool.rb', 'BODY_SECRET\n').parent
        self.write('/legacy/blog/config/environment.rb', 'SECRET_SETTINGS_NOT_READ\n')
        assets = self.root / 'srv/www/assets'
        assets.symlink_to(public)
        with (self.root / 'etc/lighttpd/lighttpd.conf').open('a') as f:
            f.write('''$HTTP["host"] == "files.example.invalid" {
server.document-root = "/srv/www/assets"
}
$HTTP["host"] == "static.example.invalid" {
server.document-root = "/srv/www/assets"
}
''')
        data = self.collect()
        roots = [r for r in data['records'] if r['type'] == 'web_asset_root'
                 and r['document_root'] == '/srv/www/assets']
        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0]['resolved_path'], '/legacy/blog/public/files/downloads')
        self.assertEqual(roots[0]['symlink'], 'true')
        context = next(r for r in data['records'] if r['type'] == 'application_context')
        self.assertEqual(context['path'], '/legacy/blog')
        self.assertEqual(context['activity'], 'unknown')
        self.assertEqual(context['execution'], 'not_implied_by_asset_use')
        self.assertNotIn('SECRET_SETTINGS_NOT_READ', json.dumps(data))

    def test_fastcgi_socket_uses_pool_version(self):
        with (self.root / 'etc/lighttpd/lighttpd.conf').open('a') as f:
            f.write('''server.modules += ( "mod_fastcgi" )
fastcgi.server = ( ".php" => (( "socket" => "/run/php/site.sock" )) )
''')
        data = self.collect('''manifest_fpm_sockets=(/run/php/site.sock)
manifest_fpm_versions=(8.4.12)
manifest_fpm_packages=(php8.4-fpm)
manifest_fpm_users=(site)
''')
        handler = next(r for r in data['records'] if r['type'] == 'website_handler')
        self.assertEqual(handler['language'], 'PHP')
        self.assertEqual(handler['runtime_version'], '8.4.12')
        self.assertEqual(handler['runtime_version_source'], 'fpm_pool_config')

    def test_missing_or_ambiguous_pool_does_not_invent_version(self):
        with (self.root / 'etc/lighttpd/lighttpd.conf').open('a') as f:
            f.write('server.modules += ( "mod_fastcgi" )\nfastcgi.server = ( "/app" => (( "host" => "127.0.0.1", "port" => 9000 )) )\n')
        data = self.collect('''manifest_fpm_sockets=(unknown)
manifest_fpm_versions=(8.4.12)
manifest_fpm_packages=(php8.4-fpm)
''')
        handler = next(r for r in data['records'] if r['type'] == 'website_handler')
        self.assertEqual(handler['runtime_version'], 'unknown')
        self.assertEqual(handler['language'], 'unknown')

    def test_ambiguous_fpm_pools_do_not_select_first_version(self):
        with (self.root / 'etc/lighttpd/lighttpd.conf').open('a') as f:
            f.write('server.modules += ( "mod_fastcgi" )\nfastcgi.server = ( ".php" => (( "socket" => "/run/php/site.sock" )) )\n')
        data = self.collect('''manifest_fpm_sockets=(/run/php/site.sock /run/php/site.sock)
manifest_fpm_versions=(8.2.1 8.4.12)
manifest_fpm_packages=(php8.2-fpm php8.4-fpm)
''')
        handler = next(r for r in data['records'] if r['type'] == 'website_handler')
        self.assertEqual(handler['runtime_version'], 'unknown')
        self.assertEqual(handler['runtime_version_source'], 'ambiguous_fpm_pool_config')

    def test_module_and_service_recognition(self):
        data = self.collect('''manifest_processes=lighttpd
packages_output_inventory() { printf 'lighttpd\\t1.4.79-2\\tinstall ok installed\\tamd64\\n'; }
ss() { printf 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\\nLISTEN 0 128 192.0.2.10:80 *:* users:(("lighttpd",pid=101,fd=3))\\n'; }
''', body='manifest_packages\nmanifest_listeners')
        service = next(r for r in data['records'] if r['type'] == 'service')
        self.assertEqual(service['name'], 'lighttpd')
        self.assertEqual(service['running'], 'yes')
        listener = next(r for r in data['records'] if r['type'] == 'listener')
        self.assertEqual(listener['application'], 'lighttpd')

    def test_exited_daemon_wrapper_does_not_establish_running_application(self):
        (self.root / 'run/systemd/system').mkdir(parents=True)
        (self.root / 'proc/1').mkdir(parents=True)
        (self.root / 'proc/1/exe').symlink_to('/lib/systemd/systemd')
        setup = '''manifest_processes=
manifest_unprivileged=false
packages_output_inventory() { printf 'mysql-server\\t5.1.0\\tinstall ok installed\\ti386\\n'; }
upgrade_services_is_active() { return 0; }
manifest_run_bounded() { shift; "$@"; }
systemctl() {
  case "$*" in
    'show -p SubState -p MainPID mysql.service') printf 'SubState=exited\\nMainPID=0\\n';;
    'show -p UnitFileState mysql.service') printf 'UnitFileState=enabled\\n';;
    *) return 99;;
  esac
}
'''
        data = self.collect(setup, body='manifest_packages')
        service = next(r for r in data['records'] if r['type'] == 'service')
        self.assertEqual(service['running'], 'unknown')
        self.assertEqual(service['status_source'], 'systemd_exited_wrapper')
        data = self.collect(setup + '\nmanifest_processes=mysqld\n', body='manifest_packages')
        service = next(r for r in data['records'] if r['type'] == 'service')
        self.assertEqual(service['running'], 'yes')
        self.assertEqual(service['status_source'], 'process_name')

        data = self.collect(setup.replace('SubState=exited', 'SubState=running')
                            .replace('MainPID=0', 'MALFORMED'), body='manifest_packages')
        service = next(r for r in data['records'] if r['type'] == 'service')
        self.assertEqual(service['running'], 'unknown')
        self.assertEqual(service['status_source'], 'systemd_state_unknown')

    def test_running_custom_config_without_conventional_file_is_reported(self):
        (self.root / 'etc/lighttpd/lighttpd.conf').unlink()
        self.frontend(config='/opt/service/lighttpd.conf')
        data = self.collect()
        self.assertTrue(data['core_failed'])
        self.assertTrue(any(r['type'] == 'web_frontend' for r in data['records']))
        self.assertTrue(any(r['type'] == 'warning' and 'manual mapping' in r['reason']
                            for r in data['records']))
        self.assertFalse(any(r['type'] == 'website' for r in data['records']))

    def test_cgi_launcher_shebang_and_actual_interpreter_package(self):
        self.write('/srv/app/launch.cgi', '#!/usr/bin/python3\nraise RuntimeError("CODE_SECRET")\n')
        interpreter = self.write('/usr/bin/python3.11', b'\x7fELF\0FAKE_BINARY_NOT_EXECUTABLE')
        (interpreter.parent / 'python3').symlink_to('python3.11')
        with (self.root / 'etc/lighttpd/lighttpd.conf').open('a') as f:
            f.write('server.modules += ( "mod_cgi" )\ncgi.assign = ( ".cgi" => "/srv/app/launch.cgi --token CMD_SECRET" )\n')
        data = self.collect('''packages_output_file_owner() { [ "$1" = /usr/bin/python3.11 ] && printf python3.11; }
packages_output_inventory() { printf 'python3.11\\t3.11.10-1\\tinstall ok installed\\tamd64\\n'; }
''')
        handler = next(r for r in data['records'] if r['type'] == 'website_handler')
        self.assertEqual(handler['language'], 'Python')
        self.assertEqual(handler['runtime_version'], '3.11.10')
        self.assertEqual(handler['executable'], '/srv/app/launch.cgi')
        self.assertNotIn('CODE_SECRET', json.dumps(data))
        self.assertNotIn('CMD_SECRET', json.dumps(data))

    def test_dynamic_and_mismatched_active_configuration_stay_unknown(self):
        self.frontend('/etc/lighttpd/other.conf')
        data = self.collect()
        self.assertTrue(data['core_failed'])
        self.assertTrue(all(r['runtime'] == 'unknown' for r in data['records'] if r['type'] == 'website'))
        with (self.root / 'etc/lighttpd/lighttpd.conf').open('a') as f:
            f.write('include_shell "touch /COMMAND_MUST_NOT_RUN"\n')
        data = self.collect()
        self.assertTrue(data['core_failed'])
        self.assertFalse((self.root / 'COMMAND_MUST_NOT_RUN').exists())

    def test_literal_include_does_not_source_inherited_bash_env(self):
        marker = self.root / 'ENV_MUST_NOT_RUN'
        envfile = self.write('/operator-env', 'touch ' + shlex.quote(str(marker)) + '\n')
        self.write('/etc/lighttpd/fragments/site.conf', 'server.username = "site"\n')
        with (self.root / 'etc/lighttpd/lighttpd.conf').open('a') as f:
            f.write('include "fragments/*.conf"\n')
        data = self.collect('export BASH_ENV=' + shlex.quote(str(envfile)))
        self.assertFalse(data['core_failed'])
        self.assertFalse(marker.exists())

    def test_empty_config_is_not_a_verified_static_site(self):
        self.write('/etc/lighttpd/lighttpd.conf', '')
        data = self.collect()
        self.assertTrue(data['core_failed'])
        self.assertEqual(next(r for r in data['records'] if r['type'] == 'website')['runtime'], 'unknown')

    def test_loaded_handler_module_requires_resolved_mapping(self):
        self.frontend(modules=('mod_staticfile', 'mod_fastcgi'))
        data = self.collect()
        self.assertTrue(data['core_failed'])
        self.assertEqual(next(r for r in data['records'] if r['type'] == 'website')['runtime'], 'unknown')

    def test_public_redaction_keeps_general_execution_facts(self):
        self.frontend()
        self.write('/srv/www/PRIVATE_FILE.py', 'BODY_SECRET\n')
        data = self.collect(redact=True)
        text = json.dumps(data)
        for private in ['example.invalid', '/srv/www', 'PRIVATE_FILE', 'ARG_SECRET', 'BODY_SECRET', 'mod_staticfile']:
            self.assertNotIn(private, text)
        self.assertIn('static_file_only', text)
        self.assertEqual(next(r for r in data['records'] if r['type'] == 'website')['activity'], 'unknown')

    def test_fixture_root_escape_does_not_read_application_metadata(self):
        with tempfile.TemporaryDirectory() as outside:
            secret = pathlib.Path(outside)
            (secret / 'wp-includes').mkdir()
            (secret / 'wp-includes/version.php').write_text('$wp_version = "ESCAPED_SECRET";\n')
            (self.root / 'srv/www/escape').symlink_to(secret)
            with (self.root / 'etc/lighttpd/lighttpd.conf').open('a') as f:
                f.write('$HTTP["host"] == "escape.example.invalid" {\nserver.document-root = "/srv/www/escape"\n}\n')
            data = self.collect()
            self.assertTrue(data['core_failed'])
            self.assertNotIn('ESCAPED_SECRET', json.dumps(data))
            self.assertNotIn(outside, json.dumps(data))


if __name__ == '__main__':
    unittest.main()
