#!/usr/bin/env python3
"""Isolated lighttpd config mapping, redaction and non-execution regressions."""
import pathlib
import re
import subprocess
import tempfile
import unittest

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh').read_text()


def declaration(name):
    # distrorejuve.sh: function NAME() { ... column-one } -> that declaration
    # alone, excluding initialization and administration dispatch.
    match = re.search(r'^function ' + re.escape(name) + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
    assert match, name
    return match.group()


class LighttpdParser(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.config = self.root / 'etc/lighttpd'
        self.config.mkdir(parents=True)

    def write(self, name, content):
        path = self.config / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def parse(self, content):
        main = self.write('lighttpd.conf', content)
        script = '\n'.join(declaration(name) for name in [
            'manifest_run_bounded', 'manifest_lighttpd_tokens', 'manifest_lighttpd_output_configuration'])
        script += '\nmanifest_root=$1\nmanifest_lighttpd_output_configuration "$2"\n'
        result = subprocess.run(['bash', '-s', '--', str(self.root), str(main)],
                                input=script, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.rows = [line.split('\t') for line in result.stdout.splitlines()]
        for row in self.rows:
            self.assertTrue(all(row), row)
            self.assertEqual(len(row), {'site': 13, 'handler': 10, 'redirect': 6,
                                       'warning': 4, 'meta': 3}[row[0]], row)
        return result.stdout

    def sites(self):
        return [row for row in self.rows if row[0] == 'site']

    def handlers(self):
        return [row for row in self.rows if row[0] == 'handler']

    def test_static_global_and_literal_virtual_host_inherit_root_user(self):
        output = self.parse('''server.modules = ( "mod_staticfile", "mod_access" )
server.document-root = "/srv/landing"
server.username = "www-example"
server.port = 80
ssl.engine = "disable"
$HTTP["host"] == "files.example.invalid" {
 server.document-root = "/srv/files"
}
''')
        self.assertIn('meta\tconfiguration_complete\ttrue', output)
        self.assertEqual(self.sites()[0][4:9], ['80', 'false', '/srv/landing', 'www-example', 'static_files'])
        self.assertEqual(self.sites()[1][2:9], ['files.example.invalid', 'literal_host', '80', 'false', '/srv/files', 'www-example', 'static_files'])

    def test_literal_includes_glob_and_nested_scope_preserve_parent_context(self):
        self.write('sites/api.conf', '''$HTTP["url"] =~ "^/api/" {
 server.document-root = "/srv/api"
}
''')
        self.write('enabled/10-host.conf', '''$HTTP["host"] == "api.example.invalid" {
 include "../sites/api.conf"
}
''')
        # Traversal is rejected even when it happens to stay inside the tree.
        output = self.parse('include "enabled/*.conf"\n')
        self.assertIn('warning\tunsafe_include', output)
        self.assertTrue(all(row[8] == 'unknown' for row in self.sites()))
        self.write('enabled/10-host.conf', '''$HTTP["host"] == "api.example.invalid" {
 include "/etc/lighttpd/sites/api.conf"
}
''')
        output = self.parse('''server.document-root = "/srv/default"
include "enabled/*.conf"
''')
        self.assertIn('meta\tconfiguration_complete\ttrue', output)
        self.assertEqual(self.sites()[2][3], 'url')
        self.assertEqual(self.sites()[2][6], '/srv/api')
        self.assertEqual(self.sites()[2][11], 'literal_host:api.example.invalid;url:^/api/')

    def test_multiline_cgi_fastcgi_scgi_proxy_and_private_values(self):
        output = self.parse('''server.modules = (
 "mod_staticfile", "mod_cgi", "mod_fastcgi", "mod_scgi", "mod_proxy"
)
server.document-root = "/srv/app"
cgi.assign = ( ".py" => "/usr/bin/python3", ".cgi" => "" )
fastcgi.server = ( ".php" => (
 "primary" => ( "socket" => "/run/php.sock",
 "bin-path" => "/usr/bin/php-cgi --secret PRIVATE_ARGUMENT",
 "bin-environment" => ( "host" => "PRIVATE_ENVIRONMENT", "socket" => "/PRIVATE_SOCKET" )),
 "secondary" => ("host" => "127.0.0.1", "port" => 9001)
))
scgi.server = ( "/python" => (( "host" => "127.0.0.1", "port" => 4000 )))
proxy.server = ( "/ruby" => (( "host" => "127.0.0.1", "port" => 3000 )))
''')
        self.assertNotIn('PRIVATE_', output)
        self.assertEqual(len(self.handlers()), 6)
        self.assertIn(['handler', '0', '.php', 'fastcgi', '/usr/bin/php-cgi', '/run/php.sock', 'unknown', 'unknown', '/etc/lighttpd/lighttpd.conf', '6'], self.handlers())
        self.assertIn('reverse_proxy', output)
        self.assertIn('scgi', output)
        self.assertEqual(self.sites()[0][8], 'unknown')  # Several handler kinds.

    def test_generated_dynamic_and_unreferenced_configs_never_execute(self):
        sentinel = self.root / 'EXECUTED'
        self.write('conf-enabled/unreferenced.conf', 'server.document-root = "/PRIVATE_UNREFERENCED"\n')
        output = self.parse(f'''server.document-root = "/srv/static"
include_shell "touch {sentinel}"
include var.conf_dir + "/PRIVATE_DYNAMIC"
''')
        self.assertFalse(sentinel.exists())
        for private in ['EXECUTED', 'PRIVATE_UNREFERENCED', 'PRIVATE_DYNAMIC', 'touch']:
            self.assertNotIn(private, output)
        self.assertEqual(output.count('warning\tdynamic_or_generated_include'), 2)
        self.assertIn('meta\tconfiguration_complete\tfalse', output)
        self.assertEqual(self.sites()[0][8], 'unknown')

    def test_chroot_does_not_resolve_paths_against_host_root(self):
        output = self.parse('''server.chroot = "/srv/jail"
server.document-root = "/www"
server.modules = ("mod_cgi")
cgi.assign = (".py" => "/usr/bin/python3")
''')
        self.assertIn('warning\tunresolved_chroot_paths', output)
        self.assertEqual(self.sites()[0][6], 'unknown')
        self.assertEqual(self.sites()[0][8], 'unknown')
        self.assertEqual(self.handlers(), [])

    def test_symlink_escape_and_include_cycle_fail_closed(self):
        outside = self.root / 'outside.conf'
        outside.write_text('server.document-root = "/PRIVATE_OUTSIDE"\n')
        (self.config / 'escape.conf').symlink_to(outside)
        self.write('cycle.conf', 'include "lighttpd.conf"\n')
        output = self.parse('include "escape.conf"\ninclude "cycle.conf"\n')
        self.assertIn('warning\tinclude_outside_config_tree', output)
        self.assertIn('warning\tinclude_cycle', output)
        self.assertNotIn('PRIVATE_OUTSIDE', output)
        self.assertIn('meta\tconfiguration_complete\tfalse', output)

    def test_host_regex_nested_tls_socket_and_dynamic_root(self):
        output = self.parse('''server.document-root = "/srv/default"
$SERVER["socket"] == ":443" {
 ssl.engine = "enable"
 $HTTP["host"] =~ "^(www\\.)?example\\.invalid$" {
  server.document-root = var.root + "/PRIVATE_DYNAMIC_ROOT"
 }
}
''')
        self.assertEqual(self.sites()[1][3:6], ['socket', '443', 'true'])
        # The optional regexp is retained as unknown rather than a literal URL.
        self.assertEqual(self.sites()[2][3], 'host_regex')
        self.assertEqual(self.sites()[2][6], 'unknown')
        self.assertNotIn('PRIVATE_DYNAMIC_ROOT', output)
        self.assertIn('meta\tconfiguration_complete\tfalse', output)

    def test_redirect_targets_strip_userinfo_query_and_fragment(self):
        output = self.parse('''server.modules = ("mod_redirect", "mod_staticfile")
url.redirect = ( "^/old$" => "https://PRIVATE_USER:PRIVATE_PASS@new.example.invalid/new?PRIVATE_QUERY#PRIVATE_FRAGMENT" )
''')
        self.assertIn('https://new.example.invalid/new', output)
        self.assertNotIn('PRIVATE_', output)

    def test_module_missing_or_dynamic_never_claims_handler_or_static(self):
        for config in ['cgi.assign = (".py" => "/usr/bin/python3")\n',
                       'server.modules = ("mod_staticfile" + var.extra)\n',
                       'server.modules = ("mod_magnet")\n']:
            with self.subTest(config=config):
                self.parse(config)
                self.assertEqual(self.sites()[0][8], 'unknown')
                self.assertEqual(self.handlers(), [])

    def test_replacement_and_append_of_handler_maps(self):
        self.parse('''server.modules = ("mod_cgi", "mod_staticfile")
server.document-root = "/srv/static"
cgi.assign = (".py" => "/usr/bin/python3")
cgi.assign = (".pl" => "/usr/bin/perl")
cgi.assign += (".cgi" => "")
$HTTP["host"] == "static.example.invalid" {
 cgi.assign = ()
}
''')
        self.assertEqual([row[2] for row in self.handlers()], ['.pl', '.cgi'])
        self.assertEqual(self.sites()[0][8], 'cgi')
        self.assertEqual(self.sites()[1][8], 'static_files')

    def test_literal_negative_conditions_are_preserved(self):
        output = self.parse('''server.modules = ("mod_staticfile")
server.document-root = "/srv/static"
$HTTP["host"] !~ "^(www\\.)?example\\.invalid$" {
 $HTTP["url"] !~ "^/private/" {
  server.document-root = "/srv/fallback"
 }
}
''')
        self.assertEqual(self.sites()[1][3], 'host_regex_exclusion')
        self.assertEqual(self.sites()[2][3], 'url_regex_exclusion')
        self.assertIn('host_regex_exclusion:', self.sites()[2][11])
        self.assertTrue(all(row[8] == 'static_files' for row in self.sites()))
        self.assertIn('meta\tconfiguration_complete\ttrue', output)

    def test_quoted_punctuation_cannot_change_structure(self):
        output = self.parse('''server.modules = ("mod_cgi", "mod_staticfile")
server.document-root = "/srv/static"
cgi.assign = ("(" => "/usr/bin/python3", ";" => "", "}" => "/usr/bin/perl")
$HTTP["url"] == "/;" { server.document-root = "/srv/semicolon" }
''')
        self.assertEqual([row[2] for row in self.handlers()], ['(', ';', '}'])
        self.assertEqual(self.handlers()[1][4], 'direct_shebang')
        self.assertEqual(len(self.sites()), 2)
        self.assertIn('meta\tconfiguration_complete\ttrue', output)

    def test_direct_backend_environment_and_query_conditions_stay_private(self):
        output = self.parse('''server.modules = ("mod_fastcgi")
fastcgi.server = (".php" => ("bin-path" => "/usr/bin/php-cgi", "bin-environment" => ("host" => "PRIVATE_ENV_HOST", "socket" => "/PRIVATE_ENV_SOCKET")))
$HTTP["url"] == "/login?PRIVATE_QUERY" { server.document-root = "/srv/login" }
''')
        self.assertNotIn('PRIVATE_', output)
        self.assertIn('warning\tunresolved_condition', output)
        self.assertEqual(self.handlers()[0][4], '/usr/bin/php-cgi')

    def test_unknown_module_and_alias_do_not_claim_static_only(self):
        for config in ['server.modules = ("mod_custom_execution")\n',
                       'alias.url = ("/tool" => "/srv/private/tool")\n']:
            with self.subTest(config=config):
                self.parse(config)
                self.assertEqual(self.sites()[0][8], 'unknown')

    def test_dynamic_backend_hostname_is_not_a_literal_endpoint(self):
        output = self.parse('''server.modules = ("mod_fastcgi")
fastcgi.server = (".php" => (("host" => var.PRIVATE_BACKEND, "port" => 9000)))
''')
        self.assertNotIn('PRIVATE_BACKEND', output)
        self.assertIn('warning\tdynamic_handler', output)
        self.assertEqual(self.sites()[0][8], 'unknown')
        self.assertTrue(all(row[6] == 'unknown' for row in self.handlers()))

    def test_unbalanced_and_oversized_files_warn(self):
        output = self.parse('server.document-root = (\n')
        self.assertIn('warning\tunclosed_context_or_array', output)
        self.assertEqual(self.sites()[0][8], 'unknown')
        output = self.parse('#' + 'x' * 262144)
        self.assertIn('warning\tcollection_limit', output)
        self.assertIn('meta\tconfiguration_complete\tfalse', output)


if __name__ == '__main__':
    unittest.main()
