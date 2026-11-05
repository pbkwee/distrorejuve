#!/usr/bin/env python3
"""Synthetic collector regressions: never start applications or contact hosts."""
import pathlib
import re
import subprocess
import tempfile
import unittest

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh').read_text()


def run(names, body):
    declarations=[]
    for name in names:
        match=re.search(r'^function '+re.escape(name)+r'\(\) \{\n.*?^\}',SOURCE,re.M|re.S)
        assert match,name
        declarations.append(match.group())
    return subprocess.run(['bash'],input='\n'.join(declarations)+'\n'+body,text=True,capture_output=True,timeout=20)


class CollectorImprovements(unittest.TestCase):
    def application(self, path, content, extra=()):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            marker=root/'srv/site'/path
            marker.parent.mkdir(parents=True)
            marker.write_text(content)
            for name in extra:
                target=root/'srv/site'/name
                target.parent.mkdir(parents=True,exist_ok=True)
                target.touch()
            (root/'srv/site/config.php').write_text('CREDENTIAL_SECRET')
            return run(['manifest_application','manifest_read_metadata'],f'''
manifest_root={directory!r}
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_application /srv/site
''')

    def test_moodle_build_suffix_and_invalid_metadata(self):
        for value,expected in [('4.5.4+ (Build: 20250314)','4.5.4+'),('4.3.3','4.3.3'),('4.5.4 (Build: SECRET)','unknown'),('4.5.4 (Build: 20250314) SECRET','unknown')]:
            with self.subTest(value=value):
                result=self.application('version.php','$release = "'+value+'";\n',('lib/moodlelib.php',))
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn('application Moodle version '+expected+' language PHP',result.stdout)
                self.assertNotIn('SECRET',result.stdout)

    def test_mediawiki_modern_constant_and_legacy_variable(self):
        for path,text in [('includes/Defines.php',"define( 'MW_VERSION', '1.39.11' );"),('includes/DefaultSettings.php',"$wgVersion = '1.39.11';")]:
            result=self.application(path,text)
            self.assertIn('application MediaWiki version 1.39.11',result.stdout,result.stderr)
            self.assertIn('version_file /srv/site/'+path,result.stdout)
        result=self.application('includes/Defines.php',"define('MW_VERSION', '1.39.11' . 'SECRET');")
        self.assertIn('version unknown',result.stdout)
        self.assertNotIn('SECRET',result.stdout)

    def test_vbulletin_literal_only(self):
        for value,expected in [('4.2.5','4.2.5'),('3.8.7 Patch Level 5','3.8.7 Patch Level 5'),('4.2.5 SECRET','unknown')]:
            result=self.application('includes/version_vbulletin.php',"define('FILE_VERSION_VBULLETIN', '"+value+"');")
            self.assertIn('application vBulletin version '+expected+' language PHP',result.stdout,result.stderr)
            self.assertNotIn('SECRET',result.stdout)
        result=self.application('includes/version_vbulletin.php',"define('FILE_VERSION_VBULLETIN', getenv('SECRET'));")
        self.assertIn('version unknown',result.stdout)

    def test_legacy_process_columns_are_independent_options(self):
        result=run(['manifest_process_names'],r'''
manifest_run_bounded() { [ "$*" = '5 ps -eo pid= -o comm=' ] || return 99; printf '10 java\n11 proxysql\n'; }
manifest_process_names
printf 'available=%s\n' "$manifest_processes_available"
''')
        self.assertIn('available=true',result.stdout,result.stderr)

    def apache(self, main, site):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            (root/'main.conf').write_text(main)
            (root/'site.conf').write_text(site)
            return run(['manifest_websites','manifest_read_metadata'],f'''
manifest_root={directory!r}
manifest_website() {{ printf 'site %s\\n' "$*"; }}
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_lighttpd_websites() {{ :; }}
manifest_config_files() {{ [ "$1" != apache ] || printf '%s\\n' {str(root/'main.conf')!r} {str(root/'site.conf')!r}; }}
manifest_websites
''')

    def test_apache_global_default_and_tls_inheritance(self):
        result=self.apache('ServerName example.invalid\nDocumentRoot /var/www/html\nSSLEngine on\n','<VirtualHost *:443>\n</VirtualHost>\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('site apache example.invalid 80 true /var/www/html',result.stdout)
        self.assertIn('site apache example.invalid 443 true /var/www/html',result.stdout)
        self.assertIn('subdirectories not_discovered',result.stdout)

    def test_apache_explicit_vhost_overrides_globals(self):
        result=self.apache('ServerName default.invalid\nDocumentRoot /srv/default\n','<VirtualHost *:80>\nServerName actual.invalid\nDocumentRoot /srv/actual\nSSLEngine off\n</VirtualHost>\n')
        self.assertIn('site apache actual.invalid 80 false /srv/actual',result.stdout)
        self.assertNotIn('site apache default.invalid 80',result.stdout)

    def test_apache_conditional_ssl_remains_unknown(self):
        result=self.apache('ServerName example.invalid\nDocumentRoot /srv/site\n','<IfModule mod_ssl.c>\n<VirtualHost *:443>\nSSLEngine on\n</VirtualHost>\n</IfModule>\n')
        self.assertIn('site apache example.invalid 443 unknown /srv/site',result.stdout,result.stderr)

    def test_unknown_tls_probes_both_protocols_without_invented_url(self):
        result=run(['manifest_website'],r'''
manifest_root=
manifest_fpm_sockets=()
manifest_seen_roots='|/missing|'
manifest_apache_php_available=false
manifest_dns() { :; }
manifest_emit() { printf '%s\n' "$*"; }
manifest_http() { printf 'probe %s\n' "$*"; }
manifest_website apache example.invalid 443 unknown /missing unknown unknown example.conf
''')
        self.assertIn('url unknown primary_url unknown',result.stdout,result.stderr)
        self.assertIn('probe example.invalid http 443',result.stdout)
        self.assertIn('probe example.invalid https 443',result.stdout)

    def test_collector_correlation_keeps_genuine_child_indicator(self):
        result=run(['manifest_process_indicators'],r'''
manifest_collector_pid=100
manifest_collector_script=/tmp/collector.sh
manifest_emit() { printf '%s\n' "$*"; }
manifest_run_bounded() { printf '%s\n' '100 1 0 9000 bash /tmp/collector.sh' '101 100 0 9000 bash /tmp/collector.sh' '102 100 0 9000 python3 /tmp/unrelated.py'; }
manifest_process_indicators
''')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('process_count 2 sample_pid 101 parent_pid 100 uid 0 collector_process_count 1',result.stdout)
        self.assertIn('process_count 1 sample_pid 100 parent_pid 1 uid 0 collector_process_count 1',result.stdout)
        self.assertEqual(result.stdout.count('assessment requires_review'),2)
        self.assertNotIn('unrelated.py',result.stdout)

    def test_standalone_webmin_keeps_runtime_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            (root/'etc/webmin').mkdir(parents=True)
            (root/'etc/webmin/version').write_text('1.370\n')
            result=run(['manifest_hosting_panels','manifest_read_metadata'],f'''
manifest_root={directory!r}
upgrade_panel_output_installed() {{ :; }}
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_hosting_panels
''')
        self.assertIn('hosting_panel name webmin version 1.370',result.stdout,result.stderr)
        self.assertIn('installed yes running unknown',result.stdout)

    def test_proxysql_package_is_named_service(self):
        result=run(['manifest_packages'],r'''
manifest_package_backend=dpkg
manifest_php_packages=(); manifest_php_versions=()
packages_output_inventory() { printf 'proxysql\t3.0.11\tinstall ok installed\tamd64\n'; }
manifest_service() { printf 'service %s\n' "$*"; }
manifest_emit() { :; }
manifest_packages
''')
        self.assertIn('service proxysql proxysql 3.0.11',result.stdout,result.stderr)

    def test_unsupported_dsa_does_not_hide_supported_key_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            (root/'etc/ssh').mkdir(parents=True)
            (root/'etc/ssh/ssh_host_dsa_key.pub').write_text('ssh-dss AAAA PRIVATE_COMMENT\n')
            (root/'etc/ssh/ssh_host_ed25519_key.pub').write_text('ssh-ed25519 AAAA PRIVATE_COMMENT\n')
            result=run(['manifest_ssh_host_keys'],f'''
manifest_root={directory!r}
manifest_emit() {{ printf '%s\\n' "$*"; }}
ssh-keygen() {{ return 1; }}
manifest_ssh_host_keys
''')
        self.assertIn('status unsupported_legacy_algorithm',result.stdout,result.stderr)
        self.assertIn('SHA256 fingerprinting failed',result.stdout)
        self.assertNotIn('PRIVATE_COMMENT',result.stdout)

    def test_tomcat_live_jdk_custom_appbase_and_library_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            process=root/'proc/501'; process.mkdir(parents=True)
            (process/'status').write_text('Name:\tjava\nPid:\t501\n')
            (process/'stat').write_text('501 (java worker) S '+'0 '*18+'123456\n')
            (process/'exe').symlink_to('/opt/jdk27/bin/java')
            (process/'cmdline').write_bytes(b'java\0-Dcatalina.base=/srv/tomcat\0-Dcatalina.home=/opt/tomcat\0-Dpassword=SECRET\0')
            (process/'maps').write_text('a-b r-xp 0 08:01 123 /usr/lib/libssl.so.3 (deleted)\na-b r-xp 0 08:01 124 /private/SECRET.so\n')
            (root/'opt/jdk27').mkdir(parents=True)
            (root/'opt/jdk27/release').write_text('JAVA_VERSION="27.0.1"\nTOKEN="SECRET"\n')
            props=root/'opt/tomcat/lib/org/apache/catalina/util'; props.mkdir(parents=True)
            (props/'ServerInfo.properties').write_text('server.info=Apache Tomcat/9.0.114\n')
            (root/'srv/tomcat/conf').mkdir(parents=True)
            (root/'srv/tomcat/conf/server.xml').write_text('<Server><Host name="example.invalid" appBase="apps"><Resource password="SECRET"/></Host></Server>')
            result=run(['manifest_tomcat','manifest_output_proc_starttime','manifest_read_metadata'],f'''
manifest_root={directory!r}
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_tomcat
''')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('runtime kind Java version 27.0.1 executable /opt/jdk27/bin/java',result.stdout)
        self.assertIn('application application Tomcat version 9.0.114',result.stdout)
        self.assertIn('app_base /srv/tomcat/apps',result.stdout)
        self.assertIn('library /usr/lib/libssl.so.3 device 08:01 inode 123 replaced yes',result.stdout)
        self.assertNotIn('SECRET',result.stdout)


    def test_tomcat_disappeared_or_reused_pid_discards_buffered_facts(self):
        for final in ('999999', ''):
            with self.subTest(final=final), tempfile.TemporaryDirectory() as directory:
                root=pathlib.Path(directory)
                process=root/'proc/501'; process.mkdir(parents=True)
                (process/'status').write_text('Name:\tjava\nPid:\t501\n')
                (process/'exe').symlink_to('/opt/jdk/bin/java')
                (process/'cmdline').write_bytes(b'java\0-Dcatalina.base=/srv/tomcat\0')
                (process/'maps').write_text('')
                counter=root/'counter'
                result=run(['manifest_tomcat','manifest_read_metadata'],f"""
manifest_root={directory!r}
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_output_proc_starttime() {{
  if [ ! -e {str(counter)!r} ]; then : > {str(counter)!r}; printf '123456\\n';
  else printf '%s\\n' {final!r}; [ -n {final!r} ]; fi
}}
manifest_tomcat
""")
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn('reason java_process_disappeared_or_reused',result.stdout)
                self.assertNotIn('application application Tomcat',result.stdout)
                self.assertNotIn('runtime kind Java',result.stdout)


if __name__=='__main__': unittest.main()
