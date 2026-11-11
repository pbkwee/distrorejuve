#!/usr/bin/env python3
"""Offline first-pass metadata fixtures; no script entrypoint or live collection."""
import pathlib
import re
import subprocess
import tempfile
import unittest

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh').read_text()


def run(names, body):
    declarations = []
    for name in names:
        # Script declarations begin `function NAME() {`; their closing brace is column one.
        match = re.search(r'^function ' + re.escape(name) + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
        assert match, name
        declarations.append(match.group())
    return subprocess.run(['bash'], input='\n'.join(declarations) + '\n' + body,
                          text=True, capture_output=True)


class Firstpass(unittest.TestCase):
    def test_capacity_numeric_fields_and_command_failure(self):
        result = run(['manifest_capacity'], r'''
manifest_root=
manifest_emit() { printf '%s\n' "$*"; }
manifest_run_bounded() { [ "${@: -1}" = / ] || return 98; printf '%s\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on' '/secret/device 100000 40000 60000 40% /secret/mount'; }
manifest_read_metadata() { printf '%s\n' 'MemTotal: 2048000 kB' 'MemAvailable: 512000 kB' 'Password: SECRET' 'SwapTotal: 0 kB'; }
manifest_capacity
manifest_run_bounded() { return 124; }
manifest_read_metadata() { return 1; }
manifest_capacity
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('total_kib 100000 used_kib 40000 available_kib 60000 used_percent 40', result.stdout)
        self.assertIn('metric available value_kib 512000', result.stdout)
        self.assertIn('kind filesystem_root_inodes total 100000 used 40000 available 60000', result.stdout)
        self.assertIn('reason df_failed metric filesystem_root command_status 124', result.stdout)
        self.assertIn('reason meminfo_unavailable', result.stdout)
        self.assertNotIn('secret', result.stdout)
        self.assertNotIn('SECRET', result.stdout)

    def test_cron_literal_consumers_no_commands_or_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'etc/cron.d').mkdir(parents=True)
            (root / 'var/spool/cron/crontabs').mkdir(parents=True)
            (root / 'etc/crontab').write_text('TOKEN=SECRET\n0 * * * * root /usr/bin/python2.7 /srv/PRIVATE.py --token SECRET\n@daily root /usr/bin/php /srv/PRIVATE.php\n')
            (root / 'var/spool/cron/crontabs/demo').write_text('@hourly /usr/bin/ruby /srv/PRIVATE.rb SECRET\n0 * * * * env SECRET=x python3 /srv/PRIVATE.py\n')
            result = run(['manifest_language_consumers', 'manifest_read_metadata'], f'''
manifest_root={directory!r}
manifest_processes_available=true
manifest_processes=$'python2.7\\npython3\\nworker.py\\nnode\\nphp-fpm8.1'
manifest_unprivileged=false
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_language_consumers
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('language Python process_count 2', result.stdout)
        self.assertIn('source_file /etc/crontab source_line 2 language Python interpreter python2.7', result.stdout)
        self.assertIn('source_line 3 language PHP interpreter php', result.stdout)
        self.assertIn('source_file /var/spool/cron/crontabs/demo source_line 1 language Ruby', result.stdout)
        self.assertNotIn('SECRET', result.stdout)
        self.assertNotIn('PRIVATE', result.stdout)
        self.assertNotIn('worker.py', result.stdout)
        self.assertNotIn('language PHP process_count', result.stdout)

    def test_reduced_mode_and_missing_snapshot(self):
        result = run(['manifest_language_consumers'], r'''
manifest_root=/fixture
manifest_processes_available=false
manifest_unprivileged=true
manifest_emit() { printf '%s\n' "$*"; }
manifest_read_metadata() { printf SECRET; return 99; }
manifest_language_consumers
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('reason process_snapshot_unavailable', result.stdout)
        self.assertIn('cron skipped_unprivileged', result.stdout)
        self.assertNotIn('SECRET', result.stdout)

    def test_tcp_and_udp_listeners_preserve_transport_and_ownership(self):
        result = run(['manifest_listeners', 'manifest_listener_rows'], r'''
manifest_emit() { printf '%s\n' "$*"; }
manifest_run_bounded() {
  case "$2:$3" in
    ss:-lntp) printf '%s\n' 'LISTEN 0 128 127.0.0.1:25 *:* users:(("master",pid=12,fd=3))';;
    ss:-lnup) printf '%s\n' 'UNCONN 0 0 [::]:9987 [::]:* users:(("ts3server",pid=42,fd=3))' 'UNCONN 0 0 0.0.0.0:443 0.0.0.0:*' 'UNCONN 0 0 missing-port *:*' 'ESTAB 0 0 127.0.0.1:53 192.0.2.10:123';;
    ss:-lnt) printf '%s\n' 'Recv-Q Send-Q Local Address:Port Peer Address:Port' '0 128 *:10011 *:*';;
    ss:-lnu) return 1;;
    netstat:-lnu) printf '%s\n' 'udp6 0 0 :::9987 :::*' 'udp 0 0 127.0.0.1:53 0.0.0.0:*';;
    *) return 1;;
  esac
}
manifest_listeners
manifest_unprivileged=true
manifest_listeners
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('service smtp transport tcp address 127.0.0.1 port 25 program master', result.stdout)
        self.assertIn('service udp transport udp address [::] port 9987 program ts3server', result.stdout)
        self.assertIn('service udp transport udp address 0.0.0.0 port 443 program unknown', result.stdout)
        self.assertIn('service tcp transport tcp address * port 10011 program unknown', result.stdout)
        self.assertIn('service udp transport udp address :: port 9987 program unknown', result.stdout)
        self.assertIn('service udp transport udp address 127.0.0.1 port 53 program unknown', result.stdout)
        self.assertEqual(result.stdout.count('reachability unknown'), 6)

    def test_mariadb_tls_manifest_finding_is_advisory(self):
        result = run(['manifest_service'], r'''
manifest_emit() { printf '%s\n' "$*"; }
manifest_root=/nonexistent-fixture
manifest_unprivileged=true
manifest_processes=mariadbd
manifest_service mariadb mariadb-server 10.11
manifest_service mysql mysql-server 8.0
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('warning area mariadb_client_tls'), 1)
        self.assertIn('verify application and replication clients', result.stdout)

    def test_service_state_failures_preserve_partial_rows_and_fail_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / 'run/systemd/system').mkdir(parents=True)
            result = run(['manifest_service_states', 'manifest_probe'], f'''
manifest_root={directory!r}
manifest_unprivileged=false
manifest_processes_available=true
manifest_processes=mysqld
manifest_warning_count=0
manifest_collection_failed=false
manifest_emit() {{
  [ "$1" != warning ] || manifest_warning_count=$((manifest_warning_count+1))
  printf '%s\\n' "$*"
}}
readlink() {{ printf '/usr/lib/systemd/systemd\\n'; }}
systemctl() {{ :; }}
manifest_run_bounded() {{
  case "${{@: -1}}" in
    mysql.service) printf '%s\\n' LoadState=loaded ActiveState=active SubState=running; return 124;;
    mariadb.service) printf '%s\\n' LoadState=loaded ActiveState=SECRET_INVALID;;
    postgresql.service) printf '%s\\n' LoadState=not-found ActiveState=inactive SubState=dead; return 1;;
    dovecot.service) printf '%s\\n' LoadState=loaded ActiveState=inactive SubState=dead;;
  esac
}}
manifest_probe service_states manifest_service_states
status=$?
printf 'collector_failed=%s probe_exit=%s warnings=%s\\n' "$manifest_collection_failed" "$status" "$manifest_warning_count"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('name mysql load_state loaded active_state active sub_state running', result.stdout)
        self.assertIn('name mariadb load_state loaded active_state unknown sub_state unknown', result.stdout)
        self.assertIn('probe service_states result unknown command_status 1', result.stdout)
        self.assertIn('collector_failed=true probe_exit=1 warnings=2', result.stdout)
        self.assertNotIn('SECRET', result.stdout)

    def test_missing_optional_units_are_successful_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / 'run/systemd/system').mkdir(parents=True)
            result = run(['manifest_service_states', 'manifest_probe'], f'''
manifest_root={directory!r}
manifest_unprivileged=false
manifest_processes_available=false
manifest_warning_count=0
manifest_emit() {{ printf '%s\\n' "$*"; }}
readlink() {{ printf '/usr/lib/systemd/systemd\\n'; }}
systemctl() {{ :; }}
manifest_run_bounded() {{ printf '%s\\n' LoadState=not-found ActiveState=inactive SubState=dead; return 1; }}
manifest_probe service_states manifest_service_states
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('load_state not-found'), 4)
        self.assertIn('probe service_states result observed command_status 0', result.stdout)
        self.assertNotIn('warning ', result.stdout)


if __name__ == '__main__':
    unittest.main()
