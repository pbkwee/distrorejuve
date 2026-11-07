#!/usr/bin/env python3
"""PowerDNS boundary checks and migrations on isolated package/config fixtures."""
import os
import hashlib
import pathlib
import runpy
import shlex
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
declaration = runpy.run_path(str(ROOT / 'tests/test-upgrade-review.py'))['declaration']
NAMES = ('upgrade_pdns_output_installed_version', 'upgrade_pdns_version_is_at_least', 'upgrade_pdns_output_review_target',
         'upgrade_pdns_is_safe_file', 'upgrade_pdns_check_running_binary', 'upgrade_pdns_check_config_selection',
         'upgrade_pdns_output_config_files', 'upgrade_pdns_output_config_findings',
         'upgrade_pdns_output_compatibility_issue', 'upgrade_pdns_rewrite_file',
         'upgrade_pdns_validate_saved_attempt', 'upgrade_pdns_reconcile_attempts',
         'upgrade_pdns_reconcile_history', 'upgrade_pdns_prepare_pending_configuration',
         'upgrade_pdns_restore_migration', 'upgrade_pdns_prepare_plan',
         'manifest_read_metadata', 'manifest_output_proc_starttime')


class PdnsMigration(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.config = self.root / 'etc/powerdns/pdns.conf'
        self.config.parent.mkdir(parents=True)
        self.config.write_text('# retained header\nmaster = yes # writer\nslave=no\ngmysql-password=SECRET_FIXTURE\n')
        self.config.chmod(0o640)
        self.baseline = self.root / 'job/original'
        self.baseline.parent.mkdir(mode=0o700)
        self.plan = self.root / 'selected.plan'
        self.write_plan('4.9.3-1')
        self.events = self.root / 'events'

    def write_plan(self, version, package='pdns-server', action='Inst'):
        self.plan.write_text(f'1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n'
                             f'{action} {package} [4.7.3-2] ({version} Debian:stable [amd64])\n'
                             if action=='Inst' else f'0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nConf {package} ({version} Debian:stable [amd64])\n')

    def run_fixture(self, action=None, extra='', real_permissions=False, functions=NAMES):
        shell = '\n'.join(declaration(name) for name in functions)
        # Fixtures model root ownership while preserving real file modes, hardlink
        # checks and symlink behavior. Production permission rejection is tested too.
        permissions = '' if real_permissions else '''
upgrade_pdns_is_safe_file() {
  [ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] || return 1
  [ "$(command stat -c %h -- "$1")" = 1 ] || return 1
  mode=$(command stat -c %a -- "$1") || return 1
  (( (8#$mode & 022) == 0 ))
}
stat() {
  if [ "$1:$2" = '-c:%u:%a' ]; then shift 2; command stat -c '0:%a' "$@"
  else command stat "$@"; fi
}
'''
        setup = f'''
fixture_root={shlex.quote(str(self.root))}
fixture_plan={shlex.quote(str(self.plan))}
fixture_baseline={shlex.quote(str(self.baseline))}
fixture_status='install ok installed'; fixture_installed=4.7.3-2; fixture_candidate=4.9.3-1
fixture_sources=bookworm
DR_MIGRATE_PDNS_ROLE_SETTINGS=true
timeout() {{ shift; shift; "$@"; }}
pgrep() {{ return 1; }}
usrmerge_output_executable_origin() {{ printf 'packaged\\tpdns-server\\n'; }}
dpkg-query() {{
  case "$*" in *pdns-server) printf '%s\\t%s\\n' "$fixture_status" "$fixture_installed";; *) return 99;; esac
}}
apt-cache() {{ [ "$*" = 'policy pdns-server' ] || return 99; printf '  Candidate: %s\\n' "$fixture_candidate"; }}
apt_sources_list() {{ printf '/fixture.list\\t1\\tdebian\\tdeb\\thttps://deb.debian.org/debian\\t%s\\tmain\\t*\\n' "$fixture_sources"; }}
record_config_state() {{ printf 'baseline\\n' >> "$fixture_root/events"; [ -f "$fixture_baseline" ] || printf original > "$fixture_baseline"; }}
config_state_output_baseline() {{ printf '%s\\n' "$fixture_baseline"; }}
apt-get() {{ echo unexpected-apt >> "$fixture_root/events"; return 99; }}
systemctl() {{ echo unexpected-systemctl >> "$fixture_root/events"; return 99; }}
pdns_control() {{ echo unexpected-pdns-control >> "$fixture_root/events"; return 99; }}
'''
        action = action or 'upgrade_pdns_prepare_plan "$fixture_plan" "$fixture_root"'
        return subprocess.run(['bash'], input=shell+'\n'+permissions+setup+'\n'+extra+'\n'+action+'\n',
                              capture_output=True, text=True)

    def attempts(self):
        return sorted(self.baseline.parent.glob('original.pdns-role-migration/attempt.*'))

    def test_earlier_target_and_unrelated_plan_do_not_read_or_rewrite_configuration(self):
        original = self.config.read_bytes()
        for version, package in [('4.7.3-2', 'pdns-server'), ('4.8.3-1', 'pdns-server'), ('9.0', 'other-package')]:
            with self.subTest(version=version, package=package):
                self.write_plan(version, package)
                result = self.run_fixture(extra='upgrade_pdns_output_config_files() { echo unexpected-config-read >&2; return 99; }')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.config.read_bytes(), original)
                self.assertFalse(self.events.exists())
                self.assertNotIn('unexpected', result.stderr)

    def test_false_flag_warns_and_stops_before_backup_or_change(self):
        original = self.config.read_bytes()
        result = self.run_fixture(extra='DR_MIGRATE_PDNS_ROLE_SETTINGS=false')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('DR_MIGRATE_PDNS_ROLE_SETTINGS=true', result.stderr)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertFalse(self.events.exists())

    def test_migration_preserves_values_comments_secrets_modes_and_original_backup(self):
        original = self.config.read_bytes()
        result = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.config.read_bytes(), original.replace(b'master =', b'primary =').replace(b'slave=', b'secondary='))
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o640)
        attempt = self.attempts()[0]
        self.assertEqual((attempt/'original.0').read_bytes(), original)
        self.assertTrue((attempt/'completed.tsv').exists())
        self.assertFalse((attempt/'incomplete').exists())
        self.assertNotIn('SECRET_FIXTURE', result.stdout+result.stderr)
        self.assertEqual(self.events.read_text().splitlines(), ['baseline'])

    def test_retry_with_canonical_keys_is_idempotent(self):
        self.assertEqual(self.run_fixture().returncode, 0)
        first = self.config.read_bytes()
        result = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.config.read_bytes(), first)
        self.assertEqual(len(self.attempts()), 1)

    def test_no_final_newline_is_preserved(self):
        self.config.write_bytes(b'master=yes\nslave=no')
        result = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.config.read_bytes(), b'primary=yes\nsecondary=no')

    def test_active_conf_includes_are_migrated_and_inactive_backups_are_untouched(self):
        include = self.config.parent/'pdns.d'; include.mkdir()
        self.config.write_text('include-dir=/etc/powerdns/pdns.d\n# main\n')
        active = include/'roles.conf';active.write_text('master=yes\nslave=no\n');active.chmod(0o640)
        inactive=include/'roles.conf.old';inactive.write_text('master=no\n')
        result=self.run_fixture()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(active.read_text(),'primary=yes\nsecondary=no\n')
        self.assertEqual(inactive.read_text(),'master=no\n')
        self.assertEqual(self.config.read_text(),'include-dir=/etc/powerdns/pdns.d\n# main\n')
        self.assertEqual((self.attempts()[0]/'original.1').read_text(),'master=yes\nslave=no\n')

    def test_conflicting_or_duplicate_roles_are_manual_and_never_rewritten(self):
        for text in ['master=yes\nprimary=no\n', 'master=yes\nmaster=yes\n', 'master=maybe\nslave=no\n']:
            self.config.write_text(text)
            result=self.run_fixture()
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.config.read_text(),text)
            self.assertFalse(self.events.exists())

    def test_duplicate_roles_across_includes_fail(self):
        include=self.config.parent/'pdns.d';include.mkdir()
        self.config.write_text('include-dir=/etc/powerdns/pdns.d\nmaster=yes\n')
        (include/'roles.conf').write_text('primary=yes\n');(include/'roles.conf').chmod(0o640)
        result=self.run_fixture()
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.events.exists())

    def test_other_legacy_settings_and_queries_are_reported_for_manual_migration(self):
        for setting in ['superslave=yes', 'slave-renotify=no', 'gmysql-supermaster-query=SELECT SECRET_QUERY']:
            self.config.write_text('master=yes\nslave=no\n'+setting+'\n')
            result=self.run_fixture()
            self.assertNotEqual(result.returncode,0)
            self.assertIn('manual migration',result.stderr)
            self.assertNotIn('SECRET_QUERY',result.stdout+result.stderr)
            self.assertFalse(self.events.exists())

    def test_symlinks_custom_includes_and_service_overrides_fail_closed(self):
        original=self.config.read_bytes()
        self.config.rename(self.config.with_suffix('.original'))
        self.config.symlink_to(self.config.with_suffix('.original'))
        self.assertNotEqual(self.run_fixture().returncode,0)
        self.config.unlink();self.config.write_bytes(original)
        self.config.write_text('include-dir=/other\nmaster=yes\n')
        self.assertNotEqual(self.run_fixture().returncode,0)
        self.config.write_bytes(original)
        unit=self.root/'etc/systemd/system/pdns.service.d/custom.conf';unit.parent.mkdir(parents=True)
        unit.write_text('[Service]\n')
        self.assertNotEqual(self.run_fixture().returncode,0)
        self.assertFalse(self.events.exists())

    def test_source_before_45_is_not_rewritten_for_direct_49_transition(self):
        original=self.config.read_bytes()
        result=self.run_fixture(extra='fixture_installed=4.4.3-1')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('older than 4.5',result.stderr)
        self.assertEqual(self.config.read_bytes(),original)
        self.assertFalse(self.events.exists())

    def test_debian_epochs_do_not_enable_earlier_binary_capabilities(self):
        original=self.config.read_bytes()
        self.write_plan('1:4.8.3-1')
        result=self.run_fixture(extra='fixture_installed=1:4.4.3-1')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.config.read_bytes(),original)
        self.assertFalse(self.events.exists())
        self.write_plan('1:4.9.3-1')
        result=self.run_fixture(extra='fixture_installed=1:4.4.3-1')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.config.read_bytes(),original)
        result=self.run_fixture(extra='fixture_installed=1:4.7.3-2')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.attempts()[0]/'completed.tsv').read_text().startswith('1:4.7.3-2\t1:4.9.3-1\t'))

    def test_bare_boolean_roles_require_manual_review_without_rewriting(self):
        text='master # implicit yes\nslave\n'
        self.config.write_text(text)
        result=self.run_fixture()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.config.read_text(),text)
        self.assertFalse(self.events.exists())
        result=self.run_fixture(action='upgrade_pdns_output_compatibility_issue debian bookworm trixie "$fixture_root"')
        self.assertTrue(result.stdout.startswith('manual\tpdns-49'))

    def test_unknown_selected_and_installed_upstream_versions_fail_closed(self):
        original=self.config.read_bytes()
        self.write_plan('2026-custom')
        result=self.run_fixture()
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Cannot establish the selected PowerDNS upstream version',result.stderr)
        self.assertEqual(self.config.read_bytes(),original)
        self.assertFalse(self.events.exists())
        self.write_plan('4.9.3-1')
        result=self.run_fixture(extra='fixture_installed=2026-custom')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Cannot prove',result.stderr)
        self.assertNotIn('older than 4.5',result.stderr)
        self.assertEqual(self.config.read_bytes(),original)
        self.assertFalse(self.events.exists())

    def test_multihop_waits_until_installed_binary_and_selected_target_are_compatible(self):
        original=self.config.read_bytes()
        self.write_plan('4.7.3-2')
        result=self.run_fixture(extra='fixture_installed=4.4.3-1')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.config.read_bytes(),original)
        self.write_plan('4.9.3-1')
        result=self.run_fixture(extra='fixture_installed=4.7.3-2')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b'primary',self.config.read_bytes())

    def test_configuration_only_retry_uses_selected_modern_version(self):
        self.write_plan('4.9.3-1',action='Conf')
        result=self.run_fixture(extra="fixture_installed=4.9.3-1; fixture_status='install ok unpacked'")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.attempts()[0]/'completed.tsv').exists())

    def test_read_only_preflight_warns_without_mutation_for_both_flag_values(self):
        original=self.config.read_bytes()
        for flag,action in [('false','manual'),('true','warn')]:
            result=self.run_fixture(action='upgrade_pdns_output_compatibility_issue debian bookworm trixie "$fixture_root"',
                                    extra='DR_MIGRATE_PDNS_ROLE_SETTINGS='+flag)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue(result.stdout.startswith(action+'\tpdns-49\t4.9\t'))
            self.assertEqual(self.config.read_bytes(),original)
            self.assertFalse(self.events.exists())

    def test_known_release_boundary_is_used_only_when_existing_candidate_is_not_target_evidence(self):
        result=self.run_fixture(action='upgrade_pdns_output_compatibility_issue debian bookworm trixie "$fixture_root"',
                                extra='fixture_candidate=4.7.3-2; fixture_sources=bookworm')
        self.assertIn('pdns-49',result.stdout)
        result=self.run_fixture(action='upgrade_pdns_output_compatibility_issue debian bookworm trixie "$fixture_root"',
                                extra='fixture_candidate=4.8.3-1; fixture_sources=trixie')
        self.assertEqual(result.stdout,'')
        result=self.run_fixture(action='upgrade_pdns_output_compatibility_issue ubuntu noble resolute "$fixture_root"',
                                extra='fixture_candidate=4.8.3-1; fixture_sources=noble')
        self.assertIn('pdns-49',result.stdout)

    def test_write_validation_failure_restores_original_and_retry_succeeds(self):
        original=self.config.read_bytes()
        result=self.run_fixture(extra='''
mv() {
  case "$*" in *'/new.0 '*) command mv "$@" || return; printf corrupt > "${!#}";; *) command mv "$@";; esac
}
''')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.config.read_bytes(),original)
        self.assertTrue((self.attempts()[0]/'rolled-back').exists())
        self.assertEqual(self.config.stat().st_mode & 0o777,0o640)
        result=self.run_fixture()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b'primary',self.config.read_bytes())
        self.assertEqual(len(self.attempts()),2)
        third=self.run_fixture()
        self.assertEqual(third.returncode,0,third.stderr)
        self.assertEqual(len(self.attempts()),2)
        self.assertTrue(any((attempt/'reconciled-rollback.tsv').exists() for attempt in self.attempts()))

    def test_second_file_write_failure_rolls_back_every_owned_replacement(self):
        include=self.config.parent/'pdns.d';include.mkdir()
        self.config.write_text('include-dir=/etc/powerdns/pdns.d\nmaster=yes\n')
        child=include/'roles.conf';child.write_text('slave=no\n');child.chmod(0o640)
        original=self.config.read_bytes();child_original=child.read_bytes()
        result=self.run_fixture(extra="""
mv() { case "$*" in *'/new.1 '*) return 29;; *) command mv "$@";; esac; }
""")
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.config.read_bytes(),original)
        self.assertEqual(child.read_bytes(),child_original)
        self.assertTrue((self.attempts()[0]/'rolled-back').exists())

    def test_unresolved_failed_rollback_blocks_mixed_and_canonical_retries(self):
        include=self.config.parent/'pdns.d';include.mkdir()
        self.config.write_text('include-dir=/etc/powerdns/pdns.d\nmaster=yes\n')
        child=include/'roles.conf';child.write_text('slave=no\n');child.chmod(0o640)
        result=self.run_fixture(extra="""
mv() { case "$*" in *'/new.1 '*|*distrorejuve-restore*) return 29;; *) command mv "$@";; esac; }
""")
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'primary=yes',self.config.read_bytes())
        self.assertEqual(child.read_text(),'slave=no\n')
        attempt=self.attempts()[0]
        self.assertTrue((attempt/'incomplete').exists())
        self.assertFalse((attempt/'rolled-back').exists())
        for make_canonical in (False,True):
            if make_canonical: child.write_text('secondary=no\n')
            before=(self.config.read_bytes(),child.read_bytes())
            result=self.run_fixture()
            self.assertNotEqual(result.returncode,0)
            self.assertIn('rollback is unresolved',result.stderr)
            self.assertEqual((self.config.read_bytes(),child.read_bytes()),before)
            self.assertEqual(len(self.attempts()),1)

    def test_forged_rollback_marker_or_changed_original_digest_blocks_retry(self):
        for tamper in ('original','current'):
            with self.subTest(tamper=tamper):
                # Each subcase has its own failed transaction and protected evidence.
                if self.attempts():
                    for attempt in self.attempts():
                        import shutil
                        shutil.rmtree(attempt)
                self.config.write_text('master=yes\nslave=no\n')
                result=self.run_fixture(extra="""
mv() { case "$*" in *'/new.0 '*) command mv "$@" || return; printf corrupt > "${!#}";; *) command mv "$@";; esac; }
""")
                self.assertNotEqual(result.returncode,0)
                attempt=self.attempts()[0]
                self.assertTrue((attempt/'rolled-back').exists())
                if tamper=='original': (attempt/'original.0').write_text('tampered-backup\n')
                else: self.config.write_text('master=no\nslave=no\n')
                before=self.config.read_bytes()
                result=self.run_fixture()
                self.assertNotEqual(result.returncode,0)
                self.assertIn('digests do not agree',result.stderr)
                self.assertEqual(self.config.read_bytes(),before)
                self.assertEqual(len(self.attempts()),1)

    def test_pending_configuration_uses_exact_unpacked_version_before_postinst(self):
        result=self.run_fixture(action='upgrade_pdns_prepare_pending_configuration "$fixture_root"',
                                extra="fixture_installed=4.9.3-1; fixture_candidate=5.2.0-1; fixture_status='install ok unpacked'")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b'primary',self.config.read_bytes())
        attempt=self.attempts()[0]
        receipt=(attempt/'completed.tsv').read_text().split('\t')
        self.assertEqual(receipt[1],'4.9.3-1')
        self.assertEqual(receipt[3].strip(),'pending-dpkg')
        self.assertIn('4.9.3-1 installed-pending',(attempt/'selection.txt').read_text())
        self.assertNotIn('5.2.0-1',(attempt/'selection.txt').read_text())

    def test_pending_earlier_or_fully_configured_packages_are_not_rewritten(self):
        original=self.config.read_bytes()
        for status,version in [('install ok unpacked','4.7.3-1'),('install ok installed','4.9.3-1')]:
            result=self.run_fixture(action='upgrade_pdns_prepare_pending_configuration "$fixture_root"',
                                    extra=f"fixture_installed={version}; fixture_status='{status}'")
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(self.config.read_bytes(),original)
            self.assertFalse(self.events.exists())

    def test_both_raw_configure_passes_migrate_first_or_stop_before_postinst(self):
        for command in ('apt_get_upgrade','apt_get_dist_upgrade'):
            for flag in ('true','false'):
                with self.subTest(command=command,flag=flag):
                    if self.attempts():
                        for attempt in self.attempts():
                            import shutil
                            shutil.rmtree(attempt)
                    self.events.unlink(missing_ok=True)
                    self.config.write_text('master=yes\nslave=no\n')
                    pending=declaration('upgrade_pdns_prepare_pending_configuration').replace(
                        'function upgrade_pdns_prepare_pending_configuration()', 'function fixture_prepare_pending()')
                    mocks=pending+"""
fixture_installed=4.9.3-1; fixture_status='install ok unpacked'
function [() {
  case "$*" in '! -f /etc/debian_version'|'-e /etc/redhat-release'|'-e /var/log/syslog'|'-e /etc/my/my.cnf') return 1;; esac
  builtin [ "$@"
}
upgrade_pdns_prepare_pending_configuration() { fixture_prepare_pending "$fixture_root"; }
pause_check() { :; }
upgrade_precondition_checks() { :; }
apt_sources_archive() { :; }
apt_get_update() { :; }
upgrade_php_runtime_prepare() { :; }
upgrade_php_runtime_verify() { :; }
upgrade_prepare_debian_locales() { :; }
apt_get_autoremove() { :; }
apt_get_f_install() { :; }
apt_get_install() { :; }
apt_state_output_signature() { return 1; }
apt_state_repositories_are_current() { return 1; }
apt-get() { :; }
apt_get_apply() { echo package-apply >> "$fixture_root/events"; }
apt_get_upgrade() { :; }
tweak_broken_configs() { :; }
print_distro_info() { echo fixture; }
dpkg() {
  case "$1" in
    --compare-versions) command dpkg "$@";;
    --configure)
      if ! grep -q '^primary=yes' "$fixture_root/etc/powerdns/pdns.conf"; then echo BAD-postinst >> "$fixture_root/events"; return 91; fi
      echo postinst-after-migration >> "$fixture_root/events";;
    *) return 99;;
  esac
}
"""
                    # Restore the actual selected top-level function after defaults.
                    mocks+='\n'+declaration(command)+'\nDR_MIGRATE_PDNS_ROLE_SETTINGS='+flag
                    result=self.run_fixture(action=command,extra=mocks)
                    events=self.events.read_text() if self.events.exists() else ''
                    self.assertNotIn('BAD-postinst',events)
                    self.assertEqual(result.returncode==0,flag=='true',result.stderr)
                    if flag=='true': self.assertIn('postinst-after-migration',events)
                    else: self.assertNotIn('postinst-after-migration',events)

    def test_stage_failure_does_not_change_source(self):
        original=self.config.read_bytes()
        result=self.run_fixture(extra='upgrade_pdns_rewrite_file() { return 29; }')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.config.read_bytes(),original)
        self.assertEqual((self.attempts()[0]/'activated.tsv').read_bytes(),b'')

    def test_custom_running_config_selector_is_rejected_without_argument_disclosure(self):
        proc=self.root/'proc/42';proc.mkdir(parents=True)
        proc.joinpath('stat').write_text('42 (pdns_server) S '+' '.join(['0']*18+['12345'])+'\n')
        binary=self.root/'usr/sbin/pdns_server';binary.parent.mkdir(parents=True);binary.write_bytes(b'fixture');binary.chmod(0o755)
        proc.joinpath('exe').symlink_to(binary)
        proc.joinpath('cmdline').write_bytes(b'/usr/sbin/pdns_server\0--config-dir=/other\0--api-key=SECRET_ARGS\0')
        result=self.run_fixture(extra='pgrep() { echo 42; }')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('SECRET_ARGS',result.stdout+result.stderr)
        self.assertFalse(self.events.exists())

    def test_running_default_config_is_recognized_but_command_line_roles_are_manual(self):
        proc=self.root/'proc/42';proc.mkdir(parents=True)
        proc.joinpath('stat').write_text('42 (pdns_server) S '+' '.join(['0']*18+['12345'])+'\n')
        binary=self.root/'usr/sbin/pdns_server';binary.parent.mkdir(parents=True);binary.write_bytes(b'fixture');binary.chmod(0o755)
        proc.joinpath('exe').symlink_to(binary)
        for argument,allowed in [(b'--config-dir=/etc/powerdns',True),(b'--master=yes',False),
                                 (b'--slave',False),(b'--config-name=other',False)]:
            with self.subTest(argument=argument):
                proc.joinpath('cmdline').write_bytes(b'/usr/sbin/pdns_server\0'+argument+b'\0')
                result=self.run_fixture(action='upgrade_pdns_check_config_selection "$fixture_root"',extra='pgrep() { echo 42; }')
                self.assertEqual(result.returncode==0,allowed,result.stderr)
                self.assertEqual(result.stdout,'')

    def test_stale_or_modified_running_binary_requires_manual_review(self):
        proc=self.root/'proc/42';proc.mkdir(parents=True)
        proc.joinpath('stat').write_text('42 (pdns_server) S '+' '.join(['0']*18+['12345'])+'\n')
        proc.joinpath('cmdline').write_bytes(b'/usr/sbin/pdns_server\0')
        binary=self.root/'usr/sbin/pdns_server';binary.parent.mkdir(parents=True);binary.write_bytes(b'fixture');binary.chmod(0o755)
        proc.joinpath('exe').symlink_to(binary)
        result=self.run_fixture(
                                extra="pgrep() { echo 42; }; usrmerge_output_executable_origin() { printf 'modified_package\\tpdns-server\\n'; }")
        self.assertNotEqual(result.returncode,0)
        proc.joinpath('exe').unlink();proc.joinpath('exe').symlink_to(str(binary)+' (deleted)')
        self.assertNotEqual(self.run_fixture(extra='pgrep() { echo 42; }').returncode,0)

    def test_canonical_noop_does_not_require_alias_migration_binary_proof(self):
        self.config.write_text('primary=yes\nsecondary=no\n')
        proc=self.root/'proc/42';proc.mkdir(parents=True)
        proc.joinpath('stat').write_text('42 (pdns_server) S '+' '.join(['0']*18+['12345'])+'\n')
        proc.joinpath('cmdline').write_bytes(b'/usr/sbin/pdns_server\0')
        result=self.run_fixture(extra='pgrep() { echo 42; }; upgrade_pdns_check_running_binary() { echo unexpected-binary-proof >&2; return 99; }')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('unexpected-binary-proof',result.stderr)
        self.assertFalse(self.events.exists())

    def test_running_binary_origin_uses_explicit_large_executable_bound(self):
        proc=self.root/'proc/42';proc.mkdir(parents=True)
        binary=self.root/'usr/sbin/pdns_server';binary.parent.mkdir(parents=True)
        content=b'fixture executable\n'*100000
        binary.write_bytes(content);binary.chmod(0o755)
        proc.joinpath('exe').symlink_to(binary)
        info=self.root/'var/lib/dpkg/info';info.mkdir(parents=True)
        (info/'pdns-server.md5sums').write_text(hashlib.md5(content).hexdigest()+'  usr/sbin/pdns_server\n')
        origin=declaration('packages_output_file_origin').replace('function packages_output_file_origin()', 'function fixture_file_origin()')
        extra=origin+'\n'+declaration('usrmerge_output_executable_origin')+"""
packages_output_file_origin() { fixture_file_origin "$1" "$2" "$fixture_root" "${4:-1048576}"; }
packages_output_file_owner() { echo pdns-server; }
dpkg-query() { :; }
"""
        result=self.run_fixture(action='upgrade_pdns_check_running_binary "$fixture_root/proc/42" "$fixture_root"',extra=extra)
        self.assertEqual(result.returncode,0,result.stderr)
        binary.write_bytes(content+b'changed')
        result=self.run_fixture(action='upgrade_pdns_check_running_binary "$fixture_root/proc/42" "$fixture_root"',extra=extra)
        self.assertNotEqual(result.returncode,0)

    def test_real_permission_check_refuses_unowned_or_writable_input(self):
        result=self.run_fixture(action='upgrade_pdns_is_safe_file "$fixture_root/etc/powerdns/pdns.conf"',real_permissions=True)
        if os.geteuid()!=0:
            self.assertNotEqual(result.returncode,0)
        self.config.chmod(0o666)
        result=self.run_fixture(action='upgrade_pdns_is_safe_file "$fixture_root/etc/powerdns/pdns.conf"',real_permissions=True)
        self.assertNotEqual(result.returncode,0)

    def test_normal_apt_flow_gates_selected_pdns_before_any_package_execution(self):
        functions=NAMES+('apt_get_apply',)
        helper=declaration('upgrade_pdns_prepare_plan').replace('function upgrade_pdns_prepare_plan()', 'function fixture_prepare_pdns()')
        extra=helper+'''
upgrade_pdns_prepare_plan() { fixture_prepare_pdns "$1" "$fixture_root"; }
apt_package_lock_warn() { :; }
upgrade_php_runtime_prepare() { :; }
apt_print_t64_replacements() { :; }
apt_space_check_plan() { :; }
upgrade_php_output_new_apache_packages() { :; }
dpkg-query() {
  case "$*" in *pdns-server) printf '%s\\t%s\\n' "$fixture_status" "$fixture_installed";; *) printf 'install ok installed\\tpdns-server\\n';; esac
}
apt-get() {
  case "$*" in *--simulate*) cat "$fixture_plan";; *) echo apt-applied >> "$fixture_root/events"; grep -q '^primary' "$fixture_root/etc/powerdns/pdns.conf";; esac
}
'''
        result=self.run_fixture(action='apt_get_apply -y dist-upgrade',extra=extra,functions=functions)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.events.read_text().splitlines(),['baseline','apt-applied'])


if __name__=='__main__':
    unittest.main()
