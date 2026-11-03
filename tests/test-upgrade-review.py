#!/usr/bin/env python3
"""Offline regressions: extract function declarations; never run script entrypoint."""
import json
import pathlib
import hashlib
import re
import shlex
import subprocess
import tempfile
import unittest

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'distrorejuve.sh').read_text()


def declaration(name):
    # Producer is the script's top-level `function NAME() {` ... column-one `}`.
    # `function logging_run() (` ... column-one `)` is a subshell declaration.
    # Nested delimiters are indented; do not source initialization or dispatch code.
    match = re.search(r'^function ' + re.escape(name) + r'\(\) (\{\n.*?^\}|\(\n.*?^\))', SOURCE, re.M | re.S)
    assert match, name
    return match.group()


def run(names, body):
    script = '\n'.join(declaration(name) for name in names) + '\n' + body
    return subprocess.run(['bash'], input=script, text=True, capture_output=True)


def crossgrade_fixture(current='trusty', native='i386', bits=32, kernel='x86_64',
                      selected=True, ubuntu_enabled=True, conversion='success'):
    # Script assignment LTS_UBUNTU="trusty xenial bionic" supplies that literal
    # declaration; use the real release order without sourcing initialization.
    releases = '\n'.join(re.search(r'^' + name + r'="[^"]*"$', SOURCE, re.M).group()
                         for name in ('ALL_DEBIAN', 'ALL_UBUNTU', 'LTS_UBUNTU'))
    settings = f'''
fixture_release={current!r}
fixture_native={native!r}
fixture_bits={bits}
fixture_kernel={kernel!r}
fixture_conversion={conversion!r}
UPGRADE_CROSSGRADE={'true' if selected else 'false'}
DR_ENABLE_UBUNTU_CROSSGRADE={'true' if ubuntu_enabled else 'false'}
upgrade_retry_command=()
'''
    mocks = r'''
# Fix the distro marker for the simulated source; other tests use Bash's test.
function [() {
  if builtin [ "$#" = 3 ] && builtin [ "$1" = -f ]; then
    case "$2" in /etc/debian_version) return 0;; /etc/redhat-release) return 1;; esac
  fi
  # The caller already supplies the closing ] as the final argument.
  builtin [ "$@"
}
distro_output_codename() { printf '%s\n' "$fixture_release"; }
dpkg() { builtin [ "$*" = --print-architecture ] || return 99; printf '%s\n' "$fixture_native"; }
getconf() { builtin [ "$*" = LONG_BIT ] || return 99; printf '%s\n' "$fixture_bits"; }
uname() { builtin [ "$*" = -m ] || return 99; printf '%s\n' "$fixture_kernel"; }
crossgrade_output_core_package_issues() { :; }
crossgrade_output_foreign_packages() {
  if builtin [ "$fixture_native" = i386 ]; then printf 'bash:i386\n'; fi
}
crossgrade_bookworm_output_pending_directory() { return 1; }
crossgrade_check_apt_architecture_config() { :; }
crossgrade_check_source_architectures() { :; }
upgrade_panel_refuse_generic() { :; }
usrmerge_check_upgrade_path() { :; }
usrmerge_recover_pending() { :; }
upgrade_check_crossgrade_package_blockers() { :; }
upgrade_output_crossgrade_obsolete_packages() { :; }
upgrade_output_compatibility_issues() { :; }
upgrade_check_incompatible_packages() { :; }
apt_sources_check_releases_and_vendors() { :; }
apt_package_lock_warn() { :; }
pause_check() { :; }
check_disk_space() { :; }
upgrade_check_crossgrade_checkpoint() {
  builtin [ "$fixture_release" = "$2" ] || return 98
  printf 'event:checkpoint:%s:%s:%s\n' "$2" "$fixture_native" "$fixture_bits"
}
crossgrade_debian() {
  printf 'event:crossgrade:%s\n' "$fixture_release"
  case "$fixture_conversion" in
    fail) return 7;;
    unchanged) return 0;;
    native_only) fixture_native=amd64;;
    success) fixture_native=amd64; fixture_bits=64;;
    *) return 99;;
  esac
}
upgrade_prepare_nss_lookup() { :; }
upgrade_precondition_checks() { :; }
apt_sources_prepare() { :; }
check_usrmerge() { :; }
upgrade_prepare_php_source_retry() { :; }
apt_get_upgrade() { printf 'event:package-update:%s\n' "$fixture_release"; }
retain_etc_networking_naming_re_enX0() { :; }
upgrade_record_package_origins() { :; }
apt_sources_upgrade() {
  printf 'event:sources:%s:%s:%s:%s\n' "$2" "$3" "$fixture_native" "$fixture_bits"
  fixture_next=$3
}
apt_get_update() { :; }
apt_get_install() { :; }
upgrade_migrate_php_packages() { :; }
apt_get_dist_upgrade() { fixture_release=$fixture_next; }
upgrade_remove_retired_packages() { :; }
upgrade_autoremove_packages() { :; }
upgrade_outcome_record() { :; }
upgrade_php_runtime_verify() { :; }
'''
    return releases + '\n' + settings + mocks


class CrossgradeUpgrade(unittest.TestCase):
    planning_functions = ['is_distro_name_older', 'is_distro_name_newer',
                          'upgrade_output_crossgrade_release']
    upgrade_functions = planning_functions + [
        'ubuntu_output_next_release', 'ubuntu_output_latest_lts',
        'upgrade_check_path', 'upgrade_preflight_action',
        'upgrade_crossgrade_before_release', 'dist_upgrade_ubuntu_to_latest']

    def test_i386_release_boundaries_and_crossgrade_permission(self):
        cases = [
            # Native upgrades remain possible up to the last i386 LTS.
            ('ubuntu', 'trusty', 'bionic', False, False, 'i686', 0, ''),
            ('ubuntu', 'trusty', 'bionic', True, False, 'i686', 0, ''),
            ('ubuntu', 'trusty', 'resolute', False, True, 'x86_64', 1, '--crossgrade'),
            ('ubuntu', 'bionic', 'focal', True, False, 'x86_64', 1, 'DR_ENABLE_UBUNTU_CROSSGRADE'),
            ('ubuntu', 'trusty', 'resolute', True, True, 'i686', 1, 'running x86_64 kernel'),
            ('ubuntu', 'trusty', 'resolute', True, True, 'x86_64', 0, 'bionic'),
            ('ubuntu', 'bionic', 'focal', True, True, 'x86_64', 0, 'bionic'),
            ('ubuntu', 'bionic', 'eoan', False, True, 'x86_64', 1, '--crossgrade'),
            ('ubuntu', 'cosmic', 'focal', True, True, 'x86_64', 1, 'before later release sources'),
            ('debian', 'bullseye', 'bookworm', False, False, 'i686', 0, ''),
            ('debian', 'bullseye', 'trixie', False, False, 'x86_64', 1, '--crossgrade'),
            ('debian', 'bullseye', 'trixie', True, False, 'x86_64', 0, 'bookworm'),
        ]
        for family, current, target, selected, enabled, kernel, status, message in cases:
            with self.subTest(family=family, current=current, target=target,
                              selected=selected, enabled=enabled, kernel=kernel):
                result = run(self.planning_functions,
                             crossgrade_fixture(current=current, selected=selected,
                                                ubuntu_enabled=enabled, kernel=kernel)
                             + f'\nupgrade_output_crossgrade_release {family} {current} {target}\n')
                self.assertEqual(result.returncode, status, result.stderr)
                if status == 0:
                    self.assertEqual(result.stdout.strip(), message)
                else:
                    self.assertIn(message, result.stderr)

    def test_native_amd64_needs_no_crossgrade(self):
        result = run(self.upgrade_functions,
                     crossgrade_fixture(native='amd64', bits=64, selected=False,
                                        ubuntu_enabled=False)
                     + '\ndist_upgrade_ubuntu_to_latest\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('event:crossgrade:', result.stdout)
        self.assertIn('event:sources:bionic:focal:amd64:64', result.stdout)

    def test_supported_i386_step_needs_no_64bit_kernel_or_opt_in(self):
        for selected in (False, True):
            with self.subTest(selected=selected):
                result = run(self.upgrade_functions,
                             crossgrade_fixture(current='xenial', kernel='i686',
                                                selected=selected, ubuntu_enabled=False)
                             + '\ndist_upgrade_ubuntu_to_latest 1\n')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('event:crossgrade:', result.stdout)
                self.assertIn('event:sources:xenial:bionic:i386:32', result.stdout)

    def test_ubuntu_crossgrades_on_bionic_before_focal_sources(self):
        result = run(self.upgrade_functions,
                     crossgrade_fixture() + '\ndist_upgrade_ubuntu_to_latest\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        events = [line for line in result.stdout.splitlines() if line.startswith('event:')]
        switches = [line for line in events if line.startswith('event:sources:')]
        self.assertEqual(switches, [
            'event:sources:trusty:xenial:i386:32',
            'event:sources:xenial:bionic:i386:32',
            'event:sources:bionic:focal:amd64:64',
            'event:sources:focal:jammy:amd64:64',
            'event:sources:jammy:noble:amd64:64',
            'event:sources:noble:resolute:amd64:64'])
        self.assertEqual(events.count('event:crossgrade:bionic'), 1)
        conversion = events.index('event:crossgrade:bionic')
        self.assertEqual(events[conversion - 1], 'event:checkpoint:bionic:i386:32')
        self.assertEqual(events[conversion + 1], 'event:checkpoint:bionic:amd64:64')
        self.assertLess(conversion, events.index('event:sources:bionic:focal:amd64:64'))

    def test_blocked_full_path_does_not_start_package_or_source_changes(self):
        for settings in ({'selected': False}, {'ubuntu_enabled': False}, {'kernel': 'i686'}):
            with self.subTest(settings=settings):
                result = run(self.upgrade_functions,
                             crossgrade_fixture(**settings)
                             + '\nupgrade_preflight_action --to-latest\n')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('blocked before changes', result.stderr)
                self.assertNotIn('event:', result.stdout)

    def test_failed_or_incomplete_conversion_stops_before_source_changes(self):
        for conversion, status in [('fail', 7), ('unchanged', 1), ('native_only', 1)]:
            with self.subTest(conversion=conversion):
                result = run(self.upgrade_functions,
                             crossgrade_fixture(current='bionic', conversion=conversion)
                             + '\ndist_upgrade_ubuntu_to_latest\n')
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertIn('event:crossgrade:bionic', result.stdout)
                self.assertNotIn('event:sources:', result.stdout)
                self.assertNotIn('event:package-update:', result.stdout)


class UpgradeReview(unittest.TestCase):
    def test_current_label_retry_checks_init_before_package_mutation(self):
        function = declaration('packages_upgrade').replace('if [ -f /etc/debian_version ]; then', 'if true; then')
        noops = ['crossgrade_bookworm_recover_bootstrap', 'usrmerge_recover_pending',
                 'upgrade_prepare_nss_lookup', 'upgrade_precondition_checks', 'apt_sources_prepare',
                 'fix_missing_lsb_release', 'add_missing_debian_keys', 'apt_get_update', 'record_config_state']
        body = '\n'.join(name + '() { :; }' for name in noops) + '''
ALL_DEBIAN=
ALL_UBUNTU='resolute'
packages_output_backend() { printf 'dpkg\\n'; }
distro_output_codename() { printf 'resolute\\n'; }
is_distro_name_older() { return 1; }
upgrade_check_target_init_plan() { printf 'guard:%s\\n' "$1"; return 1; }
apt_get_install() { printf 'mutation attempted\\n'; }
upgrade_migrate_php_packages() { printf 'mutation attempted\\n'; }
apt_get_upgrade() { printf 'mutation attempted\\n'; }
packages_upgrade
'''
        result = subprocess.run(['bash'], input=function + '\n' + body, text=True, capture_output=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('guard:resolute', result.stdout)
        self.assertNotIn('mutation attempted', result.stdout)

    def test_target_init_guard_stops_kept_back_provider_without_mutation(self):
        modes = [('already', 0), ('planned', 0), ('kept', 1), ('held', 1),
                 ('metadata_failure', 1), ('policy_failure', 1), ('no_candidate', 1),
                 ('archive_failure', 1), ('wrong_archive', 1), ('wrong_arch', 1),
                 ('fullplan_failure', 1), ('prerequisite_failure', 1), ('mismatch', 1),
                 ('sysv', 0), ('planned_wrong_version', 1), ('planned_wrong_arch', 1)]
        for mode, expected in modes:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                result = run(['upgrade_check_target_init_plan'], rf'''
mode={mode}
APT_GET_INSTALL_OPTIONS='-y -o APT::Get::AllowUnauthenticated=false'
check_systemd_install_matches_init() {{ [ "$mode" != mismatch ]; }}
readlink() {{ if [ "$mode" = sysv ]; then printf '/sbin/init\n'; else printf '/usr/lib/systemd/systemd\n'; fi; }}
dpkg-query() {{
  [ "$mode" != metadata_failure ] || return 1
  printf 'install ok installed\t255.4\tamd64\n'
}}
apt-cache() {{
  case "$1" in
    policy)
      [ "$mode" != policy_failure ] || return 1
      case "$mode" in already) printf '  Candidate: 255.4\n';; no_candidate) printf '  Candidate: (none)\n';; *) printf '  Candidate: 259.1\n';; esac;;
    madison)
      [ "$mode" != archive_failure ] || return 1
      case "$mode" in
        wrong_archive) printf 'systemd | 259.1 | https://archive.example.invalid noble/main amd64 Packages\n';;
        wrong_arch) printf 'systemd | 259.1 | https://archive.example.invalid resolute/main arm64 Packages\n';;
        *) printf 'systemd | 259.1 | https://archive.example.invalid resolute/main amd64 Packages\n';;
      esac;;
    *) return 90;;
  esac
}}
dpkg() {{
  if [ "$1" = --get-selections ]; then
    if [ "$mode" = held ]; then printf 'systemd\thold\n'; else printf 'systemd\tinstall\n'; fi
  elif [ "$1" = --compare-versions ]; then command dpkg "$@"
  else printf 'mutation attempted\n' >&2; return 90; fi
}}
config_state_output_baseline() {{ printf '%s/baseline\n' {directory!r}; }}
upgrade_php_prepare_normal_upgrade_plan() {{
  printf fullplan > {directory!r}/fullplan.called
  [ "$mode" != fullplan_failure ] || return 100
  case "$mode" in
    planned) printf 'Inst systemd [255.4] (259.1 Ubuntu:26.04/resolute [amd64])\n';;
    planned_wrong_version) printf 'Inst systemd [255.4] (258.1 Ubuntu:26.04/resolute [amd64])\n';;
    planned_wrong_arch) printf 'Inst systemd [255.4] (259.1 Ubuntu:26.04/resolute [arm64])\n';;
    *) printf '0 upgraded, 0 newly installed, 0 to remove\n';;
  esac > "$1/normal-dist-upgrade.plan"
}}
apt-get() {{
  case " $* " in *' --simulate install systemd:amd64=259.1 '*) :;; *) printf 'mutation attempted\n' >&2; return 90;; esac
  printf prerequisite > {directory!r}/prerequisite.called
  printf 'Inst systemd [255.4] (259.1 Ubuntu:26.04/resolute [amd64])\n'
  [ "$mode" != prerequisite_failure ] || return 100
}}
upgrade_check_target_init_plan resolute
''')
                self.assertEqual(result.returncode, expected, result.stderr)
                root = pathlib.Path(directory)
                self.assertNotIn('mutation attempted', result.stderr)
                if mode in ('already', 'held', 'metadata_failure', 'policy_failure', 'no_candidate',
                            'archive_failure', 'wrong_archive', 'wrong_arch', 'mismatch', 'sysv'):
                    self.assertFalse((root / 'fullplan.called').exists())
                if mode in ('kept', 'prerequisite_failure', 'planned_wrong_version', 'planned_wrong_arch'):
                    plan = next(root.glob('baseline.init-resolute.*/systemd-prerequisite.plan'))
                    self.assertIn('Inst systemd', plan.read_text())
                    status = plan.with_name('systemd-prerequisite.status').read_text().strip()
                    self.assertEqual(status, '100' if mode == 'prerequisite_failure' else '0')
                    self.assertIn('Target package changes stopped', result.stderr)
                if mode == 'planned': self.assertFalse((root / 'prerequisite.called').exists())


    def test_native_planner_exact_selection_and_fail_closed_guards(self):
        import json
        import os
        helper = SOURCE.split("<<'PY_NATIVE_PLAN'\n", 1)[1].split('\nPY_NATIVE_PLAN', 1)[0]
        transcript = ('Inst fixture-provider (1.0 Ubuntu:26.04/resolute [all])\n'
                      'Conf fixture-provider:amd64 broken\n Breaks:fixture-tools:amd64\n'
                      'Inst fixture-tools [1.0] (2.0 Ubuntu:26.04/resolute [all])\n'
                      'Conf fixture-tools (2.0 Ubuntu:26.04/resolute [all])\n'
                      'E: Conf Broken fixture-provider:amd64\n')
        # The fake binding supplies only read-only Cache methods. Any commit/fetch
        # call, disk-backed cache, or unsupported native API access fails the test.
        binding = r'''
import os,sys,types,pathlib,runpy,re
mode=sys.argv[1]; directory=pathlib.Path(sys.argv[2]); helper=sys.argv[3]
class Config:
    def __init__(self): self.values={}
    def exists(self,k): return mode=='binary_config' and k=='Binary::apt-get'
    def set(self,k,v): self.values[k]=v
    def find(self,k,d=''): return self.values.get(k,d)
    def find_b(self,k,d=False): return self.values.get(k,str(d)).lower() in ('true','1','yes')
    def find_file(self,k): return str(directory/'status')
    def find_dir(self,k): return str(directory/'lists')
    def dump(self): return repr(sorted(self.values.items()))
config=Config()
def compare(a,b): return (a>b)-(a<b)
def parse_depends(text):
    if not text:return []
    name,op,version=re.fullmatch(r'(\S+) \((\S+) (\S+)\)',text).groups()
    return [[(name,version,op)]]
apt_pkg=types.ModuleType('apt_pkg')
apt_pkg.VERSION='3.0.3';apt_pkg.init_config=lambda:None;apt_pkg.init_system=lambda:None
apt_pkg.config=config;apt_pkg.version_compare=compare;apt_pkg.parse_depends=parse_depends
apt_pkg.check_dep=lambda a,op,b: compare(a,b)<0 if op=='<<' else False
sys.modules['apt_pkg']=apt_pkg
class Version:
    def __init__(self,version,breaks=''):
        self.version=version;self.architecture='all';self.record={'Breaks':breaks}
        self.downloadable=mode!='undownloadable'
        self.origins=[types.SimpleNamespace(trusted=mode!='untrusted')]
class Package:
    def __init__(self,name,old,new,breaks=''):
        self.fullname=name+':amd64';self.installed=Version(old) if old else None
        self.candidate=Version(new,breaks);self.marked_delete=False
        self.marked_install=False;self.marked_upgrade=False
        self.versions=[self.candidate]
        self.marked_downgrade=mode=='downgrade';self.marked_reinstall=mode=='reinstall'
        self.essential=False
    def mark_install(self,auto_fix=True,auto_inst=True,from_user=True):
        assert (auto_fix,auto_inst,from_user)==(False,False,False),'automatic resolution forbidden'
        self.marked_install=self.installed is None;self.marked_upgrade=self.installed is not None
    def mark_delete(self,auto_fix=True,purge=True):
        assert (auto_fix,purge)==(False,False),'automatic repair/purge forbidden'
        self.marked_delete=True
class Cache:
    def __init__(self,memonly=False):
        assert memonly,'persistent cache forbidden'
        (directory/'cache.opened').write_text('opened')
        self.provider=Package('fixture-provider',None,'1.0','fixture-tools (<< 2.0)')
        self.tools=Package('fixture-tools','1.0','2.0')
        if mode=='version_mismatch': self.tools.candidate.version='3.0'
        if mode=='candidate_override':
            self.tools.versions=[self.tools.candidate,Version('3.0')]
            self.tools.candidate=self.tools.versions[1]
        if mode=='old_mismatch': self.tools.installed.version='0.9'
        if mode=='arch_mismatch': self.provider.candidate.architecture='arm64'
        if mode=='missing_relationship':self.provider.candidate.record={}
        if mode=='unresolved_relationship':self.provider.candidate.record={'Breaks':'fixture-tools (<< 3.0)'}
        if mode in ('essential_remove','protected_remove'):
            self.tools.essential=mode=='essential_remove'
            if mode=='protected_remove':self.tools.installed.record['Protected']='yes'
        self.packages={'fixture-provider':self.provider,'fixture-tools':self.tools}
        self.packages.update({p.fullname:p for p in list(self.packages.values())})
        self.changes=[self.provider,self.tools]
        if mode in ('valid_remove','native_drift'):
            obsolete=Package('fixture-obsolete','1.0','1.0')
            if mode=='native_drift':obsolete.marked_delete=True
            self.packages['fixture-obsolete']=obsolete;self.packages[obsolete.fullname]=obsolete
            self.changes.append(obsolete)
        self.broken_count=1 if mode=='broken' else 0
    def upgrade(self,*a,**k):raise AssertionError('second resolver forbidden')
    def actiongroup(self):return self
    def __enter__(self):return self
    def __exit__(self,*a):
        if mode=='status_drift':(directory/'status').write_text('changed')
        if mode=='index_drift':(directory/'lists/index').write_text('changed')
    def get_changes(self):return [p for p in self.changes if p.marked_install or p.marked_upgrade or p.marked_delete]
    def __contains__(self,key):return key in self.packages
    def __getitem__(self,key):return self.packages[key]
    def commit(self,*a,**k):raise AssertionError('mutation forbidden')
    def fetch_archives(self,*a,**k):raise AssertionError('fetch forbidden')
apt=types.ModuleType('apt');apt.Cache=Cache;sys.modules['apt']=apt
if mode=='old_python':sys.version_info=(3,6,9)
if mode=='missing_binding':sys.modules['apt']=None
if mode=='missing_cache_api':Cache.actiongroup=None
if mode=='missing_native_api':apt_pkg.check_dep=None
sys.argv=[helper,str(directory)]+(['--unknown'] if mode=='unsupported_option' else [])
runpy.run_path(helper,run_name='__main__')
'''
        modes = ['valid', 'valid_remove', 'candidate_override', 'native_drift', 'version_mismatch', 'old_mismatch', 'arch_mismatch', 'broken',
                 'held', 'untrusted', 'undownloadable', 'downgrade', 'reinstall',
                 'essential_remove', 'protected_remove', 'missing_relationship',
                 'unresolved_relationship', 'status_drift', 'index_drift', 'unsupported_option',
                 'binary_config', 'engine_mismatch', 'unknown_error', 'partial_selection',
                 'duplicate_action', 'malformed_action', 'purge', 'malformed_conf',
                 'old_python', 'missing_binding', 'missing_cache_api', 'missing_native_api']
        for mode in modes:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                directory = pathlib.Path(temporary)
                (directory / 'lists').mkdir()
                (directory / 'lists/index').write_text('initial')
                (directory / 'status').write_text('initial')
                (directory / 'planner.py').write_text(helper)
                (directory / 'binding.py').write_text(binding)
                text = transcript
                if mode == 'valid_remove': text += 'Remv fixture-obsolete [1.0]\n'
                if mode in ('essential_remove','protected_remove'):
                    text = text.replace('Inst fixture-tools [1.0] (2.0 Ubuntu:26.04/resolute [all])', 'Remv fixture-tools [1.0]')
                    text = text.replace('Conf fixture-tools (2.0 Ubuntu:26.04/resolute [all])\n', '')
                if mode == 'unknown_error': text += 'E: Could not open lock file\n'
                if mode == 'partial_selection': text = text.replace('Inst fixture-tools [1.0] (2.0 Ubuntu:26.04/resolute [all])\n', '')
                if mode == 'duplicate_action': text += 'Inst fixture-provider (1.0 Ubuntu:26.04/resolute [all])\n'
                if mode == 'malformed_action': text += 'Inst malformed\n'
                if mode == 'purge': text += 'Purg obsolete [1.0]\n'
                if mode == 'malformed_conf': text = text.replace('Conf fixture-tools (2.0 Ubuntu:26.04/resolute [all])', 'Conf fixture-tools unexpected')
                (directory / 'normal-dist-upgrade.plan.new').write_text(text)
                version = '2.8.3' if mode == 'engine_mismatch' else '3.0.3'
                for command, output in [('apt-get', 'apt '+version+' (amd64)'),
                                        ('dpkg', 'fixture-tools hold' if mode == 'held' else 'fixture-tools install')]:
                    path = directory / command
                    path.write_text('#!/bin/sh\nprintf "%s\\n" "'+output+'"\n')
                    path.chmod(0o700)
                result = subprocess.run(['python3', '-I', str(directory / 'binding.py'), mode,
                                         str(directory), str(directory / 'planner.py')],
                                        env={**os.environ, 'PATH': str(directory)+':'+os.environ['PATH']},
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0 if mode in ('valid', 'valid_remove', 'candidate_override') else 1, result.stderr)
                prerequisite_errors = {'old_python': 'Python 3.7 or newer is required',
                                       'missing_binding': 'matching system python3-apt is required',
                                       'missing_cache_api': 'lacks required native validation APIs',
                                       'missing_native_api': 'lacks required native validation APIs',
                                       'engine_mismatch': 'APT CLI and native library versions differ'}
                if mode in prerequisite_errors:
                    self.assertIn(prerequisite_errors[mode], result.stderr)
                    self.assertFalse((directory / 'cache.opened').exists())
                proof = directory / 'normal-dist-upgrade.native.json.new'
                self.assertEqual(proof.exists(), mode in ('valid', 'valid_remove', 'candidate_override'))
                mismatch = directory / 'normal-dist-upgrade.native-mismatch.json'
                if mode == 'native_drift':
                    self.assertTrue(mismatch.exists(), result.stderr)
                    detail = json.loads(mismatch.read_text())
                    self.assertGreater(detail['mismatch_count'], 0)
                    self.assertLessEqual(len(detail['differences']), 100)
                    self.assertIn('Native selection mismatch:', result.stderr)
                    self.assertEqual(set(detail['differences'][0]), {'name', 'cli', 'native'})
                if mode in ('valid', 'valid_remove', 'candidate_override'):
                    self.assertFalse(mismatch.exists())
                if mode in ('valid', 'valid_remove', 'candidate_override'):
                    record = json.loads(proof.read_text())
                    self.assertEqual(len(record['actions']), 3 if mode == 'valid_remove' else 2)
                    self.assertEqual(record['relationships'][0]['resolved_breaks'][0]['new'], '2.0')
                    self.assertIn('Inst fixture-tools:amd64 [1.0] (2.0 native-planner [all])',
                                  (directory / 'normal-dist-upgrade.native.plan.new').read_text())

    def test_native_planner_missing_commands_stop_before_launch(self):
        for tool in ['python3', 'timeout']:
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as directory:
                result = run(['upgrade_php_native_normal_upgrade_plan'], rf'''
command() {{
  if [ "$1:$2" = '-v:{tool}' ]; then return 1; fi
  builtin command "$@"
}}
timeout() {{ printf invoked > {directory!r}/invoked; return 1; }}
upgrade_php_native_normal_upgrade_plan {directory!r}
''')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('requires ' + tool, result.stderr)
                self.assertFalse((pathlib.Path(directory) / 'invoked').exists())

    def test_normal_plan_invokes_native_only_for_configuration_replay_failure(self):
        import shlex
        transcript = ('Inst fixture-provider (1.0 Ubuntu:26.04/resolute [all])\n'
                      'Conf fixture-provider:amd64 broken\n'
                      'E: Conf Broken fixture-provider:amd64\n')
        cases = [(status, transcript, status == 100) for status in [0, 1, 130, 137, 100]]
        cases += [(100, 'E: Could not open lock file\n', False),
                  (100, transcript + 'E: Failed to fetch archive\n', False),
                  (100, transcript.replace('E: Conf Broken ', 'E: Conf Broken malformed '), False),
                  (100, '\n'.join(transcript.splitlines()[1:]) + '\n', False),
                  (100, transcript.replace('Conf fixture-provider:amd64 broken\n', ''), False),
                  (100, '', False)]
        for status, text, invoked in cases:
            with self.subTest(status=status, text=text), tempfile.TemporaryDirectory() as directory:
                result = run(['upgrade_php_prepare_normal_upgrade_plan'], rf'''
apt-get() {{ printf '%s' {shlex.quote(text)}; return {status}; }}
upgrade_php_native_normal_upgrade_plan() {{ printf invoked > {directory!r}/invoked; return 1; }}
upgrade_php_prepare_normal_upgrade_plan {directory!r}
''')
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual((pathlib.Path(directory) / 'invoked').exists(), invoked)
                self.assertTrue((pathlib.Path(directory) / 'normal-dist-upgrade.plan.new').exists() if status else
                                (pathlib.Path(directory) / 'normal-dist-upgrade.plan').exists())

    def test_normal_plan_promotes_validated_replay_proposal_and_retains_failed_transcript(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run(['upgrade_php_prepare_normal_upgrade_plan'], rf'''
apt-get() {{
  printf '%s\n' 'Inst fixture-provider (1.0 Ubuntu:26.04/resolute [all])' 'Conf fixture-provider:amd64 broken' 'E: Conf Broken fixture-provider:amd64'
  return 100
}}
upgrade_php_native_normal_upgrade_plan() {{
  printf 'validated proposal\n' > "$1/normal-dist-upgrade.native.plan.new"
  printf 'validation proof\n' > "$1/normal-dist-upgrade.native.json.new"
}}
upgrade_php_prepare_normal_upgrade_plan {directory!r}
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            root = pathlib.Path(directory)
            self.assertEqual((root / 'normal-dist-upgrade.plan').read_text(), 'validated proposal\n')
            self.assertEqual((root / 'normal-dist-upgrade.native.json').read_text(), 'validation proof\n')
            self.assertIn('E: Conf Broken', (root / 'normal-dist-upgrade.plan.new').read_text())

    def test_failed_native_revalidation_invalidates_previous_accepted_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory)
            (path / 'normal-dist-upgrade.native.json').write_text('old proof')
            (path / 'normal-dist-upgrade.plan').write_text('old native plan')
            result = run(['upgrade_php_prepare_normal_upgrade_plan'], rf'''
apt-get() {{ return 100; }}
upgrade_php_native_normal_upgrade_plan() {{ return 1; }}
upgrade_php_prepare_normal_upgrade_plan {directory!r}
''')
            self.assertEqual(result.returncode, 100, result.stderr)
            self.assertFalse((path / 'normal-dist-upgrade.native.json').exists())
            self.assertFalse((path / 'normal-dist-upgrade.plan').exists())
            self.assertTrue((path / 'normal-dist-upgrade.plan.new').exists())

    def test_php_failed_full_upgrade_simulation_retains_actionable_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run(['upgrade_php_prepare_normal_upgrade_plan'], rf'''
apt-get() {{
  printf '%s\n' 'Inst coreutils-from-uutils (1.0 Ubuntu:26.04/resolute [all])' 'Conf coreutils-from-uutils:amd64 broken' 'E: Conf Broken coreutils-from-uutils:amd64'
  return 100
}}
upgrade_php_native_normal_upgrade_plan() {{ return 1; }}
upgrade_php_prepare_normal_upgrade_plan {directory!r}
''')
            self.assertEqual(result.returncode, 100, result.stderr)
            self.assertIn('APT status 100', result.stderr)
            self.assertIn('E: Conf Broken coreutils-from-uutils:amd64', result.stderr)
            self.assertIn('Native dependency validation failed', result.stderr)
            self.assertTrue((pathlib.Path(directory) / 'normal-dist-upgrade.plan.new').exists())
            self.assertFalse((pathlib.Path(directory) / 'normal-dist-upgrade.plan').exists())

    def test_apt_update_rejects_exit_zero_failed_indexes_and_allows_clean_retry(self):
        for mode, expected, calls in [('dns_failure', 1, 2), ('clean_retry', 0, 2),
                                      ('benign_warning', 0, 1), ('signature_failure', 1, 2)]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                script = '\n'.join(declaration(name) for name in ['apt_get_update', 'apt_get_update_has_failed_indexes'])
                result = subprocess.run(['bash'], cwd=directory, text=True, capture_output=True,
                                        input=script + rf'''
mode={mode}
APT_GET_INSTALL_OPTIONS=
apt_state_updated=
apt_package_lock_warn() {{ :; }}
pause_check() {{ :; }}
apt_configure_archive_authentication() {{ :; }}
apt_state_output_signature() {{ printf '%s-state\n' "$1"; }}
apt-cache() {{ :; }}
apt-get() {{
  count=0; [ ! -f calls ] || read -r count < calls
  count=$((count+1)); printf '%s\n' "$count" > calls
  if [ "$mode" = benign_warning ]; then printf 'W: legacy keyring warning\n'; return 0; fi
  if [ "$mode" = clean_retry ] && [ "$count" -gt 1 ]; then printf 'Hit:1 http://archive.ubuntu.com/ubuntu resolute InRelease\n'; return 0; fi
  if [ "$mode" = signature_failure ]; then
    printf 'W: An error occurred during the signature verification. The repository is not updated and the previous index files will be used.\n'; return 0
  fi
  printf '%s\n' 'Err:1 http://security.ubuntu.com/ubuntu resolute-security InRelease' \
    "  Temporary failure resolving 'security.ubuntu.com'" \
    "W: Failed to fetch http://archive.ubuntu.com/ubuntu/dists/resolute/InRelease  Temporary failure resolving 'archive.ubuntu.com'" \
    'W: Some index files failed to download. They have been ignored, or old ones used instead.'
  return 0
}}
apt_get_update
status=$?
printf 'cache=%s\n' "$apt_state_updated"
exit "$status"
''')
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(int((pathlib.Path(directory) / 'calls').read_text()), calls)
                if expected:
                    self.assertIn('stale indexes cannot authorize', result.stderr)
                    self.assertIn('cache=\n', result.stdout)
                elif mode == 'clean_retry':
                    self.assertIn('cache=repositories-state', result.stdout)

    def test_default_php_branch_requires_selector_and_runtime_archive_candidates(self):
        for mode, expected in [('valid', 0), ('status_only', 1), ('runtime_status_only', 1),
                               ('metadata_failure', 1)]:
            with self.subTest(mode=mode):
                result = run(['upgrade_php_output_default_branch', 'upgrade_php_has_candidate'], rf'''
mode={mode}
apt-cache() {{
  case "$1" in
    policy)
      [ "$mode" != metadata_failure ] || return 1
      printf ' Candidate: 8.5.0-1\n';;
    madison)
      [ "$mode" != status_only ] || return 0
      if [ "$mode" = runtime_status_only ]; then case "$2" in php8.5-cli|libapache2-mod-php8.5) return 0;; esac; fi
      printf '%s | 8.5.0-1 | https://archive.ubuntu.com/ubuntu resolute/main amd64 Packages\n' "$2";;
    depends)
      case "$2" in php-cli) printf ' Depends: php8.5-cli\n';; *) printf ' Depends: libapache2-mod-php8.5\n';; esac;;
  esac
}}
upgrade_php_output_default_branch
''')
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected == 0: self.assertEqual(result.stdout, '8.5\n')
                else: self.assertEqual(result.stdout, '')

    def test_cleanup_dependency_conflict_diagnostics_are_exact(self):
        resolver = 'E: Error, pkgProblemResolver::Resolve generated breaks, this may be caused by held packages.\n'
        cases = [(resolver, 0), ('E: Unable to correct problems, you have held broken packages.\n', 0),
                 (resolver + 'E: Could not open lock file\n', 1),
                 ('E: Failed to fetch archive\n', 1), ('Unmet dependencies:\n', 1)]
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'plan'
            for text, expected in cases:
                with self.subTest(text=text):
                    path.write_text(text)
                    result = run(['upgrade_cleanup_plan_has_dependency_conflict'],
                                 f'upgrade_cleanup_plan_has_dependency_conflict {str(path)!r}\n')
                    self.assertEqual(result.returncode, expected, result.stderr)

    def test_obsolete_cleanup_solver_failure_uses_protected_subset_or_defers(self):
        for mode, expected in [('subset', 0), ('protected_conflict', 0), ('index_failure', 1)]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                baseline = root / 'baseline'
                transition = root / 'baseline.obsolete-packages/ubuntu-jammy-to-noble'
                transition.mkdir(parents=True)
                (transition / 'prepared').write_text('')
                (transition / 'provenance').write_text('libaio1\tamd64\t1\nlibold1\tamd64\t1\n')
                (transition / 'native').write_text('amd64\n')
                result = run(['upgrade_remove_retired_packages', 'upgrade_cleanup_plan_has_dependency_conflict',
                              'upgrade_cleanup_output_removals'], rf'''
mode={mode}
APT_GET_INSTALL_OPTIONS=
id() {{ printf '0\n'; }}
config_state_output_baseline() {{ printf '%s\n' {str(baseline)!r}; }}
upgrade_cleanup_record() {{ printf 'record:%s\n' "$*"; }}
apt_state_output_signature() {{ printf 'unchanged\n'; }}
apt_sources_list() {{ :; }}
apt_packages_output_inventory() {{ printf '%s\n' $'install ok installed\tlibaio1\tamd64\t1\tno\toptional' $'install ok installed\tlibold1\tamd64\t1\tno\toptional' $'hold ok installed\tmysql-server-core-5.7\tamd64\t5.7\tno\toptional'; }}
apt_packages_output_repository_versions() {{ :; }}
apt_packages_output_official_installed_versions() {{ :; }}
apt_packages_output_classifications() {{ printf '%s\n' $'libaio1\tamd64\t1\tobsolete' $'libold1\tamd64\t1\tobsolete'; }}
upgrade_cleanup_output_safe_package() {{ printf '%s\n' "$1"; }}
upgrade_packages_backup_modified_files() {{ :; }}
pause_check() {{ :; }}
tar() {{ :; }}
apt-config() {{ printf 'Dir::State::extended_states "extended_states";\n'; }}
dpkg() {{ case "$1" in --print-architecture) printf 'amd64\n';; --help) printf -- '--print-foreign-architectures\n';; --audit) :;; esac; }}
dpkg-query() {{ printf '%s\n' $'install ok installed\tlibaio1\tamd64\t1\tno\toptional' $'hold ok installed\tmysql-server-core-5.7\tamd64\t5.7\tno\toptional'; }}
apt-get() {{
  case "$*" in
    *--simulate*)
      case "$*" in
        *extended_states*)
          printf 'protected subset selected\n' >&2
          if [ "$mode" = protected_conflict ]; then printf 'E: Unable to correct problems, you have held broken packages.\n'; return 100; fi
          printf 'Remv libold1 [1]\n';;
        *libaio1:amd64*)
          if [ "$mode" = index_failure ]; then printf 'E: Could not read package indexes\n'; else printf 'E: Error, pkgProblemResolver::Resolve generated breaks, this may be caused by held packages.\n'; fi
          return 100;;
        *) printf 'Remv libold1 [1]\n';;
      esac;;
    *--no-download*) printf 'applied:%s\n' "$*";;
    check) :;;
  esac
}}
upgrade_remove_retired_packages ubuntu jammy noble
''')
                self.assertEqual(result.returncode, expected, result.stderr)
                if mode == 'subset':
                    self.assertIn('applied:', result.stdout)
                    applied = [line for line in result.stdout.splitlines() if line.startswith('applied:')]
                    self.assertTrue(applied)
                    self.assertTrue(all('libaio1' not in line and 'mysql-server-core' not in line for line in applied))
                    self.assertIn('libold1:amd64', result.stdout)
                    self.assertIn('Retaining obsolete packages', result.stderr)
                elif mode == 'protected_conflict':
                    self.assertIn('record:obsolete deferred - protected dependency conflict', result.stdout)
                    self.assertIn('APT status 100', result.stderr)
                    self.assertNotIn('applied:', result.stdout)
                else:
                    self.assertIn('simulation failed (APT status 100)', result.stderr)
                    self.assertNotIn('protected subset selected', result.stderr)
                    self.assertNotIn('applied:', result.stdout)

    def test_combined_php_plan_retains_dependent_applications(self):
        packages = ('install ok installed\tphp8.1-cli\tamd64\t8.1\n'
                    'install ok installed\twordpress\tamd64\t5.8.3\n'
                    'install ok installed\twordpress-l10n\tall\t5.8.3\n'
                    'install ok installed\tphp-pear\tall\t1.10\n')
        removal = 'Remv php8.1-cli [8.1]\nRemv wordpress [5.8.3]\nRemv wordpress-l10n [5.8.3]\nRemv php-pear [1.10]\n'
        combined = 'Remv php8.1-cli [8.1]\nInst php8.3-cli (8.3 noble [amd64])\n'
        scenarios = [('retained', 0), ('combined_app_removal', 1), ('combined_all_app_removal', 1),
                     ('combined_purge', 1), ('separate_install', 1), ('separate_purge', 1),
                     ('unknown_extra', 1), ('target_installs', 0), ('target_only', 0),
                     ('target_version_mismatch', 1), ('target_arch_mismatch', 1),
                     ('old_version_mismatch', 1), ('downgrade', 1), ('duplicate_install', 1),
                     ('malformed_install', 1), ('unmatched_conf', 1), ('duplicate_conf', 1),
                     ('unknown_action', 1), ('arch_collision', 1)]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for mode, expected in scenarios:
                with self.subTest(mode=mode):
                    (root / 'apache.allowed-removals').write_text('php8.1-cli:amd64\n')
                    (root / 'install.allowed-removals').write_text('php8.1-cli:amd64\nwordpress:amd64\nwordpress-l10n:all\n')
                    separate_plan, combined_plan = removal, combined
                    if mode == 'combined_app_removal': combined_plan += 'Remv wordpress [5.8.3]\n'
                    if mode == 'combined_all_app_removal': combined_plan += 'Remv wordpress-l10n:all [5.8.3]\n'
                    if mode == 'combined_purge': combined_plan += 'Purg php8.1-cli [8.1]\n'
                    if mode == 'separate_install': separate_plan += 'Inst libc6 (2.39 noble [amd64])\n'
                    if mode == 'separate_purge': separate_plan += 'Purg php8.1-cli [8.1]\n'
                    if mode == 'unknown_extra': separate_plan += 'Remv unknown-app [1.0]\n'
                    target = ('Inst php8.5-cli (8.5.0 Ubuntu:26.04/resolute [amd64])\n'
                              'Inst libxml2-16 (2.15 Ubuntu:26.04/resolute [amd64])\n'
                              'Inst php-common [2:93] (2:99 Ubuntu:26.04/resolute [all])\n'
                              'Conf php8.5-cli (8.5.0 Ubuntu:26.04/resolute [amd64])\n')
                    target_modes = {'target_installs', 'target_only', 'target_version_mismatch',
                                    'target_arch_mismatch', 'old_version_mismatch', 'downgrade',
                                    'duplicate_install', 'malformed_install', 'unmatched_conf',
                                    'duplicate_conf', 'unknown_action', 'arch_collision'}
                    if mode in target_modes:
                        separate_plan += target
                        combined_plan += target
                    if mode == 'target_only': separate_plan = 'Remv php8.1-cli [8.1]\n' + target
                    if mode == 'target_version_mismatch': separate_plan = separate_plan.replace('(8.5.0 ', '(8.5.1 ')
                    if mode == 'target_arch_mismatch': separate_plan = separate_plan.replace('libxml2-16 (2.15 Ubuntu:26.04/resolute [amd64])', 'libxml2-16 (2.15 Ubuntu:26.04/resolute [arm64])')
                    if mode == 'old_version_mismatch': separate_plan = separate_plan.replace('[2:93]', '[2:92]')
                    if mode == 'downgrade':
                        separate_plan = separate_plan.replace('[2:93] (2:99 ', '[2:99] (2:93 ')
                        combined_plan = combined_plan.replace('[2:93] (2:99 ', '[2:99] (2:93 ')
                    if mode == 'duplicate_install': separate_plan += 'Inst php8.5-cli (8.5.0 Ubuntu:26.04/resolute [amd64])\n'
                    if mode == 'malformed_install': separate_plan += 'Inst invalid\n'
                    if mode == 'unmatched_conf': separate_plan += 'Conf unknown (1.0 Ubuntu:26.04/resolute [amd64])\n'
                    if mode == 'duplicate_conf': separate_plan += 'Conf php8.5-cli (8.5.0 Ubuntu:26.04/resolute [amd64])\n'
                    if mode == 'unknown_action': separate_plan += 'Blah package [1.0]\n'
                    if mode == 'arch_collision': separate_plan = separate_plan.replace('Inst php8.5-cli ', 'Inst php8.5-cli:all ')
                    (root / 'remove.plan').write_text(separate_plan)
                    (root / 'install.plan').write_text(combined_plan)
                    result = run(['upgrade_php_check_plan', 'upgrade_php_output_preserved_packages',
                                  'upgrade_php_apache_combined_plan_is_safe'], f'''
packages={packages!r}
packages=$(printf '%b' "$packages")
upgrade_php_apache_combined_plan_is_safe {directory!r} amd64 "$packages"
''')
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual((root / 'apache.allowed-removals').read_text(), 'php8.1-cli:amd64\n')

    def test_combined_php_requires_persistent_mask_and_inactive_service(self):
        scenarios = [('masked', 'inactive', True, 0), ('masked', 'active', True, 1),
                     ('loaded', 'inactive', True, 1), ('masked', 'inactive', False, 1)]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'apache.state').write_text('ActiveState=active\n')
            persistent = root / 'apache2.service'
            script = declaration('upgrade_php_apache_combined_guard_is_active').replace(
                '/etc/systemd/system/apache2.service', str(persistent))
            for load, active, mask, expected in scenarios:
                with self.subTest(load=load, active=active, mask=mask):
                    if persistent.is_symlink(): persistent.unlink()
                    if mask: persistent.symlink_to('/dev/null')
                    result = subprocess.run(['bash'], input=script + f'''
systemctl() {{ printf '%s\n' LoadState={load} ActiveState={active}; }}
upgrade_php_apache_combined_guard_is_active {directory!r}
''', text=True, capture_output=True)
                    self.assertEqual(result.returncode, expected, result.stderr)

    def test_php_t64_replacement_requires_exact_archive_plan_and_relationships(self):
        base_plan = 'Remv libzip4 [1.7.3-1ubuntu2]\nInst libzip4t64 (1.7.3-1.1ubuntu2 Ubuntu:24.04/noble [amd64])\n'
        scenarios = [('valid', 0), ('show_failure', 2), ('wrong_arch', 1),
                     ('wrong_version', 1), ('wrong_provides', 1), ('no_replaces', 1),
                     ('policy_mismatch', 1), ('status_only', 1), ('plan_wrong_arch', 1),
                     ('plan_unrelated', 1)]
        with tempfile.TemporaryDirectory() as directory:
            plan = pathlib.Path(directory) / 'install.plan'
            for mode, expected in scenarios:
                with self.subTest(mode=mode):
                    text = base_plan
                    if mode == 'plan_wrong_arch':
                        text = text.replace('[amd64]', '[i386]')
                    elif mode == 'plan_unrelated':
                        text = text.replace('libzip4t64', 'libother1')
                    plan.write_text(text)
                    result = run(['upgrade_php_has_candidate', 'upgrade_php_output_t64_replacement'], rf'''
mode={mode}
apt-cache() {{
  case "$1" in
    policy)
      if [ "$mode" = policy_mismatch ]; then printf ' Candidate: 2.0\n'; else printf ' Candidate: 1.7.3-1.1ubuntu2\n'; fi;;
    madison)
      [ "$mode" != status_only ] || return 0
      printf 'libzip4t64 | 1.7.3-1.1ubuntu2 | https://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n';;
    show)
      [ "$mode" != show_failure ] || return 1
      printf 'Package: libzip4t64\n'
      if [ "$mode" = wrong_version ]; then printf 'Version: 2.0\n'; else printf 'Version: 1.7.3-1.1ubuntu2\n'; fi
      if [ "$mode" = wrong_arch ]; then printf 'Architecture: i386\n'; else printf 'Architecture: amd64\n'; fi
      if [ "$mode" = wrong_provides ]; then printf 'Provides: libzip40\n'; else printf 'Provides: libzip4 (= 1.7.3-1.1ubuntu2)\n'; fi
      [ "$mode" = no_replaces ] || printf 'Replaces: libzip4\n'
      printf 'Description: fixture\n';;
  esac
}}
upgrade_php_output_t64_replacement libzip4:amd64 {str(plan)!r} amd64
''')
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if expected == 0:
                        self.assertEqual(result.stdout, 'libzip4t64:amd64=1.7.3-1.1ubuntu2\n')
                    else:
                        self.assertEqual(result.stdout, '')

    def test_t64_allowance_does_not_approve_unrelated_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            allowed = pathlib.Path(directory) / 'allowed'
            plan = pathlib.Path(directory) / 'plan'
            allowed.write_text('libzip4:amd64\n')
            plan.write_text('Remv libzip4 [1.7.3]\nInst libzip4t64 (1.7.3-1 noble [amd64])\nRemv mysql-server-core-5.7 [5.7]\n')
            result = run(['upgrade_php_check_plan'], f'upgrade_php_check_plan {str(allowed)!r} {str(plan)!r} false amd64 fixture\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('mysql-server-core-5.7', result.stderr)

    def test_config_repairs_do_not_reinstall_removed_database_server(self):
        inventories = [
            'rc mysql-server-5.7 5.7.40 amd64\nii mysql-server-core-5.7 5.7.40 amd64\n',
            'ii mysql-client 8.0 amd64\n',
            'ii mysql-server-8.0 8.0 amd64\n',
            'ii mariadb-server 10.11 amd64\n',
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'etc/mysql').mkdir(parents=True)
            script = declaration('tweak_broken_configs')
            # Keep even file-presence checks inside the fixture; no host config/log reads.
            for path in ['/etc/mysql', '/etc/init.d/mysql', '/var/log/daemon.log']:
                script = script.replace(path, str(root) + path)
            for inventory in inventories:
                with self.subTest(inventory=inventory):
                    installed = root / 'installs'
                    installed.write_text('')
                    result = subprocess.run(['bash'], input=script + f'''
dpkg() {{ printf '%b' {inventory!r}; printf 'ii udev-fixture 1 amd64\n'; }}
find() {{ :; }}
apt_get_install() {{ printf '%s\n' "$*" >> {str(installed)!r}; }}
tweak_broken_configs
''', text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(installed.read_text(), '')

    def test_migration_residual_package_config_keeps_strict_runtime_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'etc/init.d/example'
            path.parent.mkdir(parents=True)
            path.write_text('legacy service configuration\n')
            result = run(['packages_output_file_owner', 'packages_output_file_origin',
                          'manifest_migration_file_origin', 'manifest_migration_path'], rf'''
manifest_root={directory!r}
manifest_package_backend=dpkg
manifest_collection_failed=false
manifest_migration_unverified=0
manifest_emit() {{ printf '%s\n' "$*"; }}
dpkg-query() {{
  case "$1" in
    -S) printf 'example: /etc/init.d/example\n';;
    -W) printf 'deinstall ok config-files';;
  esac
}}
manifest_migration_path custom_service "$manifest_root/etc/init.d/example" /etc/init.d
printf 'failed=%s unverified=%s\n' "$manifest_collection_failed" "$manifest_migration_unverified"
packages_output_file_owner /etc/init.d/example dpkg
printf 'runtime_owner_status=%s\n' "$?"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('path /etc/init.d/example', result.stdout)
        self.assertIn('ownership residual_package_config package example', result.stdout)
        self.assertIn('failed=false unverified=0', result.stdout)
        self.assertIn('runtime_owner_status=2', result.stdout)

    def test_migration_origin_query_failure_unowned_and_installed(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'etc/init.d/example'
            path.parent.mkdir(parents=True)
            path.write_text('service configuration\n')
            digest = hashlib.md5(path.read_bytes()).hexdigest()
            for mode in ['query_failure', 'unowned', 'installed']:
                with self.subTest(mode=mode):
                    result = run(['packages_output_file_owner', 'packages_output_file_origin',
                                  'manifest_migration_file_origin', 'manifest_migration_path'], rf'''
manifest_root={directory!r}
manifest_package_backend=dpkg
manifest_collection_failed=false
manifest_migration_unverified=0
mode={mode}
manifest_emit() {{ printf '%s\n' "$*"; }}
dpkg-query() {{
  case "$1:$mode" in
    -S:query_failure) return 2;;
    -S:unowned) return 1;;
    -S:installed) printf 'example: /etc/init.d/example\n';;
    -W:installed)
      case "$2" in *Status*) printf 'install ok installed';; *) printf ' /etc/init.d/example {digest}\n';; esac;;
  esac
}}
manifest_migration_path custom_service "$manifest_root/etc/init.d/example" /etc/init.d
printf 'failed=%s unverified=%s\n' "$manifest_collection_failed" "$manifest_migration_unverified"
''')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    if mode == 'query_failure':
                        self.assertIn('ownership unknown', result.stdout)
                        self.assertIn('failed=true unverified=1', result.stdout)
                    elif mode == 'unowned':
                        self.assertIn('ownership unowned', result.stdout)
                        self.assertIn('failed=false unverified=0', result.stdout)
                    else:
                        self.assertNotIn('migration_path', result.stdout)
                        self.assertIn('failed=false unverified=0', result.stdout)

    def test_compatibility_regex_preserves_literal_brackets_and_dots(self):
        implementations = [pathlib.Path('/usr/bin') / name for name in ('awk', 'gawk', 'mawk')]
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory) / 'pam-example'
            for implementation in implementations:
                if not implementation.is_file():
                    continue
                for text, expected in [
                    ('auth\t[success=ok default=die] pam_lastlog.so\n', 0),
                    ('auth [success=ok default=die] pam_lastlogXso\n', 1),
                    ('# auth [success=ok default=die] pam_lastlog.so\n', 1),
                    ('auth requisite pam_lastlog.so\n', 1),
                ]:
                    with self.subTest(awk=implementation.name, text=text):
                        config.write_text(text)
                        result = run(['upgrade_compatibility_config_matches'], rf'''
awk() {{ command {str(implementation)!r} "$@"; }}
upgrade_compatibility_config_matches '^[[:space:]]*auth[[:space:]]+\[[^]]*default=(die|bad)[^]]*\][[:space:]]+pam_lastlog\.so$' {str(config)!r}
''')
                        self.assertEqual(result.returncode, expected, result.stderr)
                        self.assertEqual(result.stderr, '')

    def test_manifest_preserves_residual_selection_state_without_claiming_a_runtime(self):
        records = ('python\t2.7.12-1~16.04\tinstall ok config-files\ti386\n'
                   'python3\t3.13.5-1\tinstall ok installed\tamd64\n'
                   'example\t1\tpurge ok not-installed\ti386\n')
        result = run(['manifest_packages'], f'''
manifest_package_backend=dpkg
packages_output_inventory() {{ printf '%s' {shlex.quote(records)}; }}
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_service() {{ echo 'unexpected daemon'; }}
manifest_packages
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('package_state name python version 2.7.12-1~16.04 architecture i386 status install ok config-files', result.stdout)
        self.assertNotIn('package name python version', result.stdout)
        self.assertIn('package name python3 version', result.stdout)
        self.assertNotIn('name example', result.stdout)

    def test_manifest_package_review_reports_metadata_without_cleanup_and_preserves_unknowns(self):
        records = ('libold\tamd64\t1.0\tunavailable\torigin unknown\n'
                   'oldmeta\tall\t1\tobsolete\tprevious official release\n'
                   'current\tamd64\t2\tavailable\tbinary exists\n'
                   'python\ti386\t2.7\tresidual-config\tconfiguration only\n')
        for backend, root, query_status in [('dpkg', '', 0), ('dpkg', '', 1),
                                             ('dpkg', '/fixture', 0), ('rpm', '', 0)]:
            with self.subTest(backend=backend, root=root, query_status=query_status):
                result = run(['manifest_package_review'], f'''
manifest_package_backend={backend!r}; manifest_root={root!r}
manifest_emit() {{ printf '%s\\n' "$*"; }}
apt_packages_output_review() {{ printf '%s' {shlex.quote(records)}; return {query_status}; }}
apt_get_update() {{ echo unexpected-update; return 99; }}
apt_get_install() {{ echo unexpected-install; return 99; }}
apt_get_remove() {{ echo unexpected-remove; return 99; }}
manifest_package_review
''')
                expected_unknown = backend == 'dpkg' and (bool(root) or query_status != 0)
                self.assertEqual(result.returncode, int(expected_unknown), result.stderr)
                self.assertNotIn('unexpected-', result.stdout + result.stderr)
                if expected_unknown:
                    self.assertIn('warning area package_review', result.stdout)
                elif backend == 'dpkg':
                    self.assertIn('classification unavailable', result.stdout)
                    self.assertIn('classification obsolete', result.stdout)
                    self.assertIn('freshness unverified removal_safety unverified', result.stdout)
                    self.assertNotIn('name current', result.stdout)
                    self.assertNotIn('name python', result.stdout)

    def test_classifier_treats_install_selected_config_files_as_residual_not_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            inventory = root / 'inventory'
            inventory.write_text('install ok config-files\tpython\ti386\t2.7.12-1~16.04\tno\toptional\told Python\n')
            available = root / 'available'
            available.touch()
            result = run(['apt_packages_output_classifications'],
                         f'apt_packages_output_classifications {str(inventory)!r} amd64 {str(available)!r}\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('\tresidual-config\t', result.stdout)
            self.assertNotIn('\tincomplete\t', result.stdout)

    def test_deprecated_cleanup_reuses_only_current_recorded_transition_and_never_purges(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = pathlib.Path(directory) / 'preupgrade'
            parent = pathlib.Path(str(baseline) + '.obsolete-packages')
            parent.mkdir()
            for transition in ('debian-bookworm-to-trixie', 'debian-bullseye-to-bookworm', 'ubuntu-noble-to-plucky'):
                path = parent / transition
                path.mkdir()
                (path / 'prepared').touch()
            for has_baseline, audit, refresh_status, obsolete_status, source_status in [(True, '', 0, 0, 0), (False, '', 0, 0, 0),
                                                                                       (True, 'pending package', 0, 0, 0),
                                                                                       (True, '', 7, 0, 0), (True, '', 0, 8, 0),
                                                                                       (True, '', 0, 0, 1)]:
                with self.subTest(has_baseline=has_baseline, audit=audit, refresh_status=refresh_status, obsolete_status=obsolete_status, source_status=source_status):
                    result = run(['upgrade_cleanup_deprecated_packages'], f'''
ALL_DEBIAN='bookworm trixie'; ALL_UBUNTU='noble plucky'
distro_output_codename() {{ echo trixie; }}
dpkg() {{ printf '%s' {audit!r}; }}
apt_sources_check_releases_and_vendors() {{ return {source_status}; }}
apt_get_update() {{ echo refresh; return {refresh_status}; }}
config_state_output_baseline() {{ printf '%s' {str(baseline)!r}; return {0 if has_baseline else 1}; }}
upgrade_remove_retired_packages() {{ printf 'obsolete %s\\n' "$*"; return {obsolete_status}; }}
upgrade_autoremove_packages() {{ echo autoremove; }}
apt_packages_print_review() {{ echo availability; }}
apt_get_remove() {{ echo unexpected-legacy-remove; return 99; }}
apt_get_install() {{ echo unexpected-install; return 99; }}
leftover_packages0() {{ echo unexpected-leftover-helper; return 99; }}
upgrade_cleanup_deprecated_packages
''')
                    self.assertEqual(result.returncode, 1 if audit or source_status else refresh_status or obsolete_status, result.stderr)
                    self.assertNotIn('unexpected-', result.stdout + result.stderr)
                    if audit or refresh_status or source_status:
                        self.assertNotIn('autoremove', result.stdout)
                        self.assertNotIn('obsolete ', result.stdout)
                    else:
                        self.assertEqual('obsolete debian bookworm trixie' in result.stdout, has_baseline)
                        self.assertNotIn('obsolete debian bullseye', result.stdout)
                        self.assertEqual('autoremove' in result.stdout, obsolete_status == 0)

    def test_deprecated_cli_dispatch_never_invokes_legacy_selection_or_removal(self):
        result = run(['distrorejuve_main'], '''
unset DR_ACTION
upgrade_panel_handled=false
apt_package_lock_warn() { :; }
upgrade_panel_dispatch() { :; }
upgrade_cleanup_deprecated_packages() { echo guarded-cleanup; return 7; }
has_leftover_packages() { echo unexpected-selection; return 0; }
remove_leftover_packages() { echo unexpected-removal; return 99; }
distrorejuve_main --remove-deprecated-packages
''')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn('guarded-cleanup', result.stdout)
        self.assertNotIn('unexpected-', result.stdout + result.stderr)

    def test_package_review_producer_and_human_report_share_classifications(self):
        inventory = ('install ok installed\tlibold\tamd64\t1\tno\toptional\told library\n'
                     'install ok config-files\tpython\ti386\t2.7\tno\toptional\told Python\n')
        body = f'''
ALL_DEBIAN=trixie; ALL_UBUNTU=''
dpkg() {{ echo amd64; }}
distro_output_codename() {{ echo trixie; }}
apt_packages_output_inventory() {{ printf '%s' {shlex.quote(inventory)}; }}
apt_packages_output_repository_versions() {{ :; }}
apt_packages_output_official_installed_versions() {{ :; }}
apt_sources_list() {{ :; }}
config_state_output_baseline() {{ return 1; }}
apt_get_update() {{ echo unexpected-update; return 99; }}
apt_packages_output_review
apt_packages_print_review
'''
        result = run(['apt_packages_output_classifications', 'apt_packages_output_review', 'apt_packages_print_review'], body)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('libold\tamd64\t1\tunavailable\t', result.stdout)
        self.assertIn('python\ti386\t2.7\tresidual-config\t', result.stdout)
        self.assertIn('Installed package libold:amd64 (1) has no versions', result.stdout)
        self.assertNotIn('Installed package python:', result.stdout)
        self.assertNotIn('unexpected-', result.stdout + result.stderr)

    def test_conffile_reports_ignore_removed_multiarch_digests_and_missing_rc_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            active = root / 'access.conf'
            active.write_text('packaged native configuration\n')
            modified = root / 'custom.conf'
            modified.write_text('retained customization\n')
            (root / 'custom.conf.dpkg-old').write_text('previous customization\n')
            baseline = root / 'baseline'
            baseline.touch()
            digest = hashlib.md5(active.read_bytes()).hexdigest()
            # Literal dpkg-query -W output: removed foreign-arch records can
            # retain the same conffile path with a different packaged digest.
            records = (f'Package: libpam-modules:amd64\tinstall ok installed\n {active} {digest}\n'
                       f'Package: libpam-modules:i386\tdeinstall ok config-files\n {active} {"0" * 32}\n'
                       f' {root / "absent.conf"} {"0" * 32}\n'
                       f'Package: example\thold ok installed\n {modified} {"0" * 32}\n')
            function = declaration('print_pkg_to_modified_diff').replace('/var/lib/ucf/', str(root / 'ucf') + '/')
            for mode in ('', 'summary', 'review'):
                with self.subTest(mode=mode):
                    body = f'''
dpkg-query() {{ printf '%s' {shlex.quote(records)}; }}
print_minimal_config_diff() {{ echo 'fixture difference'; return 1; }}
print_pkg_to_modified_diff {mode!r} {str(baseline)!r}
'''
                    result = subprocess.run(['bash'], input=function + '\n' + body,
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn(str(active), result.stdout + result.stderr)
                    self.assertNotIn('absent.conf', result.stdout + result.stderr)
                    self.assertIn(str(modified), result.stdout)
                    if mode == 'review':
                        self.assertIn('Previous copy:', result.stdout)
                        self.assertNotIn('retained customization', result.stdout)

    def test_completion_reviews_config_replacements_when_application_comparison_is_unavailable(self):
        for comparison in ('disabled', 'missing', 'unchanged', 'changed'):
            with self.subTest(comparison=comparison):
                body = '''
DR_RUN_DIRECTORY=''
config_state_output_baseline() { echo /fixture/preupgrade; }
upgrade_services_check() { return 0; }
upgrade_php_runtime_check() { return 0; }
upgrade_php_runtime_findings_complete() { return 0; }
upgrade_outcome_output_php_removals() { return 0; }
print_pkg_to_modified_diff() { printf 'configuration-review %s %s\\n' "$1" "$2"; }
'''
                if comparison == 'disabled':
                    body += 'DR_UPGRADE_MANIFEST=false\n'
                else:
                    status = {'missing': 2, 'unchanged': 0, 'changed': 1}[comparison]
                    body += f'manifest_compare_baseline() {{ return {status}; }}\n'
                body += 'upgrade_finish_run 0 /fixture/run.log\n'
                result = run(['manifest_compare_baseline', 'upgrade_finish_run'], body)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual('configuration-review review /fixture/preupgrade' in result.stdout,
                                 comparison in ('disabled', 'missing'))

    def test_mysql_server_presence_excludes_rc_clients_and_core_only(self):
        for records, query_status, expected in [
                ('mysql-server-5.0:i386\tdeinstall ok config-files\nlibmariadbclient18\tinstall ok installed', 0, 1),
                ('mariadb-server-core-10.5\tinstall ok installed', 0, 1),
                ('mariadb-server-10.5\tinstall ok half-configured', 0, 0),
                ('mysql-server\thold ok installed', 0, 0), ('', 2, 2)]:
            with self.subTest(records=records, query_status=query_status):
                result = run(['upgrade_database_has_mysql_server'], f'''
dpkg-query() {{ printf '%s\\n' {shlex.quote(records)}; return {query_status}; }}
upgrade_database_has_mysql_server
''')
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_config_repairs_never_revive_removed_database_servers(self):
        for udev_state, query_status, expected_calls, expected_status in [
                ('install ok installed', 0, [], 0), ('hold ok installed', 0, [], 0),
                ('deinstall ok config-files', 0, ['udev'], 0), ('', 2, [], 2)]:
            with self.subTest(udev_state=udev_state, query_status=query_status), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                (root / 'mysql').mkdir()
                (root / 'daemon.log').touch()
                # Isolate this extracted repair function's paths. A regressed
                # RC-based server-install branch must exercise the fixture.
                function = declaration('upgrade_database_has_mysql_server') + '\n' + declaration('tweak_broken_configs')
                function = function.replace('/etc/mysql', str(root / 'mysql'))
                function = function.replace('/var/log/daemon.log', str(root / 'daemon.log'))
                body = f'''
dpkg() {{ printf 'rc  mysql-server-5.0:i386 5.0 i386 old server\\nii  libmariadbclient18:amd64 10.1 amd64 client library\\n'; }}
dpkg-query() {{
  case "$*" in *udev*) printf '%s' {udev_state!r}; return {query_status};; esac
  printf 'mysql-server-5.0:i386\\tdeinstall ok config-files\\nlibmariadbclient18\\tinstall ok installed\\n'
}}
apt_get_install() {{ printf '%s\\n' "$*"; return 0; }}
find() {{ :; }}
grep() {{ return 1; }}
tweak_broken_configs
'''
                result = subprocess.run(['bash'], input=function + '\n' + body, text=True, capture_output=True)
                self.assertEqual(result.returncode, expected_status, result.stderr)
                calls = [line for line in result.stdout.splitlines() if not line.startswith('dss:')]
                self.assertEqual(calls, expected_calls)

    def test_missing_debian_signers_are_pinned_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / 'apt.log'
            log.write_text('NO_PUBKEY 112695A0E562B32A\nNO_PUBKEY 112695A0E562B32A\n'
                           'NO_PUBKEY 648ACFD622F3D138\nNO_PUBKEY 0123456789ABCDEF\n')
            result = run(['apt_repair_debian_signing_keys'], f'''
apt_sources_list() {{ printf '/fixture.list\\t1\\tdebian\\tdeb\\thttps://archive.debian.org/debian\\tstretch\\tmain\\t*\\n'; }}
apt-config() {{ :; }}
apt_config_has_standard_paths() {{ return 0; }}
apt_debian_archive_key_install() {{ printf '%s %s\\n' "$1" "$2"; }}
apt_repair_debian_signing_keys {str(log)!r}
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), [
                'archive-key-10 80D15823B7FD1561F9F7BCDDDC30D7C23CBBABEE',
                'archive-key-10-security 5E61B217265DA9807A23C5FF4DFAB270CAA96DFA'])

    def test_unknown_or_non_debian_signers_do_not_fetch_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / 'apt.log'
            for provider, diagnostic in [('ubuntu', 'NO_PUBKEY 112695A0E562B32A'),
                                         ('debian', 'NO_PUBKEY 0123456789ABCDEF'),
                                         ('debian', 'EXPKEYSIG AA8E81B4331F7F50')]:
                with self.subTest(provider=provider, diagnostic=diagnostic):
                    log.write_text(diagnostic + '\n')
                    result = run(['apt_repair_debian_signing_keys'], f'''
apt_sources_list() {{ printf '/fixture.list\\t1\\t{provider}\\tdeb\\thttps://example.invalid/archive\\told\\tmain\\t*\\n'; }}
apt-config() {{ :; }}
apt_config_has_standard_paths() {{ return 0; }}
apt_debian_archive_key_install() {{ echo unexpected-install; return 99; }}
apt_repair_debian_signing_keys {str(log)!r}
''')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn('unexpected', result.stdout + result.stderr)

    def test_key_repair_refuses_custom_apt_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / 'apt.log'
            log.write_text('NO_PUBKEY 112695A0E562B32A\n')
            result = run(['apt_repair_debian_signing_keys'], f'''
apt_sources_list() {{ printf '/fixture.list\\t1\\tdebian\\tdeb\\thttps://archive.debian.org/debian\\tstretch\\tmain\\t*\\n'; }}
apt-config() {{ :; }}
apt_config_has_standard_paths() {{ return 1; }}
apt_debian_archive_key_install() {{ echo unexpected-install; }}
apt_repair_debian_signing_keys {str(log)!r}
''')
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('unexpected', result.stdout + result.stderr)

    def test_downloaded_key_must_match_pinned_primary_before_activation(self):
        expected = '5E61B217265DA9807A23C5FF4DFAB270CAA96DFA'
        for mode in ['valid', 'wget', 'wrong-primary', 'expired', 'revoked', 'tls-failure']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                target = pathlib.Path(directory) / 'trusted/key.gpg'
                result = run(['apt_debian_archive_key_install'], f'''
curl() {{
  for test_argument in "$@"; do case "$test_argument" in --insecure|-k) echo unexpected-insecure; return 99;; esac; done
  [ {mode!r} != tls-failure ] || return 22
  while [ "$#" -gt 0 ]; do
    if [ "$1" = --output ]; then printf 'fixture-public-key' > "$2"; return 0; fi
    shift
  done
  return 98
}}
command() {{
  if [ {mode!r} = wget ] && [ "$1" = -v ] && [ "$2" = curl ]; then return 1; fi
  builtin command "$@"
}}
wget() {{
  for test_argument in "$@"; do
    case "$test_argument" in
      --no-check-certificate) echo unexpected-insecure; return 99;;
      --output-document=*) printf 'fixture-public-key' > "${{test_argument#--output-document=}}";;
    esac
  done
}}
gpg() {{
  case "$*" in
    *--import*) return 0;;
    *--list-keys*)
      test_validity=-; test_fingerprint={expected}
      [ {mode!r} != wrong-primary ] || test_fingerprint=0000000000000000000000000000000000000000
      [ {mode!r} != expired ] || test_validity=e
      [ {mode!r} != revoked ] || test_validity=r
      printf 'pub:%s:4096:1:4DFAB270CAA96DFA:1:9999999999::::\\nfpr:::::::::%s:\\n' "$test_validity" "$test_fingerprint";;
    *--export*) printf 'verified-public-key-bytes';;
    *) return 97;;
  esac
}}
gpgconf() {{ :; }}
apt_debian_archive_key_install archive-key-10-security {expected} {str(target)!r}
''')
                if mode in ('valid', 'wget'):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(target.read_text(), 'verified-public-key-bytes')
                    self.assertEqual(target.stat().st_mode & 0o777, 0o644)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(target.exists())
                self.assertNotIn('unexpected', result.stdout + result.stderr)

    def test_apt_update_repairs_before_retry_and_stops_if_repair_fails(self):
        for repaired, initial_status, still_bad in [(True, 100, False), (True, 0, False),
                                                   (False, 100, False), (False, 0, False), (True, 0, True)]:
            with self.subTest(repaired=repaired, initial_status=initial_status, still_bad=still_bad), tempfile.TemporaryDirectory() as directory:
                result = run(['apt_get_update'], f'''
cd {directory!r}
apt_package_lock_warn() {{ :; }}
pause_check() {{ :; }}
apt_configure_archive_authentication() {{ :; }}
apt_state_output_signature() {{ printf 'fixture-signature'; }}
apt-get() {{
  printf 'called\\n' >> attempts
  if [ -f repaired ] && [ {str(still_bad).lower()} = false ]; then echo 'Fetched indexes'; return 0; fi
  echo 'NO_PUBKEY 112695A0E562B32A'
  return {initial_status}
}}
apt_repair_debian_signing_keys() {{
  [ {str(repaired).lower()} = true ] || return 1
  touch repaired
}}
apt-cache() {{ return 0; }}
apt_get_update
status=$?
printf 'RESULT=%s ATTEMPTS=%s\\n' "$status" "$(wc -l < attempts)"
exit "$status"
''')
                if repaired and not still_bad:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('RESULT=0 ATTEMPTS=2', result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('ATTEMPTS=' + ('2' if repaired else '1'), result.stdout)

    def test_explicit_validated_archive_exception_keeps_its_existing_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run(['apt_get_update'], f'''
cd {directory!r}
apt_package_lock_warn() {{ :; }}
pause_check() {{ :; }}
apt_configure_archive_authentication() {{ apt_archive_authentication_enabled=true; }}
apt_state_output_signature() {{ printf fixture; }}
apt-get() {{ echo 'NO_PUBKEY 0123456789ABCDEF'; return 0; }}
apt_repair_debian_signing_keys() {{ echo unexpected-retry; return 99; }}
apt-cache() {{ return 0; }}
apt_get_update
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('unexpected', result.stdout + result.stderr)

    def test_explicit_readiness_dispatch_cannot_enter_upgrade_or_inventory(self):
        result = run(['distrorejuve_run', 'distrorejuve_main', 'environment_validate_settings'], '''
DR_ACTION=--to-latest
DR_UPGRADE_MANIFEST=false
upgrade_print_check() { printf 'readiness-only\n'; return 7; }
manifest_output() { echo 'unexpected collector'; return 99; }
manifest_capture() { echo 'unexpected capture'; return 99; }
logging_run() { echo 'unexpected mutation'; return 99; }
distrorejuve_run --check-upgrade
''')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn('readiness-only', result.stdout)
        self.assertNotIn('unexpected', result.stdout + result.stderr)

    def test_disabled_upgrade_inventory_never_collects_or_reads_old_baseline(self):
        for name in ['manifest_capture', 'manifest_compare_baseline']:
            with self.subTest(name=name):
                result = run([name], '''
DR_UPGRADE_MANIFEST=false
manifest_output() { echo 'unexpected collector'; return 99; }
mkdir() { echo 'unexpected directory creation'; return 99; }
head() { echo 'unexpected baseline read'; return 99; }
stat() { echo 'unexpected metadata read'; return 99; }
''' + name + ' /does-not-exist\n')
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn('disabled by DR_UPGRADE_MANIFEST=false', result.stderr)

    def test_upgrade_inventory_default_still_publishes_capture(self):
        for setting in ['', 'true']:
            with self.subTest(setting=setting), tempfile.TemporaryDirectory() as directory:
                target = pathlib.Path(directory) / 'inventory'
                result = run(['manifest_capture'], f'''
DR_UPGRADE_MANIFEST={setting!r}
manifest_output() {{
  printf '%s\\n' '{{"schema_version":1,"records":[]}}'
  printf '%s\\n' 'system example' > "$4"
}}
manifest_capture {str(target)!r}
''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((target / 'manifest.review').read_text(),
                                 'manifest-review-v1\nsystem example\n')
                self.assertIn('"records":[]', (target / 'manifest.json').read_text())

    def test_upgrade_inventory_setting_rejects_invalid_before_collection(self):
        for name in ['environment_validate_settings', 'manifest_capture', 'manifest_compare_baseline']:
            with self.subTest(name=name):
                result = run([name], '''
DR_UPGRADE_MANIFEST=invalid
manifest_output() { echo 'unexpected collector'; return 99; }
''' + name + ' /does-not-exist\n')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn('DR_UPGRADE_MANIFEST must be true or false', result.stderr)

    PACKAGE_ERROR = ("dpkg: error processing archive /private/EXAMPLE.deb (--unpack):\n"
                     " trying to overwrite shared '/etc/example.conf', which is different from other instances\n")
    PACKAGE_OUTCOME = ('dss:trace: Package recovery health: verified.\n'
                       'dss:stage: Outcome: release verified (trixie); '
                       'packages verified (trixie); services verified.\n')

    def test_package_error_recovery_requires_later_verified_outcome_and_success(self):
        for log, status, expected in [
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME, 0, 'verified_recovered'),
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME, 1, 'unresolved_or_unverified'),
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME, 'unknown', 'unresolved_or_unverified'),
            (self.PACKAGE_OUTCOME + self.PACKAGE_ERROR, 0, 'unresolved_or_unverified'),
            (self.PACKAGE_ERROR, 0, 'unresolved_or_unverified'),
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME.replace('packages verified (trixie)',
                                                            'packages failed final verification'),
             0, 'unresolved_or_unverified'),
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME.replace('packages verified (trixie)',
                                                            'packages verified (bookworm)'),
             0, 'unresolved_or_unverified'),
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME +
             'dss:stage: Outcome: release not verified; packages not verified; services unknown.\n',
             0, 'unresolved_or_unverified'),
            (self.PACKAGE_ERROR + self.PACKAGE_OUTCOME.replace(
                'dss:trace: Package recovery health: verified.\n', ''), 0, 'unresolved_or_unverified'),
            (self.PACKAGE_OUTCOME, 0, 'none_observed'),
        ]:
            with self.subTest(log=log, status=status), tempfile.TemporaryDirectory() as directory:
                logfile = pathlib.Path(directory) / 'output.log'
                logfile.write_text(log)
                result = run(['support_output_package_error_recovery'],
                             f'support_output_package_error_recovery {str(logfile)!r} {status!r}')
                self.assertEqual(result.returncode, 0, result.stderr)
                categories = 'none' if expected == 'none_observed' else 'dpkg package_file_conflict'
                self.assertEqual(result.stdout, f'{expected}\t{categories}\n')
                self.assertEqual(logfile.read_text(), log)

    def test_package_recovery_console_keeps_final_health_and_exit_checks(self):
        for health, action_status, expected_status in [('clean', 0, 0), ('held_back', 0, 0),
                                                       ('missing_summary', 0, 0), ('pending', 0, 1),
                                                       ('audit_failed', 0, 1), ('audit_stderr', 0, 1),
                                                       ('service_failed', 0, 1),
                                                       ('clean', 7, 7)]:
            with self.subTest(health=health, action_status=action_status), tempfile.TemporaryDirectory() as directory:
                result = run(['logging_run', 'upgrade_finish_run', 'upgrade_outcome_record',
                              'support_output_package_error_recovery', 'is_complete_package_plan'], f'''
DR_LOG_DIRECTORY={directory!r}
DR_ACTION=--to-latest
config_state_output_baseline() {{ printf 'fixture-baseline\n'; }}
upgrade_services_check() {{ return {1 if health == 'service_failed' else 0}; }}
upgrade_php_runtime_check() {{ return 0; }}
upgrade_php_runtime_findings_complete() {{ return 0; }}
upgrade_php_runtime_write_review() {{ return 0; }}
upgrade_outcome_output_php_removals() {{ :; }}
manifest_compare_baseline() {{ :; }}
support_print_report() {{ printf 'fixture support report\n'; }}
dpkg() {{ [ "$*" = --audit ] || return 99; {'return 2' if health == 'audit_failed' else "printf 'audit diagnostic\\n' >&2" if health == 'audit_stderr' else ':'}; }}
apt-get() {{
  [ "$*" = '-s dist-upgrade' ] || return 99
  {'return 0' if health == 'missing_summary' else ':'}
  printf '%s\n' {'"Inst example [1.0] (2.0 fixture [amd64])"' if health == 'pending' else '"0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded."' if health == 'held_back' else '"0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."'}
}}
distrorejuve_main() {{
  printf '%b' {self.PACKAGE_ERROR!r}
  upgrade_outcome_record release verified trixie || return 99
  upgrade_outcome_record packages verified trixie || return 99
  return {action_status}
}}
logging_run distrorejuve_main --to-latest
''')
                self.assertEqual(result.returncode, expected_status, result.stderr)
                logfile, = pathlib.Path(directory).glob('run.*/output.log')
                self.assertIn('dpkg: error processing archive', logfile.read_text())
                if health == 'clean' and expected_status == 0:
                    self.assertIn('Earlier package errors were recovered', result.stderr)
                    self.assertNotIn('remain unresolved or unverified', result.stderr)
                else:
                    self.assertNotIn('Earlier package errors were recovered', result.stderr)
                    self.assertIn('remain unresolved or unverified', result.stderr)
                if health in ('pending', 'audit_failed', 'audit_stderr'):
                    self.assertIn('packages failed final verification', logfile.read_text())

    def test_support_report_keeps_evidence_and_rechecks_current_package_health(self):
        for health in ('clean', 'pending', 'audit_failed', 'audit_incomplete', 'audit_stderr',
                       'held_back', 'missing_summary', 'partial_summary', 'malformed_summary', 'nonzero_summary',
                       'duplicate_summary', 'inconsistent_summary'):
            with self.subTest(health=health), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                (root / 'support.context').write_text('0\t--to-latest\t' + 'a' * 64 + '\tfalse\tunknown\n')
                (root / 'output.log').write_text(self.PACKAGE_ERROR + self.PACKAGE_OUTCOME)
                result = run(['support_print_report', 'support_output_package_error_recovery',
                              'is_complete_package_plan'], f'''
ALL_DEBIAN='bookworm trixie'
ALL_UBUNTU='noble'
distro_output_codename() {{ printf 'trixie\n'; }}
sha256sum() {{ printf '%s  fixture-script\n' {'a' * 64!r}; }}
dpkg() {{
  case "$*" in
    --print-architecture) printf 'amd64\n';;
    --audit) {'return 2' if health == 'audit_failed' else "printf 'example is unpacked but not configured\\n'" if health == 'audit_incomplete' else "printf 'PRIVATE AUDIT WARNING\\n' >&2" if health == 'audit_stderr' else ':'};;
    *) return 99;;
  esac
}}
dpkg-query() {{
  case "$*" in
    *Version*) printf '1.0\n';;
    *Status*) printf 'install ok installed\n';;
    *) return 99;;
  esac
}}
apt-cache() {{ [ "$*" = policy ]; }}
apt-get() {{
  [ "$*" = '-s dist-upgrade' ] || return 99
  {'return 0' if health == 'missing_summary' else ':'}
  {'printf "0 upgraded, 0 newly installed, 0 to remove\\n"; return 0' if health == 'partial_summary' else ':'}
  {'printf "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded. extra\\n"; return 0' if health == 'malformed_summary' else ':'}
  {'printf "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\\n"' if health == 'duplicate_summary' else ':'}
  {'printf "Inst example [1.0] (2.0 fixture [amd64])\\n"' if health in ('pending', 'inconsistent_summary') else ':'}
  printf '{1 if health in ('pending', 'nonzero_summary') else 0} upgraded, 0 newly installed, 0 to remove and {1 if health == 'held_back' else 0} not upgraded.\n'
}}
df() {{ printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\nfixture 8192000 4096000 4096000 50%% /\n'; }}
uname() {{ [ "$*" = -r ] || return 99; printf '6.12.0-fixture\n'; }}
support_print_report {directory!r}
''')
                self.assertEqual(result.returncode, 1 if health == 'missing_summary' else 0, result.stderr)
                expected = 'verified_recovered' if health == 'clean' else 'unresolved_or_unverified'
                self.assertIn(f'recorded_package_error_recovery: {expected}', result.stdout)
                expected_health = 'verified' if health == 'clean' else 'unverified'
                self.assertIn(f'current_package_health: {expected_health}', result.stdout)
                self.assertIn('observed_package_error_categories: dpkg package_file_conflict', result.stdout)
                observed = re.search(r'^observed_error_categories: (.*)$', result.stdout, re.M).group(1).split()
                self.assertIn('dpkg', observed)
                self.assertIn('package_file_conflict', observed)
                self.assertIn('recorded_completion_verification: verified', result.stdout)
                self.assertNotIn('/private/', result.stdout)
                self.assertNotIn('/etc/example.conf', result.stdout)
                self.assertNotIn('PRIVATE AUDIT WARNING', result.stdout + result.stderr)

    def test_process_snapshot_precedes_parser(self):
        result = run(['manifest_process_indicators'], r'''
manifest_emit() { printf '%s\n' "$*"; }
manifest_run_bounded() {
  # A parser containing our heuristic must not be alive during collection.
  if ps -eww -o args= | grep '^awk ' | grep -q 'mining_command_arguments'; then return 1; fi
  printf '%s\n' '100 1 0 9000 nginx: worker process' \
    '101 100 1000 9000 worker --algo rx/0 --url pool.example.test --user TOKEN' \
    '102 100 1000 9000 /tmp/worker'
}
manifest_process_indicators
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('indicator mining_command_arguments'), 1)
        self.assertIn('sample_pid 101', result.stdout)
        self.assertIn('sample_pid 102', result.stdout)
        self.assertNotIn('sample_pid 100 ', result.stdout)

    def test_process_failure_is_incomplete(self):
        result = run(['manifest_process_indicators'], '''
manifest_emit() { :; }
manifest_run_bounded() { return 124; }
manifest_collection_failed=false
manifest_process_indicators
$manifest_collection_failed
''')
        self.assertEqual(result.returncode, 0)

    def test_virtualmin_remnant_then_installed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = root / 'etc/webmin/virtual-server/config'
            config.parent.mkdir(parents=True)
            config.write_text('private-data-not-read\n')
            names = ['upgrade_panel_output_installed', 'manifest_hosting_panels']
            body = f'manifest_root={directory!r}\nmanifest_emit() {{ printf "%s\\n" "$*"; }}\nmanifest_hosting_panels\n'
            result = run(names, body)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('panel_remnant name virtualmin', result.stdout)
            self.assertNotIn('hosting_panel', result.stdout)
            module = root / 'usr/share/webmin/virtual-server/module.info'
            module.parent.mkdir(parents=True)
            module.write_text('version=8.0.0\n')
            result = run(names, body)
            self.assertIn('hosting_panel name virtualmin version 8.0.0', result.stdout)
            self.assertNotIn('panel_remnant', result.stdout)

    def test_review_ignores_runtime_fluctuations_and_keeps_cron_changes(self):
        result = run(['manifest_output_review_record'], r'''
manifest_json_string() { printf '"%s"' "$1"; }
manifest_output_review_record capacity kind memory metric available value_kib 123
manifest_output_review_record upgrade_directory path /var/cache/apt/archives status observed allocated_kib 123
manifest_output_review_record language_consumer source process_comm language Python process_count 2
manifest_output_review_record collection_scope probe language_consumers cron skipped_unprivileged
before=$(manifest_output_review_record service_state name mysql active_state inactive daemon_process_count 0 query_status 0)
after=$(manifest_output_review_record service_state name mysql active_state inactive daemon_process_count 1 query_status 124)
[ "$before" = "$after" ] || exit 42
manifest_output_review_record language_consumer source cron source_file /etc/cron.d/example source_line 2 language Python interpreter python3
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertIn('source_file="/etc/cron.d/example"', result.stdout)
        self.assertNotIn('process_count', result.stdout)

    def test_http_probe_is_bounded_cached_and_preserves_failure_codes(self):
        result = run(['manifest_http'], r'''
manifest_unprivileged=false
manifest_http_enabled=true
manifest_http_seen=
manifest_http_started=$SECONDS
manifest_http_count=0
manifest_emit() { printf '%s\n' "$*"; }
curl() { :; }
manifest_run_bounded() {
  case "$*" in *--head*--output*/dev/null*--connect-timeout*--max-time*--max-redirs*--proto*) :;; *) return 99;; esac
  case "$*" in *--location*|*--cookie*) return 98;; esac
  case "${@: -1}" in
    http://example.test:80/) printf '500|192.0.2.10|0';;
    https://example.test:443/) printf '000|192.0.2.10|0'; return 35;;
    https://missing.test:443/) printf '000||0'; return 6;;
  esac
}
manifest_http example.test http 80
manifest_http example.test http 80
manifest_http example.test https 443
manifest_http missing.test https 443
manifest_http 'user:password@example.test' https 443
manifest_http 'example.test/?token=SECRET' https 443
manifest_http '*.example.test' http 80
manifest_http unknown http 80
manifest_http '[::1]' https 99999
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('website_probe'), 3)
        self.assertIn('http_status 500 remote_ip 192.0.2.10', result.stdout)
        self.assertIn('curl_status 35 reason curl_error', result.stdout)
        self.assertIn('http_status 000 remote_ip unknown tls_verify_result unknown curl_status 6', result.stdout)
        self.assertNotIn('SECRET', result.stdout)
        self.assertNotIn('password', result.stdout)

    def test_http_probe_skips_disabled_reduced_and_exhausted_budget(self):
        for setting, expected in [('manifest_http_enabled=false', 'disabled'),
                                  ('manifest_unprivileged=true', 'skipped_unprivileged'),
                                  ('manifest_http_count=40', 'probe_limit'),
                                  ('manifest_http_started=$((SECONDS-46))', 'probe_limit')]:
            with self.subTest(setting=setting):
                result = run(['manifest_http'], r'''
manifest_http_seen=
manifest_http_enabled=true
manifest_unprivileged=false
manifest_http_count=0
manifest_http_started=$SECONDS
manifest_emit() { printf '%s\n' "$*"; }
curl() { :; }
manifest_run_bounded() { printf 'unexpected curl\n'; }
''' + setting + '\nmanifest_http example.test http 80\n')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('reason ' + expected, result.stdout)
                self.assertNotIn('unexpected curl', result.stdout)

    def test_missing_document_root_retains_vhost_and_dns_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run(['manifest_website'], f'''
manifest_root={directory!r}
manifest_apache_php_available=false
manifest_seen_roots=
manifest_emit() {{ printf '%s\n' "$*"; }}
manifest_dns() {{ manifest_dns_result=other; manifest_dns_addresses=192.0.2.20; manifest_dns_reason=resolved; }}
manifest_http() {{ :; }}
manifest_application() {{ :; }}
manifest_web_indicators() {{ :; }}
manifest_website apache example.test 80 false /var/www/missing www-data unknown /etc/apache2/sites-enabled/example.conf
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('document_root /var/www/missing document_root_exists false', result.stdout)
        self.assertIn('config /etc/apache2/sites-enabled/example.conf dns other dns_addresses 192.0.2.20', result.stdout)

    def test_conventional_panel_configs_are_parsed_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            apache_paths = ['etc/apache2/conf/httpd.conf', 'usr/local/apache/conf/httpd.conf',
                            'var/www/vhosts/system/site.test/conf/httpd.conf',
                            'usr/local/directadmin/data/users/example/httpd.conf']
            nginx_paths = ['var/www/vhosts/system/site.test/conf/nginx.conf',
                           'usr/local/directadmin/data/users/example/nginx.conf']
            for i, path in enumerate(apache_paths):
                file = root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(f'<VirtualHost *:80>\nServerName apache{i}.test\nDocumentRoot /var/www/site{i}\n</VirtualHost>\n')
            for i, path in enumerate(nginx_paths):
                file = root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(f'server {{\nlisten 80;\nserver_name nginx{i}.test;\nroot /var/www/nginx{i};\n}}\n')
            alias = root / 'etc/apache2/sites-enabled/duplicate.conf'
            alias.parent.mkdir(parents=True)
            alias.symlink_to(root / apache_paths[0])
            result = run(['manifest_config_files', 'manifest_read_metadata', 'manifest_websites'], f'''
manifest_root={directory!r}
manifest_website() {{ printf '%s\n' "$*"; }}
manifest_websites
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 6)
        for i in range(4):
            self.assertIn(f'apache apache{i}.test 80', result.stdout)
        for i in range(2):
            self.assertIn(f'nginx nginx{i}.test 80', result.stdout)

    def test_fixed_service_states_keep_unit_and_daemon_states_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / 'run/systemd/system').mkdir(parents=True)
            result = run(['manifest_service_states'], f'''
manifest_root={directory!r}
manifest_unprivileged=false
manifest_processes_available=true
manifest_processes=$'postgres\npostgres\nmaster'
manifest_emit() {{ printf '%s\n' "$*"; }}
readlink() {{ printf '/usr/lib/systemd/systemd\n'; }}
systemctl() {{ :; }}
manifest_run_bounded() {{
  case "$*" in *Environment*|*ExecStart*) return 99;; esac
  case "${{@: -1}}" in
    mysql.service) printf '%s\n' LoadState=loaded ActiveState=failed SubState=failed UnitFileState=enabled Result=exit-code Environment=SECRET;;
    mariadb.service) printf '%s\n' LoadState=loaded ActiveState=inactive SubState=dead UnitFileState=masked Result=success;;
    postgresql.service) printf '%s\n' LoadState=loaded ActiveState=active SubState=exited UnitFileState=enabled Result=success;;
    dovecot.service) printf '%s\n' LoadState=not-found ActiveState=inactive SubState=dead; return 1;;
  esac
}}
manifest_service_states
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = result.stdout.splitlines()
        self.assertIn('name mysql load_state loaded active_state failed sub_state failed unit_file_state enabled result exit-code', rows[0])
        self.assertIn('daemon_process_name mysqld daemon_process_count 0', rows[0])
        self.assertIn('name mariadb load_state loaded active_state inactive sub_state dead unit_file_state masked', rows[1])
        self.assertIn('active_state active sub_state exited', rows[2])
        self.assertIn('daemon_process_name postgres daemon_process_count 2', rows[2])
        self.assertIn('load_state not-found', rows[3])
        self.assertIn('query_status 1', rows[3])
        self.assertNotIn('SECRET', result.stdout)
        self.assertNotIn('Environment', result.stdout)

    def test_service_states_keep_unit_state_when_process_snapshot_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / 'run/systemd/system').mkdir(parents=True)
            result = run(['manifest_service_states'], f'''
manifest_root={directory!r}
manifest_unprivileged=false
manifest_processes_available=false
manifest_processes=
manifest_emit() {{ printf '%s\n' "$*"; }}
readlink() {{ printf '/usr/lib/systemd/systemd\n'; }}
systemctl() {{ :; }}
manifest_run_bounded() {{ printf '%s\n' LoadState=loaded ActiveState=active SubState=running UnitFileState=enabled Result=success; }}
manifest_service_states
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('daemon_process_count unknown'), 4)
        self.assertIn('active_state active sub_state running', result.stdout)
        self.assertNotIn('daemon_process_count 0', result.stdout)

    def test_fixed_service_states_reduced_mode_skips_systemctl(self):
        result = run(['manifest_service_states'], r'''
manifest_root=/fixture
manifest_unprivileged=true
manifest_processes_available=true
manifest_processes=$'mysqld\nmaster'
manifest_emit() { printf '%s\n' "$*"; }
manifest_run_bounded() { printf 'unexpected query\n'; return 99; }
manifest_service_states
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('state_source skipped_unprivileged'), 4)
        self.assertIn('daemon_process_name mysqld daemon_process_count 1', result.stdout)
        self.assertNotIn('unexpected query', result.stdout)

    def test_wordpress_application_retains_version_file(self):
        with tempfile.TemporaryDirectory() as directory:
            version_file = pathlib.Path(directory) / 'var/www/example.test/wp-includes/version.php'
            version_file.parent.mkdir(parents=True)
            version_file.write_text('$wp_version = "6.5.3";\n')
            result = run(['manifest_application', 'manifest_read_metadata'], f'''
manifest_root={directory!r}
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_application /var/www/example.test
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('document_root /var/www/example.test application WordPress version 6.5.3', result.stdout)
        self.assertIn('version_file /var/www/example.test/wp-includes/version.php', result.stdout)

    def test_mail_without_optional_stores_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run(['manifest_mail', 'manifest_mail_root', 'manifest_probe'], f'''
manifest_root={directory!r}
manifest_mail_seen=
manifest_warning_count=0
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_probe mail manifest_mail
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('probe mail result observed command_status 0', result.stdout)
        self.assertNotIn('mail_storage', result.stdout)

    def test_probe_marks_partial_and_unknown(self):
        result = run(['manifest_probe'], """
manifest_warning_count=0
manifest_emit() { printf '%s\n' "$*"; }
probe_partial() { manifest_warning_count=1; }
probe_failure() { return 7; }
manifest_probe sample probe_partial
manifest_probe broken probe_failure
""")
        self.assertEqual(result.returncode, 7)
        self.assertIn('result partial', result.stdout)
        self.assertIn('result unknown command_status 7', result.stdout)

    def test_custom_virtualmin_command_allows_normal_checks(self):
        result = run(['upgrade_panel_refuse_generic', 'upgrade_panel_uses_distro_packages'], """
upgrade_panel_output_installed() { :; }
virtualmin() { :; }
upgrade_panel_refuse_generic
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('blocked', result.stderr)

    def test_distro_panels_pass_generic_guard_but_other_panels_still_block(self):
        for panels, expected in [('virtualmin', 0), ('ispconfig', 0),
                                 ('virtualmin ispconfig', 0), ('virtualmin directadmin', 1),
                                 ('plesk', 1), ('cpanel', 1), ('hestiacp', 1)]:
            with self.subTest(panels=panels):
                result = run(['upgrade_panel_refuse_generic', 'upgrade_panel_uses_distro_packages',
                              'upgrade_panel_output_procedure_url'], f'''
upgrade_panel_output_installed() {{ for panel in {panels}; do printf '%s\\tunknown\\n' "$panel"; done; }}
upgrade_panel_refuse_generic
''')
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_collection_status_is_transient(self):
        result = run(['manifest_output_review_record'], "manifest_output_review_record collection_status warning_count 2")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

    def test_small_disk_floor(self):
        for free, expected in [(2300, 0), (2048, 0), (2047, 1)]:
            result = run(['check_disk_space'], f'''
df() {{ printf 'Filesystem 1048576-blocks Used Available Capacity Mounted-on\\n/dev/test 8000 5000 {free} 70%% /\\n'; }}
check_disk_space
''')
            self.assertEqual(result.returncode, expected, result.stderr)
        result = run(['check_disk_space'], '''
df() { return 1; }
check_disk_space
''')
        self.assertNotEqual(result.returncode, 0)

    def test_configuration_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'etc/network').mkdir(parents=True)
            (root / 'etc/network/interfaces').write_text('iface tun0 inet6 v4tunnel\niface tun0 inet6 v4tunnel\n')
            (root / 'etc/fstab').write_text('/dev/test / ext4 defaults,usrquota 0 1\n')
            (root / 'etc/logrotate.d').mkdir()
            (root / 'etc/logrotate.conf').write_text('/var/log/example.log {\n}\n')
            (root / 'etc/logrotate.d/duplicate').write_text('/var/log/example.log {\n postrotate\n /bin/kill worker\n endscript\n}\n')
            (root / 'etc/monit/conf.d').mkdir(parents=True)
            (root / 'etc/monit/conf.d/example').write_text('if failed port 808080 then restart\nstart program = "service nginx start"\nstop program = "/usr/bin/systemctl stop nginx"\n')
            result = run(['upgrade_configuration_review'], f'upgrade_configuration_review {directory!r}')
            self.assertEqual(result.stderr.count('duplicate_log_path'), 1)
            self.assertEqual(result.stderr.count('invalid_monitor_port'), 1)
            self.assertEqual(result.stderr.count('relative_monitor_program'), 1)
            self.assertIn('duplicate_interface', result.stderr)
            self.assertIn('previous line 1', result.stderr)
            self.assertIn('quota_dependency', result.stderr)

    def test_database_earlier_target_warns(self):
        result = run(['upgrade_database_verify'], """
mariadb() { :; }
manifest_run_bounded() {
  case "$*" in
    *'SELECT 1'*) printf '1\n';;
    *'SELECT @@innodb_buffer_pool_size'*) printf '1\n';;
    *mysql.global_priv*) printf 'socket_identity_requires_review';;
    *) return 99;;
  esac
}
upgrade_database_verify bookworm
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('dss:warn: Root unix_socket', result.stderr)
        self.assertNotIn('dss:error:', result.stderr)

    def test_database_existing_option_file_fallback(self):
        result = run(['upgrade_database_verify'], """
mariadb() { :; }
manifest_run_bounded() {
  case "$*" in
    *'SELECT 1'*)
      case "$*" in *--no-defaults*) return 1;; esac
      printf '1\n';;
    *'SELECT @@innodb_buffer_pool_size'*) printf '1\n';;
    *mysql.global_priv*) :;;
    *) return 99;;
  esac
}
upgrade_database_verify trixie
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('maintenance succeeded', result.stderr)

    def test_database_no_live_commands(self):
        for identity, fail, expected in [('', False, 0), ('socket_identity_requires_review', False, 1), ('', True, 1)]:
            result = run(['upgrade_database_verify'], f'''
mariadb() {{ :; }}
manifest_run_bounded() {{
  case "$*" in
    *'SELECT 1'*) {'return 1' if fail else "printf '1\\n'"};;
    *'SELECT @@innodb_buffer_pool_size'*) printf '1\\n';;
    *mysql.global_priv*) printf '%s' {identity!r};;
    *) return 99;;
  esac
}}
upgrade_database_verify trixie
''')
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertNotIn('legacy-hash', result.stderr)


class PrecompiledLocales(unittest.TestCase):
    def preparation(self, count=100, extra='', plan='Inst locales-all (2.36 Debian [amd64])',
                    install_status=0, available=None, change_selection=False):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            selection = root / 'locale.gen'
            supported = root / 'SUPPORTED'
            entries = [f'xx_{index:03}.UTF-8 UTF-8' for index in range(count)]
            original = '# Preserve this comment and the configured selection.\n' + '\n'.join(entries) + '\n'
            selection.write_text(original)
            supported.write_text('\n'.join(entries) + '\n')
            if available is None:
                available = 'C\nC.utf8\nPOSIX\n' + '\n'.join(entry.split()[0].replace('UTF-8', 'utf8') for entry in entries)
            functions = '\n'.join(declaration(name) for name in (
                'upgrade_locales_output_standard_count', 'upgrade_prepare_debian_locales'))
            for path, replacement in [('/etc/locale.gen', selection),
                                      ('/usr/share/i18n/SUPPORTED', supported),
                                      ('/usr/local/share/i18n/SUPPORTED', root / 'custom')]:
                functions = functions.replace(path, str(replacement))
            body = f'''
unset I18NPATH LOCPATH DR_ALLOW_UNAUTHENTICATED_ARCHIVES DR_PRECOMPILED_LOCALES
ALL_DEBIAN='stretch buster bullseye bookworm trixie'
APT_GET_INSTALL_OPTIONS='-y'
prepared=false
all_state=''
all_query_status=1
locales_state='install ok installed'
locales_query_status=0
after_state='install ok installed'
fixture_custom={str(root / 'custom')!r}
distro_output_codename() {{ printf 'bookworm\\n'; }}
dpkg-query() {{
  case "${{@: -1}}" in
    locales-all*)
      if $prepared; then printf '%s' "$after_state"; return 0; fi
      printf '%s' "$all_state"; return "$all_query_status";;
    locales) printf '%s' "$locales_state"; return "$locales_query_status";;
    *) return 99;;
  esac
}}
dpkg() {{ printf 'amd64\\n'; }}
locale() {{ printf '%s\\n' {shlex.quote(available)}; }}
apt-get() {{ printf 'simulate %s\\n' "$*" >> {str(root / 'calls')!r}; printf '%s\\n' {shlex.quote(plan)}; }}
apt_get_install() {{
  printf 'install %s\\n' "$*" >> {str(root / 'calls')!r}
  prepared=true
  {'printf "# changed\\n" >> ' + shlex.quote(str(selection)) if change_selection else ':'}
  return {install_status}
}}
{extra}
upgrade_prepare_debian_locales
status=$?
if [ "$status" -eq 0 ]; then upgrade_prepare_debian_locales; status=$?; fi
exit "$status"
'''
            result = subprocess.run(['bash'], input=functions + '\n' + body, capture_output=True, text=True)
            calls = (root / 'calls').read_text().splitlines() if (root / 'calls').exists() else []
            if not change_selection:
                self.assertEqual(selection.read_text(), original)
            return result, calls

    def test_bulk_standard_selection_installs_once_with_authenticated_no_removal_policy(self):
        result, calls = self.preparation()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2, calls)
        self.assertTrue(calls[0].startswith('simulate '))
        self.assertTrue(calls[1].startswith('install '))
        for call in calls:
            for argument in ('AllowUnauthenticated=false', 'AutomaticRemove=false', '--no-remove',
                             '--no-install-recommends', 'locales-all:amd64'):
                self.assertIn(argument, call)
        self.assertIn('100 configured locales', result.stderr)

    def test_small_custom_held_existing_and_disabled_cases_do_not_install(self):
        for count, extra, available in [
                (99, '', None), (100, 'DR_PRECOMPILED_LOCALES=false', None),
                (100, "distro_output_codename() { echo noble; }", None),
                (100, "all_state='hold ok not-installed'; all_query_status=0", None),
                (100, "all_state='install ok installed'; all_query_status=0", None),
                (100, "all_state='install ok unpacked'; all_query_status=0", None),
                (100, "locales_state='deinstall ok config-files'", None),
                (100, "locales_state='hold ok installed'", None),
                (100, 'DR_ALLOW_UNAUTHENTICATED_ARCHIVES=true', None),
                (100, 'I18NPATH=/fixture/custom', None),
                (100, 'LOCPATH=/fixture/custom', None),
                (100, 'printf custom > "$fixture_custom"', None),
                (100, '', 'C\ncustom_LOCALE.utf8')]:
            with self.subTest(count=count, extra=extra, available=available):
                result, calls = self.preparation(count=count, extra=extra, available=available)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [])

    def test_codeset_aliases_and_unknown_selections(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            supported = root / 'SUPPORTED'
            selection = root / 'locale.gen'
            supported.write_text('en_US.UTF-8 UTF-8\nde_DE@euro ISO-8859-15\n')
            selection.write_text('# comment\n en_US.UTF-8 UTF-8 # selected\nde_DE@euro ISO-8859-15\n')
            available = 'C\nC.UTF-8\nPOSIX\nen_US.utf8\nde_DE.iso885915@euro'
            result = run(['upgrade_locales_output_standard_count'],
                         f'upgrade_locales_output_standard_count {str(supported)!r} {str(selection)!r} {shlex.quote(available)}')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), '2')
            selection.write_text(selection.read_text() + 'custom_LOCALE UTF-8\n')
            result = run(['upgrade_locales_output_standard_count'],
                         f'upgrade_locales_output_standard_count {str(supported)!r} {str(selection)!r} {shlex.quote(available)}')
            self.assertEqual(result.stdout.strip(), '0')

    def test_unsafe_or_unavailable_plans_keep_normal_generation(self):
        for plan in ('', 'Inst locales-all (2.36 Debian [amd64])\nRemv locales [2.36]',
                     'Inst locales-all (2.36 Debian [amd64])\nInst libc6 (2.36 Debian [amd64])'):
            with self.subTest(plan=plan):
                result, calls = self.preparation(plan=plan)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(all(call.startswith('simulate ') for call in calls))
        result, calls = self.preparation(extra="apt-get() { return 100; }")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])
        result, calls = self.preparation(plan='Inst libc-l10n (2.36 Debian [all])\nInst locales-all (2.36 Debian [amd64])')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)

    def test_install_and_state_failures_stop_preparation(self):
        result, _ = self.preparation(install_status=42)
        self.assertEqual(result.returncode, 42, result.stderr)
        result, _ = self.preparation(extra='all_query_status=2')
        self.assertEqual(result.returncode, 2, result.stderr)
        result, _ = self.preparation(extra='locales_query_status=2')
        self.assertEqual(result.returncode, 2, result.stderr)
        result, _ = self.preparation(extra="after_state='install ok unpacked'")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not fully installed', result.stderr)
        result, _ = self.preparation(change_selection=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Locale selection changed', result.stderr)
        for name in ('environment_validate_settings', 'upgrade_prepare_debian_locales'):
            result = run([name], 'DR_PRECOMPILED_LOCALES=invalid\n' + name)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('must be true or false', result.stderr)

    def test_upgrade_prepares_locales_after_refresh_and_baseline_before_configuration(self):
        for preparation_status, baseline_status in ((0, 0), (42, 0), (0, 17)):
            with self.subTest(preparation_status=preparation_status, baseline_status=baseline_status):
                result = run(['apt_get_upgrade'], f'''
pause_check() {{ :; }}
upgrade_precondition_checks() {{ :; }}
apt_sources_archive() {{ :; }}
apt_get_update() {{ echo refresh; }}
upgrade_php_runtime_prepare() {{ :; }}
apt_state_output_signature() {{ echo signature; }}
apt_state_repositories_are_current() {{ return 1; }}
record_config_state() {{ echo baseline; return {baseline_status}; }}
upgrade_prepare_debian_locales() {{ echo preparation; return {preparation_status}; }}
dpkg() {{ echo configure; }}
apt_get_autoremove() {{ :; }}
apt_get_f_install() {{ :; }}
apt_get_apply() {{ echo upgrade; }}
apt-get() {{ :; }}
upgrade_php_runtime_verify() {{ :; }}
apt_get_upgrade
''')
                self.assertEqual(result.returncode, baseline_status or preparation_status, result.stderr)
                events = [line for line in result.stdout.splitlines() if line in
                          ('refresh', 'baseline', 'preparation', 'configure', 'upgrade')]
                self.assertEqual(events[:3], ['refresh', 'baseline'] if baseline_status else ['refresh', 'baseline', 'preparation'])
                self.assertEqual('configure' in events, preparation_status == 0 and baseline_status == 0)

class ManifestHostKeys(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.ssh = self.root / 'etc/ssh'
        self.ssh.mkdir(parents=True)
        # Generate disposable fixture keys outside the collector's search path.
        self.fixture_key = self.root / 'fixture-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                        '-C', 'COMMENT-MUST-NOT-APPEAR', '-f', str(self.fixture_key)],
                       check=True, capture_output=True)
        self.public_text = self.fixture_key.with_suffix('.pub').read_text()
        result = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f',
                                 str(self.fixture_key.with_suffix('.pub'))],
                                check=True, capture_output=True, text=True)
        self.fingerprint = result.stdout.split()[1]

    def collect(self, output_format='json', redact=False, override=''):
        body = f'''
manifest_root={shlex.quote(str(self.root))}
manifest_format={output_format}
manifest_redact={str(redact).lower()}
manifest_separator=
{override}
if [ "$manifest_format" = json ]; then printf '['; fi
manifest_ssh_host_keys
if [ "$manifest_format" = json ]; then printf ']'; fi
'''
        return run(['manifest_json_string', 'manifest_emit', 'manifest_ssh_host_keys'], body)

    def test_public_hash_in_text_and_json_without_private_files_or_comments(self):
        public = self.ssh / 'ssh_host_ed25519_key.pub'
        public.write_text(self.public_text)
        (self.ssh / 'ssh_host_ed25519_key').write_text('PRIVATE-CONTENT-MUST-NOT-APPEAR')
        # A symlink to a valid key would yield a second record if followed.
        (self.ssh / 'ssh_host_alias_key.pub').symlink_to(public)
        (self.ssh / 'ssh_host_bad_key.pub').write_text('NOT-A-KEY PRIVATE-MARKER\n')
        (self.ssh / 'ssh_host_directory_key.pub').mkdir()
        for output_format in ('text', 'json'):
            with self.subTest(output_format=output_format):
                result = self.collect(output_format)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(self.fingerprint, result.stdout)
                self.assertNotIn('COMMENT-MUST-NOT-APPEAR', result.stdout + result.stderr)
                self.assertNotIn('PRIVATE-', result.stdout + result.stderr)
                if output_format == 'json':
                    records = json.loads(result.stdout)
                    keys = [r for r in records if r['type'] == 'ssh_host_key']
                    self.assertEqual(len(keys), 1)
                    self.assertEqual(keys[0]['path'], '/etc/ssh/ssh_host_ed25519_key.pub')
                    self.assertEqual(keys[0]['key_type'], 'ssh-ed25519')
                    self.assertEqual(keys[0]['bits'], '256')
                    self.assertEqual(keys[0]['active'], 'unknown')
                    self.assertTrue(any(r['type'] == 'warning' for r in records))

    def test_public_redaction_removes_stable_host_identity(self):
        (self.ssh / 'ssh_host_ed25519_key.pub').write_text(self.public_text)
        for output_format in ('text', 'json'):
            with self.subTest(output_format=output_format):
                result = self.collect(output_format, redact=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn(self.fingerprint, result.stdout)
                self.assertNotIn('/etc/ssh/', result.stdout)
                self.assertIn('[redacted]', result.stdout)
                if output_format == 'json':
                    self.assertEqual(json.loads(result.stdout)[0]['fingerprint'], '[redacted]')

    def test_reduced_manifest_output_includes_host_key_probe(self):
        (self.ssh / 'ssh_host_ed25519_key.pub').write_text(self.public_text)
        for output_format in ('text', 'json'):
            with self.subTest(output_format=output_format):
                result = run(['manifest_json_string', 'manifest_emit',
                              'manifest_ssh_host_keys', 'manifest_output'], f'''
id() {{ printf '1000\\n'; }}
hostname() {{ printf 'fixture.example.invalid\\n'; }}
ip() {{ :; }}
ps() {{ :; }}
packages_output_backend() {{ printf 'dpkg\\n'; }}
# Other collectors are outside this fixture's input and side-effect scope.
manifest_probe() {{ if [ "$1" = ssh_host_keys ]; then shift; "$@"; fi; }}
manifest_output {output_format} false {shlex.quote(str(self.root))}
''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(self.fingerprint, result.stdout)
                if output_format == 'json':
                    records = json.loads(result.stdout)['records']
                    self.assertEqual(sum(r['type'] == 'ssh_host_key' for r in records), 1)

    def test_missing_files_and_unavailable_or_old_tool_remain_unknown(self):
        result = self.collect()
        records = json.loads(result.stdout)
        self.assertTrue(any('No conventional public host-key' in r.get('reason', '') for r in records))
        (self.ssh / 'ssh_host_ed25519_key.pub').write_text(self.public_text)
        overrides = [
            'command() { if [ "$*" = "-v ssh-keygen" ]; then return 1; fi; builtin command "$@"; }',
            'ssh-keygen() { return 1; }',
            'ssh-keygen() { printf "256 MD5:invalid (stdin) (ED25519)\\n"; }',
        ]
        for override in overrides:
            with self.subTest(override=override):
                result = self.collect(override=override)
                self.assertEqual(result.returncode, 0, result.stderr)
                records = json.loads(result.stdout)
                self.assertFalse(any(r['type'] == 'ssh_host_key' for r in records))
                self.assertTrue(any(r['type'] == 'warning' for r in records))
                self.assertNotIn('MD5:', result.stdout)


if __name__ == '__main__':
    unittest.main()
