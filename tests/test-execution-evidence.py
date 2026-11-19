#!/usr/bin/env python3
"""Isolated execution evidence checks; no live clients, services or databases."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('execution_evidence', Path(__file__).resolve().parents[1] / 'scripts/execution-evidence.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ClientTests(unittest.TestCase):
    def result(self, output=b'', code=0, error=b''):
        return subprocess.CompletedProcess([], code, output, error)

    def test_engine_recovery_requires_nontransactional_coverage(self):
        mixed = MODULE.engine_metadata(b'InnoDB\t12\t8192\nMyISAM\t3\t4096\n')
        self.assertFalse(mixed['transaction_only_recovery_covers_all_tables'])
        self.assertEqual(mixed['nontransactional_or_unverified_tables'], 3)
        self.assertTrue(MODULE.engine_metadata(b'InnoDB\t12\t8192\n')['transaction_only_recovery_covers_all_tables'])
        self.assertFalse(MODULE.engine_metadata(b'UNKNOWN\t1\t0\n')['transaction_only_recovery_covers_all_tables'])
        for raw in (b'InnoDB\tsecret\t1\n', b'InnoDB\t1\t2\nInnoDB\t1\t2\n', b'password=secret\t1\t2\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                MODULE.engine_metadata(raw)

    def test_explicit_database_and_designated_defaults_without_empty_init(self):
        run = Mock(return_value=self.result(b'MyISAM\t2\t4096\n'))
        value = MODULE.collect_engines('mysql', Path('/approved/client.cnf'), 'application', run=run)
        self.assertEqual(value['status'], 'observed')
        command = run.call_args.args[0]
        self.assertEqual(command[1], '--defaults-file=/approved/client.cnf')
        self.assertIn('--database=application', command)
        self.assertTrue(command[-1].startswith('--execute=SELECT COALESCE(ENGINE'))
        self.assertNotIn('--user=root', command)
        self.assertFalse(any('init-command' in arg for arg in command))
        for database in ('', 'app\nsecret', 'app --password=secret'):
            with self.subTest(database=database), self.assertRaises(ValueError):
                MODULE.client_command('mysql', '/approved/client.cnf', database, 'SELECT 1')

    def test_denied_or_malformed_metadata_stays_unknown(self):
        for result in (self.result(code=1, error=b'credential-sentinel'), self.result(b'bad row\n')):
            value = MODULE.collect_engines('mysql', '/approved/client.cnf', 'app', run=Mock(return_value=result))
            self.assertEqual(value['status'], 'unknown')
            self.assertIsNone(value['transaction_only_recovery_covers_all_tables'])
            self.assertNotIn('credential-sentinel', json.dumps(value))

    def test_proxy_normalizes_split_users_without_returning_identifiers(self):
        runtime = b'app\t10\tNULL\t1\t0\napp\t10\t\t0\t1\n'
        disk = b'app\t10\t\t1\t1\n'
        self.assertEqual(MODULE.proxy_projection('users', runtime), MODULE.proxy_projection('users', disk))
        self.assertNotEqual(MODULE.proxy_projection('users', runtime), MODULE.proxy_projection('users', b'app\t20\t\t1\t1\n'))
        results = [self.result(b'10\tdb.invalid\t3306\tONLINE\t1\t100\n')] * 2
        results += [self.result(b'1\t1\t10\t1\t500\n')] * 2
        results += [self.result(runtime), self.result(disk)]
        results += [self.result(b'mysql-default_query_timeout\t36000000\n')] * 2
        run = Mock(side_effect=results)
        value = MODULE.collect_proxy('mysql', '/approved/client.cnf', run=run)
        self.assertTrue(value['matches'])
        self.assertNotIn('db.invalid', json.dumps(value))
        for call in run.call_args_list:
            query = call.args[0][-1]
            for forbidden in ('password', 'match_pattern', 'SELECT *', 'FROM global_variables WHERE variable_name NOT'):
                self.assertNotIn(forbidden, query)

    def test_proxy_real_policy_change_and_access_failure(self):
        results = [self.result(b'10\tdb.invalid\t3306\tONLINE\t1\t100\n')] * 2
        results += [self.result(b'1\t1\t10\t1\t500\n'), self.result(b'1\t1\t10\t1\t600\n')]
        results += [self.result(b'app\t10\t\t1\t1\n')] * 2
        results += [self.result(b'mysql-default_query_timeout\t36000000\n')] * 2
        self.assertFalse(MODULE.collect_proxy('mysql', '/approved/client.cnf', run=Mock(side_effect=results))['matches'])
        failed = MODULE.collect_proxy('mysql', '/approved/client.cnf', run=Mock(return_value=self.result(code=1, error=b'password-sentinel')))
        self.assertEqual(failed['status'], 'unknown')
        self.assertNotIn('password-sentinel', json.dumps(failed))

    def test_proxy_policy_is_allowlisted_and_actual_timeout_drift_survives(self):
        self.assertNotEqual(MODULE.proxy_projection('policy', b'mysql-default_query_timeout\t3000\n'),
                            MODULE.proxy_projection('policy', b'mysql-default_query_timeout\t4000\n'))
        for raw in (b'admin-admin_credentials\tpassword-sentinel\n', b'mysql-default_query_timeout\t3000\nmysql-default_query_timeout\t4000\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                MODULE.proxy_projection('policy', raw)

    def test_ready_retries_only_connection_errors(self):
        for code in (2002, 2003, 2013):
            run = Mock(side_effect=[self.result(code=1, error=('ERROR %s (HY000): secret' % code).encode()), self.result(b'1\n')])
            sleep = Mock()
            value = MODULE.wait_client('mysql', '/approved/client.cnf', attempts=2, run=run, sleep=sleep)
            self.assertEqual(value['status'], 'ready')
            self.assertEqual(value['attempts'], 2)
            sleep.assert_called_once()
        run = Mock(return_value=self.result(code=1, error=b'ERROR 1045 (28000): password-secret'))
        value = MODULE.wait_client('mysql', '/approved/client.cnf', run=run, sleep=Mock())
        self.assertEqual(value['attempts'], 1)
        self.assertEqual(run.call_count, 1)
        self.assertNotIn('password-secret', json.dumps(value))
        value = MODULE.wait_client('mysql', '/approved/client.cnf', attempts=2,
                                   run=Mock(return_value=self.result(code=1, error=b'ERROR 2003: refused')), sleep=Mock())
        self.assertEqual(value['reason'], 'connection_not_ready')


class ProtocolAndListenerTests(unittest.TestCase):
    def test_debconf_preserves_empty_status_and_rejects_other_records(self):
        self.assertEqual(MODULE.parse_debconf(b'0 \n')['value'], '')
        self.assertEqual(MODULE.parse_debconf(b'0\n')['value'], '')
        self.assertEqual(MODULE.parse_debconf(b'0 true\n', 'boolean')['value'], 'true')
        self.assertEqual(MODULE.parse_debconf(b'10 question does not exist\n')['status'], 'unavailable')
        self.assertEqual(MODULE.parse_debconf(b'0 /dev/vda, /dev/vdb\n')['value'], '/dev/vda, /dev/vdb')
        for raw in (b'0 \n0 true\n', b'password-secret', b'0 arbitrary-secret\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                MODULE.parse_debconf(raw)

    def test_listener_acceptance_checks_new_default_ports_and_unix(self):
        old = [{'protocol': 'tcp', 'address': '127.0.0.1', 'port': 6032}, {'protocol': 'unix', 'path': '/run/proxy.sock'}]
        self.assertEqual(MODULE.check_listeners(old, old)['status'], 'passed')
        for extra in ({'protocol': 'tcp', 'address': '0.0.0.0', 'port': 6132}, {'protocol': 'tcp', 'address': '::', 'port': 6133}):
            value = MODULE.check_listeners(old + [extra], old)
            self.assertEqual(value['status'], 'failed')
            self.assertEqual(len(value['unexpected']), 1)
        self.assertEqual(MODULE.check_listeners(old[:1], old)['status'], 'failed')

    def test_proc_inventory_is_owned_and_checks_pid_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            process = proc / '123'
            (process / 'fd').mkdir(parents=True)
            (process / 'net').mkdir()
            (process / 'fd' / '3').symlink_to('socket:[77]')
            (process / 'stat').write_text('123 (two word name) ' + ' '.join(['S'] + ['0'] * 18 + ['100']) + '\n')
            (process / 'net' / 'tcp').write_text('header\n 0: 0100007F:1770 00000000:0000 0A 0:0 0:0 0 1000 0 77\n 1: 00000000:17F4 00000000:0000 0A 0:0 0:0 0 1000 0 99\n')
            (process / 'net' / 'unix').write_text('header\n')
            value = MODULE.process_listeners(123, proc)
            self.assertEqual(value, [{'protocol': 'tcp', 'address': '127.0.0.1', 'port': 6000}])
            with patch.object(MODULE, 'process_start', side_effect=['100', '101']), self.assertRaises(ValueError):
                MODULE.process_listeners(123, proc)

    def test_stale_binary_requires_empty_failed_manager(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / '123').mkdir()
            installed = proc / 'installed'
            old = proc / 'old'
            installed.write_bytes(b'new')
            old.write_bytes(b'old')
            (proc / '123' / 'exe').symlink_to(old)
            manager = {'ActiveState': 'failed', 'TasksCurrent': 0}
            with patch.object(MODULE, 'process_start', return_value='100'):
                value = MODULE.stale_process(123, installed, manager, proc)
                self.assertTrue(value['targeted_refresh_review_indicated'])
                manager['TasksCurrent'] = 1
                self.assertFalse(MODULE.stale_process(123, installed, manager, proc)['targeted_refresh_review_indicated'])
                (proc / '123' / 'exe').unlink()
                (proc / '123' / 'exe').symlink_to(installed)
                manager['TasksCurrent'] = 0
                self.assertFalse(MODULE.stale_process(123, installed, manager, proc)['running_binary_is_stale'])


class ExecutionAndModeTests(unittest.TestCase):
    def test_binary_receipt_survives_missing_text_codec(self):
        real_fdopen = os.fdopen
        def no_text(fd, mode, *args, **kwargs):
            if 'b' not in mode:
                raise LookupError('codec retired')
            return real_fdopen(fd, mode, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            with patch.object(MODULE.os, 'fdopen', side_effect=no_text):
                MODULE.write_receipt(path, {'status': 'passed', 'unicode': '\u0100'})
            self.assertEqual(json.loads(path.read_bytes()), {'status': 'passed', 'unicode': '\u0100'})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                MODULE.write_receipt(path, {})

    def test_check_propagates_exact_failure_and_retains_start_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / 'failed.json'
            result = MODULE.run_check([sys.executable, '-c', 'raise SystemExit(17)'], receipt)
            self.assertEqual(result, 17)
            self.assertEqual(json.loads(receipt.read_bytes())['returncode'], 17)
            self.assertEqual(json.loads(receipt.with_name('failed.json.started').read_bytes())['status'], 'started')
            with self.assertRaises(FileExistsError):
                MODULE.run_check([sys.executable, '-c', 'raise SystemExit(0)'], receipt)
            code = MODULE.run_check(['/nonexistent-client-fixture'], Path(directory) / 'missing.json')
            self.assertEqual(code, 127)

    def test_child_umask_is_scoped_and_timeout_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            before = os.umask(0o077)
            try:
                result = MODULE.run_check([sys.executable, '-c', "import os; open('" + str(path / 'public') + "','wb').close()"], path / 'modes.json', application_umask=0o022)
                self.assertEqual(result, 0)
                self.assertEqual(stat.S_IMODE((path / 'public').stat().st_mode), 0o644)
                self.assertEqual(os.umask(0o077), 0o077)
            finally:
                os.umask(before)
            result = MODULE.run_check([sys.executable, '-c', 'import time; time.sleep(10)'], path / 'timeout.json', timeout=0.02, read_only_check=True)
            self.assertEqual(result, 124)
            self.assertTrue(json.loads((path / 'timeout.json').read_bytes())['timed_out'])

    def test_timeout_requires_explicit_read_only_declaration_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / 'not-launched.json'
            child = Mock()
            with self.assertRaises(ValueError):
                MODULE.run_check(['schema-upgrade-fixture'], receipt, timeout=1, popen=child)
            child.assert_not_called()
            self.assertFalse(receipt.exists())
            result = subprocess.run([sys.executable, str(Path(MODULE.__file__)), 'check', '--timeout', '1',
                                     '--receipt', str(receipt), '--', sys.executable, '-c', 'raise SystemExit(0)'], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(receipt.exists())

    def test_outage_budget_reserves_recovery_and_reconciles_session_loss(self):
        self.assertEqual(MODULE.deadline_status(100, 1800, 300, now=lambda: 200, recorded_boot_id='fixture-boot', current_boot_id='fixture-boot')['status'], 'continue')
        reserve = MODULE.deadline_status(100, 1800, 300, now=lambda: 1600, recorded_boot_id='fixture-boot', current_boot_id='fixture-boot')
        self.assertEqual(reserve['status'], 'recovery-decision-needed')
        self.assertFalse(reserve['action_stopped_or_retried'])
        self.assertEqual(MODULE.deadline_status(100, 1800, 300, now=lambda: 1900, recorded_boot_id='fixture-boot', current_boot_id='fixture-boot')['status'], 'overrun')
        self.assertEqual(MODULE.deadline_status(100, 1800, 300, session_lost=True, now=lambda: 200, recorded_boot_id='fixture-boot', current_boot_id='fixture-boot')['status'], 'recovery-decision-needed')
        with self.assertRaises(ValueError):
            MODULE.deadline_status(100, 1800, 300, session_lost=True, session_loss_policy='continue', now=lambda: 200, recorded_boot_id='fixture-boot', current_boot_id='fixture-boot')
        self.assertEqual(MODULE.deadline_status(100, 1800, 300, session_lost=True, session_loss_policy='continue', approval='plan-r2', now=lambda: 200, recorded_boot_id='fixture-boot', current_boot_id='fixture-boot')['status'], 'continue')
        with self.assertRaises(ValueError):
            MODULE.deadline_status(100, 1800, 300, now=lambda: 99, recorded_boot_id='fixture-boot', current_boot_id='fixture-boot')

    def test_outage_budget_rejects_another_observer_boot(self):
        with self.assertRaises(ValueError):
            MODULE.deadline_status(100, 1800, 300, now=lambda: 200,
                                   recorded_boot_id='earlier-boot', current_boot_id='current-boot')

    def test_deployment_restores_recreated_parent_and_local_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'existing').mkdir(mode=0o755)
            (root / 'existing' / 'code.php').write_bytes(b'public code')
            (root / 'existing' / 'code.php').chmod(0o640)
            snapshot = MODULE.capture_modes(root, ['existing/code.php'])
            (root / 'existing' / 'code.php').unlink()
            (root / 'existing').rmdir()
            (root / 'existing').mkdir(mode=0o700)
            (root / 'existing' / 'code.php').write_bytes(b'new code')
            (root / 'existing' / 'code.php').chmod(0o600)
            MODULE.restore_modes(root, snapshot)
            self.assertEqual(stat.S_IMODE((root / 'existing').stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((root / 'existing' / 'code.php').stat().st_mode), 0o640)
            (root / 'existing' / 'code.php').unlink()
            (root / 'existing' / 'code.php').symlink_to(root / 'other')
            with self.assertRaises(ValueError):
                MODULE.restore_modes(root, snapshot)
            for bad in ('../outside', '/absolute', '.git/config'):
                with self.subTest(path=bad), self.assertRaises(ValueError):
                    MODULE.capture_modes(root, [bad])

    def test_readiness_compares_full_permission_mode_without_restoring_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / 'group-dir'
            nested.mkdir()
            nested.chmod(0o2775)
            executable = nested / 'worker'
            executable.touch()
            executable.chmod(0o4755)
            paths = root / 'paths.json'
            paths.write_text(json.dumps(['group-dir/worker']))
            expected = root / 'original.json'
            snapshot = MODULE.capture_modes(root, ['group-dir/worker'])
            self.assertEqual([row['mode'] for row in snapshot['paths']], [0o2775, 0o4755])
            MODULE.write_receipt(expected, snapshot)
            args = ['capture-modes', '--root', str(root), '--paths', str(paths),
                    '--expected', str(expected)]
            with patch('builtins.print'):
                self.assertEqual(MODULE.main(args), 0)
                nested.chmod(0o775)
                self.assertEqual(MODULE.main(args), 1)
            self.assertEqual(stat.S_IMODE(nested.stat().st_mode), 0o775)

    def test_database_retention_keeps_decimal_semantics(self):
        before = {'expire_logs_days': 10}
        self.assertEqual(MODULE.compare_database_retention(before, {'expire_logs_days': '10.000000'})['status'], 'passed')
        changed = MODULE.compare_database_retention(before, {'expire_logs_days': '10.25'})
        self.assertEqual(changed['changed_settings'], ['expire_logs_days'])
        for after in ({}, {'expire_logs_days': 10.0}, {'expire_logs_days': '10 days'}, {'unrelated': '10'}):
            with self.subTest(after=after), self.assertRaises(ValueError):
                MODULE.compare_database_retention(before, after)

    def test_cold_copy_budget_and_partial_verification(self):
        self.assertEqual(MODULE.cold_copy_budget(5200, 100, 5, 600)['copy_budget_seconds'], 520)
        self.assertEqual(MODULE.cold_copy_budget(5200, 100, 5, 300)['status'], 'failed')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, partial = root / 'original', root / 'partial'
            source.write_bytes(b'original data')
            partial.write_bytes(b'original')
            self.assertEqual(MODULE.verify_copy_prefix(source, partial)['status'], 'passed')
            self.assertEqual(MODULE.verify_copy_prefix(source, partial, complete=True)['status'], 'failed')
            partial.write_bytes(b'modified')
            self.assertEqual(MODULE.verify_copy_prefix(source, partial)['status'], 'failed')
            partial.write_bytes(source.read_bytes())
            self.assertTrue(MODULE.verify_copy_prefix(source, partial, complete=True)['complete'])
            with self.assertRaises(ValueError):
                MODULE.verify_copy_prefix(source, source)

    def test_deployment_rejects_special_files_and_hardlinks_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root / 'pipe')
            with self.assertRaises(ValueError):
                MODULE.capture_modes(root, ['pipe'])
            (root / 'file').write_bytes(b'fixture')
            os.link(root / 'file', root / 'second-link')
            with self.assertRaises(ValueError):
                MODULE.capture_modes(root, ['file'])

    def test_component_replacement_needs_exact_migration_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migration = root / 'upgrade.php'
            migration.write_bytes(b'approved upstream migration fixture')
            row = {'old': 'bundled_v1', 'new': 'bundled_v2', 'from_version': '1', 'to_version': '2',
                   'approval': 'review-fixture', 'migration_file': 'upgrade.php',
                   'migration_sha256': MODULE.hashlib.sha256(migration.read_bytes()).hexdigest()}
            before = {'bundled_v1': '1', 'custom': '5'}
            after = {'bundled_v2': '2', 'custom': '5'}
            self.assertEqual(MODULE.component_acceptance(before, after, [row], root)['status'], 'passed')
            del after['custom']
            self.assertEqual(MODULE.component_acceptance(before, after, [row], root)['missing_components'], ['custom'])
            migration.write_bytes(b'changed proof')
            with self.assertRaises(ValueError):
                MODULE.component_acceptance(before, after, [row], root)


class ReviewsAndSwapTests(unittest.TestCase):
    def original(self):
        return {'source_id': 'source-fixture', 'kernel': '5.10.1', 'machine': 'x86_64', 'root_identity': 'uuid:fixture', 'boot_mode': 'xen-pv', 'cgroup_mode': 'v2'}

    def test_kernel_change_needs_exact_bound_review(self):
        original = self.original()
        current = dict(original, kernel='5.10.2')
        self.assertEqual(MODULE.kernel_acceptance(original, original)['status'], 'passed')
        self.assertEqual(MODULE.kernel_acceptance(original, current)['status'], 'failed')
        review = {'original_sha256': MODULE.digest(original), 'current_sha256': MODULE.digest(current), 'kernel': '5.10.2',
                  'approval': 'review-fixture', 'root_checked': True, 'boot_mode_checked': True, 'cgroups_checked': True,
                  'applications_checked': True, 'provider_selection_verified': False}
        self.assertEqual(MODULE.kernel_acceptance(original, current, review)['status'], 'passed')
        current['kernel'] = '5.10.3'
        self.assertEqual(MODULE.kernel_acceptance(original, current, review)['status'], 'failed')
        current['root_identity'] = 'wrong-root'
        review['current_sha256'] = MODULE.digest(current)
        review['kernel'] = current['kernel']
        self.assertEqual(MODULE.kernel_acceptance(original, current, review)['status'], 'failed')

    def test_x11_review_cannot_skip_other_guards(self):
        original = {'source_id': 'fixture', 'release_path': 'bookworm:trixie', 'default_failure_sha256': 'a' * 64,
                    'other_checks_sha256': 'b' * 64, 'display_server_active': False,
                    'display_manager_active': False, 'other_checks_passed': True}
        review = {key: original[key] for key in ('source_id', 'release_path', 'default_failure_sha256', 'other_checks_sha256')}
        review.update(original_sha256=MODULE.digest(original), approval='review-fixture', skips=['DR_SKIP_X11_CHECK'])
        value = MODULE.x11_exception(original, review)
        self.assertEqual(value['status'], 'passed')
        self.assertFalse(value['default_readiness_passed'])
        review['skips'].append('DR_SKIP_DISK_SPACE_CHECK')
        self.assertEqual(MODULE.x11_exception(original, review)['status'], 'failed')
        review['skips'] = ['DR_SKIP_X11_CHECK']
        original['display_manager_active'] = True
        self.assertEqual(MODULE.x11_exception(original, review)['status'], 'failed')

    def test_allocated_swap_reconciliation_capacity_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'swap'
            result = MODULE.prepare_swap(path, 4096, reserve=0)
            self.assertEqual(path.stat().st_size, 4096)
            self.assertGreaterEqual(path.stat().st_blocks * 512, 4096)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertFalse(result['persistent'])
            self.assertFalse(result['mkswap_and_swapon_performed'])
            self.assertEqual(MODULE.prepare_swap(path, 4096, reserve=0, existing=result)['status'], 'verified_existing')
            with self.assertRaises(ValueError):
                MODULE.prepare_swap(path, 4096, reserve=0)
            partial = Path(directory) / 'partial'
            partial.write_bytes(b'partial')
            with self.assertRaises(ValueError):
                MODULE.prepare_swap(partial, 4096, reserve=0, existing=result)
            self.assertEqual(partial.read_bytes(), b'partial')
            low = Mock(f_bavail=0, f_frsize=4096)
            with patch.object(MODULE.os, 'statvfs', return_value=low), self.assertRaises(ValueError):
                MODULE.prepare_swap(Path(directory) / 'low', 4096)

    def test_review_requires_private_operator_owned_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'review'
            path.write_text('{}')
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                MODULE.private_json(path)
            path.chmod(0o600)
            self.assertEqual(MODULE.private_json(path), {})
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises((ValueError, OSError)):
                MODULE.private_json(link)

    def test_review_replacement_is_checked_on_actual_open_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            review = root / 'review.json'
            review.write_text('{}')
            review.chmod(0o600)
            replacement = root / 'unsafe.json'
            replacement.write_text('{"approval":"untrusted"}')
            replacement.chmod(0o644)
            actual_open = os.open
            def replace_before_open(path, flags, *args, **kwargs):
                replacement.replace(review)
                return actual_open(path, flags, *args, **kwargs)
            with patch.object(MODULE.os, 'open', side_effect=replace_before_open), self.assertRaises(ValueError):
                MODULE.private_json(review)

    def test_kernel_review_shape_is_checked_at_command_boundary(self):
        original = self.original()
        with self.assertRaises(ValueError):
            MODULE.kernel_acceptance(original, dict(original, kernel='new'), [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'original').write_text(json.dumps(original))
            (root / 'current').write_text(json.dumps(dict(original, kernel='new')))
            (root / 'review').write_text('[]')
            (root / 'review').chmod(0o600)
            result = subprocess.run([sys.executable, str(Path(MODULE.__file__)), 'kernel', '--original', str(root / 'original'),
                                     '--current', str(root / 'current'), '--review', str(root / 'review')], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b'Traceback', result.stderr)

    def test_input_json_rejects_duplicate_review_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'duplicate.json'
            path.write_text('{"approval":"first","approval":"second"}')
            with self.assertRaises(ValueError):
                MODULE.read_json(path)

    def test_fifo_input_fails_at_command_boundary_without_waiting(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fifo'
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                MODULE.bounded_bytes(path)
            result = subprocess.run([sys.executable, str(Path(MODULE.__file__)), 'debconf', '--input', str(path)],
                                    capture_output=True, timeout=2)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b'Traceback', result.stderr)

    def test_cli_propagates_check_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(Path(MODULE.__file__)), 'check', '--receipt', str(Path(directory) / 'failure.json'), '--', sys.executable, '-c', 'raise SystemExit(19)'], capture_output=True)
            self.assertEqual(result.returncode, 19)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'')


if __name__ == '__main__':
    unittest.main()
