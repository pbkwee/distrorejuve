#!/usr/bin/env python3
"""Disposable job-record tests; never open an operator's actual job store."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('job_record', Path(__file__).resolve().parents[1] / 'scripts/job-record.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class JobTests(unittest.TestCase):
    def start(self, folder):
        return MODULE.initialize(folder, 'UPG-7K3M9Q', 'source.example.invalid', 'fixture-operator', {'distrorejuve': 'reviewed-revision'})

    def test_reservation_and_immediate_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, state = self.start(folder)
            self.assertEqual(state['revision'], 1)
            self.assertIn('- job_id: UPG-7K3M9Q', (directory / 'job.md').read_text())
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual((directory / 'job.md').stat().st_mode & 0o777, 0o600)
            self.assertEqual(MODULE.load(directory)[1]['tools'], {'distrorejuve': 'reviewed-revision'})

    def test_collision_does_not_modify_existing_record(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, _ = self.start(folder)
            before = (directory / 'job.md').read_bytes()
            with self.assertRaises(FileExistsError):
                self.start(folder)
            self.assertEqual((directory / 'job.md').read_bytes(), before)

    def test_archived_collision_is_also_reserved(self):
        with tempfile.TemporaryDirectory() as folder:
            archived = Path(folder) / 'archive' / 'old' / 'UPG-7K3M9Q'
            archived.mkdir(parents=True)
            with self.assertRaises(FileExistsError):
                self.start(folder)
            self.assertFalse((Path(folder) / 'UPG-7K3M9Q').exists())

    @unittest.skipIf(os.geteuid() == 0, 'root bypasses this filesystem permission fixture')
    def test_unreadable_archive_cannot_hide_an_existing_job_id(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / 'archive'
            (archive / 'UPG-7K3M9Q').mkdir(parents=True)
            archive.chmod(0)
            try:
                with self.assertRaises(PermissionError):
                    self.start(folder)
                self.assertFalse((Path(folder) / 'UPG-7K3M9Q').exists())
            finally:
                archive.chmod(0o700)

    def test_partial_initialization_is_retained_and_never_reused(self):
        with tempfile.TemporaryDirectory() as folder:
            real = MODULE.replace_private
            def fail_state(path, content):
                if path.name == 'state.json':
                    raise OSError('fixture interruption')
                return real(path, content)
            with mock.patch.object(MODULE, 'replace_private', side_effect=fail_state), self.assertRaises(OSError):
                self.start(folder)
            self.assertIn('UPG-7K3M9Q', (Path(folder) / 'UPG-7K3M9Q/job.md').read_text())
            with self.assertRaises(FileExistsError):
                self.start(folder)

    def test_update_preserves_operator_notes_and_history(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, _ = self.start(folder)
            with (directory / 'job.md').open('a') as handle:
                handle.write('\n## Operator notes\nKeep this private reference.\n')
            result = MODULE.update(directory, 1, 'assessment', 'manifest collected', 'write report', 'operator', 'collection complete', {'execution': 'plan not approved'})
            self.assertEqual(result['revision'], 2)
            document = (directory / 'job.md').read_text()
            self.assertEqual(document.count(MODULE.START), 1)
            self.assertIn('Keep this private reference.', document)
            self.assertIn('job reserved; intake pending', document)
            self.assertIn('collection complete', document)
            self.assertIn('Blocks execution: plan not approved', document)

    def test_stale_summary_cannot_overwrite_newer_state(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, _ = self.start(folder)
            MODULE.update(directory, 1, 'assessment', 'collected', 'report', 'operator', 'first update')
            with self.assertRaises(ValueError):
                MODULE.update(directory, 1, 'execution', 'stale', 'mutate', 'operator', 'stale update')
            self.assertEqual(MODULE.load(directory)[1]['revision'], 2)

    def test_projection_recovers_every_event_after_interruption(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, _ = self.start(folder)
            with mock.patch.object(MODULE, 'project', side_effect=OSError('fixture interruption')), self.assertRaises(OSError):
                MODULE.update(directory, 1, 'assessment', 'collected', 'report', 'operator', 'must survive')
            MODULE.update(directory, 2, 'planning', 'report delivered', 'approve plan', 'operator', 'later update')
            document = (directory / 'job.md').read_text()
            self.assertIn('must survive', document)
            self.assertIn('later update', document)
            self.assertEqual(document.count('state-event:2'), 1)

    def test_active_lock_and_public_state_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, _ = self.start(folder)
            lock = directory / '.job-update.lock'
            lock.write_text('fixture owner\n')
            with self.assertRaises(FileExistsError):
                MODULE.update(directory, 1, 'assessment', 'none', 'wait', 'operator', 'blocked')
            self.assertTrue(lock.exists())
            lock.unlink()
            (directory / 'state.json').chmod(0o644)
            with self.assertRaises(ValueError):
                MODULE.load(directory)

    def test_symlink_store_or_document_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            alias = Path(folder) / 'alias'
            alias.symlink_to(folder)
            with self.assertRaises(ValueError):
                MODULE.initialize(alias)
            directory, _ = self.start(folder)
            document = directory / 'job.md'
            saved = document.read_text()
            document.unlink()
            target = Path(folder) / 'outside'
            target.write_text(saved)
            document.symlink_to(target)
            with self.assertRaises(OSError):
                MODULE.load(directory)

    def test_multiline_metadata_and_duplicate_tools_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(ValueError):
            MODULE.initialize(folder, source='source\nnew paragraph')
        with self.assertRaises(ValueError):
            MODULE.pairs(['tool=first', 'tool=second'])

    def test_fifo_state_does_not_block_record_recovery(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, _ = self.start(folder)
            (directory / 'state.json').unlink()
            os.mkfifo(directory / 'state.json', 0o600)
            result = subprocess.run(['python3', str(SPEC.origin), 'show', str(directory)],
                                    capture_output=True, text=True, timeout=2)
            self.assertEqual(result.returncode, 1)
            self.assertIn('invalid', result.stdout)


if __name__ == '__main__':
    unittest.main()
