#!/usr/bin/env python3
"""Mocked SSH diagnostics and designated sockets, without a remote connection."""

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location('access_check', Path(__file__).resolve().parents[1] / 'scripts/access-check.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
FINGERPRINT = 'SHA256:' + 'A' * 43


class AccessTests(unittest.TestCase):
    def test_offered_key_does_not_explain_authentication_denial(self):
        result = MODULE.classify_ssh(255, 'debug1: Offering public key: PRIVATE-COMMENT\nPermission denied (publickey).')
        self.assertEqual(result['status'], 'authentication_denied')
        self.assertTrue(result['public_key_offered'])
        self.assertIn('server_denial_reason', result['next_action'])
        self.assertNotIn('PRIVATE-COMMENT', json.dumps(result))

    def test_host_key_failure_takes_precedence(self):
        result = MODULE.classify_ssh(255, 'REMOTE HOST IDENTIFICATION HAS CHANGED\nPermission denied')
        self.assertEqual(result['status'], 'changed_host_key')

    def test_agent_signing_error_precedes_generic_authentication_denial(self):
        result = MODULE.classify_ssh(255, 'sign_and_send_pubkey: signing failed from agent: agent refused operation\nPermission denied (publickey).')
        self.assertEqual(result['status'], 'agent_unavailable')
        self.assertEqual(result['next_action'], 'revalidate_operator_designated_agent')

    def test_layered_fixed_outcomes(self):
        for status, diagnostic, expected in [(0, '', 'connected'), (255, 'Host key verification failed', 'host_trust_unresolved'),
                                             (255, 'connect to host: Permission denied', 'local_access_denied'),
                                             (124, '', 'route_or_probe_timeout'), (255, 'Connection refused', 'route_unavailable'),
                                             (255, 'communication with agent failed', 'agent_unavailable'), (2, 'unfamiliar', 'unknown_failure')]:
            with self.subTest(expected=expected):
                self.assertEqual(MODULE.classify_ssh(status, diagnostic)['status'], expected)

    def with_socket(self, result, callback):
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / 'designated.sock')
            with mock.patch.object(MODULE.Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK)):
                with mock.patch.object(MODULE.subprocess, 'run', return_value=result) as run:
                    callback(path, run)

    def test_designated_socket_and_fingerprint_only(self):
        result = subprocess.CompletedProcess([], 0, ('256 ' + FINGERPRINT + ' SECRET-COMMENT (ED25519)\n').encode(), b'')
        def verify(path, run):
            found = MODULE.check_agent(path, FINGERPRINT)
            self.assertEqual(found, {'status': 'agent_ready', 'fingerprints': [FINGERPRINT]})
            self.assertEqual(run.call_args.kwargs['env']['SSH_AUTH_SOCK'], path)
            self.assertNotIn('SECRET-COMMENT', json.dumps(found))
            self.assertEqual(MODULE.check_agent(path, 'SHA256:' + 'B' * 43)['status'], 'agent_identity_mismatch')
        self.with_socket(result, verify)

    def test_empty_agent_and_malformed_output(self):
        for process, reason in [(subprocess.CompletedProcess([], 1, b'The agent has no identities.', b''), 'agent_empty'),
                                (subprocess.CompletedProcess([], 0, b'malformed private output', b''), 'agent_output_unrecognised')]:
            self.with_socket(process, lambda path, run: self.assertEqual(MODULE.check_agent(path)['status'], reason))

    def test_hanging_agent_is_bounded(self):
        def verify(path, run):
            run.side_effect = subprocess.TimeoutExpired('ssh-add', 5)
            self.assertEqual(MODULE.check_agent(path)['status'], 'agent_timeout')
        self.with_socket(None, verify)

    def test_regular_file_is_not_queried_as_socket(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(MODULE.subprocess, 'run') as run:
            path = Path(folder) / 'ordinary'
            path.touch()
            self.assertEqual(MODULE.check_agent(str(path))['status'], 'agent_socket_missing')
            run.assert_not_called()

    def test_fifo_diagnostic_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'diagnostic'
            os.mkfifo(path)
            result = subprocess.run(['python3', str(SPEC.origin), 'ssh', '--status', '255', '--diagnostic', str(path)],
                                    capture_output=True, text=True, timeout=2)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)['status'], 'invalid_or_unavailable_input')


if __name__ == '__main__':
    unittest.main()
