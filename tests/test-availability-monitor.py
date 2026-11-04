#!/usr/bin/env python3
"""Offline sampler checks: every network and subprocess operation is mocked."""
import errno
import importlib.util
import json
from pathlib import Path
import socket
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('availability_monitor', Path(__file__).resolve().parents[1] / 'scripts/availability-monitor.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def config():
    return {'observer': 'synthetic-runner', 'targets': [{'name': 'web', 'protocol': 'https', 'family': 'ipv4', 'url': 'https://example.invalid/health'}]}


def dns_target():
    return MODULE.validate_config({'observer': 'fixture', 'targets': [{'name': 'dns', 'protocol': 'dns', 'family': 'ipv6', 'address': '2001:db8::53', 'question': 'example.invalid', 'qtype': 'SOA'}]})['targets'][0]


class Clock:
    value = 0.0

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds

    def now(self):
        return 'synthetic-%.3f' % self.value


class ConfigTests(unittest.TestCase):
    def test_explicit_observer_family_and_endpoint(self):
        valid = MODULE.validate_config(config())
        self.assertEqual(valid['targets'][0]['family'], 'ipv4')
        self.assertEqual(dns_target()['port'], 53)
        for change in ({'family': None}, {'url': 'https://user:password@example.invalid/'}, {'url': 'https://example.invalid/?token=secret'}, {'url': 'https://example.invalid/#secret'}, {'url': 'http://example.invalid/'}, {'url': 'https://example.invalid:99999/'}):
            bad = config()
            bad['targets'][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                MODULE.validate_config(bad)
        with self.assertRaises(ValueError):
            MODULE.validate_config({'targets': config()['targets']})

    def test_http_literal_address_must_match_recorded_family(self):
        for url, family in (('https://[2001:db8::1]/health', 'ipv4'),
                            ('https://192.0.2.1/health', 'ipv6')):
            source = config()
            source['targets'][0].update(url=url, family=family)
            with self.subTest(url=url, family=family), self.assertRaises(ValueError):
                MODULE.validate_config(source)
        source = config()
        source['targets'][0].update(url='https://[2001:db8::1]/health', family='ipv6')
        self.assertEqual(MODULE.validate_config(source)['targets'][0]['family'], 'ipv6')

    def test_literal_tcp_dns_family_and_wire_question(self):
        self.assertEqual(MODULE.dns_question('example.invalid', 'A'), b'\x07example\x07invalid\x00\x00\x01\x00\x01')
        for address, family in (('example.invalid', 'ipv4'), ('192.0.2.1', 'ipv6'), ('fe80::1%eth0', 'ipv6')):
            with self.subTest(address=address), self.assertRaises(ValueError):
                MODULE.validate_config({'observer': 'fixture', 'targets': [{'name': 'port', 'protocol': 'tcp', 'address': address, 'family': family, 'port': 443}]})
        for question in ('', 'a..invalid', 'a'*64 + '.invalid', 'secret\n.invalid'):
            with self.subTest(question=question), self.assertRaises(ValueError):
                MODULE.dns_question(question, 'A')


class ProbeTests(unittest.TestCase):
    def target(self):
        return MODULE.validate_config(config())['targets'][0]

    def test_status_only_http_command_and_result(self):
        response = subprocess.CompletedProcess([], 0, b'204')
        with patch.object(MODULE.subprocess, 'run', return_value=response) as run:
            result = MODULE.probe_http(self.target(), 2)
        self.assertEqual(result, {'status': 'ok', 'reason': 'http_status', 'http_status': 204})
        command = run.call_args.args[0]
        self.assertEqual(command[:2], ['curl', '--disable'])
        for flag in ('--head', '--ipv4', '--noproxy', '--proto'):
            self.assertIn(flag, command)
        self.assertEqual(run.call_args.kwargs['stderr'], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs['timeout'], 2)

    def test_missing_client_timeout_failure_and_unexpected_stdout(self):
        for response, expected in ((FileNotFoundError(), ('unknown', 'client_unavailable')), (subprocess.TimeoutExpired('curl', 2), ('failed', 'timeout')), (subprocess.CompletedProcess([], 28, b''), ('failed', 'timeout')), (subprocess.CompletedProcess([], 0, b'sensitive-response-body'), ('unknown', 'invalid_client_status')), (subprocess.CompletedProcess([], 0, b'503'), ('failed', 'http_status'))):
            context = patch.object(MODULE.subprocess, 'run', side_effect=response) if isinstance(response, Exception) else patch.object(MODULE.subprocess, 'run', return_value=response)
            with self.subTest(expected=expected), context:
                result = MODULE.probe_http(self.target(), 2)
                self.assertEqual((result['status'], result['reason']), expected)
                self.assertNotIn('sensitive', json.dumps(result))

    def dns_response(self, flags=0x8180, ident=123, question=None):
        question = MODULE.dns_question('example.invalid', 'SOA') if question is None else question
        return struct.pack('!HHHHHH', ident, flags, 1, 1, 0, 0) + question + b'private-answer-data-not-retained'

    def test_dns_only_retains_matching_header_status(self):
        client = Mock()
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=False)
        client.recv.return_value = self.dns_response()
        with patch.object(MODULE.socket, 'socket', return_value=client), patch.object(MODULE.secrets, 'randbits', return_value=123):
            result = MODULE.probe_socket(dns_target(), 1)
        self.assertEqual(result, {'status': 'ok', 'reason': 'dns_response', 'dns_rcode': 0})
        self.assertNotIn('private-answer', json.dumps(result))
        client.connect.assert_called_once_with(('2001:db8::53', 53))

    def test_dns_timeout_truncation_mismatch_and_error(self):
        for response, expected in ((socket.timeout(), 'timeout'), (self.dns_response(0x8380), 'truncated_dns_response'), (self.dns_response(ident=999), 'unmatched_dns_response'), (b'bad', 'malformed_dns_response'), (self.dns_response(0x8182), 'dns_response')):
            client = Mock()
            client.__enter__ = Mock(return_value=client)
            client.__exit__ = Mock(return_value=False)
            if isinstance(response, Exception):
                client.recv.side_effect = response
            else:
                client.recv.return_value = response
            with self.subTest(expected=expected), patch.object(MODULE.socket, 'socket', return_value=client), patch.object(MODULE.secrets, 'randbits', return_value=123):
                result = MODULE.probe_socket(dns_target(), 1)
                self.assertEqual(result['reason'], expected)
                self.assertIn(result['status'], ('unknown', 'failed'))

    def test_local_client_family_and_permission_failures_are_unknown(self):
        for error in (OSError(errno.EAFNOSUPPORT, 'unsupported'), PermissionError(errno.EACCES, 'blocked')):
            with self.subTest(error=error), patch.object(MODULE.socket, 'socket', side_effect=error):
                self.assertEqual(MODULE.probe_socket(dns_target(), 1), {'status': 'unknown', 'reason': 'local_probe_unavailable'})
        with patch.object(MODULE.socket, 'socket', side_effect=OSError(errno.ENETUNREACH, 'unreachable')):
            self.assertEqual(MODULE.probe_socket(dns_target(), 1), {'status': 'failed', 'reason': 'network_error'})

    def test_tcp_connection_requires_no_application_payload(self):
        target = MODULE.validate_config({'observer': 'fixture', 'targets': [{'name': 'port', 'protocol': 'tcp', 'family': 'ipv4', 'address': '192.0.2.10', 'port': 443}]})['targets'][0]
        client = Mock()
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=False)
        with patch.object(MODULE.socket, 'socket', return_value=client):
            self.assertEqual(MODULE.probe_socket(target, 1)['status'], 'ok')
        client.send.assert_not_called()
        client.recv.assert_not_called()


class SamplingTests(unittest.TestCase):
    def test_bounded_run_private_files_and_no_response_content(self):
        clock = Clock()
        def fake_probe(_target, timeout):
            self.assertLessEqual(timeout, 1)
            clock.value += 0.05
            return {'status': 'ok', 'reason': 'fixture', 'body': 'not-retained', 'stderr': 'not-retained'}
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'run'
            summary = MODULE.run(config(), output, 2, 0.5, 1, probe_fn=fake_probe, monotonic=clock.monotonic, now=clock.now, sleep=clock.sleep)
            self.assertLessEqual(clock.value, 2.00001)
            self.assertEqual(summary['targets'][0]['counts']['ok'], 4)
            self.assertTrue(json.loads((output / 'ready.json').read_text())['baseline_healthy'])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            for path in output.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertNotIn('not-retained', path.read_text())
            with self.assertRaises(FileExistsError):
                MODULE.run(config(), output, 2, 1, 1)

    def test_sample_limit_finishes_without_waiting_for_interval(self):
        clock = Clock()
        with tempfile.TemporaryDirectory() as folder:
            summary = MODULE.run(config(), Path(folder) / 'run', 10, 5, 1, max_samples=1,
                                 probe_fn=lambda _target, _timeout: {'status': 'ok'},
                                 monotonic=clock.monotonic, now=clock.now, sleep=clock.sleep)
            self.assertEqual(summary['stop_reason'], 'sample_limit')
            self.assertEqual(clock.value, 0)

    def test_cancel_finalizes_summary(self):
        stop = MODULE.Stop()
        clock = Clock()
        def cancel(_target, _timeout):
            stop.requested = True
            stop.signal_name = 'SIGTERM'
            return {'status': 'failed', 'reason': 'fixture'}
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'run'
            summary = MODULE.run(config(), output, 10, 1, 1, stop=stop, probe_fn=cancel, monotonic=clock.monotonic, now=clock.now, sleep=clock.sleep)
            self.assertEqual(summary['stop_reason'], 'SIGTERM')
            self.assertTrue((output / 'summary.json').exists())
            self.assertTrue(summary['targets'][0]['failure_windows'][0]['left_censored'])
            self.assertTrue(summary['targets'][0]['failure_windows'][0]['right_censored'])

    def test_censored_recovery_unknowns_and_sampling_gaps(self):
        def row(status, elapsed):
            return {'target': 'web', 'started_at': str(elapsed), 'elapsed_seconds': elapsed, 'status': status}
        rows = [row('failed', 0), row('unknown', 1), row('ok', 5), row('failed', 6)]
        item = MODULE.summarize(rows, config()['targets'], 'fixture', 'start', 'finish', 1)['targets'][0]
        self.assertEqual(item['counts'], {'ok': 1, 'failed': 2, 'unknown': 1})
        self.assertEqual(len(item['gaps']), 1)
        self.assertTrue(item['failure_windows'][0]['left_censored'])
        self.assertFalse(item['failure_windows'][0]['right_censored'])
        self.assertEqual(item['failure_windows'][0]['unknown_samples_during_window'], 1)
        self.assertFalse(item['failure_windows'][1]['left_censored'])
        self.assertTrue(item['failure_windows'][1]['right_censored'])
        self.assertNotIn('downtime_seconds', item)

    def test_configuration_bounds_before_output_or_probe(self):
        for duration, interval, timeout in ((0, 1, 1), (86401, 1, 1), (10, 0, 1), (10, 1, float('nan')), (10, 1, 31)):
            with tempfile.TemporaryDirectory() as folder:
                output = Path(folder) / 'run'
                fake = Mock()
                with self.subTest(bounds=(duration, interval, timeout)), self.assertRaises(ValueError):
                    MODULE.run(config(), output, duration, interval, timeout, probe_fn=fake)
                self.assertFalse(output.exists())
                fake.assert_not_called()


if __name__ == '__main__':
    unittest.main()
