#!/usr/bin/env python3
"""Isolated fixtures for runner HTTP fallback and source-side mail projections."""

import importlib.util
from io import BytesIO
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock


def load(name):
    path = Path(__file__).resolve().parents[1] / 'scripts' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WEB = load('assessment-web')
MAIL = load('assessment-mail')


class Probes(unittest.TestCase):
    def test_pinned_origin_filters_names_and_discards_redirect_details(self):
        host = 'site.example.invalid'
        records = [
            {'type': 'website', 'name': host, 'port': '443'},
            {'type': 'website_probe', 'name': 'unconfigured.example.invalid', 'port': '443',
             'protocol': 'https', 'reason': 'curl_unsupported'},
            {'type': 'website_probe', 'name': host, 'port': '443',
             'protocol': 'https', 'reason': 'curl_unsupported'},
        ]
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, b'301\nhttps://main.example.invalid:8443/x?token=SECRET'))
        result = WEB.origin_probes(records, '2001:db8::5', runner)
        runner.assert_called_once()
        command = runner.call_args.args[0]
        self.assertIn(f'{host}:443:[2001:db8::5]', command)
        self.assertIn('--noproxy', command)
        self.assertNotIn('--insecure', command)
        self.assertNotIn('--location', command)
        self.assertEqual(result['observations'][0]['redirect_authority'], 'https://main.example.invalid:8443')
        self.assertNotIn('SECRET', json.dumps(result))

    def test_mail_counts_events_and_coverage_without_record_contents(self):
        records = BytesIO(
            b'Nov 13 06:00:00 mx postfix/pickup[1]: ABC: uid=33 from=<SECRET>\n'
            b'Nov 13 06:03:00 mx postfix/smtp[1]: ABC: to=<SECRET>, relay=mx, delay=1, dsn=2.0.0, status=sent (ok)\n'
            b'2026-11-14T07:00:00+0000 mx dovecot: imap-login: Login: user=<SECRET>\n'
            b'unrecognized PRIVATE\n'
        )
        result = MAIL.summarize(records)
        self.assertEqual(result['recognized_records'], 3)
        self.assertEqual(result['unrecognized_lines'], 1)
        self.assertEqual(result['first_recognized_record'], 'Nov 13 06:00:00')
        self.assertEqual(result['last_recognized_record'], '2026-11-14T07:00:00+0000')
        self.assertEqual(result['event_counts'], {'local_submission': 1, 'smtp_relay_delivery': 1, 'imap_login': 1})
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(MAIL.summarize(BytesIO(b'x' * 25), limit=24)['coverage'], 'bounded_input')


if __name__ == '__main__':
    unittest.main()
