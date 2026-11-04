#!/usr/bin/env python3
"""Bounded, status-only availability samples from an explicitly named observer."""

import argparse
import datetime as dt
import errno
import ipaddress
import json
import math
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.parse


class Stop:
    requested = False
    signal_name = None

    def handle(self, number, _frame):
        self.requested = True
        self.signal_name = signal.Signals(number).name


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def finite_number(value, label, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not minimum <= value <= maximum:
        raise ValueError(label + ' outside supported bounds')
    return value


def dns_question(name, qtype):
    # RFC 1035 wire question: example.invalid, A ->
    # b'\x07example\x07invalid\x00\x00\x01\x00\x01' (QNAME, QTYPE=1, QCLASS=1).
    # Explicit ASCII labels avoid IDNA/search-domain transformations on probes.
    if not isinstance(name, str) or not 1 <= len(name.rstrip('.')) <= 253 or not name.isascii():
        raise ValueError('DNS question must be an explicit ASCII name')
    labels = name.rstrip('.').split('.')
    if any(not 1 <= len(label) <= 63 or any(not (char.isalnum() or char in '-_') for char in label) for label in labels):
        raise ValueError('invalid DNS question label')
    types = {'A': 1, 'AAAA': 28, 'SOA': 6}
    if qtype not in types:
        raise ValueError('DNS qtype must be A, AAAA, or SOA')
    return b''.join(bytes([len(label)]) + label.encode('ascii') for label in labels) + b'\0' + struct.pack('!HH', types[qtype], 1)


def validate_config(config):
    if not isinstance(config, dict) or not isinstance(config.get('observer'), str) or not config['observer'].strip() or len(config['observer']) > 128:
        raise ValueError('an explicit observer label is required')
    targets = config.get('targets')
    if not isinstance(targets, list) or not 1 <= len(targets) <= 32:
        raise ValueError('provide between 1 and 32 targets')
    names = set()
    result = []
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError('target must be an object')
        name = target.get('name')
        if not isinstance(name, str) or not name.strip() or len(name) > 128 or name in names:
            raise ValueError('target names must be unique nonempty labels')
        names.add(name)
        family = target.get('family')
        if family not in ('ipv4', 'ipv6'):
            raise ValueError('each target needs explicit ipv4 or ipv6 family')
        protocol = target.get('protocol')
        safe = {'name': name, 'family': family, 'protocol': protocol}
        if protocol in ('http', 'https'):
            url = target.get('url')
            if not isinstance(url, str) or any(ord(char) < 32 for char in url):
                raise ValueError('HTTP URL is invalid')
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme != protocol or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
                raise ValueError('HTTP URL must match protocol and contain no credentials, query, or fragment')
            # Force validation of malformed or out-of-range URL ports.
            parsed.port
            # curl's --ipv4/--ipv6 selects DNS resolution. A literal URL such as
            # https://[2001:db8::1]/health already supplies IPv6; recording ipv4
            # for it would mislabel the observation even if the connection worked.
            try:
                literal = ipaddress.ip_address(parsed.hostname)
            except ValueError:
                literal = None
            if literal is not None and literal.version != (4 if family == 'ipv4' else 6):
                raise ValueError('HTTP literal address must match the selected family')
            safe['url'] = url
            statuses = target.get('expected_statuses', list(range(200, 400)))
            if not isinstance(statuses, list) or not statuses or any(type(code) is not int or not 100 <= code <= 599 for code in statuses):
                raise ValueError('expected_statuses must contain HTTP status integers')
            safe['expected_statuses'] = sorted(set(statuses))
        elif protocol in ('tcp', 'dns'):
            address = target.get('address')
            if not isinstance(address, str) or '%' in address:
                raise ValueError('TCP/DNS require a literal IP address without a zone identifier')
            ip = ipaddress.ip_address(address)
            if ip.version != (4 if family == 'ipv4' else 6):
                raise ValueError('literal address must match the selected family')
            port = target.get('port', 53 if protocol == 'dns' else None)
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError('a valid port is required')
            safe.update(address=str(ip), port=port)
            if protocol == 'dns':
                safe['question'] = target.get('question')
                safe['qtype'] = target.get('qtype', 'SOA')
                dns_question(safe['question'], safe['qtype'])
                rcodes = target.get('expected_rcodes', [0])
                if not isinstance(rcodes, list) or not rcodes or any(type(code) is not int or not 0 <= code <= 15 for code in rcodes):
                    raise ValueError('expected_rcodes must be DNS response-code integers')
                safe['expected_rcodes'] = sorted(set(rcodes))
        else:
            raise ValueError('protocol must be http, https, tcp, or dns')
        result.append(safe)
    return {'observer': config['observer'], 'targets': result}


def probe_http(target, timeout):
    # --disable is first: do not read .curlrc, credentials, or implicit client
    # options. HEAD + /dev/null discards headers/body; stdout is status code only.
    command = ['curl', '--disable', '--silent', '--globoff', '--head', '--output', os.devnull,
               '--write-out', '%{http_code}', '--max-time', str(timeout), '--connect-timeout', str(timeout),
               '--noproxy', '*', '--proxy', '', '--proto', '=http,https',
               '--ipv4' if target['family'] == 'ipv4' else '--ipv6', '--', target['url']]
    try:
        response = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except FileNotFoundError:
        return {'status': 'unknown', 'reason': 'client_unavailable'}
    except subprocess.TimeoutExpired:
        return {'status': 'failed', 'reason': 'timeout'}
    except OSError:
        return {'status': 'unknown', 'reason': 'client_execution_error'}
    if response.returncode:
        reasons = {5: 'proxy_resolution_failed', 6: 'name_resolution_failed', 7: 'connection_failed',
                   28: 'timeout', 35: 'tls_failed', 51: 'tls_failed', 60: 'tls_failed'}
        return {'status': 'failed' if response.returncode in reasons else 'unknown',
                'reason': reasons.get(response.returncode, 'client_error')}
    # curl --write-out %{http_code}: b'200' -> integer 200; reject all other
    # output rather than retaining unexpected client content or response bodies.
    raw = response.stdout
    if len(raw) != 3 or any(byte < 48 or byte > 57 for byte in raw):
        return {'status': 'unknown', 'reason': 'invalid_client_status'}
    code = int(raw)
    if not 100 <= code <= 599:
        return {'status': 'unknown', 'reason': 'invalid_client_status'}
    return {'status': 'ok' if code in target['expected_statuses'] else 'failed',
            'reason': 'http_status', 'http_status': code}


def probe_socket(target, timeout):
    family = socket.AF_INET if target['family'] == 'ipv4' else socket.AF_INET6
    kind = socket.SOCK_DGRAM if target['protocol'] == 'dns' else socket.SOCK_STREAM
    try:
        deadline = time.monotonic() + timeout
        with socket.socket(family, kind) as client:
            client.settimeout(timeout)
            client.connect((target['address'], target['port']))
            if target['protocol'] == 'tcp':
                return {'status': 'ok', 'reason': 'tcp_connected'}
            ident = secrets.randbits(16)
            question = dns_question(target['question'], target['qtype'])
            query = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + question
            client.settimeout(max(0.001, deadline - time.monotonic()))
            client.send(query)
            client.settimeout(max(0.001, deadline - time.monotonic()))
            response = client.recv(4096)
            # RFC 1035 response header !6H: ID, flags, QDCOUNT, ANCOUNT,
            # NSCOUNT, ARCOUNT. Only header and echoed question are inspected;
            # answer data never enters the status records.
            if len(response) < 12 or len(response) >= 4096:
                return {'status': 'unknown', 'reason': 'malformed_dns_response'}
            reply_id, flags, questions, _, _, _ = struct.unpack('!HHHHHH', response[:12])
            if reply_id != ident or not flags & 0x8000 or questions != 1 or response[12:12 + len(question)] != question:
                return {'status': 'unknown', 'reason': 'unmatched_dns_response'}
            if flags & 0x0200:
                return {'status': 'unknown', 'reason': 'truncated_dns_response'}
            rcode = flags & 15
            return {'status': 'ok' if rcode in target['expected_rcodes'] else 'failed',
                    'reason': 'dns_response', 'dns_rcode': rcode}
    except (socket.timeout, TimeoutError):
        return {'status': 'failed', 'reason': 'timeout'}
    except ConnectionRefusedError:
        return {'status': 'failed', 'reason': 'connection_refused'}
    except OSError as error:
        if error.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EPERM, errno.EACCES, errno.ENOSYS):
            return {'status': 'unknown', 'reason': 'local_probe_unavailable'}
        if error.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNRESET, errno.ETIMEDOUT, errno.ENETDOWN, errno.EHOSTDOWN):
            return {'status': 'failed', 'reason': 'network_error'}
        return {'status': 'unknown', 'reason': 'probe_error'}


def probe(target, timeout):
    return probe_http(target, timeout) if target['protocol'] in ('http', 'https') else probe_socket(target, timeout)


def summarize(records, targets, observer, started, finished, interval, stopped=None):
    summary = {'schema_version': 1, 'observer': observer, 'started_at': started, 'finished_at': finished,
               'interval_seconds': interval, 'stop_reason': stopped or 'duration_complete', 'targets': []}
    for target in targets:
        samples = [row for row in records if row['target'] == target['name']]
        counts = {status: sum(row['status'] == status for row in samples) for status in ('ok', 'failed', 'unknown')}
        episodes = []
        current = None
        last_ok = None
        gaps = []
        previous = None
        for row in samples:
            if previous is not None and row['elapsed_seconds'] - previous['elapsed_seconds'] > interval * 1.5:
                gaps.append({'after': previous['started_at'], 'before': row['started_at'],
                             'seconds_between_samples': round(row['elapsed_seconds'] - previous['elapsed_seconds'], 3)})
            if row['status'] == 'failed':
                if current is None:
                    current = {'last_success_before': last_ok, 'first_failure': row['started_at'],
                               'last_failure': row['started_at'], 'first_success_after': None,
                               'left_censored': last_ok is None, 'right_censored': True,
                               'unknown_samples_during_window': 0}
                current['last_failure'] = row['started_at']
            elif row['status'] == 'ok':
                if current is not None:
                    current['first_success_after'] = row['started_at']
                    current['right_censored'] = False
                    episodes.append(current)
                    current = None
                last_ok = row['started_at']
            elif current is not None:
                current['unknown_samples_during_window'] += 1
            previous = row
        if current is not None:
            episodes.append(current)
        summary['targets'].append({'name': target['name'], 'protocol': target['protocol'], 'family': target['family'],
                                   'counts': counts, 'samples': len(samples), 'gaps': gaps, 'failure_windows': episodes,
                                   'unobserved': not samples,
                                   'first_sample_at': samples[0]['started_at'] if samples else None,
                                   'last_sample_at': samples[-1]['started_at'] if samples else None,
                                   'measurement_limit': 'Samples bound observations; unknown samples and gaps are not service failures or exact downtime.'})
    return summary


def write_json(path, value):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def run(config, output, duration, interval, timeout, max_samples=10000, stop=None,
        probe_fn=probe, monotonic=time.monotonic, now=utc_now, sleep=time.sleep):
    config = validate_config(config)
    finite_number(duration, 'duration', 1, 86400)
    finite_number(interval, 'interval', 0.1, 3600)
    finite_number(timeout, 'timeout', 0.1, 30)
    if type(max_samples) is not int or not 1 <= max_samples <= 100000:
        raise ValueError('max samples must be between 1 and 100000')
    output = Path(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    stop = stop or Stop()
    started = now()
    start_mono = monotonic()
    deadline = start_mono + duration
    schedule = start_mono
    records = []
    reason = None
    write_json(output / 'monitor.json', {'schema_version': 1, 'config': config, 'started_at': started,
                                        'duration_seconds': duration, 'interval_seconds': interval,
                                        'timeout_seconds': timeout, 'max_samples': max_samples})
    fd = os.open(str(output / 'samples.jsonl'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            while monotonic() < deadline and not stop.requested:
                if len(records) >= max_samples:
                    reason = 'sample_limit'
                    break
                first_cycle = not records
                for target in config['targets']:
                    remaining = deadline - monotonic()
                    if remaining <= 0 or stop.requested or len(records) >= max_samples:
                        break
                    sample_start = monotonic()
                    observed = now()
                    answer = probe_fn(target, min(timeout, remaining))
                    # Only allow fixed status fields into durable output. Custom
                    # clients cannot accidentally retain content or stderr here.
                    status = answer.get('status')
                    if status not in ('ok', 'failed', 'unknown'):
                        raise ValueError('probe returned an invalid status')
                    row = {'observer': config['observer'], 'target': target['name'], 'protocol': target['protocol'],
                           'family': target['family'], 'started_at': observed, 'finished_at': now(),
                           'elapsed_seconds': round(sample_start - start_mono, 3),
                           'latency_seconds': round(monotonic() - sample_start, 3), 'status': status}
                    for key in ('reason', 'http_status', 'dns_rcode'):
                        if key in answer:
                            row[key] = answer[key]
                    records.append(row)
                    stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + '\n')
                    stream.flush()
                if first_cycle and len(records) == len(config['targets']):
                    write_json(output / 'ready.json', {'observer': config['observer'], 'first_cycle_complete_at': now(),
                                                       'baseline_healthy': all(row['status'] == 'ok' for row in records),
                                                       'targets': {row['target']: row['status'] for row in records}})
                if len(records) >= max_samples:
                    reason = 'sample_limit'
                    break
                schedule += interval
                # Skip missed slots instead of rapid catch-up samples. Persisted
                # elapsed times expose the resulting coverage gaps in summary.
                current_time = monotonic()
                while schedule < current_time:
                    schedule += interval
                wait_until = min(schedule, deadline)
                while monotonic() < wait_until and not stop.requested:
                    sleep(min(0.1, wait_until - monotonic()))
    except BaseException:
        reason = 'monitor_error'
        raise
    finally:
        if stop.requested:
            reason = stop.signal_name or 'cancelled'
        summary = summarize(records, config['targets'], config['observer'], started, now(), interval, reason)
        write_json(output / 'summary.json', summary)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='new private output directory; parent must exist')
    parser.add_argument('--duration', required=True, type=float, help='bounded lifetime in seconds, maximum 86400')
    parser.add_argument('--interval', type=float, default=5)
    parser.add_argument('--timeout', type=float, default=3)
    parser.add_argument('--max-samples', type=int, default=10000)
    args = parser.parse_args(argv)
    os.umask(0o077)
    stop = Stop()
    signal.signal(signal.SIGINT, stop.handle)
    signal.signal(signal.SIGTERM, stop.handle)
    try:
        with args.config.open(encoding='utf-8') as stream:
            config = json.load(stream)
        summary = run(config, args.output, args.duration, args.interval, args.timeout, args.max_samples, stop)
        print('Saved status samples and summary to %s (%s).' % (args.output, summary['stop_reason']))
        return 0
    except (OSError, ValueError, TypeError, OverflowError) as error:
        print('Stopped: invalid monitor configuration or inaccessible output (%s).' % type(error).__name__, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
