#!/usr/bin/env python3
"""Collect bounded origin HEAD results on a verified source when guest curl lacks safe options."""

import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

HOST = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+')
LIMIT = 12


def redirect_authority(value):
    # curl redirect_url: https://main.example:8443/private?token=SECRET
    # -> https://main.example:8443. Never retain paths, credentials or queries.
    try:
        url = urlsplit(value)
        host = url.hostname or ''
        if url.scheme not in ('http', 'https') or not HOST.fullmatch(host) or url.username is not None:
            return None
        return url.scheme + '://' + host + (f':{url.port}' if url.port else '')
    except ValueError:
        return None


def origin_probes(records, source_address, run=subprocess.run):
    source = ipaddress.ip_address(source_address)
    address = str(source) if source.version == 4 else f'[{source}]'
    configured = set()
    for row in records:
        if row.get('type') == 'website':
            name, port = row.get('name'), row.get('port')
            if isinstance(name, str) and HOST.fullmatch(name):
                configured.add((name.lower(), port))
    results = []
    seen = set()
    for row in records:
        if row.get('type') != 'website_probe' or row.get('reason') not in ('curl_unsupported', 'curl_unavailable'):
            continue
        host, scheme, port = row.get('name'), row.get('protocol'), row.get('port')
        if not isinstance(host, str) or not HOST.fullmatch(host) or len(host) > 253:
            continue
        if scheme not in ('http', 'https') or not isinstance(port, str) or not re.fullmatch(r'[0-9]{1,5}', port) or not 1 <= int(port) <= 65535:
            continue
        host = host.lower()
        if (host, port) not in configured and not (port in ('80', '443') and any(
                (host, default) in configured for default in ('80', '443', 'unknown'))):
            continue
        if (host, scheme, port) in seen:
            continue
        seen.add((host, scheme, port))
        if len(results) == LIMIT:
            break
        url = f'{scheme}://{host}:{port}/'
        cmd = ['curl', '-q', '--globoff', '--silent', '--head', '--output', '/dev/null',
               '--noproxy', '*', '--connect-timeout', '1', '--max-time', '2',
               '--max-redirs', '0', '--proto', '=http,https', '--resolve',
               f'{host}:{port}:{address}', '--write-out', '%{http_code}\n%{redirect_url}', '--', url]
        row = {'hostname': host, 'scheme': scheme, 'port': int(port), 'vantage': 'source_pinned_origin'}
        try:
            response = run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=3, check=False)
            # curl write-out: "301\nhttps://main.example/path" -> code 301 and redirect authority.
            code, _, redirect = response.stdout[:4096].decode('ascii', errors='replace').partition('\n')
            row['http_status'] = int(code) if response.returncode == 0 and re.fullmatch(r'[1-5][0-9]{2}', code) else None
            row['curl_status'] = response.returncode
            if row['http_status'] is not None and 300 <= row['http_status'] < 400:
                row['redirect_authority'] = redirect_authority(redirect.strip())
        except subprocess.TimeoutExpired:
            row.update(http_status=None, reason='timeout')
        except OSError:
            row.update(http_status=None, reason='curl_unavailable')
            results.append(row)
            break
        results.append(row)
    return {'limit': LIMIT, 'limit_reached': len(seen) > LIMIT, 'observations': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--source-address', required=True, help='verified job source IP')
    args = parser.parse_args()
    try:
        if not args.manifest.is_file():
            raise ValueError('expected regular manifest file')
        with args.manifest.open('rb') as stream:
            data = stream.read(16 * 1024 ** 2 + 1)
        if len(data) > 16 * 1024 ** 2:
            raise ValueError('manifest too large')
        records = json.loads(data)['records']
        if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
            raise ValueError('invalid records')
        print(json.dumps(origin_probes(records, args.source_address), sort_keys=True))
    except (KeyError, OSError, TypeError, ValueError):
        print('Origin checks require a readable JSON manifest and verified source address.', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
