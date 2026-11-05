#!/usr/bin/env python3
"""Bounded agent checks and classification of an approved SSH diagnostic excerpt."""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess


def classify_ssh(status, diagnostic):
    if type(status) is not int or not 0 <= status <= 255 or len(diagnostic) > 16384:
        raise ValueError('invalid status or oversized diagnostic')
    # OpenSSH stderr: "debug1: Offering public key: ..." then "Permission
    # denied (publickey)." -> authentication_denied, never proof of a bad key.
    # Only fixed reason labels leave this classifier; arguments/key comments stay out.
    lower = diagnostic.lower()
    offered = 'offering public key:' in lower
    if status == 0:
        reason, action = 'connected', 'continue_with_recorded_discovery_scope'
    elif 'remote host identification has changed' in lower or 'offending ' in lower and ' key in ' in lower:
        reason, action = 'changed_host_key', 'resolve_expected_identity_before_retry'
    elif 'host key verification failed' in lower or 'no matching host key type found' in lower:
        reason, action = 'host_trust_unresolved', 'reuse_or_resolve_recorded_host_trust_policy'
    elif 'agent refused operation' in lower or 'communication with agent failed' in lower:
        # OpenSSH appends a generic authentication denial after a signing-agent
        # failure. Keep the explicit local cause ahead of that final fallback.
        reason, action = 'agent_unavailable', 'revalidate_operator_designated_agent'
    elif 'operation not permitted' in lower or 'permission denied' in lower and 'connect to host' in lower:
        reason, action = 'local_access_denied', 'resolve_execution_or_socket_permission'
    elif status in (124, 137) or 'connection timed out' in lower or 'operation timed out' in lower:
        reason, action = 'route_or_probe_timeout', 'verify_recorded_route_and_timeout_layer'
    elif any(marker in lower for marker in ('connection refused', 'no route to host', 'network is unreachable', 'connection reset', 'could not resolve hostname')):
        reason, action = 'route_unavailable', 'verify_recorded_endpoint_or_authorized_bastion'
    elif 'permission denied' in lower or 'authentication failed' in lower or 'too many authentication failures' in lower:
        reason, action = 'authentication_denied', 'request_bounded_server_denial_reason_or_known_working_route'
    else:
        reason, action = 'unknown_failure', 'request_only_missing_bounded_layer_evidence'
    return {'status': reason, 'public_key_offered': offered, 'next_action': action}


def check_agent(socket, expected=None, timeout=5):
    if not 0 < timeout <= 30:
        raise ValueError('timeout must be greater than zero and at most 30 seconds')
    path = Path(socket)
    if not path.is_absolute():
        raise ValueError('operator-designated socket must be absolute')
    if expected and not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{20,100}={0,2}', expected):
        raise ValueError('expected identity must be a SHA256 public fingerprint')
    try:
        if not stat.S_ISSOCK(path.stat().st_mode):
            return {'status': 'agent_socket_missing', 'fingerprints': []}
    except OSError:
        return {'status': 'agent_socket_missing', 'fingerprints': []}
    environment = os.environ.copy()
    environment['SSH_AUTH_SOCK'] = str(path)
    try:
        # Query only the socket explicitly supplied for this job. No directory
        # search or global agent mutation is needed when a proxy has gone stale.
        result = subprocess.run(['ssh-add', '-l', '-E', 'sha256'], env=environment, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {'status': 'agent_timeout', 'fingerprints': []}
    except (PermissionError, FileNotFoundError):
        return {'status': 'local_access_denied_or_client_missing', 'fingerprints': []}
    if len(result.stdout) > 16384 or len(result.stderr) > 16384:
        return {'status': 'agent_output_unrecognised', 'fingerprints': []}
    if result.returncode:
        empty = b'no identities' in (result.stdout + result.stderr).lower()
        return {'status': 'agent_empty' if empty else 'agent_unavailable', 'fingerprints': []}
    fingerprints = []
    for line in result.stdout.decode('ascii', errors='replace').splitlines():
        # ssh-add -l -E sha256: "256 SHA256:AbCd... private comment (ED25519)"
        # -> fingerprint only. The size/comment/identity label are never returned.
        match = re.match(r'^\d+ (SHA256:[A-Za-z0-9+/]{20,100}={0,2})(?:[ \t]|$)', line)
        if not match:
            return {'status': 'agent_output_unrecognised', 'fingerprints': []}
        fingerprints.append(match.group(1))
    if not fingerprints:
        return {'status': 'agent_empty', 'fingerprints': []}
    reason = 'agent_identity_mismatch' if expected and expected not in fingerprints else 'agent_ready'
    return {'status': reason, 'fingerprints': sorted(set(fingerprints))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    agent = commands.add_parser('agent')
    agent.add_argument('--socket', required=True)
    agent.add_argument('--expected-fingerprint')
    agent.add_argument('--timeout', type=float, default=5)
    ssh = commands.add_parser('ssh')
    ssh.add_argument('--status', type=int, required=True)
    ssh.add_argument('--diagnostic', type=Path, required=True, help='explicitly approved bounded client diagnostic excerpt')
    args = parser.parse_args(argv)
    try:
        if args.command == 'agent':
            result = check_agent(args.socket, args.expected_fingerprint, args.timeout)
            success = result['status'] == 'agent_ready'
        else:
            # A bounded excerpt must also be a regular file: opening a FIFO can
            # block forever before read(n) gets a chance to enforce its limit.
            descriptor = os.open(args.diagnostic, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as handle:
                metadata = os.fstat(handle.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16384:
                    raise ValueError('diagnostic must be a bounded regular file')
                raw = handle.read(16385)
            if len(raw) > 16384:
                raise ValueError('diagnostic excerpt exceeds 16 KiB')
            result = classify_ssh(args.status, raw.decode('utf-8', errors='replace'))
            success = result['status'] == 'connected'
    except (OSError, ValueError):
        result, success = {'status': 'invalid_or_unavailable_input'}, False
    print(json.dumps(result, sort_keys=True))
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
