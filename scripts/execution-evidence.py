#!/usr/bin/env python3
"""Bounded execution evidence for explicitly approved application transitions."""

import argparse
from contextlib import ExitStack
from decimal import Decimal
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

MAX_INPUT = 1024 * 1024
# Selected schema/database names such as application_prod -> one literal client
# argument; whitespace/newline or option-like input is rejected before launch.
IDENTIFIER = re.compile(r'^[A-Za-z0-9_$.-]{1,128}$')
DIGEST = re.compile(r'^[0-9a-f]{64}$')


def bounded_bytes(path, limit=MAX_INPUT):
    # A size cap applied after ordinary open does not bound a FIFO: opening it
    # can wait forever. Nonblocking/no-follow open plus descriptor type checks
    # accepts regular proc metadata and files, while refusing pipes and sockets.
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError('bounded input must be a regular file')
        with os.fdopen(descriptor, 'rb') as stream:
            descriptor = None
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError('input exceeds bound')
        return data
    finally:
        if descriptor is not None:
            os.close(descriptor)


def decode_json(data):
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result
    return json.loads(data.decode('utf-8'), object_pairs_hook=unique_fields)


def read_json(path):
    return decode_json(bounded_bytes(path))


def private_json(path):
    # Review ownership must describe the exact object read. A prior lstat plus
    # reopening the path can follow a replacement symlink or different file.
    # Open without following links, validate fstat, then read that descriptor.
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('review must be a private operator-owned regular file')
        with os.fdopen(descriptor, 'rb') as stream:
            descriptor = None
            data = stream.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise ValueError('review input exceeds bound')
        return decode_json(data)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()


def private_parent(path):
    path = Path(path)
    if not path.is_absolute() or path.parent.resolve() != path.parent:
        raise ValueError('output needs an absolute canonical parent')
    info = path.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('output parent must be operator controlled')
    return path


def write_receipt(path, value):
    path = private_parent(path)
    # A release upgrade can remove the old Python text-codec modules while its
    # supervisor keeps running. ASCII JSON plus binary fdopen avoids a late text
    # wrapper lookup; exclusive creation preserves earlier failed receipts.
    data = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def positive_int(value, maximum):
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError('positive integer outside bounds')
    return value


def client_command(client, defaults_file, database, query):
    # The client consumes the designated file itself. Do not source credentials,
    # override its account, or append the formerly used empty --init-command.
    if not Path(defaults_file).is_absolute() or not IDENTIFIER.fullmatch(database):
        raise ValueError('explicit defaults-file and database are required')
    return [client, '--defaults-file=' + str(defaults_file), '--batch', '--raw', '--skip-column-names',
            '--database=' + database, '--execute=' + query]


def client_result(command, timeout, run=subprocess.run):
    result = run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                 timeout=timeout, check=False)
    if len(result.stdout) > MAX_INPUT or len(result.stderr) > MAX_INPUT:
        raise ValueError('client output exceeds bound')
    return result


def engine_metadata(raw):
    # mysql --batch --skip-column-names aggregation:
    # InnoDB\t12\t8192\nMyISAM\t3\t4096\n -> 15 tables; transaction-only
    # recovery is insufficient. No table names, rows or authentication data.
    rows = []
    seen = set()
    for line in raw.decode('ascii').splitlines():
        fields = line.split('\t')
        if len(fields) != 3 or not IDENTIFIER.fullmatch(fields[0]) or fields[0] in seen:
            raise ValueError('unrecognized engine aggregation')
        if any(not re.fullmatch(r'[0-9]{1,16}', value) for value in fields[1:]):
            raise ValueError('unrecognized engine counts')
        seen.add(fields[0])
        rows.append({'engine': fields[0], 'tables': int(fields[1]), 'bytes': int(fields[2])})
    nontransactional = sum(row['tables'] for row in rows if row['engine'].lower() != 'innodb')
    return {'status': 'observed', 'engines': rows, 'nontransactional_or_unverified_tables': nontransactional,
            'transaction_only_recovery_covers_all_tables': nontransactional == 0}


def collect_engines(client, defaults_file, database, timeout=10, run=subprocess.run):
    query = ("SELECT COALESCE(ENGINE,'UNKNOWN'),COUNT(*),COALESCE(SUM(DATA_LENGTH+INDEX_LENGTH),0) "
             "FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' GROUP BY ENGINE")
    try:
        result = client_result(client_command(client, defaults_file, database, query), timeout, run)
        if result.returncode:
            return {'status': 'unknown', 'reason': 'client_failed', 'transaction_only_recovery_covers_all_tables': None}
        return engine_metadata(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError):
        return {'status': 'unknown', 'reason': 'metadata_unavailable_or_malformed', 'transaction_only_recovery_covers_all_tables': None}


PROXY_QUERIES = {
    'servers': ('hostgroup_id,hostname,port,status,weight,max_connections', 'mysql_servers'),
    'rules': ('rule_id,active,destination_hostgroup,apply,timeout', 'mysql_query_rules'),
    'users': ('username,default_hostgroup,default_schema,frontend,backend', 'mysql_users'),
    'policy': ('variable_name,variable_value', 'global_variables'),
}


def proxy_projection(kind, raw):
    rows = set()
    for line in raw.decode('ascii').splitlines():
        fields = line.split('\t')
        expected = {'servers': 6, 'rules': 5, 'users': 5, 'policy': 2}[kind]
        if len(fields) != expected:
            raise ValueError('unrecognized ProxySQL projection')
        if kind == 'policy':
            name, value = fields
            if name not in ('mysql-default_query_timeout', 'mysql-connect_timeout_server', 'mysql-monitor_connect_timeout') or not re.fullmatch(r'[0-9]{1,10}', value):
                raise ValueError('unapproved or malformed ProxySQL policy')
            if any(row[0] == name for row in rows):
                raise ValueError('duplicate ProxySQL policy')
            rows.add((name, int(value)))
        elif kind == 'users':
            user, group, schema, frontend, backend = fields
            if not IDENTIFIER.fullmatch(user) or frontend not in ('0', '1') or backend not in ('0', '1'):
                raise ValueError('unrecognized ProxySQL user projection')
            if schema not in ('', 'NULL', '\\N') and not IDENTIFIER.fullmatch(schema):
                raise ValueError('unrecognized schema metadata')
            if not re.fullmatch(r'[0-9]{1,10}', group):
                raise ValueError('unrecognized hostgroup')
            # ProxySQL runtime may split frontend/backend user rows while disk
            # combines them. "app\t10\tNULL\t1\t0" and "app\t10\t\t1\t1"
            # describe the same frontend route. Backend-only rows do not route
            # frontend traffic; normalized user identities never enter output.
            if frontend == '1':
                rows.add((user, int(group), '' if schema in ('NULL', '\\N') else schema))
        elif kind == 'servers':
            # runtime_mysql_servers projection: 10\tdb.invalid\t3306\tONLINE\t1\t100
            # -> hostgroup10, endpoint db.invalid:3306, ONLINE, weight1, limit100.
            group, host, port, state, weight, connections = fields
            if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}', host) or state not in ('ONLINE', 'SHUNNED', 'OFFLINE_SOFT', 'OFFLINE_HARD'):
                raise ValueError('unrecognized server metadata')
            numbers = [group, port, weight, connections]
            if any(not re.fullmatch(r'[0-9]{1,10}', field) for field in numbers) or not 1 <= int(port) <= 65535:
                raise ValueError('unrecognized server numbers')
            rows.add((int(group), host, int(port), state, int(weight), int(connections)))
        else:
            # mysql_query_rules projection: 1\t1\t10\t1\t500 -> rule1,
            # active, destination10, apply, timeout500; no match/query text.
            if any(not re.fullmatch(r'[0-9]{1,10}', field) for field in fields) or fields[1] not in ('0', '1') or fields[3] not in ('0', '1'):
                raise ValueError('unrecognized rule metadata')
            rows.add(tuple(int(field) for field in fields))
    return rows


def collect_proxy(client, defaults_file, database='main', timeout=10, run=subprocess.run):
    projections = {}
    try:
        for kind, (columns, table) in PROXY_QUERIES.items():
            compared = []
            for name in ('runtime_' + table, 'disk.' + table):
                query = 'SELECT ' + columns + ' FROM ' + name
                if kind == 'policy':
                    # Compare only explicitly nonsecret timeouts, never an
                    # unrestricted global_variables dump. For example
                    # mysql-default_query_timeout\t36000000 -> 36000000 ms.
                    query += " WHERE variable_name IN ('mysql-default_query_timeout','mysql-connect_timeout_server','mysql-monitor_connect_timeout')"
                result = client_result(client_command(client, defaults_file, database, query), timeout, run)
                if result.returncode:
                    raise ValueError('approved projection unavailable')
                compared.append(proxy_projection(kind, result.stdout))
            projections[kind] = {'runtime_rows': len(compared[0]), 'disk_rows': len(compared[1]),
                                 'matches': compared[0] == compared[1]}
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError):
        return {'status': 'unknown', 'reason': 'approved_projection_unavailable_or_malformed'}
    return {'status': 'observed', 'matches': all(row['matches'] for row in projections.values()),
            'projections': projections, 'coverage': 'server_routes_frontend_users_selected_rules_and_timeout_policy',
            'not_inspected': ['passwords', 'query_match_expressions', 'application_queries', 'unrestricted_global_variables']}


def wait_client(client, defaults_file, database='main', attempts=10, interval=0.5, timeout=2,
                run=subprocess.run, sleep=time.sleep):
    positive_int(attempts, 20)
    if not 0 <= interval <= 5 or not 0 < timeout <= 10:
        raise ValueError('readiness timing outside bounds')
    command = client_command(client, defaults_file, database, 'SELECT 1')
    for attempt in range(1, attempts + 1):
        try:
            result = client_result(command, timeout, run)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return {'status': 'unknown', 'reason': 'client_unavailable_or_timeout', 'attempts': attempt}
        if result.returncode == 0:
            return {'status': 'ready' if result.stdout.strip() == b'1' else 'unknown',
                    'reason': 'connection_ready' if result.stdout.strip() == b'1' else 'unexpected_readiness_response', 'attempts': attempt}
        # MySQL client stderr "ERROR 2003 (HY000): ..." -> connection startup;
        # "ERROR 1045 (28000): ..." -> authentication, fail immediately. Keep
        # the bounded code only; stderr can include account or secret details.
        found = re.match(rb'ERROR ([0-9]{4})(?:[ (:]|$)', result.stderr)
        code = int(found.group(1)) if found else None
        if code not in (2002, 2003, 2013):
            return {'status': 'failed', 'reason': 'nonconnection_client_error', 'client_code': code, 'attempts': attempt}
        if attempt < attempts:
            sleep(interval)
    return {'status': 'failed', 'reason': 'connection_not_ready', 'attempts': attempts}


def parse_debconf(raw, value_type='devices'):
    # debconf-communicate GET: b"0 \n" -> success,value=""; b"0 true\n"
    # -> success,value="true". Stripping all whitespace loses the first value.
    if len(raw) > 4096:
        raise ValueError('debconf response exceeds bound')
    text = raw.decode('ascii')
    if text.endswith('\n'):
        text = text[:-1]
        if text.endswith('\r'):
            text = text[:-1]
    found = re.fullmatch(r'([0-9]{1,3})(?:[ \t](.*))?', text)
    if not found:
        raise ValueError('unrecognized debconf reply')
    code = int(found.group(1))
    if code:
        return {'status': 'unavailable', 'protocol_status': code}
    value = found.group(2) or ''
    if value_type == 'boolean' and value not in ('', 'true', 'false'):
        raise ValueError('unrecognized boot boolean')
    if value_type == 'devices' and value and not re.fullmatch(r'/dev/[A-Za-z0-9_./+-]+(?:, ?/dev/[A-Za-z0-9_./+-]+)*', value):
        raise ValueError('unrecognized boot device selection')
    return {'status': 'observed', 'protocol_status': 0, 'value': value}


def process_start(pid, proc_root=Path('/proc')):
    raw = bounded_bytes(proc_root / str(pid) / 'stat', 65536).decode('ascii')
    # /proc/PID/stat: "123 (name with spaces) S ... STARTTIME ...". The final
    # ')' ends comm; field22 starttime is index19 of the remaining fields.
    split = raw.rfind(')')
    fields = raw[split + 2:].split()
    if split < 0 or len(fields) < 20 or not fields[19].isdigit():
        raise ValueError('unrecognized process identity')
    return fields[19]


def proc_address(value, family):
    address, port = value.split(':')
    if not re.fullmatch(r'[0-9A-Fa-f]{8}' if family == 4 else r'[0-9A-Fa-f]{32}', address) or not re.fullmatch(r'[0-9A-Fa-f]{4}', port):
        raise ValueError('unrecognized proc socket address')
    # /proc/net/tcp "0100007F:1770" -> 127.0.0.1:6000. Linux prints
    # each 32-bit address word in host byte order, including tcp6 words.
    packed = b''.join(struct.pack('=I', int(address[index:index + 8], 16)) for index in range(0, len(address), 8))
    return socket.inet_ntop(socket.AF_INET if family == 4 else socket.AF_INET6, packed), int(port, 16)


def process_listeners(pid, proc_root=Path('/proc')):
    positive_int(pid, 2 ** 31 - 1)
    before = process_start(pid, proc_root)
    root = proc_root / str(pid)
    inodes = set()
    descriptors = list((root / 'fd').iterdir())
    if len(descriptors) > 16384:
        raise ValueError('descriptor inventory exceeds bound')
    for path in descriptors:
        try:
            target = os.readlink(str(path))
        except FileNotFoundError:
            continue
        found = re.fullmatch(r'socket:\[([0-9]+)\]', target)
        if found:
            inodes.add(found.group(1))
    observed = []
    for table, protocol, family in (('tcp', 'tcp', 4), ('tcp6', 'tcp', 6), ('udp', 'udp', 4), ('udp6', 'udp', 6)):
        try:
            lines = bounded_bytes(root / 'net' / table).decode('ascii').splitlines()[1:]
        except FileNotFoundError:
            continue
        for line in lines:
            fields = line.split()
            # /proc/PID/net/tcp: sl local_address rem_address st ... uid timeout inode.
            # "0: 0100007F:1770 00000000:0000 0A ... 1000 0 77" -> TCP
            # listener 127.0.0.1:6000 only when socket:[77] belongs to PID.
            if len(fields) < 10:
                raise ValueError('unrecognized proc socket record')
            if fields[9] not in inodes or fields[3] != ('0A' if protocol == 'tcp' else '07'):
                continue
            address, port = proc_address(fields[1], family)
            observed.append({'protocol': protocol, 'address': address, 'port': port})
    try:
        lines = bounded_bytes(root / 'net' / 'unix').decode('utf-8').splitlines()[1:]
    except FileNotFoundError:
        lines = []
    for line in lines:
        fields = line.split(maxsplit=7)
        if len(fields) < 7:
            raise ValueError('unrecognized unix socket record')
        if fields[6] in inodes and int(fields[3], 16) & 0x10000:
            if len(fields) != 8:
                raise ValueError('unnamed listening unix socket')
            observed.append({'protocol': 'unix', 'path': fields[7]})
    after_inodes = set()
    after_descriptors = list((root / 'fd').iterdir())
    if len(after_descriptors) > 16384:
        raise ValueError('descriptor inventory exceeds bound')
    for path in after_descriptors:
        try:
            target = os.readlink(str(path))
        except FileNotFoundError:
            continue
        found = re.fullmatch(r'socket:\[([0-9]+)\]', target)
        if found:
            after_inodes.add(found.group(1))
    if after_inodes != inodes or process_start(pid, proc_root) != before:
        raise ValueError('process or sockets changed during listener inventory')
    return observed


def listener_key(row):
    if not isinstance(row, dict):
        raise ValueError('listener must be an object')
    if row.get('protocol') == 'unix':
        path = row.get('path')
        if not isinstance(path, str) or not path or len(path) > 108 or any(ord(char) < 32 for char in path):
            raise ValueError('invalid unix listener')
        return ('unix', path)
    if row.get('protocol') not in ('tcp', 'udp') or type(row.get('port')) is not int or not 1 <= row['port'] <= 65535:
        raise ValueError('invalid listener protocol or port')
    return (row['protocol'], str(ipaddress.ip_address(row['address'])), row['port'])


def check_listeners(observed, expected):
    if not isinstance(expected, list) or len(expected) > 256 or len(observed) > 256:
        raise ValueError('listener list outside bound')
    actual = {listener_key(row) for row in observed}
    allowed = {listener_key(row) for row in expected}
    # New ProxySQL versions opened PostgreSQL ports absent from old configs.
    # Compare the complete owned listener set, including UNIX sockets; an empty
    # interface setting or a healthy old MySQL listener cannot hide extra binds.
    return {'status': 'passed' if actual == allowed else 'failed', 'observed': observed,
            'unexpected': [list(row) for row in sorted(actual - allowed)],
            'missing': [list(row) for row in sorted(allowed - actual)]}


def stale_process(pid, installed, manager, proc_root=Path('/proc')):
    positive_int(pid, 2 ** 31 - 1)
    before = process_start(pid, proc_root)
    running = (proc_root / str(pid) / 'exe').stat()
    packaged = Path(installed).stat()
    if process_start(pid, proc_root) != before:
        raise ValueError('process changed during identity comparison')
    stale = (running.st_dev, running.st_ino) != (packaged.st_dev, packaged.st_ino)
    if not isinstance(manager, dict) or manager.get('ActiveState') not in ('active', 'inactive', 'failed', 'activating') or type(manager.get('TasksCurrent')) is not int or manager['TasksCurrent'] < 0:
        raise ValueError('manager state is incomplete')
    empty_failed = manager['ActiveState'] == 'failed' and manager['TasksCurrent'] == 0
    return {'status': 'observed', 'running_binary_is_stale': stale, 'empty_failed_manager': empty_failed,
            'targeted_refresh_review_indicated': stale and empty_failed, 'restart_performed': False}


def observer_boot_id():
    value = bounded_bytes('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value):
        raise ValueError('observer boot identity unavailable')
    return value


def run_check(command, receipt, timeout=None, application_umask=None, popen=subprocess.Popen, read_only_check=False):
    if not command or not all(isinstance(value, str) and value and '\0' not in value for value in command):
        raise ValueError('explicit command arguments required')
    if timeout is not None and (not read_only_check or not 0 < timeout <= 3600):
        raise ValueError('bounded timeout requires an explicit read-only check')
    if application_umask is not None and application_umask not in (0o022, 0o027, 0o077):
        raise ValueError('unsupported scoped umask')
    # Validate the receipt destination before launch; no useful action should
    # start only to discover that its final evidence cannot be written. The
    # command itself is omitted from the receipt because argv may contain data.
    receipt = private_parent(receipt)
    if receipt.exists() or receipt.is_symlink():
        raise FileExistsError('receipt already exists')
    marker = receipt.with_name(receipt.name + '.started')
    started = time.monotonic()
    write_receipt(marker, {'schema_version': 1, 'supervisor_pid': os.getpid(), 'command_sha256': digest(command),
                           'started_monotonic': started, 'observer_boot_id': observer_boot_id(), 'status': 'started'})
    child = None
    timed_out = False
    try:
        options = {'stdin': subprocess.DEVNULL, 'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL,
                   'start_new_session': True}
        if application_umask is not None:
            options['preexec_fn'] = lambda: os.umask(application_umask)
        child = popen(command, **options)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            # This bounded mode is only for approved read-only checks. Mutating
            # schema actions must use no timeout and their own reviewed recovery
            # plan; killing an ambiguous migration is not a retry strategy.
            timed_out = True
            os.killpg(child.pid, signal.SIGTERM)
            try:
                code = child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                code = child.wait()
    except OSError:
        code = 127
    value = {'schema_version': 1, 'status': 'passed' if code == 0 and not timed_out else 'failed',
             'returncode': code, 'timed_out': timed_out, 'elapsed_seconds': round(time.monotonic() - started, 3),
             'application_umask': None if application_umask is None else format(application_umask, '03o')}
    write_receipt(receipt, value)
    # A caught failure used to produce a successful supervisor. Preserve the
    # command outcome, including signal exits, after saving independent evidence.
    return 124 if timed_out else 128 - code if code < 0 else min(code, 255)


def safe_relative(root, relative):
    if not isinstance(relative, str) or not relative or relative.startswith('/') or any(part in ('', '.', '..', '.git') for part in relative.split('/')):
        raise ValueError('unsafe deployment path')
    root = Path(root)
    if root.resolve() != root or not root.is_dir():
        raise ValueError('deployment root must be canonical')
    path = root
    for part in relative.split('/'):
        path /= part
        if path.is_symlink():
            raise ValueError('deployment symlink requires separate review')
    return path


def open_deployment_path(root, relative):
    safe_relative(root, relative)
    descriptor = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = relative.split('/')
        for index, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(parts) - 1:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def capture_modes(root, paths):
    if not isinstance(paths, list) or not paths or len(paths) > 10000:
        raise ValueError('explicit deployment path list required')
    selected = set()
    for relative in paths:
        safe_relative(root, relative)
        parts = relative.split('/')
        selected.update('/'.join(parts[:index]) for index in range(1, len(parts) + 1))
    rows = []
    for relative in sorted(selected):
        descriptor = open_deployment_path(root, relative)
        try:
            info = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
            raise ValueError('unsupported deployment file type')
        rows.append({'path': relative, 'kind': 'directory' if stat.S_ISDIR(info.st_mode) else 'file',
                     'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid})
    return {'schema_version': 1, 'root': str(root), 'paths': rows}


def restore_modes(root, snapshot):
    if not isinstance(snapshot, dict) or snapshot.get('root') != str(root) or not isinstance(snapshot.get('paths'), list) or len(snapshot['paths']) > 10000:
        raise ValueError('deployment snapshot does not match root')
    selected = []
    try:
        for row in snapshot['paths']:
            descriptor = open_deployment_path(root, row['path'])
            selected.append((descriptor, row['mode']))
            info = os.fstat(descriptor)
            expected_dir = row.get('kind') == 'directory'
            if not (stat.S_ISDIR(info.st_mode) if expected_dir else stat.S_ISREG(info.st_mode) and info.st_nlink == 1) or (info.st_uid, info.st_gid) != (row['uid'], row['gid']):
                raise ValueError('deployment type or ownership changed')
            if type(row.get('mode')) is not int or not 0 <= row['mode'] <= 0o7777:
                raise ValueError('unrecognized saved mode')
        # Git may remove and recreate an existing parent. Restore every approved
        # saved path's mode, not only newly created files; ownership/type changes
        # require review. Hold no-follow descriptors through validation and chmod
        # so a later symlink replacement cannot redirect mode restoration.
        for descriptor, mode in selected:
            os.fchmod(descriptor, mode)
    finally:
        for descriptor, _mode in selected:
            os.close(descriptor)
    return {'status': 'passed', 'restored_paths': len(selected)}


def compare_database_retention(before, after):
    allowed = {'expire_logs_days', 'binlog_expire_logs_seconds'}
    if not isinstance(before, dict) or not isinstance(after, dict) or not before or before.keys() != after.keys() or before.keys() - allowed:
        raise ValueError('use matching approved numeric database settings')
    changed = []
    for name in sorted(before):
        values = []
        for value in (before[name], after[name]):
            if type(value) is int:
                value = str(value)
            # MariaDB batch output: expire_logs_days<TAB>10.000000 -> Decimal(10).
            # Preserve real fractions; reject float input that may already be rounded.
            if not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,32}(?:[.][0-9]{1,32})?', value):
                raise ValueError('retention value must be a nonnegative decimal string or integer')
            values.append(Decimal(value))
        if values[0] != values[1]:
            changed.append(name)
    return {'status': 'failed' if changed else 'passed', 'changed_settings': changed}


def cold_copy_budget(size_bytes, sample_bytes, sample_seconds, available_seconds):
    size_bytes = positive_int(size_bytes, 2**63 - 1)
    sample_bytes = positive_int(sample_bytes, 2**63 - 1)
    for value in (sample_seconds, available_seconds):
        if not math.isfinite(value) or not 0 < value <= 7 * 86400:
            raise ValueError('cold-copy durations must be positive and bounded')
    # Use a representative transfer over the actual storage route. Reserve
    # another measured copy duration for variability; recovery and verification
    # allowances are deducted by the plan before supplying available_seconds.
    estimated = math.ceil(size_bytes * sample_seconds / sample_bytes)
    budget = 2 * estimated
    return {'status': 'passed' if budget <= available_seconds else 'failed',
            'estimated_seconds': estimated, 'copy_budget_seconds': budget,
            'available_seconds': available_seconds}


def verify_copy_prefix(source, destination, complete=False):
    # While writes stay stopped, verify the entire existing prefix before
    # allowing a retry. A smaller partial cannot count as a recovery point.
    with ExitStack() as stack:
        streams = []
        for path in (source, destination):
            if not path.is_absolute() or path.parent.resolve() != path.parent:
                raise ValueError('copy verification needs canonical absolute file paths')
            fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            stack.callback(os.close, fd)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError('copy verification needs regular files')
            streams.append(stack.enter_context(os.fdopen(fd, 'rb', closefd=False)))
        original, copied = streams
        original_stat, copied_stat = [os.fstat(stream.fileno()) for stream in streams]
        if os.path.samestat(original_stat, copied_stat):
            raise ValueError('copy verification needs two distinct regular files')
        remaining = copied_stat.st_size
        matches = remaining <= original_stat.st_size and (not complete or remaining == original_stat.st_size)
        while matches and remaining:
            count = min(remaining, MAX_INPUT)
            chunk = copied.read(count)
            matches = len(chunk) == count and chunk == original.read(count)
            remaining -= count
        for stream, path, before in zip(streams, (source, destination), (original_stat, copied_stat)):
            after = os.fstat(stream.fileno())
            if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (before.st_size, before.st_mtime_ns, before.st_ctime_ns) or not os.path.samestat(after, path.lstat()):
                matches = False
        return {'status': 'passed' if matches else 'failed', 'source_bytes': original_stat.st_size,
                'copied_bytes': copied_stat.st_size,
                'complete': matches and original_stat.st_size == copied_stat.st_size}


def component_acceptance(before, after, replacements, migration_root):
    if not isinstance(before, dict) or not isinstance(after, dict) or not isinstance(replacements, list) or len(before) > 10000 or len(replacements) > 128:
        raise ValueError('component metadata outside bounds')
    missing = set(before) - set(after)
    approved = []
    for row in replacements:
        old, new = row['old'], row['new']
        if old not in missing or new not in after or before[old] != row['from_version'] or after[new] != row['to_version']:
            raise ValueError('replacement does not match exact component versions')
        if not isinstance(row.get('approval'), str) or not row['approval'].strip() or not DIGEST.fullmatch(row.get('migration_sha256', '')):
            raise ValueError('reviewed migration proof required')
        migration = safe_relative(migration_root, row['migration_file'])
        if not migration.is_file() or hashlib.sha256(bounded_bytes(migration)).hexdigest() != row['migration_sha256']:
            raise ValueError('migration proof differs')
        approved.append(old)
    # h5plib_v127 -> h5plib_v128 is a supported bundled replacement when the
    # exact pinned migration handles it. A blanket "every old file remains"
    # rule blocks that case; an unreviewed missing custom component still fails.
    unresolved = sorted(missing - set(approved))
    return {'status': 'passed' if not unresolved else 'failed', 'approved_replacements': sorted(approved),
            'missing_components': unresolved}


def kernel_acceptance(original, current, review=None):
    if review is not None and not isinstance(review, dict):
        raise ValueError('kernel review must be an object')
    for value in (original, current):
        if not isinstance(value, dict) or any(not isinstance(value.get(key), str) or not value[key] for key in ('source_id', 'kernel', 'machine', 'root_identity', 'boot_mode', 'cgroup_mode')):
            raise ValueError('kernel evidence incomplete')
    changed = original['kernel'] != current['kernel']
    stable = all(original[key] == current[key] for key in ('source_id', 'machine', 'root_identity', 'boot_mode', 'cgroup_mode'))
    accepted = stable and not changed
    reviewed = False
    if changed and review:
        reviewed = (review.get('original_sha256') == digest(original) and review.get('current_sha256') == digest(current)
                    and review.get('kernel') == current['kernel'] and isinstance(review.get('approval'), str)
                    and bool(review['approval'].strip()) and all(review.get(key) is True for key in ('root_checked', 'boot_mode_checked', 'cgroups_checked', 'applications_checked')))
        accepted = stable and reviewed
    return {'status': 'passed' if accepted else 'failed', 'kernel_changed': changed, 'reviewed_exact_change': reviewed,
            'original_kernel': original['kernel'], 'current_kernel': current['kernel'],
            'provider_selection_verified': bool(review and review.get('provider_selection_verified') is True)}


def x11_exception(original, review):
    # Keep the default readiness failure immutable. This receipt authorizes only
    # the documented X11 exception for one source/path and check digest; it never
    # changes signature, capacity, removal or other compatibility guards.
    required = ('source_id', 'release_path', 'default_failure_sha256', 'other_checks_sha256')
    valid = (isinstance(original, dict) and isinstance(review, dict)
             and all(isinstance(original.get(key), str) and original[key] and review.get(key) == original[key] for key in required)
             and all(DIGEST.fullmatch(original[key]) for key in ('default_failure_sha256', 'other_checks_sha256'))
             and original.get('display_server_active') is False and original.get('display_manager_active') is False
             and original.get('other_checks_passed') is True and review.get('skips') == ['DR_SKIP_X11_CHECK']
             and review.get('original_sha256') == digest(original) and isinstance(review.get('approval'), str)
             and bool(review['approval'].strip()))
    return {'status': 'passed' if valid else 'failed', 'default_readiness_passed': False,
            'environment': {'DR_SKIP_X11_CHECK': 'true'} if valid else {}}


def prepare_swap(path, size, reserve=64 * 1024 * 1024, existing=None):
    positive_int(size, 16 * 1024 ** 3)
    path = private_parent(path)
    if type(reserve) is not int or reserve < 0:
        raise ValueError('invalid swap reserve')
    if path.exists() or path.is_symlink():
        info = path.lstat()
        valid = (isinstance(existing, dict) and existing.get('path') == str(path) and existing.get('bytes') == size
                 and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == size and info.st_blocks * 512 >= size
                 and existing.get('device') == info.st_dev and existing.get('inode') == info.st_ino)
        if not valid:
            raise ValueError('existing or partial swap file needs explicit reconciliation')
        return dict(existing, status='verified_existing', persistent=False, activation_required_after_reboot=True)
    capacity = os.statvfs(str(path.parent))
    if capacity.f_bavail * capacity.f_frsize < size + reserve:
        raise ValueError('insufficient approved destination capacity')
    # fallocate is unsuitable on some legacy filesystems, including ext3. Write
    # allocated zero blocks through an exclusive descriptor, fsync, then verify
    # actual blocks. Leave partial files for reconciliation rather than deleting
    # evidence or overwriting them during a retry. No fstab or activation change.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        remaining = size
        block = b'\0' * min(size, 1024 * 1024)
        while remaining:
            written = os.write(fd, block[:min(len(block), remaining)])
            if written <= 0:
                raise OSError('swap allocation stalled')
            remaining -= written
        os.fsync(fd)
        info = os.fstat(fd)
        if info.st_size != size or info.st_blocks * 512 < size or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('swap allocation verification failed')
    finally:
        os.close(fd)
    return {'status': 'prepared', 'path': str(path), 'bytes': size, 'device': info.st_dev, 'inode': info.st_ino,
            'allocated_bytes': info.st_blocks * 512, 'persistent': False,
            'activation_required_after_reboot': True, 'mkswap_and_swapon_performed': False}



def deadline_status(started, outage_seconds, recovery_headroom, session_lost=False,
                    session_loss_policy='reconcile', approval=None, now=time.monotonic, recorded_boot_id=None, current_boot_id=None):
    for value in (started, outage_seconds, recovery_headroom):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError('deadline requires finite timing values')
    if started < 0 or not 0 < outage_seconds <= 86400 or not 0 <= recovery_headroom <= outage_seconds:
        raise ValueError('outage budget outside bounds')
    if type(session_lost) is not bool or session_loss_policy not in ('reconcile', 'continue'):
        raise ValueError('invalid session-loss policy')
    if session_loss_policy == 'continue' and (not isinstance(approval, str) or not approval.strip()):
        raise ValueError('continuation after session loss needs a recorded approval')
    current_boot_id = observer_boot_id() if current_boot_id is None else current_boot_id
    if not isinstance(recorded_boot_id, str) or not recorded_boot_id or recorded_boot_id != current_boot_id:
        raise ValueError('outage clock belongs to another observer boot')
    observed = now()
    if not math.isfinite(observed) or observed < started:
        raise ValueError('monotonic clock changed or restarted')
    elapsed = observed - started
    remaining = outage_seconds - elapsed
    # A maintenance window previously overran while repairs and runner approvals
    # consumed the recovery reserve. This is a status decision only: it never
    # kills or retries an ambiguous schema action. The same observer's monotonic
    # clock brackets the budget even if the supervised source reboots.
    if remaining <= 0:
        state, reason = 'overrun', 'approved_outage_budget_exhausted'
    elif remaining <= recovery_headroom:
        state, reason = 'recovery-decision-needed', 'recovery_headroom_reached'
    elif session_lost and session_loss_policy != 'continue':
        state, reason = 'recovery-decision-needed', 'operator_session_lost_reconcile'
    else:
        state, reason = 'continue', 'within_approved_budget'
    return {'status': state, 'reason': reason, 'clock': 'same_observer_monotonic',
            'observer_boot_id': current_boot_id, 'started_monotonic': started, 'elapsed_seconds': round(elapsed, 3),
            'remaining_seconds': round(remaining, 3), 'approved_outage_seconds': outage_seconds,
            'recovery_headroom_seconds': recovery_headroom, 'operator_session_lost': session_lost,
            'session_loss_policy': session_loss_policy, 'session_loss_approval_recorded': bool(approval),
            'action_stopped_or_retried': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for name in ('database-engines', 'proxysql-state', 'client-ready'):
        command = sub.add_parser(name)
        command.add_argument('--client', default='mysql')
        command.add_argument('--defaults-file', type=Path, required=True)
        command.add_argument('--database', required=True)
        command.add_argument('--timeout', type=float, default=2 if name == 'client-ready' else 10)
        if name == 'client-ready':
            command.add_argument('--attempts', type=int, default=10)
            command.add_argument('--interval', type=float, default=0.5)
    command = sub.add_parser('debconf')
    command.add_argument('--input', type=Path, required=True)
    command.add_argument('--value-type', choices=('devices', 'boolean'), default='devices')
    command = sub.add_parser('listeners')
    command.add_argument('--pid', type=int, required=True)
    command.add_argument('--expected', type=Path, required=True)
    command = sub.add_parser('stale-process')
    command.add_argument('--pid', type=int, required=True)
    command.add_argument('--installed', type=Path, required=True)
    command.add_argument('--manager-state', type=Path, required=True)
    command = sub.add_parser('check')
    command.add_argument('--receipt', type=Path, required=True)
    command.add_argument('--timeout', type=float)
    command.add_argument('--read-only-check', action='store_true', help='required for timeout; only approved read-only checks may be killed')
    command.add_argument('--application-umask', choices=('022', '027', '077'))
    command.add_argument('command', nargs=argparse.REMAINDER)
    command = sub.add_parser('capture-modes')
    command.add_argument('--root', type=Path, required=True)
    command.add_argument('--paths', type=Path, required=True)
    command.add_argument('--expected', type=Path, help='private capture-modes receipt to check without changing files')
    command = sub.add_parser('database-retention')
    command.add_argument('--before', type=Path, required=True)
    command.add_argument('--after', type=Path, required=True)
    command = sub.add_parser('cold-copy-budget')
    command.add_argument('--size-bytes', type=int, required=True)
    command.add_argument('--sample-bytes', type=int, required=True)
    command.add_argument('--sample-seconds', type=float, required=True)
    command.add_argument('--available-seconds', type=float, required=True)
    command = sub.add_parser('verify-copy-prefix')
    command.add_argument('--source', type=Path, required=True)
    command.add_argument('--destination', type=Path, required=True)
    command.add_argument('--complete', action='store_true', help='require a full byte-for-byte copy')
    command = sub.add_parser('restore-modes')
    command.add_argument('--root', type=Path, required=True)
    command.add_argument('--snapshot', type=Path, required=True)
    command = sub.add_parser('components')
    for option in ('before', 'after', 'replacements', 'migration-root'):
        command.add_argument('--' + option, type=Path, required=True)
    command = sub.add_parser('kernel')
    command.add_argument('--original', type=Path, required=True)
    command.add_argument('--current', type=Path, required=True)
    command.add_argument('--review', type=Path)
    command = sub.add_parser('x11-exception')
    command.add_argument('--original', type=Path, required=True)
    command.add_argument('--review', type=Path, required=True)
    command = sub.add_parser('prepare-swap')
    command.add_argument('--path', type=Path, required=True)
    command.add_argument('--size-mib', type=int, required=True)
    command.add_argument('--existing-receipt', type=Path)
    command = sub.add_parser('deadline')
    command.add_argument('--started-monotonic', type=float, required=True)
    command.add_argument('--observer-boot-id', required=True)
    command.add_argument('--outage-seconds', type=float, required=True)
    command.add_argument('--recovery-headroom', type=float, required=True)
    command.add_argument('--session-lost', action='store_true')
    command.add_argument('--session-loss-policy', choices=('reconcile', 'continue'), default='reconcile')
    command.add_argument('--session-loss-approval')
    command = sub.add_parser('fingerprint')
    command.add_argument('--input', type=Path, required=True)
    for command in sub.choices.values():
        if command.prog.split()[-1] != 'check':
            command.add_argument('--receipt', type=Path, help='new private evidence file; omit for status JSON on stdout')
    args = parser.parse_args(argv)
    try:
        if args.action == 'check':
            command = args.command[1:] if args.command[:1] == ['--'] else args.command
            return run_check(command, args.receipt, args.timeout, None if args.application_umask is None else int(args.application_umask, 8), read_only_check=args.read_only_check)
        if args.receipt:
            private_parent(args.receipt)
            if args.receipt.exists() or args.receipt.is_symlink():
                raise FileExistsError('receipt exists')
        if args.action == 'database-engines':
            if not 0 < args.timeout <= 30:
                raise ValueError('database timeout outside bound')
            value = collect_engines(args.client, args.defaults_file, args.database, args.timeout)
        elif args.action == 'proxysql-state':
            if not 0 < args.timeout <= 10:
                raise ValueError('metadata timeout outside bound')
            value = collect_proxy(args.client, args.defaults_file, args.database, args.timeout)
        elif args.action == 'client-ready':
            value = wait_client(args.client, args.defaults_file, args.database, args.attempts, args.interval, args.timeout)
        elif args.action == 'debconf':
            value = parse_debconf(bounded_bytes(args.input, 4096), args.value_type)
        elif args.action == 'listeners':
            value = check_listeners(process_listeners(args.pid), read_json(args.expected))
        elif args.action == 'stale-process':
            value = stale_process(args.pid, args.installed, read_json(args.manager_state))
        elif args.action == 'capture-modes':
            value = capture_modes(args.root, read_json(args.paths))
            if args.expected:
                value['status'] = 'passed' if value == private_json(args.expected) else 'failed'
        elif args.action == 'database-retention':
            value = compare_database_retention(private_json(args.before), private_json(args.after))
        elif args.action == 'cold-copy-budget':
            value = cold_copy_budget(args.size_bytes, args.sample_bytes, args.sample_seconds, args.available_seconds)
        elif args.action == 'verify-copy-prefix':
            value = verify_copy_prefix(args.source, args.destination, args.complete)
        elif args.action == 'restore-modes':
            value = restore_modes(args.root, private_json(args.snapshot))
        elif args.action == 'components':
            value = component_acceptance(read_json(args.before), read_json(args.after), private_json(args.replacements), args.migration_root)
        elif args.action == 'kernel':
            value = kernel_acceptance(read_json(args.original), read_json(args.current), private_json(args.review) if args.review else None)
        elif args.action == 'x11-exception':
            value = x11_exception(read_json(args.original), private_json(args.review))
        elif args.action == 'deadline':
            value = deadline_status(args.started_monotonic, args.outage_seconds, args.recovery_headroom, args.session_lost, args.session_loss_policy, args.session_loss_approval, recorded_boot_id=args.observer_boot_id)
        elif args.action == 'fingerprint':
            value = {'status': 'observed', 'sha256': digest(read_json(args.input))}
        elif args.action == 'prepare-swap':
            value = prepare_swap(args.path, args.size_mib * 1024 * 1024, existing=private_json(args.existing_receipt) if args.existing_receipt else None)
        if args.receipt:
            write_receipt(args.receipt, value)
        else:
            print(json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False))
        return 1 if value.get('status') in ('failed', 'unknown', 'unavailable', 'recovery-decision-needed', 'overrun') or value.get('matches') is False else 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError):
        print('Execution evidence failed: input, client or destination could not be verified.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
