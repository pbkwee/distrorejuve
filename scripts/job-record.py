#!/usr/bin/env python3
"""Reserve private upgrade jobs and update their resumable state without losing history."""

import argparse
import contextlib
import datetime as dt
import json
import os
from pathlib import Path
import re
import secrets
import stat

ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
START = '<!-- current-job-state:start -->'
END = '<!-- current-job-state:end -->'


def timestamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def text(value, name, maximum=1000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(char) < 32 for char in value):
        raise ValueError(name + ' must be one bounded nonempty line')
    return value


def private_directory(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError('use an absolute canonical job-store path without symlinks')
    metadata = path.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise ValueError('job directory must be owned by this user and private')
    return path


def read_private(path):
    # A malformed record may be a FIFO. Nonblocking open lets fstat reject it
    # without hanging before the regular-file check or following a replacement.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077 or metadata.st_size > 2 * 1024 * 1024:
            raise ValueError('record must be a bounded private single-link file')
        return handle.read().decode('utf-8')


def replace_private(path, content):
    if path.exists() or path.is_symlink():
        read_private(path)
    temporary = path.with_name('.' + path.name + '-' + secrets.token_hex(12))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        # Binary writes also remain usable when an upgrade has replaced Python's
        # lazy text-codec modules. Never truncate the old record before fsync.
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(content.encode('utf-8'))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


@contextlib.contextmanager
def lock(directory):
    path = directory / '.job-update.lock'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, (str(os.getpid()) + '\n').encode('ascii'))
        os.close(descriptor)
        yield
    finally:
        path.unlink()


def current_block(state):
    current = state['current']
    lines = [START, '- State revision: ' + str(state['revision']), '- Stage: ' + current['stage'],
             '- Last verified state: ' + current['verified'], '- Next permitted action: ' + current['next_action']]
    for stage, reason in sorted(current.get('blockers', {}).items()):
        lines.append('- Blocks ' + stage + ': ' + reason)
    return '\n'.join(lines + [END])


def project(directory, state):
    path = directory / 'job.md'
    document = read_private(path)
    if document.count(START) != 1 or document.count(END) != 1:
        raise ValueError('job.md current-state markers are missing or ambiguous')
    before, tail = document.split(START)
    _, after = tail.split(END)
    # One marked summary can change; operator-written sections and every earlier
    # event remain intact. state.json is authoritative if projection was interrupted.
    document = before + current_block(state) + after
    for number, entry in enumerate(state['history'], 1):
        marker = '<!-- state-event:' + str(number) + ' -->'
        if marker not in document:
            document += '\n' + marker + '\n- ' + entry['at'] + ' — ' + entry['actor'] + ': ' + entry['event'] + '\n'
    replace_private(path, document)


def used_ids(root):
    # Archives may contain old IDs below one or more grouping directories. Inspect
    # directory names only, and prune each recognized job before its evidence tree.
    found = set()
    def incomplete(error):
        # os.walk normally skips unreadable archives. Treat that as an incomplete
        # ID index so initialization cannot reserve an existing hidden job ID.
        raise error
    for _, directories, _ in os.walk(root, followlinks=False, onerror=incomplete):
        for name in list(directories):
            if name.startswith('UPG-'):
                found.add(name)
                directories.remove(name)
    return found


def initialize(root, job_id=None, source='unknown', actor='operator', tools=None):
    root = private_directory(root)
    text(source, 'source')
    text(actor, 'actor')
    tools = tools or {}
    for name, revision in tools.items():
        text(name, 'tool name', 80)
        text(revision, 'tool revision', 200)
    occupied = used_ids(root)
    if job_id is not None:
        # Shared ID protocol: UPG-7K3M9Q -> prefix + six unambiguous characters.
        # Legacy IDs stay valid in existing records; this only governs new IDs.
        if not re.fullmatch(r'UPG-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{6}', job_id):
            raise ValueError('new job ID must follow the shared six-character format')
        if job_id in occupied:
            raise FileExistsError('job ID is already reserved, including archived jobs')
    for _ in range(64):
        candidate = job_id or 'UPG-' + ''.join(secrets.choice(ALPHABET) for _ in range(6))
        if candidate in occupied:
            if job_id:
                raise FileExistsError('job already exists')
            continue
        directory = root / candidate
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            if job_id:
                raise
            continue
        created = timestamp()
        state = {'schema_version': 1, 'job_id': candidate, 'revision': 1, 'created_at': created,
                 'source': source, 'tools': tools,
                 'current': {'stage': 'intake', 'verified': 'identity and scope not yet verified',
                             'next_action': 'resolve missing intake choices', 'blockers': {}},
                 'history': [{'at': created, 'actor': actor, 'event': 'job reserved; intake pending'}]}
        # Write the ID immediately after exclusive reservation. If a later write
        # fails, retain this partial reservation for explicit recovery, never reuse it.
        document = '# Upgrade job\n\n- job_id: ' + candidate + '\n- Created at: ' + created + '\n- Source reference: ' + source + '\n'
        for name, revision in sorted(tools.items()):
            document += '- Tool ' + name + ': ' + revision + '\n'
        document += '\n' + current_block(state) + '\n\n## Timeline\n'
        replace_private(directory / 'job.md', document)
        replace_private(directory / 'state.json', json.dumps(state, ensure_ascii=True, indent=2) + '\n')
        project(directory, state)
        return directory, state
    raise RuntimeError('could not reserve a unique job ID')


def load(directory):
    directory = private_directory(directory)
    state = json.loads(read_private(directory / 'state.json'))
    if state.get('job_id') != directory.name or state.get('schema_version') != 1 or type(state.get('revision')) is not int:
        raise ValueError('state identity/schema mismatch')
    document = read_private(directory / 'job.md')
    if ('- job_id: ' + state['job_id'] + '\n') not in document:
        raise ValueError('job.md identity mismatch')
    return directory, state


def update(directory, expected_revision, stage, verified, next_action, actor, event, blockers=None):
    directory = private_directory(directory)
    for value, name in [(stage, 'stage'), (verified, 'verified'), (next_action, 'next action'), (actor, 'actor'), (event, 'event')]:
        text(value, name)
    for key, value in (blockers or {}).items():
        text(key, 'blocked stage', 80)
        text(value, 'blocker')
    with lock(directory):
        _, state = load(directory)
        if state['revision'] != expected_revision:
            raise ValueError('stale revision: reload the current state before updating')
        state['revision'] += 1
        state['current'] = {'stage': stage, 'verified': verified, 'next_action': next_action, 'blockers': blockers or {}}
        state['history'].append({'at': timestamp(), 'actor': actor, 'event': event})
        replace_private(directory / 'state.json', json.dumps(state, ensure_ascii=True, indent=2) + '\n')
        project(directory, state)
        return state


def pairs(values):
    result = {}
    for value in values:
        name, separator, content = value.partition('=')
        if not separator or name in result:
            raise ValueError('use unique name=value pairs')
        text(name, 'name', 80)
        text(content, 'value')
        result[name] = content
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    start = commands.add_parser('init')
    start.add_argument('--root', required=True)
    start.add_argument('--job-id')
    start.add_argument('--source', default='unknown')
    start.add_argument('--actor', required=True)
    start.add_argument('--tool', action='append', default=[])
    for command in ('show', 'render', 'update'):
        sub = commands.add_parser(command)
        sub.add_argument('directory')
        if command == 'update':
            sub.add_argument('--expected-revision', required=True, type=int)
            for field in ('stage', 'verified', 'next-action', 'actor', 'event'):
                sub.add_argument('--' + field, required=True)
            sub.add_argument('--blocker', action='append', default=[])
    args = parser.parse_args(argv)
    try:
        if args.command == 'init':
            directory, state = initialize(args.root, args.job_id, args.source, args.actor, pairs(args.tool))
        elif args.command == 'update':
            directory = Path(args.directory)
            state = update(directory, args.expected_revision, args.stage, args.verified, args.next_action, args.actor, args.event, pairs(args.blocker))
        else:
            directory, state = load(args.directory)
            if args.command == 'render':
                with lock(directory):
                    directory, state = load(directory)
                    project(directory, state)
        print(json.dumps({'directory': str(directory), 'job_id': state['job_id'], 'revision': state['revision'], 'current': state['current']}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'status': 'failed', 'reason': 'job_record_unavailable_conflicting_or_invalid'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
