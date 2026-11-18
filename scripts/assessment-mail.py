#!/usr/bin/env python3
"""Summarize approved source-side Postfix and Dovecot log input without returning records."""

import argparse
from collections import Counter
import json
import re
import sys

# journalctl -o short-iso: "2026-11-13T15:00:00+0000 mx postfix/local[1]: ABC: ..."
# syslog: "Nov 13 15:00:00 mx dovecot: imap-login: Login: user=..."
# Return only timestamps, fixed service names and event counts. Legacy stamps
# preserve their local format and need the operator's year/time-zone context.
RECORD = re.compile(
    rb'^(?P<stamp>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
    rb'(?:Z|[+-][0-9]{2}:?[0-9]{2})|'
    rb'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}[0-9]{1,2} '
    rb'[0-9]{2}:[0-9]{2}:[0-9]{2}) [^ \t]+ '
    rb'(?P<service>postfix/(?:smtpd|smtp|local|virtual|lmtp|pickup|qmgr)|dovecot)(?:\[[0-9]+\])?: (?P<event>.*)$'
)
# Postfix: "ABC: to=<user@example>, relay=local, ..., status=sent (delivered ...)"
# -> local_delivery. A deferred smtp row is a delivery attempt, never a message count.
DELIVERY = re.compile(rb'^[A-Za-z0-9]+: to=<[^>]*>, relay=[^,]*, [^()\n]*\bstatus=(sent|deferred|bounced)(?: |$)')
# Dovecot: "imap-login: Login: user=<...>" -> imap_login; "Disconnected: Auth failed" -> failure.
LOGIN = re.compile(rb'^(imap|pop3)-login: (Login:|Disconnected:.*(?:auth failed|Authentication failed))', re.I)


def summarize(stream, limit=32 * 1024 ** 2):
    counts = Counter()
    first = last = None
    read_bytes = matched = unrecognized = 0
    bounded = False
    # The bound applies to decompressed input and to each line, even without a newline.
    while read_bytes < limit:
        raw = stream.readline(min(16385, limit - read_bytes + 1))
        if not raw:
            break
        read_bytes += len(raw)
        if read_bytes > limit or len(raw) > 16384:
            bounded = True
            break
        record = RECORD.fullmatch(raw.rstrip(b'\r\n'))
        if not record:
            unrecognized += 1
            continue
        matched += 1
        last = record['stamp'].decode('ascii')
        first = first or last
        service, event = record['service'], record['event']
        delivery = DELIVERY.match(event)
        login = LOGIN.match(event) if service == b'dovecot' else None
        if delivery and service in (b'postfix/local', b'postfix/virtual', b'postfix/lmtp', b'postfix/smtp'):
            if delivery[1] == b'sent':
                label = {b'postfix/local': 'local_delivery', b'postfix/virtual': 'virtual_delivery',
                         b'postfix/lmtp': 'lmtp_delivery', b'postfix/smtp': 'smtp_relay_delivery'}[service]
            else:
                label = delivery[1].decode('ascii')
            counts[label] += 1
        elif service == b'postfix/pickup' and re.match(rb'^[A-Za-z0-9]+: uid=[0-9]+(?: |,|$)', event):
            counts['local_submission'] += 1
        elif service == b'postfix/smtpd':
            if re.match(rb'^[A-Za-z0-9]+: client=', event):
                counts['smtp_client_accepted'] += 1
            if b'SASL ' in event and b'authentication failed' in event:
                counts['smtp_auth_failed'] += 1
            elif re.match(rb'^[A-Za-z0-9]+: client=', event) and b', sasl_method=' in event:
                counts['smtp_authenticated_submission'] += 1
        elif login:
            label = login[1].lower().decode('ascii')
            counts[label + ('_login' if login[2].lower() == b'login:' else '_auth_failed')] += 1
    return {'coverage': 'bounded_input' if bounded or read_bytes >= limit else 'supplied_input_only',
            'first_recognized_record': first, 'last_recognized_record': last,
            'recognized_records': matched, 'unrecognized_lines': unrecognized,
            'event_counts': dict(counts)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(summarize(sys.stdin.buffer), sort_keys=True))


if __name__ == '__main__':
    main()
