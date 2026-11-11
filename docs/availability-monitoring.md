# Availability evidence during a change

Run `scripts/availability-monitor.py` on an approved observer runner with Python
3. It is optional runner tooling: it adds no Python requirement to legacy source
hosts. The sampler records bounded status observations, not response bodies,
headers, application records, DNS answers, or command stderr. Its output belongs
in protected job evidence outside Git.

Choose the observer, endpoints, protocols, address families, and expected statuses
in the approved plan. Name each observer by location/role so that source-local
and external observations remain distinguishable. A successful TCP connection
proves a listening port, and an HTTP HEAD status proves that endpoint's response;
use workload acceptance checks separately for application correctness.

An invented configuration illustrates external HTTPS and explicit IPv4/IPv6
DNS checks:

```json
{
  "observer": "external-observer-example",
  "required_families": ["ipv4", "ipv6"],
  "required_dns_addresses": ["192.0.2.53", "2001:db8::53"],
  "required_dns_transports": ["udp", "tcp"],
  "targets": [
    {"name": "web-v4", "protocol": "https", "family": "ipv4",
     "url": "https://example.invalid/health", "expected_statuses": [200]},
    {"name": "dns-v4-udp", "protocol": "dns", "family": "ipv4", "transport": "udp",
     "address": "192.0.2.53", "port": 53,
     "question": "example.invalid", "qtype": "SOA", "expected_rcodes": [0]},
    {"name": "dns-v4-tcp", "protocol": "dns", "family": "ipv4", "transport": "tcp",
     "address": "192.0.2.53", "port": 53,
     "question": "example.invalid", "qtype": "SOA", "expected_rcodes": [0]},
    {"name": "dns-v6-udp", "protocol": "dns", "family": "ipv6", "transport": "udp",
     "address": "2001:db8::53", "port": 53,
     "question": "example.invalid", "qtype": "SOA", "expected_rcodes": [0]},
    {"name": "dns-v6-tcp", "protocol": "dns", "family": "ipv6", "transport": "tcp",
     "address": "2001:db8::53", "port": 53,
     "question": "example.invalid", "qtype": "SOA", "expected_rcodes": [0]}
  ]
}
```

Replace examples with the approved endpoints. An IP literal in an HTTP/HTTPS
URL must match its configured address family; DNS resolution flags cannot
convert an IPv6 literal into an IPv4 observation. TCP targets use `"protocol":"tcp"`,
a literal `address`, explicit `family`, and required `port`. DNS uses `"transport":"udp"`
(the compatibility default) or `"transport":"tcp"`, an explicit ASCII question
and A/AAAA/SOA type; expected response codes default to NOERROR (`0`). DNS-over-TCP
checks a bounded length-prefixed DNS response, beyond the TCP connection alone.
Both transports validate transaction ID, response flag and the echoed question,
returning only the response code. Truncated, mismatched and malformed messages
remain unknown. Answer content is discarded; UDP never silently falls back to TCP.

For a dual-stack upgrade, declare every public DNS address and required transport
as above. Missing family/address/transport coverage is rejected before monitoring.
These optional declarations preserve existing single-family configurations, but
one IPv4 sample must not be described as evidence of IPv6 availability. Run the
same reviewed sampler on an approved observer with the required connectivity.
Keep its location and SSH/launcher outcome in the job; inability to start or reach
that observer is a measurement gap. Local unsupported-family, permission and
no-route conditions are unknown observer failures, not measured DNS downtime.

HTTP/HTTPS uses an installed `curl`, disables `.curlrc`, proxies, redirects, and
URL globbing, verifies TLS using curl's normal trust configuration, makes a HEAD
request, and discards headers and body. Credentials, query strings, and fragments
are rejected in URLs. Use a public, status-only health path; do not pass tokens,
cookies, authenticated URLs, or sensitive paths. No other client is required for
TCP/DNS. Missing curl is `unknown/client_unavailable`, distinct from an actual
probe `failed/timeout` or a returned unhealthy status.

## Start before the first production action

Start the sampler under the job's approved supervisor so it outlives an SSH or
terminal interruption. For example, from the observer runner:

```bash
systemd-run --user --unit=job-availability --collect \
  python3 /verified/tool/scripts/availability-monitor.py \
  --config /protected/job/probes.json --output /protected/job/availability-external \
  --duration 7200 --interval 5 --timeout 3
```

Use a unique supervisor unit and new output directory per job/observer attempt.
Where a user service manager is unavailable, use an existing approved supervisor
or a dedicated foreground terminal and retain its identity in the job log. Do
not silently leave the sampler tied to a disposable command session.

Before production changes, inspect the new output directory's `ready.json`.
It appears only after the first complete cycle and includes `baseline_healthy`
and each target status. Investigate unhealthy or unknown initial observations;
record any accepted pre-existing failure. A running process alone does not prove
measurement readiness. A second source-local sampler may use the same script
when Python 3 is already available and its installation/use is approved. An
external observation remains needed for external reachability.

The duration is mandatory and bounded to 1–86400 seconds. Each probe has a timeout
of 0.1–30 seconds. Intervals are 0.1–3600 seconds; probes are sequential, so choose
an interval that covers the target count and timeout budget. A maximum sample
count (default 10000, maximum 100000) also bounds output. Missed slots are skipped
rather than replayed in a burst. Increase observation lifetime deliberately if
the operation lasts longer; a terminated sampler cannot establish later health.

## Continue, stop, and interpret

Record the observer label, supervisor identity, start/finish times, interval,
probe timeout, output path, and measurement gaps in the job handoff. Keep the
sampler running across the action and through recovery. Cancel using the recorded
supervisor, or send SIGTERM/SIGINT to the recorded process. Cancellation waits
for at most the current bounded probe and writes `summary.json`; it never changes
a monitored service. An uncatchable kill or runner loss can leave no summary;
retain `samples.jsonl` and report that unfinished observation explicitly.

The sampler publishes JSON receipts atomically. A storage failure can leave a
final sample line incomplete or prevent the summary entirely. Retain the
original sample log and supervisor outcome. After a restart, use a new output
directory and keep each attempt's outcome. For each target and observer, combine
the last complete sample of the old attempt and first complete sample of the
replacement as the boundaries of an unobserved interval. If either boundary
is missing, report it as unknown. Do not join failure windows across the gap.

The new directory uses `u=rwx,go=` and files use `u=rw,go=`:

- `monitor.json`: approved target metadata and sampling bounds.
- `ready.json`: first complete cycle and baseline statuses.
- `samples.jsonl`: observer/target/family and DNS transport, UTC start/finish, monotonic elapsed time,
  latency, status, fixed reason, and optional HTTP/DNS response code.
- `summary.json`: counts, gaps between samples, and bounded failure windows.

A window that starts with failure is left-censored when no earlier successful
sample exists. A window without a later successful sample is right-censored.
Unknown samples and scheduling gaps remain explicit uncertainty. Separate
source-local and external observers may disagree for routing, DNS, or client
reasons. Report last-success/first-failure/last-failure/first-success timestamps
and their limits; these samples cannot establish exact interruption duration,
prove continuity between samples, or reconstruct an event before monitoring
began. A missing client is a measurement failure, not measured service downtime.

## Offline checks

```bash
python3 tests/test-availability-monitor.py
```

The suite mocks curl, sockets, DNS responses, time, and cancellation. It covers
missing clients and observer routes versus timeouts, required-family/transport
coverage, partial TCP frames, discarded content, bounded
lifetimes, protected output, gaps, censoring, and summary finalization. It never
probes a customer endpoint or changes a service.
