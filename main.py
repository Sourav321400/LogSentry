"""LogSentry: simple rule-based log analysis for a documented sample format."""
import argparse
import csv
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import numpy as np


def parse_line(line):
    """Expected: YYYY-MM-DD HH:MM:SS EVENT user=NAME ip=ADDRESS"""
    parts = line.strip().split()
    if len(parts) != 5:
        raise ValueError('Expected five whitespace-separated fields')
    stamp = datetime.strptime(' '.join(parts[:2]), '%Y-%m-%d %H:%M:%S')
    event = parts[2]
    if event not in {'LOGIN_SUCCESS', 'LOGIN_FAILED', 'ERROR', 'LOGOUT'}:
        raise ValueError('Unknown event')
    if not parts[3].startswith('user=') or not parts[4].startswith('ip='):
        raise ValueError('Missing user/ip field')
    user, ip = parts[3][5:], parts[4][3:]
    if not user or not ip:
        raise ValueError('Empty user/ip field')
    return {'time': stamp, 'event': event, 'user': user, 'ip': ip}


def analyze(path, threshold=5):
    records, rejected = [], []
    with open(path, encoding='utf-8') as source:
        for number, line in enumerate(source, 1):
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            try:
                records.append(parse_line(line))
            except ValueError as exc:
                rejected.append((number, str(exc)))
    events = Counter(r['event'] for r in records)
    failed = Counter(r['user'] for r in records if r['event'] == 'LOGIN_FAILED')
    ips = Counter(r['ip'] for r in records)
    counts = np.array(list(failed.values()), dtype=int)
    mean = float(np.mean(counts)) if counts.size else 0.0
    maximum = int(np.max(counts)) if counts.size else 0
    suspicious = {user: count for user, count in failed.items() if count >= threshold}
    return records, rejected, events, failed, ips, mean, maximum, suspicious


def main():
    parser = argparse.ArgumentParser(description='Analyze structured activity logs')
    parser.add_argument('file', nargs='?', default='logs/sample.log')
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--report', default='reports/summary.csv')
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error('threshold must be at least 1')
    try:
        records, rejected, events, failed, ips, mean, maximum, suspicious = analyze(args.file, args.threshold)
    except OSError as exc:
        parser.exit(1, f'Cannot read log: {exc}\n')
    print('=== LogSentry Analysis ===')
    print(f'Valid events: {len(records)} | Rejected lines: {len(rejected)}')
    for event in ('LOGIN_SUCCESS', 'LOGIN_FAILED', 'ERROR', 'LOGOUT'):
        print(f'{event}: {events[event]}')
    print(f'Unique IP addresses: {len(ips)}')
    print(f'NumPy mean failed logins per user with failures: {mean:.2f}')
    print(f'NumPy maximum failed logins: {maximum}')
    print(f'Alert threshold: {args.threshold} failed logins (across entire file)')
    if suspicious:
        for user, count in sorted(suspicious.items()):
            print(f'ALERT: {user} has {count} failed logins')
    else:
        print('No threshold alerts')
    for number, reason in rejected:
        print(f'Skipped line {number}: {reason}')
    destination = Path(args.report)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('w', newline='', encoding='utf-8') as output:
        writer = csv.writer(output)
        writer.writerow(['user', 'failed_logins', 'alert'])
        for user, count in sorted(failed.items()):
            writer.writerow([user, count, 'YES' if user in suspicious else 'NO'])
    print(f'CSV report saved: {destination}')


if __name__ == '__main__':
    main()
