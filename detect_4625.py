#!/usr/bin/env python3
"""
detect_4625.py

Parse a Windows Security log exported as plain text from Event Viewer
and extract failed logon events (Event ID 4625).

Outputs a CSV with columns: timestamp, username, source_ip

Usage:
    python detect_4625.py -i exported_security_log.txt -o failed_logins.csv

Notes:
- This script is built to work with the typical text export format from Windows Event Viewer
  (fields like "Date:", "Event ID:", sections such as "Account For Which Logon Failed:",
  and "Network Information" with "Source Network Address:").
- It includes fallbacks for slightly different label variants and best-effort IP extraction.
"""

import re
import csv
import argparse
from typing import List, Tuple, Optional

# Regular expressions for matching fields and IP addresses
RE_EVENT_ID = re.compile(r'^\s*Event\s*ID\s*:\s*(\d+)', re.IGNORECASE)
RE_DATE = re.compile(r'^\s*(Date|Time Created|Logged|Time)\s*:\s*(.+)$', re.IGNORECASE)
RE_ACCOUNT_FOR_WHICH = re.compile(r'^\s*Account For Which Logon Failed\s*:', re.IGNORECASE)
RE_ACCOUNT_NAME = re.compile(r'^\s*Account\s+Name\s*:\s*(.+)$', re.IGNORECASE)
RE_SOURCE_NETWORK = re.compile(r'^\s*(Source\s+Network\s+Address|Source IP|Source Network Address)\s*:\s*(.+)$', re.IGNORECASE)
# General Account Name if better-targeted field not found (subject/account sections)
RE_ANY_ACCOUNT_NAME = re.compile(r'^\s*Account\s+Name\s*:\s*(.+)$', re.IGNORECASE)

# IPv4 and a simple IPv6-ish pattern (best-effort)
RE_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_IPV6 = re.compile(r'\b[0-9a-fA-F:]{3,}\b')


def find_event_indices(lines: List[str]) -> List[int]:
    """
    Return list of line indices where an Event ID line appears.
    """
    indices = []
    for i, line in enumerate(lines):
        if RE_EVENT_ID.search(line):
            indices.append(i)
    return indices


def extract_event_id(line: str) -> Optional[int]:
    m = RE_EVENT_ID.search(line)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def extract_date_from_block(lines: List[str], event_idx: int) -> Optional[str]:
    """
    Search backwards from the event index up to some number of lines to find a Date/Time field.
    """
    # look back up to 30 lines for Date/Time fields
    start = max(0, event_idx - 40)
    for j in range(event_idx, start - 1, -1):
        m = RE_DATE.search(lines[j])
        if m:
            return m.group(2).strip()
    # fallback: search forward a little in case Date shown after Event Id in some exports
    end = min(len(lines), event_idx + 10)
    for j in range(event_idx + 1, end):
        m = RE_DATE.search(lines[j])
        if m:
            return m.group(2).strip()
    return None


def extract_username_from_block(lines: List[str], event_idx: int) -> Optional[str]:
    """
    For a failed logon event, prefer the Account Name under "Account For Which Logon Failed".
    If that section isn't found, fall back to other Account Name occurrences in the block.
    """
    # Define a block window after the event id where fields usually appear
    start = event_idx
    end = min(len(lines), event_idx + 300)

    # Search for "Account For Which Logon Failed" heading first
    for j in range(start, end):
        if RE_ACCOUNT_FOR_WHICH.search(lines[j]):
            # from this heading search forward up to 30 lines for Account Name
            for k in range(j + 1, min(end, j + 40)):
                m = RE_ACCOUNT_NAME.search(lines[k])
                if m:
                    return m.group(1).strip()
            break

    # If not found, try searching the whole event block for Account Name lines
    # We attempt to find the Account Name that is not empty or a hyphen
    candidates = []
    for j in range(start, end):
        m = RE_ANY_ACCOUNT_NAME.search(lines[j])
        if m:
            name = m.group(1).strip()
            if name and name != '-' and name.lower() != 'n/a':
                candidates.append(name)

    if candidates:
        # Prefer the last candidate in the block (often the one in the failure section)
        return candidates[-1]

    return None


def extract_source_ip_from_block(lines: List[str], event_idx: int) -> Optional[str]:
    """
    Search in the event block for a "Source Network Address" or similar line.
    If found, validate and return an IP (IPv4 or IPv6). If the field contains '-', return empty.
    """
    start = event_idx
    end = min(len(lines), event_idx + 300)

    for j in range(start, end):
        m = RE_SOURCE_NETWORK.search(lines[j])
        if m:
            val = m.group(2).strip()
            if val == '-' or val.lower() == 'n/a':
                return None
            # try to extract IPv4 first
            ipv4 = RE_IPV4.search(val)
            if ipv4:
                return ipv4.group(0)
            # try IPv6-ish fallback
            ipv6 = RE_IPV6.search(val)
            if ipv6:
                return ipv6.group(0)
            # else return raw trimmed value
            return val

    # fallback: sometimes source IP appears on lines like "Source Network Address : 192.168.1.1"
    # Search for any IPv4/IPv6-looking token in the block
    for j in range(start, end):
        ipv4 = RE_IPV4.search(lines[j])
        if ipv4:
            return ipv4.group(0)
        ipv6 = RE_IPV6.search(lines[j])
        if ipv6:
            # filter out obvious non-IP tokens like hex process ids by checking for colon present
            if ':' in ipv6.group(0):
                return ipv6.group(0)
    return None


def parse_failed_logons(file_path: str) -> List[Tuple[str, str, str]]:
    """
    Parse the text log file and return a list of tuples: (timestamp, username, source_ip)
    for each Event ID 4625 found.
    """
    with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
        lines = fh.readlines()

    # Pre-strip newline characters for easier regex matching
    lines = [ln.rstrip('\r\n') for ln in lines]

    event_indices = find_event_indices(lines)
    results: List[Tuple[str, str, str]] = []

    for idx in event_indices:
        eid = extract_event_id(lines[idx])  # should be present
        if eid != 4625:
            continue

        timestamp = extract_date_from_block(lines, idx) or ''
        username = extract_username_from_block(lines, idx) or ''
        source_ip = extract_source_ip_from_block(lines, idx) or ''

        results.append((timestamp, username, source_ip))

    return results


def write_csv(rows: List[Tuple[str, str, str]], out_path: str) -> None:
    """
    Write the parsed rows to a CSV file with a header.
    """
    with open(out_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['timestamp', 'username', 'source_ip'])
        for r in rows:
            writer.writerow(r)


def main():
    parser = argparse.ArgumentParser(description='Detect Event ID 4625 failed logons in Event Viewer text export and output CSV.')
    parser.add_argument('-i', '--input', required=True, help='Path to the exported Event Viewer .txt file')
    parser.add_argument('-o', '--output', required=True, help='Path to output CSV file')
    args = parser.parse_args()

    print(f'Parsing input file: {args.input}')
    rows = parse_failed_logons(args.input)
    print(f'Found {len(rows)} Event ID 4625 entries.')

    print(f'Writing CSV to: {args.output}')
    write_csv(rows, args.output)
    print('Done.')


if __name__ == '__main__':
    main()