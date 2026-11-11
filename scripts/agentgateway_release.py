#!/usr/bin/env python3
"""Is the pinned agentgateway still the latest upstream release?

Reads deploy/agentgateway/agentgateway.lock.json, then asks GitHub for the releases of the
project named there and for its published security advisories. Reports every release newer
than the pinned one and every advisory whose affected range includes the pinned version.

The project follows the latest upstream release, and upstream has so far fixed advisories
only in a new release, never in a patch to an older line. This is how to find out when the
pin has fallen behind:

    python3 scripts/agentgateway_release.py

It is the only script in the repository that needs the network, and no test calls it.
Exit status: 0 the pinned release is the latest and no published advisory affects it;
1 there is a newer release, or an advisory that affects (or may affect) the pinned version;
2 no answer (network, rate limit, an unexpected reply). GITHUB_TOKEN, if set, is sent to
api.github.com to raise the rate limit.
"""
from __future__ import annotations
import json, os, re, sys, urllib.error, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'deploy/agentgateway/agentgateway.lock.json'
RELEASE = re.compile(r'v?(\d+)\.(\d+)\.(\d+)')
CONSTRAINT = re.compile(r'\s*(<=|>=|<|>|=)\s*(\S+)\s*')


def parse(version: str) -> tuple[int, int, int] | None:
    """'1.7.0' or 'v1.7.0' -> (1, 7, 0). None for anything else, pre-release tags included."""
    m = RELEASE.fullmatch(version.strip())
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def affects(vulnerable_range: str, pinned: tuple[int, int, int]) -> bool | None:
    """Is pinned inside an advisory range such as '<v1.7.0' or '>= 1.5.0, < 1.7.0'? None: cannot tell."""
    verdicts = []
    for part in vulnerable_range.split(','):
        m = CONSTRAINT.fullmatch(part)
        bound = parse(m[2]) if m else None
        if bound is None:
            return None
        verdicts.append({'<': pinned < bound, '<=': pinned <= bound, '>': pinned > bound,
                         '>=': pinned >= bound, '=': pinned == bound}[m[1]])
    return all(verdicts)


def assess(pinned_version: str, releases: list[dict], advisories: list[dict]) -> dict:
    """What GitHub's two replies say about the pinned version. Pure: no network, no files."""
    pinned = parse(pinned_version)
    if pinned is None:
        raise ValueError(f'the pinned version {pinned_version!r} is not a release version')
    # A pre-release is recognised by its tag. The prerelease flag is not reliable upstream:
    # several alpha and beta tags were published without it.
    stable = sorted((r for r in releases if not r.get('draft') and not r.get('prerelease') and parse(r.get('tag_name') or '')),
                    key=lambda r: parse(r['tag_name']))
    describe = lambda r: {'tag': r['tag_name'], 'published': (r.get('published_at') or '')[:10], 'url': r.get('html_url') or ''}
    affecting, unclear = [], []
    for advisory in advisories:
        if advisory.get('state', 'published') != 'published':
            continue
        ranges = [v.get('vulnerable_version_range') or '' for v in advisory.get('vulnerabilities') or []]
        verdicts = [affects(r, pinned) for r in ranges]
        entry = {'id': advisory.get('ghsa_id') or '', 'severity': advisory.get('severity') or '', 'summary': advisory.get('summary') or '',
                 'affected': '; '.join(ranges),
                 'patched': '; '.join(str(v.get('patched_versions') or '') for v in advisory.get('vulnerabilities') or []),
                 'url': advisory.get('html_url') or ''}
        if any(v is True for v in verdicts):
            affecting.append(entry)
        elif not verdicts or any(v is None for v in verdicts):
            unclear.append(entry)
    return {'pinned': pinned_version,
            'latest': describe(stable[-1]) if stable else None,
            'newer': [describe(r) for r in stable if parse(r['tag_name']) > pinned],
            'pinned_is_a_release_upstream': any(parse(r['tag_name']) == pinned for r in stable),
            'advisories_affecting_the_pin': affecting, 'advisories_with_a_range_not_understood': unclear}


def get(url: str) -> list:
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'idp-gateway-release-check'}
    if os.environ.get('GITHUB_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['GITHUB_TOKEN']
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as response:
        reply = json.loads(response.read())
    if not isinstance(reply, list):
        raise ValueError(f'{url}: expected a list, got {type(reply).__name__}')
    return reply


def main() -> int:
    lock = json.loads(LOCK.read_text(encoding='utf-8'))
    where = re.fullmatch(r'https://github\.com/([^/]+/[^/]+)/releases/tag/.+', lock['release'])
    if not where:
        print(f"{LOCK.relative_to(ROOT)}: release is not a GitHub release URL: {lock['release']}"); return 2
    api = f'https://api.github.com/repos/{where[1]}'
    try:
        result = assess(lock['version'], get(api + '/releases?per_page=100'), get(api + '/security-advisories?per_page=100'))
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f'no answer from GitHub about {where[1]}: {type(e).__name__}: {e}'); return 2

    print(f"pinned: agentgateway {result['pinned']} ({LOCK.relative_to(ROOT).as_posix()})")
    latest = result['latest']
    print('latest upstream release: ' + (f"{latest['tag']}, published {latest['published']}" if latest else 'none found'))
    if not result['pinned_is_a_release_upstream']:
        print('  the pinned version is not among the upstream releases: check the lock')
    for r in result['newer']:
        print(f"  newer: {r['tag']}, published {r['published']}  {r['url']}")
    for title, key in (('published advisories that affect the pinned version', 'advisories_affecting_the_pin'),
                       ('published advisories whose affected range this script could not read (read them)', 'advisories_with_a_range_not_understood')):
        if result[key] or key == 'advisories_affecting_the_pin':
            print(f"{title}: {len(result[key]) or 'none'}")
        for a in result[key]:
            print(f"  {a['id']} [{a['severity']}] {a['summary']}\n    affected: {a['affected']} | fixed in: {a['patched']}\n    {a['url']}")
    behind = bool(result['newer'] or result['advisories_affecting_the_pin'] or result['advisories_with_a_range_not_understood']
                  or not result['pinned_is_a_release_upstream'])
    print('the pin needs attention: see deploy/agentgateway/README.md for how to move it.' if behind
          else 'the pinned release is the latest, and no published advisory affects it.')
    return 1 if behind else 0


if __name__ == '__main__':
    sys.exit(main())
