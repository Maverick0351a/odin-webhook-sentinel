#!/usr/bin/env python
"""Derive next semantic version from conventional commit messages since last tag.

Rules (in order):
- If any commit message body or footer contains 'BREAKING CHANGE' or header has '!' before ':', bump MAJOR.
- Else if any commit type in (feat) -> bump MINOR.
- Else if any commit type in (fix, perf, refactor, docs, chore, test, build, ci, security) -> bump PATCH.
- Fallback: PATCH.

Outputs the next version to stdout. Existing version read from pyproject.toml.
"""
from __future__ import annotations
import subprocess, re, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / 'pyproject.toml'

def current_version() -> str:
    m = re.search(r'version\s*=\s*"(\d+\.\d+\.\d+)"', PYPROJECT.read_text(encoding='utf-8'))
    if not m:
        print('0.0.0')
        return '0.0.0'
    return m.group(1)

def last_tag() -> str | None:
    try:
        out = subprocess.check_output(['git','describe','--tags','--abbrev=0'], text=True).strip()
        return out
    except subprocess.CalledProcessError:
        return None

def collect_commits(since_tag: str | None) -> list[str]:
    rev_range = f'{since_tag}..HEAD' if since_tag else 'HEAD'
    out = subprocess.check_output(['git','log','--format=%H%x01%s%x01%b%x02', rev_range], text=True)
    entries = []
    for block in out.split('\x02'):
        block = block.strip()
        if not block:
            continue
        parts = block.split('\x01')
        if len(parts) >= 3:
            _, subject, body = parts[0], parts[1], parts[2]
            entries.append(subject + '\n' + body)
    return entries

def classify(commits: list[str]) -> str:
    major = False
    minor = False
    patch = False
    for c in commits:
        # Breaking change markers
        if 'BREAKING CHANGE' in c or re.search(r'^\w+!:', c):
            major = True
            break
        header_match = re.match(r'^(\w+)(?:\([^)]*\))?(!?):', c)
        if header_match:
            ctype, bang = header_match.group(1), header_match.group(2)
            if bang == '!':
                major = True
                break
            if ctype == 'feat':
                minor = True
            elif ctype in {'fix','perf','refactor','docs','chore','test','build','ci','security'}:
                patch = True
        else:
            patch = True
    if major:
        return 'major'
    if minor:
        return 'minor'
    return 'patch' if patch or commits else 'patch'

def bump(version: str, kind: str) -> str:
    major, minor, patch = map(int, version.split('.'))
    if kind == 'major':
        return f'{major+1}.0.0'
    if kind == 'minor':
        return f'{major}.{minor+1}.0'
    return f'{major}.{minor}.{patch+1}'

def main():
    cur = current_version()
    tag = last_tag()
    commits = collect_commits(tag)
    kind = classify(commits)
    nxt = bump(cur, kind)
    print(nxt)

if __name__ == '__main__':
    main()
