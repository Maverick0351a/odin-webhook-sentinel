#!/usr/bin/env python
import re, sys, pathlib, datetime

if len(sys.argv) != 2:
    print("Usage: bump_version.py <new_version>")
    sys.exit(1)

new_version = sys.argv[1]
root = pathlib.Path(__file__).resolve().parents[1]
pyproject = root / "pyproject.toml"
chart = root / "charts" / "sentinel" / "Chart.yaml"
changelog = root / "CHANGELOG.md"

text = pyproject.read_text(encoding='utf-8')
text = re.sub(r'version\s*=\s*"[0-9]+\.[0-9]+\.[0-9]+"', f'version = "{new_version}"', text)
pyproject.write_text(text, encoding="utf-8")

# Update Helm chart versions (both chart version and appVersion) if present
if chart.exists():
    chart_text = chart.read_text(encoding="utf-8")
    # chart version line (e.g., version: 0.1.1) – align chart version with app version for simplicity
    chart_text = re.sub(r"^version:\s*.*$", f"version: {new_version}", chart_text, flags=re.MULTILINE)
    chart_text = re.sub(r'^appVersion:\s*".*"$', f'appVersion: "{new_version}"', chart_text, flags=re.MULTILINE)
    chart.write_text(chart_text, encoding="utf-8")

today = datetime.date.today().isoformat()
cl = changelog.read_text(encoding='utf-8')
if '## [Unreleased]' in cl:
    cl = cl.replace('## [Unreleased]', f'## [Unreleased]\n\n## [{new_version}] - {today}')
else:
    cl += f'\n## [{new_version}] - {today}\n'
changelog.write_text(cl, encoding="utf-8")

print(f'Updated version to {new_version}')
