#!/usr/bin/env python3
"""Offline demo: no AWS credentials, resource changes, or email delivery."""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detection.risky_ssh import detect

for name in ('risky-ssh', 'safe-mixed-rules'):
    event = json.loads((Path(__file__).resolve().parents[1] / 'examples' / f'{name}.json').read_text())
    findings = detect(event)
    print(f'{name}: {len(findings)} finding(s)')
    if findings:
        print(json.dumps(findings, indent=2))
