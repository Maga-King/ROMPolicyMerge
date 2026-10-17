"""Materialize the release keystore from an Actions secret, without logging it."""
import base64
import os
from pathlib import Path

encoded = os.environ.get('ROMPOLICY_JKS_BASE64')
if not encoded:
    raise SystemExit('Missing repository secret ROMPOLICY_JKS_BASE64')
path = Path(os.environ['RUNNER_TEMP']) / 'rompolicy-release.jks'
path.write_bytes(base64.b64decode(encoded, validate=True))
with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as output:
    output.write('ROMPOLICY_KEYSTORE=' + str(path) + '\n')
print('Release signing key is ready.')
