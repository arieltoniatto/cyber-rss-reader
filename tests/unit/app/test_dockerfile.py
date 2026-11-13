import re
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[3] / 'Dockerfile'


def test_every_stage_uses_the_same_base_image_pinned_by_digest():
    bases = re.findall(r'^FROM\s+(\S+)', DOCKERFILE.read_text(), flags=re.MULTILINE)
    assert len(bases) == 2
    assert all(re.fullmatch(r'python:3\.12-slim-bookworm@sha256:[0-9a-f]{64}', base) for base in bases)
    assert len(set(bases)) == 1
