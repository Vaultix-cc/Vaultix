import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # the vaultix package of this checkout
sys.path.insert(0, str(HERE))         # zk1_server helpers


def _vectors_path() -> Path:
    """The shared zk1 vectors: tests/vectors/zk1.json (a copy of the Vaultix
    backend's backend/tests/crypto_vectors/zk1.json), or $VAULTIX_ZK1_VECTORS."""
    return Path(os.environ.get("VAULTIX_ZK1_VECTORS") or HERE / "vectors" / "zk1.json")


@pytest.fixture(scope="session")
def vectors():
    path = _vectors_path()
    if not path.is_file():
        pytest.skip(f"zk1 vectors not found at {path} (set VAULTIX_ZK1_VECTORS)")
    return json.loads(path.read_text(encoding="utf-8"))
