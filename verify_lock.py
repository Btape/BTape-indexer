import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
lock = json.loads((root / "config/uco.lock.json").read_text())
for name, expected in lock["files"].items():
    actual = hashlib.sha256((root / "btap_indexer/vendor/uco" / name).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"Upstream file changed: {name}")
print(f"UCO lock verified: {lock['commit']} ({len(lock['files'])} unchanged files)")
