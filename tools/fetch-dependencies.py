#!/usr/bin/env python3
"""Fetch the pinned host tools; never silently accept a mismatching cache entry.

Downloads the files of dependencies.lock.json marked "use": "host" (the docker-compose binary the lab tools run,
as nothing is installed on the host) into .cache/deps unless already there, and checks the SHA-256 of each against
the lock file. The archives the images need ("use": "image") are fetched by the image builds themselves
(docker/fetch). No 3GPP behaviour.
"""

import hashlib
import json
import pathlib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------------------
def main():
    """Download the missing pinned files and verify every cached file against its SHA-256."""
    cache = ROOT / ".cache/deps"
    cache.mkdir(parents=True, exist_ok=True)
    for item in json.loads((ROOT / "dependencies.lock.json").read_text())["software"]:
        if item.get("use") != "host":
            continue
        target = cache / item["file"]
        if not target.exists():
            request = urllib.request.Request(item["url"], headers={"User-Agent": "Mozilla/5.0"})
            partial = target.with_suffix(target.suffix + ".partial")
            try:
                with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as out:
                    while chunk := response.read(1024 * 1024):
                        out.write(chunk)
                if hashlib.sha256(partial.read_bytes()).hexdigest() != item["sha256"]:
                    raise RuntimeError(f"SHA-256 mismatch: {item['file']}")
                partial.rename(target)
            finally:
                partial.unlink(missing_ok=True)
        if hashlib.sha256(target.read_bytes()).hexdigest() != item["sha256"]:
            raise RuntimeError(f"SHA-256 mismatch: {target}; remove it and retry")
        if target.name.startswith("docker-compose"):
            target.chmod(0o755)
        print(f"verified {target.name}")


if __name__ == "__main__":
    main()
