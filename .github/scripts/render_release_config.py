from __future__ import annotations

import argparse
import re
from pathlib import Path


DEFAULT_RUNTIME_IMAGE = "ghcr.io/deevashwer/openclaw-runtime"
DEFAULT_AUTH_PROXY_IMAGE = "ghcr.io/deevashwer/openclaw-auth-proxy"


def replace_image_ref(content: str, repo: str, replacement: str) -> str:
    pattern = re.compile(rf"{re.escape(repo)}:[^\"@\s]+(?:@sha256:[0-9a-f]+)?")
    updated, count = pattern.subn(replacement, content, count=1)
    if count != 1:
        raise ValueError(f"expected exactly one image reference for {repo}, found {count}")
    return updated


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render a release-specific Tinfoil config with updated GHCR tags and digests.",
    )
    parser.add_argument("--input", required=True, dest="input_path")
    parser.add_argument("--output", required=True, dest="output_path")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--runtime-image", default=DEFAULT_RUNTIME_IMAGE)
    parser.add_argument("--auth-proxy-image", default=DEFAULT_AUTH_PROXY_IMAGE)
    parser.add_argument("--runtime-digest", required=True)
    parser.add_argument("--auth-proxy-digest", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = Path(args.input_path)
    output_path = Path(args.output_path)

    content = input_path.read_text()
    replacements = {
        args.runtime_image: f"{args.runtime_image}:{args.tag}@{args.runtime_digest}",
        args.auth_proxy_image: f"{args.auth_proxy_image}:{args.tag}@{args.auth_proxy_digest}",
    }

    for repo, replacement in replacements.items():
        content = replace_image_ref(content, repo, replacement)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
