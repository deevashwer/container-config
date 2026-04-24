from __future__ import annotations

import argparse
import re
from pathlib import Path


DEFAULT_RUNTIME_IMAGE = "ghcr.io/deevashwer/container-config-openclaw-runtime"
DEFAULT_AUTH_PROXY_IMAGE = "ghcr.io/deevashwer/container-config-auth-proxy"
LEGACY_RUNTIME_IMAGE = "ghcr.io/deevashwer/openclaw-runtime"
LEGACY_AUTH_PROXY_IMAGE = "ghcr.io/deevashwer/openclaw-auth-proxy"


def replace_any_image_ref(content: str, repos: tuple[str, ...], replacement: str) -> str:
    total_count = 0
    updated = content
    for repo in repos:
        pattern = re.compile(rf"{re.escape(repo)}:[^\"@\s]+(?:@sha256:[0-9a-f]+)?")
        updated, count = pattern.subn(replacement, updated, count=1)
        total_count += count
    if total_count != 1:
        repo_list = ", ".join(repos)
        raise ValueError(f"expected exactly one image reference for one of [{repo_list}], found {total_count}")
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
    content = replace_any_image_ref(
        content,
        (args.runtime_image, LEGACY_RUNTIME_IMAGE),
        f"{args.runtime_image}:{args.tag}@{args.runtime_digest}",
    )
    content = replace_any_image_ref(
        content,
        (args.auth_proxy_image, LEGACY_AUTH_PROXY_IMAGE),
        f"{args.auth_proxy_image}:{args.tag}@{args.auth_proxy_digest}",
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
