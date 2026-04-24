from __future__ import annotations

import argparse
import re
from pathlib import Path


DEFAULT_RUNTIME_IMAGE = "ghcr.io/deevashwer/container-config-openclaw-runtime"
DEFAULT_AUTH_PROXY_IMAGE = "ghcr.io/deevashwer/container-config-auth-proxy"
LEGACY_RUNTIME_IMAGE = "ghcr.io/deevashwer/openclaw-runtime"
LEGACY_AUTH_PROXY_IMAGE = "ghcr.io/deevashwer/openclaw-auth-proxy"


def replace_any_image_ref(content: str, repos: tuple[str, ...], replacement: str, *, expected_count: int = 1) -> str:
    total_count = 0
    updated = content
    for repo in repos:
        pattern = re.compile(rf"{re.escape(repo)}:[^\"`\s@]+(?:@sha256:[0-9a-f]+)?")
        updated, count = pattern.subn(replacement, updated)
        total_count += count
    if total_count != expected_count:
        repo_list = ", ".join(repos)
        raise ValueError(
            f"expected {expected_count} image reference(s) for one of [{repo_list}], found {total_count}"
        )
    return updated


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Update tracked release refs so the repo stays aligned with the published GHCR images.",
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--runtime-image", default=DEFAULT_RUNTIME_IMAGE)
    parser.add_argument("--auth-proxy-image", default=DEFAULT_AUTH_PROXY_IMAGE)
    parser.add_argument("--runtime-digest", required=True)
    parser.add_argument("--auth-proxy-digest", required=True)
    parser.add_argument("--config", default="tinfoil-config.yml")
    parser.add_argument("--readme", default="README.md")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runtime_ref = f"{args.runtime_image}:{args.tag}@{args.runtime_digest}"
    auth_proxy_ref = f"{args.auth_proxy_image}:{args.tag}@{args.auth_proxy_digest}"

    config_path = Path(args.config)
    config_content = config_path.read_text()
    config_content = replace_any_image_ref(
        config_content,
        (args.runtime_image, LEGACY_RUNTIME_IMAGE),
        runtime_ref,
    )
    config_content = replace_any_image_ref(
        config_content,
        (args.auth_proxy_image, LEGACY_AUTH_PROXY_IMAGE),
        auth_proxy_ref,
    )
    config_path.write_text(config_content)

    readme_path = Path(args.readme)
    readme_content = readme_path.read_text()
    readme_content = replace_any_image_ref(
        readme_content,
        (args.auth_proxy_image, LEGACY_AUTH_PROXY_IMAGE),
        auth_proxy_ref,
    )
    readme_content = replace_any_image_ref(
        readme_content,
        (args.runtime_image, LEGACY_RUNTIME_IMAGE),
        runtime_ref,
    )
    readme_path.write_text(readme_content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
