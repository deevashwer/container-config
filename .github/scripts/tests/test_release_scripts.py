from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = REPO_ROOT / ".github" / "scripts"
RENDER_SCRIPT = SCRIPTS_DIR / "render_release_config.py"
SYNC_SCRIPT = SCRIPTS_DIR / "sync_release_refs.py"

RUNTIME_IMAGE = "ghcr.io/deevashwer/openclaw-runtime"
AUTH_PROXY_IMAGE = "ghcr.io/deevashwer/openclaw-auth-proxy"
TAG = "v9.9.9"
RUNTIME_DIGEST = "sha256:" + "1" * 64
AUTH_PROXY_DIGEST = "sha256:" + "2" * 64


def run_script(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        check=True,
        text=True,
        capture_output=True,
    )


def test_render_release_config_updates_both_image_refs(tmp_path: Path) -> None:
    input_path = REPO_ROOT / "tinfoil-config.yml"
    output_path = tmp_path / "release-tinfoil-config.yml"

    run_script(
        RENDER_SCRIPT,
        "--input",
        str(input_path),
        "--output",
        str(output_path),
        "--tag",
        TAG,
        "--runtime-image",
        RUNTIME_IMAGE,
        "--auth-proxy-image",
        AUTH_PROXY_IMAGE,
        "--runtime-digest",
        RUNTIME_DIGEST,
        "--auth-proxy-digest",
        AUTH_PROXY_DIGEST,
    )

    rendered = output_path.read_text()
    assert f"{RUNTIME_IMAGE}:{TAG}@{RUNTIME_DIGEST}" in rendered
    assert f"{AUTH_PROXY_IMAGE}:{TAG}@{AUTH_PROXY_DIGEST}" in rendered


def test_sync_release_refs_updates_tracked_files(tmp_path: Path) -> None:
    config_path = tmp_path / "tinfoil-config.yml"
    readme_path = tmp_path / "README.md"
    config_path.write_text((REPO_ROOT / "tinfoil-config.yml").read_text())
    readme_path.write_text((REPO_ROOT / "README.md").read_text())

    run_script(
        SYNC_SCRIPT,
        "--tag",
        TAG,
        "--runtime-image",
        RUNTIME_IMAGE,
        "--auth-proxy-image",
        AUTH_PROXY_IMAGE,
        "--runtime-digest",
        RUNTIME_DIGEST,
        "--auth-proxy-digest",
        AUTH_PROXY_DIGEST,
        "--config",
        str(config_path),
        "--readme",
        str(readme_path),
    )

    expected_runtime_ref = f"{RUNTIME_IMAGE}:{TAG}@{RUNTIME_DIGEST}"
    expected_auth_proxy_ref = f"{AUTH_PROXY_IMAGE}:{TAG}@{AUTH_PROXY_DIGEST}"

    assert expected_runtime_ref in config_path.read_text()
    assert expected_auth_proxy_ref in config_path.read_text()
    assert expected_runtime_ref in readme_path.read_text()
    assert expected_auth_proxy_ref in readme_path.read_text()
