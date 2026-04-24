from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.security import key_id_from_public_jwk, private_jwk_from_key, public_jwk_from_key


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an owner keypair for the auth-proxy browser unlock flow."
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        help="Write the browser-importable owner state JSON to this path.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the state file if it already exists.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = public_jwk_from_key(private_key.public_key())
    private_jwk = private_jwk_from_key(private_key)
    key_id = key_id_from_public_jwk(public_jwk)
    state_payload = {
        "owner_private_jwk": private_jwk,
        "owner_public_jwk": public_jwk,
        "owner_key_id": key_id,
    }

    if args.state_file:
        if args.state_file.exists() and not args.force:
            raise SystemExit(f"state file already exists: {args.state_file}")
        args.state_file.parent.mkdir(parents=True, exist_ok=True)
        args.state_file.write_text(json.dumps(state_payload, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(args.state_file, 0o600)
        except OSError:
            pass

    print("# Save the private JWK in one browser only. Do not commit it.")
    print(f"OWNER_PUBLIC_KEY_JWK='{json.dumps(public_jwk, separators=(',', ':'))}'")
    print()
    if args.state_file:
        print(f"# owner state file written to {args.state_file}")
    else:
        print("# Browser-importable owner state JSON:")
        print(json.dumps(state_payload, indent=2))
    print()
    print(f"# key_id={key_id}")


if __name__ == "__main__":
    main()
