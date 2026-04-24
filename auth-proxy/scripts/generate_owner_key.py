from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.security import key_id_from_public_jwk, private_jwk_from_key, public_jwk_from_key


def main() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = public_jwk_from_key(private_key.public_key())
    private_jwk = private_jwk_from_key(private_key)
    key_id = key_id_from_public_jwk(public_jwk)

    print("# Save the private JWK in one browser only. Do not commit it.")
    print(f"OWNER_PUBLIC_KEY_JWK='{json.dumps(public_jwk, separators=(',', ':'))}'")
    print()
    print("# Import this private JWK into the demo client or keep it in a local env file.")
    print(json.dumps(private_jwk, indent=2))
    print()
    print(f"# key_id={key_id}")


if __name__ == "__main__":
    main()
