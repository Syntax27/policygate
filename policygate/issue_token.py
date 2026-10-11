"""Issue a five-minute demo token locally; this is not an HTTP login service."""

import argparse
import os
import time

import jwt

from .config import Settings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("reader", "admin"), required=True)
    parser.add_argument("--subject", default="demo-user")
    args = parser.parse_args()
    if not args.subject.strip() or len(args.subject) > 128:
        parser.error("Subject must be nonblank and at most 128 characters.")
    try:
        settings = Settings(secret=os.environ.get("POLICYGATE_SECRET", ""))
    except ValueError as exc:
        parser.error(str(exc))
    now = int(time.time())
    print(jwt.encode({
        "sub": args.subject,
        "role": args.role,
        "iss": settings.issuer,
        "aud": settings.audience,
        "iat": now,
        "exp": now + 300,
    }, settings.secret, algorithm="HS256"))


if __name__ == "__main__":
    main()
