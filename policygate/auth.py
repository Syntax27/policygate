"""Validate signed demo identities; authorization lives in the gateway."""

from dataclasses import dataclass
import math

import jwt

from .config import Settings


class InvalidIdentity(ValueError):
    """The credential cannot establish an accepted demo identity."""


@dataclass(frozen=True)
class Identity:
    subject: str
    role: str


def authenticate(authorization: str | None, settings: Settings) -> Identity:
    if not authorization or len(authorization) > 8192:
        raise InvalidIdentity("A valid bearer credential is required.")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise InvalidIdentity("A valid bearer credential is required.")
    try:
        claims = jwt.decode(
            parts[1],
            settings.secret,
            algorithms=["HS256"],
            issuer=settings.issuer,
            audience=settings.audience,
            options={"require": ["exp", "iss", "aud", "sub", "role"]},
        )
        expiry = claims["exp"]
        subject = claims["sub"]
        role = claims["role"]
        if (
            isinstance(expiry, bool)
            or not isinstance(expiry, (int, float))
            or not math.isfinite(expiry)
            or not isinstance(subject, str)
            or not subject.strip()
            or len(subject) > 128
            or not isinstance(role, str)
            or role not in {"reader", "admin"}
        ):
            raise InvalidIdentity("Invalid identity claims.")
    except (jwt.InvalidTokenError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise InvalidIdentity("A valid bearer credential is required.") from exc
    return Identity(subject=subject, role=role)
