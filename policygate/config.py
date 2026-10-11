"""Explicit configuration for the local demonstration."""

from dataclasses import dataclass, field
import math
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    secret: str = field(repr=False)
    issuer: str = "policygate-demo"
    audience: str = "policygate-api"
    upstream_url: str = "http://127.0.0.1:8001"
    upstream_timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not isinstance(self.secret, str) or len(self.secret.encode("utf-8")) < 32:
            raise ValueError("POLICYGATE_SECRET must contain at least 32 UTF-8 bytes.")
        if not self.issuer or not self.audience:
            raise ValueError("Issuer and audience must be nonempty.")
        try:
            parsed = urlsplit(self.upstream_url)
            port = parsed.port
        except (ValueError, TypeError) as exc:
            raise ValueError("Upstream must be an HTTP loopback origin.") from exc
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or port == 0
        ):
            raise ValueError("Upstream must be an HTTP loopback origin without credentials or a path.")
        if not math.isfinite(self.upstream_timeout_seconds) or self.upstream_timeout_seconds <= 0:
            raise ValueError("Upstream timeout must be finite and positive.")
        object.__setattr__(self, "upstream_url", self.upstream_url.rstrip("/"))
