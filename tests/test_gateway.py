"""Observable authentication, policy, forwarding, and audit guarantees.

These tests exercise a local educational gateway. They do not establish a
production security boundary or substitute for a security review.
"""

import json
import logging
import time
import uuid
from collections.abc import Callable

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from policygate.config import Settings
from policygate.gateway import create_app


SECRET = "test-only-secret-with-more-than-thirty-two-bytes-for-tests-not-real-credentials"
OTHER_SECRET = "other-test-secret-with-more-than-thirty-two-bytes"
ISSUER = "policygate-demo"
AUDIENCE = "policygate-api"


def claims(role="reader"):
    return {
        "sub": "test-student",
        "role": role,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": int(time.time()) + 3600,
    }


def token(payload=None, *, role="reader", secret=SECRET, algorithm="HS256"):
    return jwt.encode(
        claims(role) if payload is None else payload,
        secret,
        algorithm=algorithm,
    )


def auth(value=None, *, role="reader"):
    return {"Authorization": "Bearer " + (token(role=role) if value is None else value)}


class Upstream:
    def __init__(self, handler: Callable | None = None):
        self.requests = []
        self.handler = handler

    def __call__(self, request):
        self.requests.append(request)
        if self.handler is not None:
            return self.handler(request)
        return httpx.Response(200, json={"result": "from-test-upstream"})


def client_for(upstream):
    settings = Settings(
        secret=SECRET,
        issuer=ISSUER,
        audience=AUDIENCE,
        upstream_url="http://127.0.0.1:8001",
    )
    return TestClient(
        create_app(settings, transport=httpx.MockTransport(upstream)),
        follow_redirects=False,
    )


@pytest.fixture
def gateway():
    upstream = Upstream()
    with client_for(upstream) as client:
        yield client, upstream


def test_health_is_public_and_does_not_contact_upstream(gateway):
    client, upstream = gateway
    response = client.get("/health")
    assert response.status_code == 200
    assert upstream.requests == []


@pytest.mark.parametrize("role", ["reader", "admin"])
def test_allowed_read_reaches_upstream_once(gateway, role):
    client, upstream = gateway
    response = client.get("/reports", headers=auth(role=role))
    assert response.status_code == 200
    assert response.json() == {"result": "from-test-upstream"}
    assert len(upstream.requests) == 1
    assert upstream.requests[0].method == "GET"
    assert str(upstream.requests[0].url) == "http://127.0.0.1:8001/reports"


def test_admin_can_create_report(gateway):
    client, upstream = gateway
    response = client.post(
        "/reports", headers=auth(role="admin"), json={"title": "A local report"}
    )
    assert response.status_code == 200
    assert len(upstream.requests) == 1
    assert upstream.requests[0].method == "POST"
    assert json.loads(upstream.requests[0].content) == {"title": "A local report"}


def test_reader_cannot_create_report(gateway):
    client, upstream = gateway
    response = client.post(
        "/reports", headers=auth(role="reader"), json={"title": "Not permitted"}
    )
    assert response.status_code == 403
    assert upstream.requests == []


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer"},
     {"Authorization": "Bearer "}, {"Authorization": "Bearer not-a-jwt"}],
)
def test_missing_or_malformed_credentials_are_rejected(gateway, headers):
    client, upstream = gateway
    assert client.get("/reports", headers=headers).status_code == 401
    assert upstream.requests == []


def test_signature_with_another_secret_is_rejected(gateway):
    client, upstream = gateway
    response = client.get("/reports", headers=auth(token(secret=OTHER_SECRET)))
    assert response.status_code == 401
    assert upstream.requests == []


@pytest.mark.parametrize("algorithm", ["HS384", "HS512", "none"])
def test_only_hs256_is_accepted(gateway, algorithm):
    client, upstream = gateway
    encoded = token(secret="" if algorithm == "none" else SECRET, algorithm=algorithm)
    assert client.get("/reports", headers=auth(encoded)).status_code == 401
    assert upstream.requests == []


@pytest.mark.parametrize("missing", ["exp", "iss", "aud", "sub", "role"])
def test_required_claims_cannot_be_omitted(gateway, missing):
    client, upstream = gateway
    payload = claims()
    del payload[missing]
    assert client.get("/reports", headers=auth(token(payload))).status_code == 401
    assert upstream.requests == []


@pytest.mark.parametrize(
    "field,value",
    [("exp", 1), ("iss", "different-issuer"), ("aud", "different-audience"),
     ("role", "superadmin"), ("role", "Reader"), ("role", None),
     ("role", ["reader"]), ("role", {"role": "reader"}), ("role", 1),
     ("sub", ""), ("sub", None), ("sub", 123)],
)
def test_invalid_identity_claims_are_rejected(gateway, field, value):
    client, upstream = gateway
    payload = claims()
    payload[field] = value
    response = client.get("/reports", headers=auth(token(payload)))
    assert response.status_code == 401
    assert upstream.requests == []


@pytest.mark.parametrize(
    "expiration",
    [float("nan"), float("inf"), -float("inf"), True, False, None, [], {},
     "99999999999"],
    ids=["nan", "positive-infinity", "negative-infinity", "true", "false",
         "null", "list", "object", "numeric-string"],
)
def test_malformed_expiration_is_rejected_without_server_error(gateway, expiration):
    client, upstream = gateway
    payload = claims()
    payload["exp"] = expiration
    response = client.get("/reports", headers=auth(token(payload)))
    assert response.status_code == 401
    assert upstream.requests == []


@pytest.mark.parametrize(
    "method,path",
    [("DELETE", "/reports"), ("PUT", "/reports"), ("PATCH", "/reports"),
     ("OPTIONS", "/reports"), ("HEAD", "/reports"), ("GET", "/reports/"),
     ("GET", "/reports/123"), ("GET", "/admin"), ("GET", "/docs"),
     ("GET", "/openapi.json"), ("POST", "/health"), ("HEAD", "/health")],
)
def test_unlisted_routes_and_methods_are_denied(gateway, method, path):
    client, upstream = gateway
    response = client.request(method, path, headers=auth(role="admin"))
    assert response.status_code == 403
    assert upstream.requests == []


def test_unknown_route_without_token_is_not_public(gateway):
    client, upstream = gateway
    assert client.get("/unknown").status_code == 401
    assert upstream.requests == []


def test_query_and_credentials_cannot_control_upstream(gateway):
    client, upstream = gateway
    headers = auth()
    headers.update({
        "Cookie": "session=private-cookie-value",
        "Proxy-Authorization": "Basic private-proxy-value",
        "X-API-Key": "private-api-key-value",
        "X-Forwarded-Host": "attacker.invalid",
        "X-Upstream-URL": "https://attacker.invalid/steal",
    })
    response = client.get(
        "/reports?url=https://attacker.invalid/steal&upstream=http://127.0.0.1:9999",
        headers=headers,
    )
    assert response.status_code == 200
    assert len(upstream.requests) == 1
    forwarded = upstream.requests[0]
    assert str(forwarded.url) == "http://127.0.0.1:8001/reports"
    for header in headers:
        assert header not in forwarded.headers


def test_upstream_cookies_are_not_replayed_between_user_requests():
    upstream = Upstream(
        lambda request: httpx.Response(
            200, json={"ok": True},
            headers={"Set-Cookie": "upstream_session=private-session-sentinel; Path=/"},
        )
    )
    first_identity = {**claims("reader"), "sub": "first-user"}
    second_identity = {**claims("admin"), "sub": "second-user"}
    with client_for(upstream) as client:
        first = client.get("/reports", headers=auth(token(first_identity)))
        second = client.get("/reports", headers=auth(token(second_identity)))
    assert first.status_code == second.status_code == 200
    assert len(upstream.requests) == 2
    assert "cookie" not in upstream.requests[0].headers
    assert "cookie" not in upstream.requests[1].headers


@pytest.mark.parametrize(
    "error_type,expected_status",
    [(httpx.ConnectError, 502), (httpx.ReadError, 502),
     (httpx.ConnectTimeout, 504), (httpx.ReadTimeout, 504)],
)
def test_upstream_failures_return_generic_errors(error_type, expected_status):
    marker = "private-upstream-diagnostic-sentinel"

    def fail(request):
        raise error_type(marker, request=request)

    upstream = Upstream(fail)
    with client_for(upstream) as client:
        response = client.get("/reports", headers=auth())
    assert response.status_code == expected_status
    assert marker not in response.text
    assert len(upstream.requests) == 1


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_upstream_redirects_are_rejected_without_following(status):
    upstream = Upstream(
        lambda request: httpx.Response(
            status, headers={"Location": "https://attacker.invalid/collect"}
        )
    )
    with client_for(upstream) as client:
        response = client.get("/reports", headers=auth())
    assert response.status_code == 502
    assert "location" not in response.headers
    assert len(upstream.requests) == 1
    assert upstream.requests[0].url.host == "127.0.0.1"


def test_oversized_upstream_response_is_rejected():
    upstream = Upstream(
        lambda request: httpx.Response(200, content=b"x" * (1024 * 1024 + 1))
    )
    with client_for(upstream) as client:
        response = client.get("/reports", headers=auth())
    assert response.status_code == 502
    assert len(response.content) < 4096
    assert len(upstream.requests) == 1


@pytest.mark.parametrize(
    "body", [{}, {"title": ""}, {"title": "   "}, {"title": "x" * 201},
             {"title": "ok", "role": "admin"}, {"title": 7}, [], None],
)
def test_invalid_create_payloads_are_not_forwarded(gateway, body):
    client, upstream = gateway
    response = client.post(
        "/reports",
        headers={**auth(role="admin"), "Content-Type": "application/json"},
        content=json.dumps(body),
    )
    assert response.status_code in {400, 422}
    assert upstream.requests == []


def test_malformed_json_is_not_forwarded(gateway):
    client, upstream = gateway
    response = client.post(
        "/reports", headers={**auth(role="admin"), "Content-Type": "application/json"},
        content='{"title":',
    )
    assert response.status_code == 400
    assert upstream.requests == []


def test_oversized_body_is_not_forwarded(gateway):
    client, upstream = gateway
    response = client.post(
        "/reports", headers=auth(role="admin"), json={"title": "x" * 17000}
    )
    assert response.status_code == 413
    assert upstream.requests == []


def audit_events(caplog):
    return [json.loads(record.getMessage()) for record in caplog.records
            if record.name == "policygate.audit"]


def test_audit_omits_credentials_bodies_queries_and_untrusted_paths(gateway, caplog):
    client, upstream = gateway
    caplog.set_level(logging.INFO, logger="policygate.audit")
    encoded = token(role="admin")
    markers = ["private-body-sentinel", "private-query-sentinel",
               "private-path-sentinel", "private-header-sentinel"]
    headers = {**auth(encoded), "X-Request-ID": markers[3], "X-API-Key": markers[3]}
    first = client.post(
        "/reports?secret=" + markers[1], headers=headers, json={"title": markers[0]}
    )
    second = client.get("/" + markers[2] + "%0Aforged-event", headers=headers)
    assert first.status_code == 200
    assert second.status_code == 403
    events = audit_events(caplog)
    assert len(events) == 2
    log_text = "\n".join(record.getMessage() for record in caplog.records
                         if record.name == "policygate.audit")
    for secret in [SECRET, encoded, *markers]:
        assert secret not in log_text
    assert [event["path"] for event in events] == ["/reports", "<unmatched>"]
    assert [event["status"] for event in events] == [200, 403]
    assert events[0]["decision"] != events[1]["decision"]
    for event, response in zip(events, [first, second], strict=True):
        assert event["request_id"] == response.headers["X-Request-ID"]
        assert str(uuid.UUID(event["request_id"])) == event["request_id"]
        assert event["reason"]
    assert events[0]["request_id"] != events[1]["request_id"]
    assert len(upstream.requests) == 1


def test_malformed_method_and_path_cannot_forge_or_expand_audit(gateway, caplog):
    client, upstream = gateway
    caplog.set_level(logging.INFO, logger="policygate.audit")
    response = client.request(
        "X" * 2000, "/" + "p" * 8000 + "%0Afake-log-entry", headers=auth()
    )
    assert response.status_code in {403, 405}
    assert upstream.requests == []
    events = audit_events(caplog)
    assert len(events) == 1
    assert len(events[0]["method"]) <= 16
    assert events[0]["path"] == "<unmatched>"
    assert "fake-log-entry" not in json.dumps(events)
