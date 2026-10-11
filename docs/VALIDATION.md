# Validation record

Date: 11 October 2026.

## Environment

- Windows 11, Python 3.12.14.
- FastAPI 0.143.0, Starlette 1.7.0, HTTPX 0.28.1, PyJWT 2.15.1.
- Pytest 9.1.1, Uvicorn 0.54.0, Pydantic 2.14.0.
- Full installed package versions: `requirements-lock.txt`.

## Automated checks

Command: `python -m pytest -q`

Result: **77 passed**. The count includes parameterized cases; it is not a count of independent test functions.

The checks exercise missing/invalid/expired credentials; required claims and invalid claim types; disallowed signing algorithms; issuer/audience mismatches; role/method/route decisions; denied requests never reaching the upstream; fixed upstream routing; removal of client credentials; isolation from upstream cookies; body/schema limits; redirects; response-size limits; connection failures/timeouts; request IDs; and audit-log redaction.

The test library emits a Starlette deprecation warning about its HTTPX TestClient integration. This does not fail the pinned tests; a future dependency upgrade should migrate that test integration rather than suppress the warning without investigation.

## Live two-server demo

Command: `python scripts/demo.py`

Result: **11 live HTTP checks passed**, plus audit-output verification. Both local processes were stopped by the demo.

```text
PASS Public liveness: HTTP 200
PASS Missing token rejected: HTTP 401
PASS Reader can list: HTTP 200
PASS Reader write denied: HTTP 403
PASS Denied write left storage unchanged: HTTP 200
PASS Admin can create: HTTP 201
PASS Reader sees created report: HTTP 200
PASS Expired token rejected: HTTP 401
PASS Unknown route denied: HTTP 403
PASS Invalid report rejected: HTTP 422
PASS Stopped upstream handled: HTTP 502
PASS Audit events recorded without demo tokens or signing secret
All 11 live HTTP checks passed; both local processes stopped.
```

## Interpretation

The automated checks use a controlled HTTPX transport; the live demo verifies actual localhost forwarding and denial behavior. Neither proves production security, internet-facing resilience, cross-platform support, or performance at scale. The GitHub workflow is included; its result must be checked on GitHub after publication. No throughput or latency benchmark is claimed.
