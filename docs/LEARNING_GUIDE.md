# Understand and extend PolicyGate

## Trace one request

1. The client sends a bearer token to `GET /reports`.
2. PyJWT validates the signature and required claims. Changing `reader` to `admin` in the token payload invalidates the signature unless the attacker also has the signing secret.
3. The application checks its policy for the role, HTTP method, and exact route.
4. A reader GET is allowed; a reader POST is denied before any upstream call.
5. The gateway sends the permitted request to the configured local backend, using only the headers and body needed for that operation.
6. The client receives a response and a server-generated request ID. A structured audit event describes the outcome without recording the bearer token.

Authentication answers who a credential represents. Authorization answers what that identity may do. A valid credential is not permission for every operation.

## Read the code in this order

`config.py` -> `auth.py` -> `gateway.py` -> `upstream.py` -> tests -> `scripts/demo.py`.

For each module, explain its inputs, outputs, and one failure case. Run the tests after changing one policy rule and predict which assertion should fail before looking at the result.

## Exercises you should complete yourself

1. Add a `viewer` or `auditor` role with a clearly defined permission. Write its allowed and denied cases before changing the policy.
2. Add one new read-only endpoint and show why an unknown route remains denied.
3. Add a decision counter that does not record credentials. Explain what happens to an in-memory counter after restart or across multiple processes.
4. Explain why direct access to the local upstream bypasses this educational gateway and how a real deployment would restrict that route.
5. Write a short design note explaining one decision you changed and why. Commit the actual code, test, and explanation together.

## Questions to be ready for

- Why is decoding a JWT without verification unsafe?
- Why fix the algorithm, issuer, and audience rather than trust whatever is in the token?
- What is the difference between 401 and 403 in this project?
- How do the tests prove that a forbidden request was not forwarded?
- Why does the gateway use a fixed upstream and refuse redirects?
- Why should tokens, query strings, and request bodies be excluded from audit logs?
- What happens when the upstream is unavailable? How is that different from a timeout?
- Which limitations prevent you from calling this production-ready?
- Which parts came from libraries or AI assistance, and which changes can you personally explain and demonstrate?

## Resume evidence

After you have run, reviewed, and modified the project, a factual description of the implementation is:

> Implemented a local FastAPI access gateway with signed-token validation, role-based route permissions, and structured authorization logs.

Only claim your personal work accurately. If you are still learning this generated starting point, describe it as an assisted learning project. Do not claim production users, deployment, attack prevention, low latency, or distributed security. Add numerical test results only from the recorded run, and understand the tested behaviors rather than relying on the count.
