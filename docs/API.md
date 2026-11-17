# HTTP API

GET /health reports liveness. GET /api/state creates or refreshes an isolated session, returns topology, flows, rules, metrics, samples, audit, snapshots, revision and CSRF token. GET /api/export omits the token and includes model provenance. GET /metrics exports visitor-scoped synthetic model metrics.

POST requests require application/json, the session cookie and X-CSRF-Token from state. Use the same origin. Errors return an error string and appropriate HTTP status. Never apply a proposal from a different session.

- POST /api/propose: {intent, source: offline|gemini|json, bundle?: {rules:[...]}}. Returns immutable proposal ID, configuration revision, expiry timestamp, canonical rules, safety checks and before/after model preview. json is an advanced structured mode and still uses all safety checks.
- POST /api/apply: {id, revision}. Explicitly applies the stored proposal only if unexpired and current. Duplicate apply returns original receipt.
- POST /api/link: {id: s1-s3, up: false, revision}. Fault injection changes only the twin.
- POST /api/settings: {revision, autoheal?: boolean, proactive?: boolean, surge?: 0.25..5}.
- POST /api/rollback: {id: snapshot_id, revision}. Creates a new control revision restoring retained configuration.
- POST /api/reset: {revision}. Starts a new isolated twin.

Policy fields are documented by validate_schema in core.py. All unrecognized fields are rejected. Modes and provenance are present on every state/export response.
