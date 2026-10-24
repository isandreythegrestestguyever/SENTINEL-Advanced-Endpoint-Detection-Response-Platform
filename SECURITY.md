# Security policy

SENTINEL is an early local development project and is not suitable for production monitoring. Do not expose its default HTTP listener beyond loopback, and do not submit sensitive telemetry.

Report suspected vulnerabilities privately to the repository owner through GitHub's security advisory feature. Include affected version, reproduction steps, and impact. Do not include live secrets or personal data in public issues.

Mutating endpoints require a bearer token; by default a fresh token is logged on each start. Read endpoints are unauthenticated. HTTPS can be enabled with certificate and key environment variables, but mTLS is not implemented. There is no formal release signing, dependency scanning pipeline, RBAC, rate limiting, or external security review. The simulator creates synthetic records and does not execute attack actions.
