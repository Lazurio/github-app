# Lazurio for GitHub broker

Public, auditable source for the small credential boundary used by Lazurio
Team Workspaces. The broker exchanges an authenticated Workspace request for a
short-lived GitHub App installation token restricted to one immutable
repository id and `contents: write`.

The source is public so customers can review what handles the App private key.
Public source alone is not deployment proof: an operator must also record the
exact source commit, immutable runtime image and deployment attestation.

## Trust boundary

The broker makes one machine authorization decision:

```text
Workspace id + Workspace credential + repository id
    -> exact deployment policy
    -> live GitHub App installation grant
    -> one-repository installation token
```

- It never asks which human last used the Workspace.
- It never receives a browser session or OAuth token.
- The GitHub App private key exists only in the broker workload.
- A Workspace credential authorizes only that Workspace's configured
  repository ids.
- Repository names are assertions for human readback; immutable GitHub ids are
  the authorization keys.
- Installation tokens are neither logged nor written to disk by this service.
- The client credential helper must also avoid disk persistence.

Human entry to T3 Code, Launchpad and module applications is a separate
GitHub-backed gateway decision. See [ARCHITECTURE.md](./ARCHITECTURE.md).

## Runtime

Requirements: Node.js 24 or newer.

```sh
npm test
npm run check
```

Run with custody-mounted files:

```sh
GITHUB_APP_ID=1234 \
GITHUB_APP_PRIVATE_KEY_FILE=/run/secrets/github-app.pem \
BROKER_POLICY_FILE=/run/config/policy.json \
node src/broker.mjs
```

The policy schema is demonstrated in
[`examples/policy.example.json`](./examples/policy.example.json). Secret files
contain one high-entropy value and are referenced by path; their values never
belong in the policy or Git.

### API

`POST /v1/token`

```http
Authorization: Bearer <workspace credential>
X-Lazurio-Workspace-ID: customer-team
Content-Type: application/json

{"repository_id": 2345}
```

The response contains the installation token and GitHub expiry timestamp with
`Cache-Control: no-store`. `GET /health` returns `204` only after startup
policy verification has succeeded.

The broker rereads the mounted policy before every token request. A changed
policy is parsed and reverified against GitHub before becoming active; an
invalid or drifted replacement fails closed while the prior policy is never
used for that request.

Operators can revalidate the same live contract without starting another
listener:

```sh
node src/broker.mjs --verify-only
```

The command reads the same mounted policy, App key and Workspace credentials,
performs the exact live GitHub readback, emits no secret or token, and exits
non-zero on drift. Deployment automation should run it on every desired-state
apply in addition to the startup gate.

## Container build

The Dockerfile deliberately has no floating base-image default:

```sh
docker build \
  --build-arg NODE_RUNTIME_IMAGE='node:24.19.0-bookworm@sha256:<digest>' \
  -t lazurio-github-app-broker:<source-commit> .
```

Operators must pin the complete image reference and attest the resulting image
id. No customer policy, secret or App credential is baked into the image.
The committed `.dockerignore` sends only `src/` as build context input.

## Security

Read [SECURITY.md](./SECURITY.md) before reporting a vulnerability. Do not put
tokens, private keys, customer policy or live infrastructure identifiers in a
public issue.
