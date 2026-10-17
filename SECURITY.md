# Security policy

Please report suspected vulnerabilities through GitHub's private vulnerability
reporting for this repository. If that surface is unavailable, contact a named
Lazurio Organization owner privately and ask for a secure reporting channel.

Do not open a public issue containing:

- GitHub App private keys or installation tokens;
- Workspace credentials;
- GitHub Actions OIDC tokens, even expired ones;
- customer policy files or private repository metadata, including Deployment
  Repo ids and audit lines; or
- live hostnames, addresses or recovery information not already public.

Include the affected source commit, a minimal reproduction with synthetic ids
and the security impact. We will coordinate validation, remediation and public
disclosure without requesting production secrets.

The threat model, including what the public GitHub Actions OIDC route can and
cannot reach, is in [ARCHITECTURE.md](./ARCHITECTURE.md#threat-model).

Only the latest `main` and explicitly supported releases receive security
fixes. A public commit is not proof that a deployment runs that commit; verify
the operator's deployment attestation separately.
