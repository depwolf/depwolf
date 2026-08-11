# Security Policy

depwolf is a supply-chain security tool; its own security matters. We
follow a 90-day coordinated disclosure window.

## Reporting a vulnerability

Do **not** open a public issue for security defects. Report privately:

- **GitHub**: use [GitHub private vulnerability reporting](https://github.com/depwolf/depwolf/security/advisories)
  (preferred), or
- **Email**: `security@depwolf.dev` with a PGP-encrypted report if possible.

Include, if available:

- Affected versions (`depwolf --version`)
- A minimal reproducer (scanner input or command line)
- Impact and any proposed fix

## What we accept

- Vulnerabilities in depwolf's own code (parsing, matching, DB handling,
  CLI)
- Malicious/malformed input handling (arbitrary code execution, path
  traversal, denial of service from crafted scanner reports)
- Supply-chain risks: poisoned index data, unsafe sync behavior
- Dependency advisories affecting the runtime

## What we do

1. Acknowledge within **48 hours**.
2. Confirm, triage, and prepare a fix.
3. Release a patched version and disclose publicly after **90 days** (or
   sooner if a fix is out and users are exposed).

## Severity handling

| Severity | Release target |
|----------|----------------|
| Critical | 24–72 hours |
| High     | within 7 days |
| Medium   | next regular release |
| Low      | next regular release |

## Scope: what is NOT covered

The `cpe_index.db` dataset is a derived artifact of NVD/EPSS/KEV public data;
data-quality issues should be reported to the upstream sources.
