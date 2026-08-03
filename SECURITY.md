# Security Policy

## Authorized Use

XSSentinel is intended only for systems you own or have explicit permission to test. Do not use it for unauthorized scanning, exploitation, disruption, or data access.

## Reporting Security Issues

If you find a security issue in XSSentinel itself, please open a GitHub issue with a minimal reproduction and avoid posting sensitive target data, private URLs, credentials, cookies, or exploit evidence from third-party systems.

When sharing scan output, remove:

- Session cookies and authorization headers.
- Access tokens, API keys, and passwords.
- Private hostnames, internal IP addresses, and customer data.
- Payload URLs that include sensitive query values.

## Safe Defaults

The repository ignores common local secrets, scan reports, logs, caches, virtual environments, and build artifacts. Review your changes with `git status` before publishing.
