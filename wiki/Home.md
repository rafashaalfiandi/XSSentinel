# XSSentinel Wiki

Welcome to the XSSentinel documentation. XSSentinel is a command-line scanner for authorized cross-site scripting (XSS) testing, with a focus on useful evidence, practical triage, and browser-based confirmation.

This wiki provides a concise starting point for installing XSSentinel, running scans, and interpreting the results.

## Overview

XSSentinel helps security testers, developers, and QA teams investigate how user-controlled input reaches web application responses. It supports reflected XSS testing, DOM XSS triage, reflection-context analysis, API evidence, and optional browser validation.

The scanner distinguishes confirmed browser execution from lower-confidence reflection and risk signals. This helps keep findings reproducible and reduces false positives.

## Key Capabilities

- Test GET and POST input surfaces discovered from a target URL.
- Analyze reflected input in HTML, attribute, JavaScript, and other contexts.
- Prioritize high-signal payloads for a more focused scan.
- Use Chromium or Playwright to confirm browser-side execution.
- Report API reflections, CSP hints, WAF-like behavior, and DOM-risk signals.
- Present findings with concise markers and evidence for manual verification.

## Installation

Clone the repository and run the installer:

```bash
git clone https://github.com/rafashaalfiandi/XSSentinel.git
cd XSSentinel
chmod +x install.sh
./install.sh
```

Verify that the command is available:

```bash
xssentinel -h
```

## Quick Start

Scan a URL with a query parameter:

```bash
xssentinel "https://target.test/search?q=test"
```

Test all parameters together:

```bash
xssentinel --all-params "https://target.test/search?q=test&category=test"
```

Stop after the first browser-confirmed finding:

```bash
xssentinel --stop-on-confirmed "https://target.test/search?q=test"
```

Replace `https://target.test` with a target that you own or are explicitly authorized to test.

## Result Markers

| Marker | Meaning |
| --- | --- |
| `[VALID]` | Browser execution was confirmed. |
| `[API]` | The input was reflected in an API or data response and requires manual sink validation. |
| `[RISK]` | A strong reflection signal was found, but browser execution was not confirmed. |
| `[LOW]` | Reflection was detected with lower confidence. |
| `[NO]` | No useful evidence was found for the attempt. |
| `[SKIP]` | The target was unreachable or the attempt was skipped after unsuitable responses. |

## Browser Validation

Browser validation is optional. Scans can still run using HTTP and reflection evidence when browser support is unavailable.

To enable Playwright-based validation:

```bash
python3 -m pip install playwright
python3 -m playwright install chromium
```

For systems with a locally installed Chromium browser, XSSentinel may be able to use that browser directly.

## Recommended Workflow

1. Start with a specific, authorized URL and a small test scope.
2. Review the reported marker and the reflected context.
3. Reproduce promising results manually in a controlled environment.
4. Treat `[API]`, `[RISK]`, and `[LOW]` results as leads that require validation.
5. Record the tested URL, parameter, payload, response evidence, and browser behavior.

## Responsible Use

Use XSSentinel only against systems that you own or are explicitly authorized to test. Unauthorized scanning, exploitation, disruption, or data access may violate laws, contracts, and acceptable-use policies.

Do not include credentials, session cookies, access tokens, private URLs, or sensitive target data in public issues or pull requests.

## Project Resources

- [Project README](https://github.com/rafashaalfiandi/XSSentinel/blob/main/README.md)
- [Contributing Guide](https://github.com/rafashaalfiandi/XSSentinel#collaborators-and-contributing)
- [Code of Conduct](https://github.com/rafashaalfiandi/XSSentinel/blob/main/CODE_OF_CONDUCT.md)
- [Security Policy](https://github.com/rafashaalfiandi/XSSentinel/blob/main/SECURITY.md)
- [Apache License 2.0](https://github.com/rafashaalfiandi/XSSentinel/blob/main/LICENSE)
