<div align="center">

<img src="xssentinel_core/manifest/assets/thumbanail.png" alt="XSSentinel" width="760">

<br><br>

<h1>XSSentinel</h1>

<p>
  <strong>CLI scanner for authorized XSS testing with reflection checks, browser validation, API evidence, CSP hints, and practical terminal output.</strong>
</p>

<p>
  A focused open-source <strong>cross-site scripting (XSS) scanner</strong> for reflected XSS,
  DOM XSS triage, parameter fuzzing, and browser-based confirmation.
</p>

<p>
  <a href="https://www.python.org/"><img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white"></a>
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux-555555?style=for-the-badge">
  <img alt="License" src="https://img.shields.io/badge/License-Apache--2.0-2f7d32?style=for-the-badge">
  <img alt="Use" src="https://img.shields.io/badge/Use-Authorized%20Testing%20Only-d46a6a?style=for-the-badge">
</p>

<p>
  <a href="https://github.com/rafashaalfiandi/XSSentinel/issues"><img alt="Issues and feedback" src="https://img.shields.io/badge/Contribute-Issues%20%26%20PRs-1f6feb?style=flat-square&logo=github&logoColor=white"></a>
  <a href="https://github.com/rafashaalfiandi/XSSentinel"><img alt="Source code" src="https://img.shields.io/badge/Source-Open%20Source-24292f?style=flat-square&logo=github&logoColor=white"></a>
</p>

</div>

> XSSentinel is an open-source security testing tool for authorized penetration testing, bug bounty reconnaissance, and defensive web application assessments.

## Contents

- [Overview](#overview)
- [Why XSSentinel](#why-xssentinel)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Upgrading Legacy Installations](#upgrading-legacy-installations)
- [Browser Validation](#browser-validation)
- [Support the Project](#support-the-project)
- [Responsible Use](#responsible-use)
- [Collaborators and Contributing](#collaborators-and-contributing)
- [License](#license)

## Demo

<div align="center">

<img src="xssentinel_core/manifest/assets/vd.gif" alt="XSSentinel demo" width="760">

</div>

## Overview

XSSentinel is a Python-based command-line XSS scanner that helps security testers find and triage reflected cross-site scripting, DOM XSS risk, and API responses that reflect input. It fuzzes URL and form parameters, analyzes reflection contexts, and uses Chromium or Playwright to verify browser-side execution when available.

XSSentinel does not mark every reflection as confirmed XSS. It separates confirmed browser execution from lower-confidence reflection, API, and risk signals.

The project is built for readable terminal workflows: start with one URL, inspect the evidence, reproduce the result manually, and report only authorized findings.

## Why XSSentinel

XSSentinel is designed for security testers who need useful evidence instead of a noisy payload dump. It combines parameter discovery, context-aware payload prioritization, reflection analysis, API evidence, and optional browser confirmation in one focused CLI workflow.

It is useful for:

- Reflected XSS testing in query strings, forms, and JSON request bodies.
- DOM XSS triage and browser-based confirmation.
- Bug bounty reconnaissance on authorized targets.
- QA regression checks for input encoding and output sanitization.
- Developers learning where untrusted input reaches an HTML or JavaScript context.

The project aims to be fast to try, easy to inspect, and practical to extend with tests and plugins.

## Features

- Scans GET and POST input surfaces discovered from a target URL.
- Tests one parameter at a time by default for clearer evidence.
- Supports multi-parameter testing with `--all-params`.
- Prioritizes high-signal payloads first.
- Shows practical finding markers: `[VALID]`, `[API]`, `[RISK]`, `[LOW]`, `[NO]`, and `[SKIP]`.
- Uses Chromium or Playwright when available for browser confirmation.
- Provides CSP, WAF-like, API, and DOM-risk hints.
- Keeps evidence tied to the tested payload to reduce false-positive browser confirmations.
- Works well for security researchers, bug bounty testers, QA teams, and developers reviewing web input handling.

## Quick Start

```bash
git clone https://github.com/rafashaalfiandi/XSSentinel.git
cd XSSentinel
chmod +x install.sh
./install.sh
xssentinel "https://target.test/search?q=test"
```

Only scan targets that you own or are explicitly authorized to test.

## Responsible Use

Use XSSentinel only on applications you own or have explicit permission to test. Unauthorized scanning can disrupt systems and may violate laws, contracts, or acceptable-use policies.

## Installation

```bash
git clone https://github.com/rafashaalfiandi/XSSentinel.git
cd XSSentinel
chmod +x install.sh
./install.sh
```

Verify the command:

```bash
xssentinel -h
```

If `xssentinel` is not found, add `~/.local/bin` to your `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Usage

Scan a target URL:

```bash
xssentinel "https://target.test/search?q=test"
```

Scan a URL with multiple parameters:

```bash
xssentinel "https://target.test/search?q=test&category=test"
```

Send each test to all parameters at once:

```bash
xssentinel --all-params "https://target.test/search?q=test&category=test"
```

Stop after the first confirmed finding:

```bash
xssentinel --stop-on-confirmed "https://target.test/search?q=test"
```

Update the installed tool:

```bash
xssentinel -update
```

## Upgrading Legacy Installations

Older XSSentinel releases expected the payload catalogs in the repository root. Current releases keep them inside `xssentinel_core/manifest/payloads/` and no longer install payload files at the runtime root.

Because an older updater runs before the new updater is installed, users upgrading from a legacy release may need this one-time migration:

```bash
cd ~/.local/share/xssentinel-source
git pull --ff-only origin main
rm -f xss-payloads.txt smart-selected-180-payloads.txt
bash ./install.sh
hash -r
xssentinel -update
```

After this migration, future `xssentinel -update` commands use the new updater and do not require payload files in the root directory.

Show help:

```bash
xssentinel -h
```

## Output Markers

| Marker | Meaning |
| --- | --- |
| `[VALID]` | Browser execution was confirmed. |
| `[API]` | An API or data response reflected input and needs manual sink validation. |
| `[RISK]` | Strong reflection signal, but browser execution was not confirmed. |
| `[LOW]` | Reflection exists, but confidence is lower. |
| `[NO]` | No useful evidence was found for that attempt. |
| `[SKIP]` | The target was unreachable or skipped after repeated unsuitable responses. |

## Browser Validation

XSSentinel can use a local Chromium browser or Playwright to confirm execution. If browser support is unavailable, scans still run, but results are based on HTTP and reflection evidence.

Install Chromium on Debian/Ubuntu-based systems:

```bash
sudo apt install chromium
```

Or install Playwright support:

```bash
python3 -m pip install playwright
python3 -m playwright install chromium
```

## Support the Project

If XSSentinel helps with research, QA, or defensive security work, a coffee helps keep maintenance, testing, and documentation moving.

<p>
  <a href="https://etherscan.io/address/0xd1915d2D117aA1b8C832c4aA6DF1dD4D8E336Ff9"><img alt="Ethereum donation address" src="https://img.shields.io/badge/Donate-Ethereum-627eea?style=for-the-badge&logo=ethereum&logoColor=white"></a>
  <a href="https://www.blockchain.com/explorer/addresses/btc/1336ujHfSXmkGdtP1nDKxfx6ZPh75xDRPp"><img alt="Bitcoin donation address" src="https://img.shields.io/badge/Donate-Bitcoin-f7931a?style=for-the-badge&logo=bitcoin&logoColor=white"></a>
</p>

### Donation Addresses

| Network | Address |
| --- | --- |
| Ethereum (ETH) | `0xd1915d2D117aA1b8C832c4aA6DF1dD4D8E336Ff9` |
| Bitcoin (BTC) | `1336ujHfSXmkGdtP1nDKxfx6ZPh75xDRPp` |

Always verify the address and network before sending. Never send assets from an unsupported network or exchange format.

## Collaborators and Contributing

XSSentinel is maintained by [Rafasha Alfiandi](https://github.com/rafashaalfiandi) and welcomes security researchers, Python developers, QA engineers, and documentation contributors.

<p align="left">
  <a href="https://github.com/fahmiammar" title="Fahmi Ammar">
    <img src="https://github.com/fahmiammar.png?size=120" alt="Fahmi Ammar" width="88" height="88" style="border-radius: 50%;">
  </a>
</p>

**Collaborator:** [Fahmi Ammar](https://github.com/fahmiammar)

Useful ways to collaborate:

- Report reproducible bugs with the target behavior, command, environment, and expected result.
- Add focused tests for scanner decisions, payload parsing, browser evidence, and false-positive prevention.
- Improve documentation, examples, payload context handling, and platform support.
- Open a pull request with a small, clearly described change.

Please read [SECURITY.md](SECURITY.md) before reporting a security issue. Do not include private target data, credentials, or unauthorized scan results in public issues.

### Suggested Contribution Flow

```bash
git checkout -b improve-xss-detection
python -m unittest discover -s tests -p "test_*.py"
git diff --check
```

Keep changes focused, add a regression test for bug fixes, and explain how the result was verified.

## Troubleshooting

### `xssentinel: command not found`

Add `~/.local/bin` to your `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
xssentinel -h
```

### Browser validation is disabled

Install Chromium or Playwright, then run the scan again.

### `[API]` appears but there is no popup

That is expected. API responses usually return data instead of rendering HTML directly. Treat `[API]` as evidence that needs manual validation in the frontend that consumes the response.

### Many `[RISK]` or `[LOW]` results appear

The payload was reflected, but execution was not confirmed. Common causes include browser validation being unavailable, sanitization, CSP, or the endpoint returning data instead of rendered HTML.

### The scan feels slow

Large targets and many discovered inputs can take longer. Start with a specific URL when you want a faster focused scan.

## Uninstall

```bash
./uninstall.sh
```

## License

XSSentinel is released under the Apache License 2.0. See [LICENSE](LICENSE) for details.
