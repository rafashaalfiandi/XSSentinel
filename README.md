<div align="center">

<pre>
 __  __ ____ ____             _   _            _
 \ \/ // ___/ ___|  ___ _ __ | |_(_)_ __   ___| |
  \  / \___ \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
  /  \  ___) |__) |  __/ | | | |_| | | | |  __/ |
 /_/\_\|____/____/ \___|_| |_|\__|_|_| |_|\___|_|
</pre>

<h1>XSSentinel</h1>

<p><strong>A focused XSS fuzz scanner with smart payload selection, browser validation, CSP checks, WAF hints, and DOM sink analysis.</strong></p>

<p>
  <a href="https://www.python.org/"><img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white"></a>
  <a href="#quick-start"><img alt="Platform" src="https://img.shields.io/badge/Platform-Linux-555555?style=flat-square"></a>
  <a href="#responsible-use"><img alt="Use" src="https://img.shields.io/badge/Use-Authorized%20Testing%20Only-d46a6a?style=flat-square"></a>
</p>

</div>

## Overview

XSSentinel helps test reflected and DOM-based XSS behavior by combining payload fuzzing, response reflection analysis, target intelligence, and optional browser confirmation. It is built for authorized security testing where clear runtime output matters as much as raw scan volume.

What it does during a scan:

- Normalizes the target URL and finds fuzzable query or form parameters.
- Discovers GET links, GET forms, POST forms, standalone inputs, and parameter names from same-origin JavaScript.
- Expands and prioritizes XSS payloads in smart mode.
- Detects reflection context such as HTML text, attribute, script block, comment, or raw response.
- Reviews CSP posture, WAF-like signals, JavaScript sources, and DOM sinks.
- Optionally confirms execution in Chromium or Playwright by watching JavaScript dialogs.
- Runs discovered parameters in parallel while keeping each parameter's context, request flow, and skip threshold separate.

## Quick Start

Install the tool:

```bash
git clone https://github.com/rafashaalfiandi/XSSentinel.git
cd XSSentinel
chmod +x install.sh
./install.sh
```

Run interactively:

```bash
xssentinel
```

Scan a target directly:

```bash
xssentinel "https://target.test/search?q=test"
```

If `xssentinel` is not found after installation, add `~/.local/bin` to your shell path:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Requirements

Required:

- Linux shell environment.
- Python 3.10 or newer.
- Network access to the target application.
- Explicit permission to test the target application.
- Repository data files: `xss-payloads.txt`, `useragents.txt`, and `xssentinel_core/`.

Optional but recommended:

- Chromium or Google Chrome for browser-based confirmation.
- Playwright with Chromium support when local Chromium is not available.

XSSentinel still works without browser support. In that mode it performs HTTP fuzzing, reflection analysis, CSP checks, WAF hints, and DOM sink analysis, but it cannot prove JavaScript dialog execution in a real browser.

## Usage

Targets with query parameters are fuzzed automatically. For example:

```text
https://target.test/search?q=test&id=1
```

XSSentinel treats the query values as replaceable fuzz points and prints a normalized target in the scan log.

When the starting URL has no query parameter, XSSentinel requests the page and attempts to discover testable inputs from:

- GET forms.
- POST forms.
- Links with query strings.
- Standalone input fields.
- Inline or same-origin JavaScript parameter names.

POST scanning is created automatically when a POST form is discovered. The current command-line entrypoint accepts a target URL; discovered forms and links are handled by the scanner flow.

## Scan Flow

1. Normalize the target and confirm it uses `http://` or `https://`.
2. Build scan targets from query parameters, or discover GET/POST inputs when no query parameter exists.
3. Load payloads from `xss-payloads.txt`.
4. Expand, deduplicate, and prioritize payloads in smart mode.
5. Probe the target to infer reflection context.
6. Analyze target intelligence: CSP, WAF-like signals, scripts, DOM sources, and DOM sinks.
7. Send payload requests and inspect response reflection.
8. Confirm suitable reflected payloads in a browser when Chromium or Playwright is available.
9. Continue from the first smart batch into exhaustive fallback when no browser-confirmed result is found.

## Reading The Log

XSSentinel uses compact markers so scan output can be reviewed quickly. The terminal output uses real colors; this README mirrors those colors with badges because normal Markdown code blocks do not reliably preserve terminal color on every renderer.

### Result Markers

| Marker | Meaning | What to do |
| --- | --- | --- |
| <img alt="VALID" src="https://img.shields.io/badge/VALID-confirmed-2ea44f?style=flat-square"> | Browser-confirmed JavaScript execution. | Treat as confirmed XSS and review the payload, URL, and browser evidence. |
| <img alt="RISK" src="https://img.shields.io/badge/RISK-reflected%20risk-d29922?style=flat-square"> | Strong reflection with high XSS risk. | Review manually or rerun with browser validation enabled. |
| <img alt="LOW" src="https://img.shields.io/badge/LOW-reflected%20signal-6f42c1?style=flat-square"> | Reflection exists, but the context is weaker. | Useful for manual follow-up and payload tuning. |
| <img alt="NO" src="https://img.shields.io/badge/NO-not%20confirmed-6a737d?style=flat-square"> | No useful reflection or confirmation. | Usually informational. |
| <img alt="SKIP" src="https://img.shields.io/badge/SKIP-skipped-e3b341?style=flat-square"> | Target unreachable, network error, or an allowed HTTP skip threshold was reached. | Check connectivity or the skipped status reason. |

### Startup Fields

| Field | Description |
| --- | --- |
| `target` | Normalized URL being tested. Fuzzed values are hidden in this display. |
| `method` | HTTP method used for the scan target, usually `GET` or discovered `POST`. |
| `param` | First fuzzed parameter name for the current scan target. |
| `payloads` | Total payload count after loading, expansion, and deduplication. |
| `selected` | First smart batch size. The default first batch is 90 payloads. |
| `chromium` | Browser validation availability: `on` or `off`. |
| `dom` | DOM/script analysis status. |
| `csp` | Detected Content Security Policy posture summary. |
| `waf` | WAF-like fingerprint when one is detected. |
| `context` | Detected reflection context, or `none` when probes do not reveal one. |

### Worker States

When multiple endpoints or parameters are discovered, XSSentinel uses a worker pool. Worker activity appears as `agent=NN/TT state=...`.

Common states:

- `assigned`: worker received a target.
- `analyzing`: reflection, CSP, WAF, and DOM intelligence are being collected.
- `analysis-done`: intelligence pass completed and the detected context is printed.
- `batch`: smart or exhaustive payload batch started.
- `progress`: payload queue progress for that worker.
- `confirmed`: browser-confirmed execution was found.
- `skip-threshold`: an HTTP skip candidate reached the configured threshold.
- `done`: worker finished its assigned target.

The live progress line looks like this:

```text
[START] scanning | active=4/33 done=0/33 phases=analysis:4
```

That line refreshes in place in the terminal, so long analysis phases still show movement without flooding the screen.

## HTTP Skip Behavior

Only these HTTP status codes are treated as HTTP skip candidates:

- `204 No Content`
- `304 Not Modified`

XSSentinel does not stop a parameter immediately when one of those statuses appears. It only skips after the same allowed skip status appears 11 times in a row without reflection.

All other HTTP status codes continue through normal scanning. This includes `400`, `401`, `403`, `404`, `405`, `406`, `410`, `413`, `415`, `429`, and `5xx` responses.

If a response reflects the payload, it remains eligible for `REFLECTED_LOW`, `REFLECTED_RISK`, and browser validation even when its status is `204` or `304`.

## Example Output

Startup and discovery:

```text
[INFO] endpoints=3 mode=auto-discovery payloads=235
[INFO] base=https://target.test
[INFO] priority=POST forms before GET endpoints
  01. [HIGH] POST /login username, password [high-value-form]
  02. [FORM] POST /search q [form]
  03. [GET] GET /search q [link]
  breakdown HIGH=1 | POST=1 | LINK=1
  total-fuzz 3 injection points in 3 endpoints

[START] workers=3 targets=3 parallel=on
[START] will proceed in 2 seconds...
[START] scanning | active=3/3 done=0/3 phases=analysis:3
[START] agent=01/03 state=assigned source=high-value-form method=POST param=username
[START] agent=01/03 state=analyzing
[START] agent=01/03 state=analysis-done context=html-text
[START] agent=01/03 state=batch name=smart selected=90
[START] agent=01/03 state=progress tested=1 queue=90

[INFO]
  target=https://target.test/search?q=
  method=GET
  param=q
  payloads=235
  selected=90
  chromium=on
  dom=on
  csp=strict
  waf=none
  context=html-text
```

Result stream:

```text
[VALID] #0001 GET HTTP=200 CONFIRMED payload="\"><svg/onload=prompt(1)>" evidence="prompt:1"
[RISK ] #0002 GET HTTP=200 REFLECTED_RISK DOM=attribute:reflected in attribute value
[LOW  ] #0003 GET HTTP=200 REFLECTED_LOW DOM=text:reflected in HTML text
[NO   ] #0004 GET HTTP=200 NOT_CONFIRMED DOM=no-reflection
[SKIP ] target skipped: connection timed out
```

Confirmed finding summary:

```text
[FOUND] confirmed XSS
  method: GET    http: 200    tested: 4
  stats: confirmed=1 risk=1 low=1 no=1 skipped=1
  payload: "><svg/onload=prompt(1)>
  browser: prompt:1
  url: https://target.test/search?q=%22%3E%3Csvg/onload%3Dprompt(1)%3E
```

No-confirmation summary:

```text
[DONE] no confirmed execution
  stats: confirmed=0 risk=2 low=5 no=18 skipped=1
```

## Payload Files

`xss-payloads.txt` is the default payload source. Blank lines and comments are ignored. In smart mode, XSSentinel expands source payloads into encoded, decoded, escaped, and syntax-mutated variants, then removes duplicates.

`smart-selected-180-payloads.txt` is kept for compatibility and manual experiments. It is not the default scanner source. If selected explicitly in code or by a future CLI option, the scanner uses only those curated payloads.

`selected=90` in the startup block does not mean only 90 payloads exist. It means 90 high-priority payloads are tested first before exhaustive fallback continues with the remaining payloads.

## Browser Validation

XSSentinel uses local Chromium or Playwright when available. Browser validation launches a controlled browser session, injects dialog hooks, navigates to the payload target, and checks whether the payload triggers a valid JavaScript dialog signal.

Install Chromium on Debian/Ubuntu-based systems:

```bash
sudo apt install chromium
```

Or install Playwright in the same Python environment:

```bash
python3 -m pip install playwright
python3 -m playwright install chromium
```

If browser support is missing, the scanner prints or behaves as `chromium=off` and continues with non-browser analysis.

## Project Layout

```text
.
|-- main.py
|-- install.sh
|-- uninstall.sh
|-- xss-payloads.txt
|-- smart-selected-180-payloads.txt
|-- useragents.txt
`-- xssentinel_core/
```

Keep these files together when running from source. The installer copies the required files into `~/.local/share/xssentinel` and creates the wrapper command at `~/.local/bin/xssentinel`.

## Uninstall

```bash
./uninstall.sh
```

## Responsible Use

Use XSSentinel only on applications you own or have explicit permission to test. Unauthorized scanning can disrupt systems and may violate laws, contracts, or acceptable-use policies.
