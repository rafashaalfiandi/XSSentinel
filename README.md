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
  <a href="#installation"><img alt="Platform" src="https://img.shields.io/badge/Platform-Linux-555555?style=flat-square"></a>
  <a href="#responsible-use"><img alt="Security" src="https://img.shields.io/badge/Use-Authorized%20Testing%20Only-d46a6a?style=flat-square"></a>
</p>

</div>

## Overview

XSSentinel helps test reflected and DOM-based XSS behavior by combining high-signal payload fuzzing with lightweight target intelligence. It can inspect reflection context, analyze CSP posture, identify WAF-like signals, and optionally confirm browser execution through local Chromium or Playwright.

The default payload source is `xss-payloads.txt`. In smart mode, XSSentinel expands and prioritizes that file, runs the highest-value payloads first, and continues with the remaining payloads when no browser-confirmed result is found in the first batch.

The scanner is designed around observable runtime output. At startup it shows the normalized target, the test method, the first fuzzed parameter, the payload count, whether browser validation is enabled, CSP/WAF hints, and the detected reflection context. During the scan it prints one line per payload result, then finishes with a compact summary.

## Features

- Smart payload prioritization and expansion from local payload files.
- Automatic GET/POST form and query parameter discovery.
- HTML reflection context analysis for script, attribute, text, comment, and raw response locations.
- CSP analysis with concise risk hints.
- WAF signal detection from headers, response codes, and blocking text.
- DOM sink analysis for common JavaScript sources and sinks.
- Optional browser confirmation for alert, confirm, prompt, and dialog execution.

## Requirements

Required:

- Linux shell environment.
- Python 3.10 or newer.
- Network access to the target application.
- Permission to test the target application.
- Local data files included with this repository: `xss-payloads.txt`, `useragents.txt`, and the `xssentinel_core/` package.

Optional but recommended:

- Chromium or Google Chrome for browser-based XSS confirmation. The scanner looks for `chromium`, `chromium-browser`, `google-chrome`, or `google-chrome-stable` in `PATH`.
- Playwright with Chromium support. If local Chromium is not found, XSSentinel can use Playwright when it is installed and usable.

Browser support is not required for basic scanning. Without Chromium or Playwright, XSSentinel still performs HTTP requests, reflection analysis, CSP checks, WAF detection, and DOM sink analysis, but it cannot confirm JavaScript dialog execution in a real browser.

## Installation

```bash
git clone https://github.com/rafashaalfiandi/XSSentinel.git
cd XSSentinel
chmod +x install.sh
./install.sh
```

The installer copies the tool to `~/.local/share/xssentinel` and creates the command wrapper at `~/.local/bin/xssentinel`.

If the command is not available after installation, add this to your shell configuration:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Usage

Run the scanner interactively:

```bash
xssentinel
```

Or pass a target directly:

```bash
xssentinel "https://target.test/search?q=test"
```

Targets with query parameters are normalized for fuzzing automatically. For example, `https://target.test/search?q=test&id=1` is treated as a fuzzable target where query values are replaced during scanning.

When no query parameter is available, XSSentinel requests the page and attempts to discover testable inputs from:

- GET forms.
- POST forms.
- Links with query strings.
- Standalone input fields.
- Parameter names found in inline or same-origin JavaScript.

The current command-line entrypoint accepts a target URL. POST scanning is created automatically when a POST form is discovered on the page.

## Scan Flow

1. Normalize the target URL and ensure it uses `http://` or `https://`.
2. Build scan targets from existing query parameters, or discover GET/POST forms when no query parameter is present.
3. Load payloads from `xss-payloads.txt` by default.
4. In smart mode, expand payload variants, remove duplicates, score them against detected contexts, and select the first smart batch.
5. Probe the target to infer reflection context such as script block, HTML attribute, HTML text, comment, or raw response.
6. Analyze target intelligence: CSP, WAF-like signals, scripts, DOM sources, and DOM sinks.
7. Send payload requests and inspect response reflection.
8. If Chromium or Playwright is available, verify suitable reflected payloads in a browser and watch for `alert`, `confirm`, `prompt`, or JavaScript dialog execution.
9. If the smart batch does not produce a confirmed result, continue with the remaining payloads through exhaustive fallback.

## Log Format

The output is intentionally compact so you can scan results quickly.

Startup fields:

- `target`: normalized target URL being tested.
- `method`: `GET` or discovered `POST`.
- `param`: fuzzed parameter names for the current target.
- `payloads`: total payload count after loading and expansion.
- `selected`: first smart batch size.
- `chromium`: browser validation availability.
- `dom`: DOM/script analysis status.
- `csp`: CSP posture summary.
- `waf`: WAF-like fingerprint, if any.
- `context`: detected reflection context.

Per-payload markers:

- `[VALID]`: browser-confirmed execution.
- `[RISK]`: strong reflection with high XSS risk.
- `[LOW]`: reflection found, but weaker signal.
- `[NO]`: no useful confirmation.
- `[SKIP]`: target unreachable or network error.

Final summary markers:

- `[FOUND]`: confirmed XSS.
- `[DONE]`: no confirmed execution.

Example startup and discovery output:

```text
[INFO] endpoints=3 mode=auto-discovery payloads=235
[INFO] base=https://target.test
[INFO] ★ Priority: POST forms → GET endpoints
  01. ★ POST /login username, password [high-value-form]
  02. ◆ POST /search q [form]
  03. ● GET /search q [link]
  breakdown ★ HIGH=1 | POST=1 | LINK=1
  total-fuzz 3 injection points in 3 endpoints

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

Example result stream:

```text
[VALID] #0001 GET HTTP=200 CONFIRMED payload="\"><svg/onload=prompt(1)>" evidence="prompt:1"
[RISK ] #0002 GET HTTP=200 REFLECTED_RISK DOM=attribute:reflected in attribute value
[LOW  ] #0003 GET HTTP=200 REFLECTED_LOW DOM=text:reflected in HTML text
[NO   ] #0004 GET HTTP=200 NOT_CONFIRMED DOM=no-reflection
[SKIP ] target unreachable: connection timed out

[FOUND] confirmed XSS
  method: GET    http: 200    tested: 4
  stats: confirmed=1 risk=1 low=1 no=1 skipped=1
  payload: \"><svg/onload=prompt(1)>
  browser: prompt:1
  url: https://target.test/search?q=%22%3E%3Csvg/onload%3Dprompt(1)%3E
```

Example no-confirmation summary:

```text
[DONE] no confirmed execution
  stats: confirmed=0 risk=2 low=5 no=18 skipped=1
```

## Payload Files

`xss-payloads.txt` is the main payload source and is used by default. Comments and blank lines are ignored. With smart expansion enabled, one source payload can produce multiple encoded, decoded, escaped, and syntax-mutated variants.

`smart-selected-180-payloads.txt` is a curated payload list kept in the project for compatibility and manual experiments. It is not the default scanner source anymore. If this file is selected explicitly in code or a future CLI option, the scanner will use only those 180 curated payloads.

In the startup info block:

- `payloads` is the number of payloads loaded for the current run after deduplication or smart expansion.
- `selected` is the first smart batch size. By default this is 90 payloads.
- `selected=90` does not mean only 90 payloads exist. It means 90 payloads are tested first before exhaustive fallback continues with the rest.

Example:

```text
[INFO]
  target=https://target.test/search
  method=GET
  param=q
  payloads=97,235
  selected=90
  chromium=on
  dom=on
  csp=strict
  waf=cloudflare
  context=none
```

## Browser Validation

XSSentinel uses local Chromium or Playwright when available. Browser validation launches a controlled browser session, injects dialog hooks, navigates to the payload target, and checks whether the payload triggers a valid JavaScript dialog signal.

Install one of these before scanning if you want `chromium=on`:

```bash
sudo apt install chromium
```

or provide Google Chrome / Chromium through your normal system package manager. Playwright can also be used when installed in the same Python environment:

```bash
python3 -m pip install playwright
python3 -m playwright install chromium
```

If browser support is missing, the scanner prints or behaves as `chromium=off` and continues with non-browser analysis.

## Output Fields

- `target`: normalized target URL being tested. Fuzzed values are hidden in this display.
- `method`: HTTP method used for the scan target, usually `GET` or discovered `POST`.
- `param`: first fuzzed parameter name.
- `payloads`: total payload count for the run after loading and expansion.
- `selected`: first smart batch count.
- `chromium`: browser validation availability.
- `dom`: DOM/script analysis status.
- `csp`: detected CSP posture summary.
- `waf`: detected WAF-like fingerprint, if any.
- `context`: detected reflection context, or `none` when probes did not reveal one.

If you are reading the scan log itself, the most important signal is the combination of `context`, the per-payload marker, and the final summary. A reflected payload with `REFLECTED_RISK` or `CONFIRMED` deserves attention first, followed by `REFLECTED_LOW` results when you are reviewing manual test cases.

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

Keep these files together when running from source. The installer copies the required files into `~/.local/share/xssentinel`.

## Uninstall

```bash
./uninstall.sh
```

## Responsible Use

Use XSSentinel only on applications you own or have explicit permission to test. Unauthorized scanning can be disruptive and may violate laws, contracts, or acceptable-use policies.
