<div align="center">

<img src="xssentinel_core/manifest/assets/thumbanail.png" alt="XSSentinel" width="760">

<br><br>

<h1>XSSentinel</h1>

<p>
  <strong>Authorized XSS testing with payload fuzzing, reflection analysis, browser validation, API evidence detection, CSP checks, WAF hints, and DOM sink review.</strong>
</p>

<p>
  <a href="https://www.python.org/"><img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white"></a>
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux-555555?style=for-the-badge">
  <img alt="License" src="https://img.shields.io/badge/License-Apache--2.0-2f7d32?style=for-the-badge">
  <img alt="Use" src="https://img.shields.io/badge/Use-Authorized%20Testing%20Only-d46a6a?style=for-the-badge">
</p>

</div>

## Demo

<div align="center">

<img src="xssentinel_core/manifest/assets/vd.gif" alt="XSSentinel demo" width="760">

</div>

## Overview

XSSentinel is a command-line scanner for reflected XSS, DOM XSS risk, and API endpoints that reflect payloads. It is built for authorized security testing where the scan flow, evidence, and final classification need to be easy to review from terminal output.

It focuses on practical evidence instead of treating every reflection as a confirmed vulnerability. Browser execution, response context, API behavior, CSP hints, and DOM sink signals are evaluated separately so findings are easier to triage.

## Highlights

- Tests discovered GET and POST parameters.
- Uses a `single-param` default mode so the vulnerable parameter is easier to identify.
- Supports `--all-params` for endpoints that only react when parameters change together.
- Runs high-priority payloads first through smart payload selection.
- Analyzes reflection context in HTML text, attributes, script blocks, comments, raw responses, API responses, and related contexts.
- Validates execution with Chromium or Playwright when available.
- Detects API evidence without automatically calling reflected API responses confirmed XSS.
- Prints full payload URLs for `[VALID]` and `[API]` findings to make manual retesting easier.
- Includes CSP analysis, WAF-like hints, JavaScript source review, DOM sink analysis, and parallel workers.

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

To make it permanent, add that line to your shell config, such as `~/.bashrc` or `~/.zshrc`.

## Quick Start

Scan a target directly:

```bash
xssentinel "https://target.test/search?q=test"
```

Scan multiple query parameters. By default, XSSentinel fuzzes one parameter per request:

```bash
xssentinel "https://target.test/articles/search?query=test&keyword=test&category=test"
```

Send the same payload to all query parameters in one request:

```bash
xssentinel --all-params "https://target.test/articles/search?query=test&keyword=test&category=test"
```

Stop the full scan after the first confirmed finding:

```bash
xssentinel --stop-on-confirmed "https://target.test/search?q=test"
```

Update the installed runtime:

```bash
xssentinel -update
```

Refresh the installed runtime from local source:

```bash
xssentinel -restart
```

## Command Reference

| Command | Purpose |
| --- | --- |
| `xssentinel <url>` | Scan a target directly from the command line. |
| `xssentinel` | Start interactive mode and prompt for a target URL. |
| `xssentinel --all-params <url>` | Send the same payload to every query parameter in one request. |
| `xssentinel --stop-on-confirmed <url>` | Stop the entire scan after the first confirmed finding. |
| `xssentinel -update` | Fetch the latest available tool state and reinstall the runtime command. |
| `xssentinel -restart` | Clean local cache and reinstall the runtime from the saved local source. Useful after local source edits. |
| `xssentinel -h` | Show built-in help. |

Important notes:

- Use `xssentinel -update` when you want the latest available tool version installed.
- Use `xssentinel -restart` after editing local source files and you want the installed `xssentinel` command to use those local changes.
- `-restart` does not fetch remote updates; it refreshes the runtime from the saved local source path.

## Parameter Modes

### Default: `single-param`

The default mode tests one parameter per request. Given this target:

```text
https://target.test/search?query=test&keyword=test&category=test
```

XSSentinel creates separate requests like:

```text
https://target.test/search?query=PAYLOAD&keyword=test&category=test
https://target.test/search?query=test&keyword=PAYLOAD&category=test
https://target.test/search?query=test&keyword=test&category=PAYLOAD
```

This mode is usually the best default because it identifies the responsible parameter, produces cleaner evidence, and reduces noise on endpoints that reject requests when many values change at once.

### Optional: `all-params`

Enable this mode with `--all-params`. All query parameters receive the same payload in one request:

```text
https://target.test/search?query=PAYLOAD&keyword=PAYLOAD&category=PAYLOAD
```

Use this mode when an endpoint only reacts to parameter combinations or when you want quick coverage for a specific endpoint.

At scan startup, XSSentinel prints the active mode:

```text
[INFO] scan-mode=single-param (one parameter is fuzzed per request)
[INFO] stop-policy=per-target-confirmed
```

or:

```text
[INFO] scan-mode=all-params (all query parameters receive the same payload in each request)
[INFO] stop-policy=per-target-confirmed
```

## Result Classification

XSSentinel does not treat every reflection as confirmed XSS. Results are classified from several evidence layers:

- Whether the payload appears in the response.
- Where the payload appears, such as HTML text, attributes, script, raw/API responses, or another context.
- Whether the payload actually executes in a browser.
- Whether the response is an API/download response that delivers payload content but does not directly execute it.

| Marker | Status | Meaning |
| --- | --- | --- |
| `[VALID]` | `CONFIRMED` | Browser/dialog execution was confirmed. |
| `[API]` | `API_REFLECTED` or `API_RISK` | An API, JSON, or download response reflects the payload. Frontend or browser sink confirmation is still required before calling it confirmed XSS. |
| `[RISK]` | `REFLECTED_RISK` | Strong reflection with high XSS likelihood, but no confirmed execution yet. |
| `[LOW]` | `REFLECTED_LOW` | Reflection exists, but the context is weaker. |
| `[NO]` | `NOT_CONFIRMED` | No useful reflection or execution evidence was found. |
| `[SKIP]` | `NETWORK_ERROR` or `HTTP_SKIPPED` | The target was unreachable or an HTTP skip threshold was reached. |

Accuracy rules:

- `[VALID]` is reserved for confirmed execution evidence.
- API responses that only reflect the payload are not automatically marked valid.
- `[API]` matters because API data can become XSS when a frontend renders it unsafely.
- When `[API]` appears, XSSentinel prints the full URL with the payload for browser, proxy, or frontend sink retesting.

## Output Examples

Example `[API]` result:

```text
[API  ] #0008 agent=01/01 GET HTTP=200 API_REFLECTED API response reflects payload; browser confirmation required
  url: https://target.test/api/search?q=%3Csvg%20onload%3Dalert%281%29%3E
  payload: <svg onload=alert(1)>
```

Example summary when no execution is confirmed:

```text
[DONE] no confirmed execution
  stats: confirmed=0 api=1 risk=0 low=0 no=7 skipped=0
  api: API_REFLECTED
  evidence: application/json reflects payload; browser=no alert/confirm/prompt popup detected
  payload: <svg onload=alert(1)>
  url: https://target.test/api/search?q=%3Csvg%20onload%3Dalert%281%29%3E
```

Example confirmed finding:

```text
[VALID] #0001 GET HTTP=200 CONFIRMED payload="\"><svg/onload=prompt(1)>" evidence="prompt:1"

[FOUND] confirmed XSS
  method: GET    http: 200    tested: 4
  stats: confirmed=1 api=0 risk=1 low=1 no=1 skipped=0
  payload: "><svg/onload=prompt(1)>
  browser: prompt:1
  url: https://target.test/search?q=%22%3E%3Csvg/onload%3Dprompt(1)%3E
```

## Scan Flow

1. Normalize the target and verify that it uses `http://` or `https://`.
2. Convert query parameters from the URL into fuzz targets.
3. If the initial URL has no query parameters, discover inputs from forms, links, standalone fields, and same-origin JavaScript.
4. Load payloads from the main payload file.
5. Use smart mode to run prioritized payloads first.
6. Run context probes to understand reflection placement.
7. Send payload requests to the target.
8. Analyze the response for reflection, API evidence, download evidence, and DOM context.
9. If browser support is available, verify suitable payloads with Chromium or Playwright.
10. If no confirmed result appears in the first smart batch, continue with broader fallback payloads.

## Target Discovery

If the starting URL has no query parameters, XSSentinel tries to find inputs from the page:

- GET forms.
- POST forms.
- Same-origin links with query strings.
- Standalone input fields.
- Parameter names inferred from same-origin JavaScript.

When multiple endpoints are discovered, the scanner uses a worker pool. Worker output looks like this:

```text
[START] workers=4 targets=12 parallel=on
[START] scanning | active=4/12 done=0/12 phases=analysis:4
[START] agent=01/04 state=assigned source=form method=POST param=q
```

## API Testing

XSS in APIs does not always trigger a popup directly because an API usually returns data instead of rendering HTML. The issue becomes confirmed XSS only when that API data reaches a frontend sink and executes, such as `innerHTML`, `document.write`, an unsafe HTML template, or active SVG/HTML rendering.

Read API results this way:

- `[API]` means the payload reached and was reflected by the API.
- The printed full URL can be used for manual retesting.
- Check which frontend page consumes that API.
- If the frontend inserts the API response into HTML without safe encoding and the payload executes, then it is confirmed XSS.

Example API endpoint:

```bash
xssentinel "https://target.test/api/search?q=test"
```

When `[API]` appears, continue manual validation by opening the printed payload URL, checking the response body and content type, finding the frontend consumer, and confirming whether the response is inserted as active HTML or safe text.

## Browser Validation

XSSentinel uses local Chromium or Playwright when available. Browser validation opens the payload URL and watches for `alert`, `confirm`, or `prompt` execution.

Install Chromium on Debian/Ubuntu-based systems:

```bash
sudo apt install chromium
```

Or install Playwright:

```bash
python3 -m pip install playwright
python3 -m playwright install chromium
```

If browser support is missing, the scanner still runs, but validation is limited to HTTP, reflection, and API evidence. In that mode, `[VALID]` findings may be less frequent because browser execution cannot be confirmed.

## HTTP Skip Behavior

Only these statuses are treated as automatic skip candidates:

- `204 No Content`
- `304 Not Modified`

XSSentinel does not skip on a single response. A skip happens only after the same candidate status appears repeatedly without reflection.

Statuses such as `400`, `401`, `403`, `404`, `405`, `406`, `410`, `413`, `415`, `429`, and `5xx` are still analyzed normally. If the payload is reflected, the result can still become `[LOW]`, `[RISK]`, `[API]`, or `[VALID]` depending on evidence.

## Payload Files

Main payload file:

```text
xss-payloads.txt
```

Supporting/experimental payload file:

```text
smart-selected-180-payloads.txt
```

Notes:

- Empty lines and comments are ignored.
- Smart mode expands payloads with encoding, escaping, and syntax mutations.
- `selected=90` in the startup output means 90 high-priority payloads are tested first. It does not mean the total payload count is only 90.

## Troubleshooting

### `xssentinel: command not found`

Add `~/.local/bin` to your `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
xssentinel -h
```

### Local source was edited but the command did not change

Run:

```bash
xssentinel -restart
```

This reinstalls the runtime from the saved local source path.

### Update the installed tool

Run:

```bash
xssentinel -update
```

This fetches the latest available tool state and reinstalls the XSSentinel runtime.

### `[API]` appears but there is no popup

That is expected. `[API]` means the payload was reflected by an API or download response, not that browser execution was confirmed. Use the printed URL to find and test the frontend sink that consumes that response.

### Many `[RISK]` or `[LOW]` results appear, but no `[VALID]`

The payload was reflected, but execution was not confirmed. Common reasons:

- Browser validation is unavailable.
- The payload is rendered as safe text, not active HTML.
- CSP or frontend sanitization blocks execution.
- The endpoint is an API and does not directly render HTML.

### Browser validation is disabled

Check the startup output for `chromium=on` or `chromium=off`. If it is `off`, install Chromium or Playwright as shown in the Browser Validation section.

### The target often returns `500` or unusual responses

Try the default mode without `--all-params`. One parameter per request is usually more stable. Use `--all-params` only when the endpoint needs multiple parameters to change together.

### The scan feels slow

This can happen when many endpoints are discovered or when fallback payloads are running. Watch worker output such as `active`, `done`, and `phases` to understand progress.

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

The installer copies the runtime to:

```text
~/.local/share/xssentinel
```

The wrapper command is created at:

```text
~/.local/bin/xssentinel
```

## Uninstall

```bash
./uninstall.sh
```

## License

XSSentinel is released under the Apache License 2.0. See [LICENSE](LICENSE) for the full license text.
