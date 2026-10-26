# XSS evidence regression record

## Original report limitation

The supplied workspace and archive contain no v1.1.0 source checkout, original scan log, or original test input. The terminal label `#0007` is generated from a shared result counter in completion order; it is not a catalog ordinal. The reported `selected=90` count therefore cannot identify the seventh test input, nor can the public-target issue be reproduced from available artifacts. No public host was contacted.

## Local equivalent: default catalog entry 7

- Catalog: `xssentinel_core/manifest/payloads/xss-payloads.txt`, non-comment payload entry 7 (also the forced smart-order position 7).
- Sanitized fingerprint: `sha256(payload UTF-8)[:20] = 79e68ac94012d5c7b579` (46 UTF-8 bytes); computed and asserted by `test_catalog_payload_seven_executes_in_controlled_attribute_fixture` without logging the raw payload.
- Method and parameter: GET, query parameter `q` (`query:q`).
- Transport: URL query-value encoding via `build_request_target`; one form/query decode restores the exact catalog value. The test asserts equality before making its loopback-only request.
- Local fixture: `/attribute` reflects `q` in a quoted `data-value` attribute.
- Expected signal: a browser dialog caused by the catalog payload's event handler, tagged with the current attempt ID and matched exactly against the payload's prompt function/token in a fresh browser run.
- Expected final result: `CONFIRMED` / `CONFIRMED_XSS`, with browser-confirmed evidence attached to that attempt ID.
- Actual local result: Chromium executed the controlled case; the regression passed with `CONFIRMED` / `CONFIRMED_XSS`. The test verifies its browser evidence item and `attempt_id:eNN` evidence ID are both linked to that finding's attempt. Attempt and evidence IDs are generated per run and are intentionally not hard-coded into this record.
- Nearby controls: escaped reflection and a reflected but non-executing payload must not confirm; a separate `/dom` fixture uses a non-popup attempt-specific signal.

The fixture is explicitly an equivalent local regression, not a claim that the unavailable original test input is known.