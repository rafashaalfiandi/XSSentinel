import unittest

from xssentinel_core.scanner.payloads import prioritize_all_payloads, prioritize_payloads, select_payload_batches


class PayloadBatchTests(unittest.TestCase):
    def test_select_payload_batches_matches_existing_smart_fallback_semantics(self) -> None:
        payloads = [
            "plain",
            "<svg onload=alert(1)>",
            "\" autofocus onfocus=alert(1) x=\"",
            "</script><script>alert(1)</script>",
        ]
        contexts = {"html-text", "html-attribute"}

        selected, fallback = select_payload_batches(payloads, contexts, 2, True)

        previous_selected = prioritize_payloads(payloads, contexts, 2)
        previous_ordered = prioritize_all_payloads(payloads, contexts)
        previous_selected_set = set(previous_selected)
        previous_fallback = [payload for payload in previous_ordered if payload not in previous_selected_set]

        self.assertEqual(selected, previous_selected)
        self.assertEqual(fallback, previous_fallback)

    def test_select_payload_batches_can_disable_fallback(self) -> None:
        selected, fallback = select_payload_batches(["plain", "<img src=x onerror=alert(1)>"], {"html-text"}, 1, False)

        self.assertEqual(len(selected), 1)
        self.assertEqual(fallback, [])


if __name__ == "__main__":
    unittest.main()
