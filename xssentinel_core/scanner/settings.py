"""
FUZZ-parameter XSS scanner.

Use only on applications you own or have explicit permission to test.
The scanner replaces GET query values or POST body values marked FUZZ with
payloads from xss-payloads.txt, checks HTTP reflection, and optionally confirms
execution with a Chromium browser when available.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable


BASE_DIR = Path(__file__).resolve().parents[2]

from xssentinel_core.runtime.engine import BANNER, FINGERPRINT_ID, rafashacodeid as _rafashacodeid, verify_identity

PAYLOAD_FILE = BASE_DIR / "xss-payloads.txt"
USER_AGENT_FILE = BASE_DIR / "useragents.txt"
FINGERPRINT_FILE = BASE_DIR / "xssentinel_core" / "fingerprint" / "rafashacodeid.sig"
INSECURE_SSL_CONTEXT = ssl._create_unverified_context()

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
DIM = "\033[2m"
CYAN = "\033[36m"
BLUE = "\033[34m"
BRIGHT_TOSCA = "\033[96m"
MAGENTA = "\033[35m"

def rafashacodeid() -> dict[str, str]:
    return _rafashacodeid()

VOID_TAGS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}

ACTIVE_XSS_PATTERNS = [
    (re.compile(r"<\s*script\b", re.I), "script tag reflected as HTML", 90),
    (re.compile(r"<\s*(svg|img|image|iframe|object|embed|body|details|marquee|video|audio|input|textarea|select|x)\b[^>]*\bon[a-z]+\s*=", re.I), "event-handler HTML reflected", 85),
    (re.compile(r"\bon[a-z]+\s*=\s*[^\s>]+", re.I), "event-handler attribute reflected", 80),
    (re.compile(r"javascript\s*:", re.I), "javascript: URL reflected", 80),
    (re.compile(r"srcdoc\s*=", re.I), "srcdoc attribute reflected", 75),
    (re.compile(r"</\s*script\s*>", re.I), "script-context breakout reflected", 85),
]

CONTEXT_PROBE_PAYLOADS = [
    "xssctx\"'`<>{}()[]:/\\",
    "</title><xssctx>",
    "</textarea><xssctx>",
    "</script><xssctx>",
    "javascript:xssctx",
]

SMART_PAYLOAD_LIMIT = 90
SMART_CONTEXT_LIMIT = 24
SMART_CONFIRM_LIMIT = 6
MAX_EXTERNAL_SCRIPT_ANALYSIS = 2

FORCED_SMART_PAYLOAD_POSITIONS = [
    (7, '"onclick=prompt(8)><svg/onload=prompt(8)>"@x.y'),
    (8, "data:text/html;base64,PHNjcmlwdD5hbGVydCgnaGFja2VkIGJ5IGthbmcgcmFmYXNoYScpPC9zY3JpcHQ+"),
]

HIGH_SIGNAL_SNIPPETS = (
    "<svg",
    "<img",
    "<iframe",
    "<math",
    "<body",
    "<details",
    "<input",
    "<textarea",
    "<select",
    "</script>",
    "onload=",
    "onerror=",
    "onfocus=",
    "ontoggle=",
    "javascript:",
    "srcdoc=",
)

DOM_SOURCE_PATTERNS = [
    (re.compile(r"\blocation\.(?:href|search|hash|pathname)\b", re.I), "location source"),
    (re.compile(r"\bdocument\.(?:URL|documentURI|referrer|cookie)\b", re.I), "document source"),
    (re.compile(r"\b(?:localStorage|sessionStorage)\b", re.I), "web storage source"),
    (re.compile(r"\bpostMessage\s*\(", re.I), "postMessage source"),
]

DOM_SINK_PATTERNS = [
    (re.compile(r"\.innerHTML\s*=", re.I), "innerHTML assignment", 90),
    (re.compile(r"\.outerHTML\s*=", re.I), "outerHTML assignment", 90),
    (re.compile(r"\binsertAdjacentHTML\s*\(", re.I), "insertAdjacentHTML", 88),
    (re.compile(r"\bdocument\.write(?:ln)?\s*\(", re.I), "document.write", 88),
    (re.compile(r"\beval\s*\(", re.I), "eval", 82),
    (re.compile(r"\bnew\s+Function\s*\(", re.I), "Function constructor", 82),
    (re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"]", re.I), "string timer execution", 78),
    (re.compile(r"\.(?:src|href|data|action)\s*=", re.I), "URL-bearing attribute assignment", 72),
    (re.compile(r"\bon[a-z]+\s*=", re.I), "event handler assignment", 75),
]

WAF_HEADER_PATTERNS = [
    ("cloudflare", re.compile(r"cloudflare|cf-ray|cf-cache-status", re.I)),
    ("sucuri", re.compile(r"sucuri|x-sucuri", re.I)),
    ("akamai", re.compile(r"akamai|akamai-ghost|x-akamai", re.I)),
    ("aws waf", re.compile(r"awselb|awsalb|x-amzn|cloudfront", re.I)),
    ("imperva/incapsula", re.compile(r"incap_ses|visid_incap|imperva", re.I)),
    ("f5 asm", re.compile(r"bigip|f5|ts[0-9a-f]{3,}", re.I)),
    ("modsecurity", re.compile(r"mod_security|modsecurity", re.I)),
]

WAF_BODY_PATTERNS = [
    re.compile(r"access denied|request blocked|forbidden|security policy|not acceptable", re.I),
    re.compile(r"web application firewall|waf|mod_security|sucuri website firewall", re.I),
]

BROWSER_INIT_SCRIPT = """
(() => {
  const root = window;
  root.__xssScannerHits = root.__xssScannerHits || [];
  for (const name of ['alert', 'confirm', 'prompt']) {
    try {
      const nativeFn = root[name];
      if (typeof nativeFn !== 'function' || nativeFn.__xssScannerWrapped) continue;
      const wrapped = function(...args) {
        const message = args.length ? String(args[0]) : '';
        try { root.__xssScannerHits.push(`${name}:${message}`); } catch (_) {}
        try {
          if (root.top && root.top !== root) {
            root.top.__xssScannerHits = root.top.__xssScannerHits || [];
            root.top.__xssScannerHits.push(`${name}:${message}`);
          }
        } catch (_) {}
        return nativeFn.apply(this, args);
      };
      Object.defineProperty(wrapped, '__xssScannerWrapped', {value: true});
      root[name] = wrapped;
    } catch (_) {}
  }
})();
"""

BROWSER_TRIGGER_SCRIPT = """
(() => {
  const eventNames = [
    'mouseover', 'mouseenter', 'mousemove', 'mousedown', 'mouseup', 'click',
    'dblclick', 'contextmenu', 'focus', 'focusin', 'input', 'change', 'keydown',
    'keypress', 'keyup', 'copy', 'cut', 'paste', 'dragstart', 'drag', 'drop',
    'touchstart', 'touchend', 'pointerover', 'pointerenter', 'pointerdown', 'pointerup'
  ];
  const elements = Array.from(document.querySelectorAll('*')).slice(0, 250);
  for (const el of elements) {
    try { el.scrollIntoView({block: 'center', inline: 'center'}); } catch (_) {}
    try { if (typeof el.focus === 'function') el.focus({preventScroll: true}); } catch (_) {}
    try { if (typeof el.click === 'function') el.click(); } catch (_) {}
    for (const name of eventNames) {
      try {
        let event;
        if (name.startsWith('key')) event = new KeyboardEvent(name, {key: 'Enter', bubbles: true, cancelable: true});
        else if (name.startsWith('mouse') || ['click', 'dblclick', 'contextmenu'].includes(name)) event = new MouseEvent(name, {bubbles: true, cancelable: true, view: window});
        else if (name.startsWith('pointer')) event = new PointerEvent(name, {bubbles: true, cancelable: true});
        else event = new Event(name, {bubbles: true, cancelable: true});
        el.dispatchEvent(event);
      } catch (_) {}
    }
  }
  return window.__xssScannerHits || [];
})();
"""
