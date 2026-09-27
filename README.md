# Path Traversal Scanner

A Burp Suite extension for detecting path traversal / local file inclusion (LFI) issues in web applications.

## What it does

- Sends a curated set of traversal payloads against each insertion point
- Tests Unix and Windows file targets such as `/etc/passwd` and `win.ini`
- Tries common encoding bypasses and traversal prefixes
- Flags high-confidence matches in server responses
- Adds a configurable suite tab in Burp for scan depth and target selection

## Requirements

- Burp Suite
- Jython 2.7.x configured in Burp
- The extension file: `PathTraversalScanner.py`

## Installation

1. Open Burp Suite.
2. Go to Extender > Java/Jython.
3. Load the `PathTraversalScanner.py` file as a Jython extension.
4. The extension will appear in the Burp suite tabs as `Path Traversal`.

## Usage

- Run active scans against target parameters or URL paths.
- Adjust the traversal depth and OS targets in the `Path Traversal` tab.
- Review findings in Burp's Scanner results.

## Notes

This tool is intended for authorized security testing only. Use it only on systems you own or are explicitly permitted to test.
