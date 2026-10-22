#!/usr/bin/env python3
"""Read-only checker for the two localhost PHP Patch Check containers.

Scope: CVE-2026-109618 and CVE-2026-109619; upstream release versions.
MITIGATED means selected values match this lab's no-upload stopgap policy.
It does not verify startup enforcement, worker restarts, or all attack paths.
Vendor backports and prereleases need separate review.
Exit codes: 0 = both patched, 1 = an unpatched server, 2 = a check failed.

Sources (reviewed 2026-10-22):
https://www.php.net/archive/2026.php
https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
"""

import json
import re
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPException


SERVERS = {"old": 8083, "new": 8084}
FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
MODES = {"apache2handler": "mod_php", "fpm-fcgi": "PHP-FPM"}
SETTINGS = (
    "session.upload_progress.enabled",
    "memory_limit",
    "post_max_size",
    "fatal_error_backtraces",
)


def parse_version(value):
    """Compare numbers, so 8.3.9 is older than 8.3.36."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise ValueError("Version is not a plain upstream release; review it manually.")
    return tuple(int(part) for part in value.split("."))


def size_bytes(value):
    """Accept whole bytes or PHP's K/M/G shorthand; reject ambiguous values."""
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"([0-9]+)([KMG]?)", value.strip(), re.IGNORECASE)
    if not match:
        return None
    factors = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3}
    return int(match[1]) * factors[match[2].upper()]


def is_off(value):
    # Missing values (None) must never be mistaken for a disabled setting.
    return isinstance(value, str) and value.strip().lower() in {"", "0", "off", "false", "no", "none"}


def read_server(port):
    """One ordinary GET to a fixed loopback endpoint; no proxy or redirects."""
    if port not in (8083, 8084):
        raise ValueError("Only the two lab ports are allowed.")
    connection = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", "/status.php", headers={"Accept": "application/json"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"HTTP {response.status}; expected 200. Redirects are not followed.")
        content_type = response.getheader("Content-Type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("Expected JSON from status.php.")
        body = response.read(16385)
        if len(body) > 16384:
            raise ValueError("Diagnostic response exceeds the 16 KiB limit.")
        return json.loads(body)
    finally:
        connection.close()


def assess(data):
    """Validate the diagnostic and return a status with its reason."""
    if not isinstance(data, dict):
        raise ValueError("Diagnostic must be a JSON object.")
    version = parse_version(data.get("php_version"))
    sapi = data.get("sapi")
    if not isinstance(sapi, str) or sapi not in MODES:
        raise ValueError("Expected the mod_php or PHP-FPM web runtime.")
    settings = data.get("settings")
    if not isinstance(settings, dict):
        raise ValueError("Diagnostic settings are missing.")
    for name in SETTINGS:
        if name not in settings or (settings[name] is not None and not isinstance(settings[name], str)):
            raise ValueError(f"Missing or invalid setting: {name}")

    if version[:2] <= (8, 1):
        return "NOT PATCHED", "Legacy branch: flagged by default; any backported fixes need separate verification."
    minimum = FIXED.get(version[:2])
    if minimum is None:
        raise ValueError("This branch has no rule in the checker; review the official advisory.")
    fixed_text = ".".join(str(part) for part in minimum)
    if version >= minimum:
        return "PATCHED", f"PHP {data['php_version']} meets the fixed release {fixed_text} for its branch."

    post_limit = size_bytes(settings["post_max_size"])
    partial_stopgaps = (
        settings["memory_limit"] == "-1"
        and is_off(settings["session.upload_progress.enabled"])
        and post_limit is not None
        and 0 < post_limit <= 8 * 1024**2
        and (version[:2] != (8, 5) or is_off(settings["fatal_error_backtraces"]))
    )
    if partial_stopgaps:
        return "NOT PATCHED BUT MITIGATED", (
            f"PHP is below {fixed_text}; observed stopgap values match, "
            "but protection is partial and enforcement is unverified."
        )
    return "NOT PATCHED", f"PHP {data['php_version']} is older than {fixed_text}; selected stopgap settings are incomplete."


def main():
    print("PHP PATCH CHECK")
    print("CVE-2026-109618 | CVE-2026-109619")
    print("Checked at:", datetime.now(timezone.utc).isoformat(timespec="seconds"))
    statuses = []
    for name, port in SERVERS.items():
        print(f"\n[{name}] http://127.0.0.1:{port}/status.php")
        try:
            data = read_server(port)
            status, reason = assess(data)
        except (OSError, HTTPException, ValueError, RecursionError) as error:
            print(f"ERROR: Unable to assess this server: {error}")
            statuses.append("ERROR")
            continue
        statuses.append(status)
        print(status)
        print("Why:", reason)
        print(f"PHP: {data['php_version']} | Mode: {MODES[data['sapi']]} ({data['sapi']})")
        for setting in SETTINGS:
            value = data["settings"][setting]
            if setting == "fatal_error_backtraces" and parse_version(data["php_version"])[:2] != (8, 5):
                text = "N/A (PHP 8.5 only)"
            else:
                text = "unavailable" if value is None else json.dumps(value)
            print(f"  {setting} = {text}")

    print("\nScope: upstream version/configuration evidence for these two CVEs.")
    print("Mitigated = selected observed settings only; an update is still required.")
    print("Vendor backports, startup enforcement and other workers require separate verification.")
    if "ERROR" in statuses:
        return 2
    return 0 if all(status == "PATCHED" for status in statuses) else 1


if __name__ == "__main__":
    raise SystemExit(main())
