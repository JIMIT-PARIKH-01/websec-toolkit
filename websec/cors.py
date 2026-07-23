"""
CORS misconfiguration checker (standard library only).

Sends requests with crafted Origin headers and inspects the
Access-Control-Allow-Origin / -Credentials response headers to spot classic
misconfigurations (reflected origin + credentials, wildcard + credentials,
null origin trusted).

Authorized use only -- test sites you own or are permitted to assess.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field

EVIL = "https://evil.example.com"


@dataclass
class CORSReport:
    url: str
    tests: list = field(default_factory=list)      # (origin, acao, acac)
    issues: list = field(default_factory=list)

    def as_text(self) -> str:
        lines = [f"URL: {self.url}", "Tests (Origin sent -> ACAO / ACAC):"]
        for origin, acao, acac in self.tests:
            lines.append(f"  {origin:<32} -> {acao or '(none)'} / creds={acac or 'no'}")
        if self.issues:
            lines.append("Misconfigurations:")
            for i in self.issues:
                lines.append(f"  ! {i}")
        else:
            lines.append("No obvious CORS misconfiguration detected.")
        return "\n".join(lines)


def _probe(url: str, origin: str, timeout: float):
    req = urllib.request.Request(
        url, method="GET",
        headers={"Origin": origin, "User-Agent": "websec-toolkit/1.0"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        h = resp.headers
    except urllib.error.HTTPError as exc:
        h = exc.headers
    except (urllib.error.URLError, OSError) as exc:
        raise ConnectionError(f"request to {url} failed: {exc}") from exc
    return (h.get("Access-Control-Allow-Origin"),
            h.get("Access-Control-Allow-Credentials"))


def analyze(url: str, timeout: float = 10.0) -> CORSReport:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    report = CORSReport(url=url)

    for origin in (EVIL, "null"):
        acao, acac = _probe(url, origin, timeout)
        report.tests.append((origin, acao, acac))
        creds = (acac or "").lower() == "true"

        if acao == origin and origin == EVIL:
            msg = "reflects an arbitrary Origin in Access-Control-Allow-Origin"
            report.issues.append(msg + (" WITH credentials (critical)" if creds else ""))
        if acao == "null" and origin == "null":
            report.issues.append("trusts Origin: null"
                                 + (" WITH credentials (critical)" if creds else ""))
        if acao == "*" and creds:
            report.issues.append("wildcard ACAO combined with credentials")
    return report
