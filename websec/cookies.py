"""
Cookie security analyzer (standard library only).

Fetches a URL and checks each Set-Cookie for the HttpOnly, Secure, and SameSite
protections, flagging cookies that are missing them. Read-only GET.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field


@dataclass
class CookieInfo:
    name: str
    http_only: bool
    secure: bool
    samesite: str

    def flags(self) -> str:
        return (f"HttpOnly={'yes' if self.http_only else 'NO'} "
                f"Secure={'yes' if self.secure else 'NO'} "
                f"SameSite={self.samesite or 'NONE'}")


@dataclass
class CookieReport:
    url: str
    cookies: list = field(default_factory=list)     # CookieInfo
    issues: list = field(default_factory=list)

    def as_text(self) -> str:
        lines = [f"URL: {self.url}", f"Cookies: {len(self.cookies)}"]
        for c in self.cookies:
            lines.append(f"  {c.name:<24} {c.flags()}")
        if self.issues:
            lines.append("Issues:")
            for i in self.issues:
                lines.append(f"  - {i}")
        elif self.cookies:
            lines.append("All cookies set HttpOnly, Secure, and SameSite. Good.")
        return "\n".join(lines)


def _parse_setcookie(raw: str) -> CookieInfo:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip()
             if "=" in p else "") for p in parts[1:]}
    return CookieInfo(name=name, http_only="httponly" in attrs,
                      secure="secure" in attrs, samesite=attrs.get("samesite", ""))


def analyze(url: str, timeout: float = 10.0) -> CookieReport:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    req = urllib.request.Request(
        url, method="GET", headers={"User-Agent": "websec-toolkit/1.0"})
    ctx = ssl.create_default_context()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        raw_headers = resp.headers
    except urllib.error.HTTPError as exc:
        raw_headers = exc.headers
    except (urllib.error.URLError, OSError) as exc:
        raise ConnectionError(f"Could not fetch {url}: {exc}") from exc

    report = CookieReport(url=url)
    for raw in raw_headers.get_all("Set-Cookie") or []:
        c = _parse_setcookie(raw)
        report.cookies.append(c)
        missing = []
        if not c.http_only:
            missing.append("HttpOnly")
        if not c.secure:
            missing.append("Secure")
        if not c.samesite:
            missing.append("SameSite")
        if missing:
            report.issues.append(f"cookie '{c.name}' missing: {', '.join(missing)}")
    return report
