"""
TLS / certificate analyzer (standard library only).

Connects to host:port over TLS and reports the negotiated protocol/cipher and
certificate details (issuer, subject, SANs, validity), flagging expiry and weak
protocol versions. Read-only handshake -- safe to run against any HTTPS host.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class TLSReport:
    host: str
    port: int
    protocol: str = ""
    cipher: str = ""
    subject: str = ""
    issuer: str = ""
    sans: list = field(default_factory=list)
    not_after: str = ""
    days_left: int = 0
    issues: list = field(default_factory=list)

    def as_text(self) -> str:
        lines = [
            f"Host      : {self.host}:{self.port}",
            f"Protocol  : {self.protocol}",
            f"Cipher    : {self.cipher}",
            f"Subject   : {self.subject}",
            f"Issuer    : {self.issuer}",
            f"Expires   : {self.not_after}  ({self.days_left} days left)",
            f"SANs      : {', '.join(self.sans[:8])}"
            + (" ..." if len(self.sans) > 8 else ""),
        ]
        if self.issues:
            lines.append("Issues:")
            for i in self.issues:
                lines.append(f"  - {i}")
        return "\n".join(lines)


def _name(pairs) -> str:
    d = {k: v for rdn in (pairs or ()) for (k, v) in rdn}
    return d.get("commonName") or d.get("organizationName") or (str(d) if d else "")


def _grab_unverified(host: str, port: int, timeout: float, report: "TLSReport") -> None:
    """Record protocol/cipher even when the cert can't be verified (parsed cert
    fields are unavailable in this mode, but the handshake info still is)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                report.protocol = ss.version() or ""
                cipher = ss.cipher()
                report.cipher = cipher[0] if cipher else ""
    except (OSError, ssl.SSLError):
        pass


def analyze(host: str, port: int = 443, timeout: float = 10.0) -> TLSReport:
    report = TLSReport(host=host, port=port)
    # A verifying handshake so getpeercert() returns the PARSED certificate.
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                report.protocol = ss.version() or ""
                cipher = ss.cipher()          # (name, tls_version, secret_bits)
                report.cipher = cipher[0] if cipher else ""
                cert = ss.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        # An invalid cert is itself a finding; still record protocol/cipher.
        report.issues.append(f"certificate verification FAILED: "
                             f"{getattr(exc, 'verify_message', None) or exc}")
        _grab_unverified(host, port, timeout, report)
        return report
    except (OSError, ssl.SSLError) as exc:
        raise ConnectionError(f"TLS connection to {host}:{port} failed: {exc}") from exc

    if not cert:
        report.issues.append("no certificate details returned")
        return report

    report.subject = _name(cert.get("subject"))
    report.issuer = _name(cert.get("issuer"))
    report.sans = [v for (t, v) in cert.get("subjectAltName", ()) if t == "DNS"]
    report.not_after = cert.get("notAfter", "")
    # ssl.cert_time_to_seconds parses OpenSSL cert timestamps locale-independently
    # (datetime.strptime("%b …") would fail on non-English locales).
    parsed_days = None
    if report.not_after:
        try:
            expires = ssl.cert_time_to_seconds(report.not_after)
            report.days_left = int((expires - time.time()) // 86400)
            parsed_days = report.days_left
        except (ValueError, OSError):
            report.issues.append("could not parse certificate expiry date")

    if parsed_days is not None:
        if parsed_days < 0:
            report.issues.append("certificate is EXPIRED")
        elif parsed_days < 15:
            report.issues.append(f"certificate expires soon ({parsed_days} days)")
    if report.protocol in WEAK_PROTOCOLS:
        report.issues.append(f"weak/deprecated protocol negotiated: {report.protocol}")
    if report.subject and report.subject == report.issuer:
        report.issues.append("certificate appears self-signed (subject == issuer)")
    return report
