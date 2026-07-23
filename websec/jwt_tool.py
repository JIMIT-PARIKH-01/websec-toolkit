"""
JWT analyzer + weak-secret cracker (standard library only).

Decodes a JSON Web Token, flags common weaknesses (alg=none, expiry, HMAC with a
guessable secret), and can dictionary-crack HS256/384/512 signing secrets offline.

For CTF and auditing your OWN tokens.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

# A small built-in list of secrets that show up in CTFs / weak configs.
COMMON_SECRETS = [
    "secret", "password", "123456", "key", "jwt", "secretkey", "admin",
    "changeme", "s3cr3t", "your-256-bit-secret", "supersecret", "test",
    "private", "token", "qwerty", "letmein", "default", "root",
]


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass
class JWTReport:
    header: dict
    payload: dict
    signature: str
    issues: list = field(default_factory=list)
    cracked_secret: str | None = None

    def as_text(self) -> str:
        lines = ["=== JWT analysis ===",
                 "Header :", json.dumps(self.header, indent=2),
                 "Payload:", json.dumps(self.payload, indent=2)]
        if self.issues:
            lines.append("Weaknesses:")
            for i in self.issues:
                lines.append(f"  - {i}")
        if self.cracked_secret is not None:
            lines.append(f"CRACKED secret: '{self.cracked_secret}'")
        return "\n".join(lines)


def decode(token: str):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Not a JWT: expected 3 dot-separated parts.")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Could not decode JWT segments: {exc}") from exc
    return header, payload, parts[2]


def crack(token: str, words) -> str | None:
    """Try each candidate as the HMAC secret; return it if the signature matches."""
    header, _payload, sig = decode(token)
    alg = str(header.get("alg", ""))
    if alg not in _HASHES:
        return None
    signing_input = token.strip().rsplit(".", 1)[0].encode("ascii")
    hashfn = _HASHES[alg]
    for word in words:
        word = word.rstrip("\n")
        computed = _b64url_encode(hmac.new(word.encode(), signing_input, hashfn).digest())
        if hmac.compare_digest(computed, sig):
            return word
    return None


def analyze(token: str, wordlist=None) -> JWTReport:
    header, payload, sig = decode(token)
    issues = []

    alg = str(header.get("alg", ""))
    if alg.lower() == "none":
        issues.append("alg=none - signature not verified; token is trivially forgeable")
    elif alg in _HASHES:
        issues.append(f"{alg} (HMAC) - forgeable if the secret is weak; try cracking it")

    if "exp" in payload:
        if float(payload["exp"]) < time.time():
            issues.append("token is EXPIRED (exp is in the past)")
    else:
        issues.append("no 'exp' claim - token does not expire")

    if "alg" not in header:
        issues.append("no 'alg' in header")

    report = JWTReport(header=header, payload=payload, signature=sig, issues=issues)

    if alg in _HASHES:
        candidates = list(COMMON_SECRETS)
        if wordlist:
            candidates += list(wordlist)
        report.cracked_secret = crack(token, candidates)
        if report.cracked_secret is not None:
            report.issues.append(f"secret cracked from wordlist: '{report.cracked_secret}'")

    return report
