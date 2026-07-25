"""Offline tests for the Web Security Toolkit."""

import base64
import hashlib
import hmac
import json

import pytest

from websec import jwt_tool as j
from websec import cookies, tls


def _b(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()


def _make(secret=b"secret", alg="HS256", payload=None):
    payload = payload or {"user": "admin"}
    h = _b(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    p = _b(json.dumps(payload).encode())
    s = _b(hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{s}"


def test_jwt_decode():
    header, payload, _sig = j.decode(_make())
    assert payload["user"] == "admin" and header["alg"] == "HS256"


def test_jwt_crack_weak_secret():
    assert j.crack(_make(b"secret"), ["nope", "secret", "x"]) == "secret"


def test_jwt_analyze_cracks_and_flags():
    r = j.analyze(_make(b"secret"))
    assert r.cracked_secret == "secret"
    assert any("HMAC" in i for i in r.issues)


def test_jwt_alg_none_flagged():
    tok = _b(json.dumps({"alg": "none"}).encode()) + "." + \
        _b(json.dumps({"admin": True}).encode()) + "."
    assert any("alg=none" in i for i in j.analyze(tok).issues)


def test_jwt_bad_token_raises():
    with pytest.raises(ValueError):
        j.decode("only.two")


def test_cookie_flags_present():
    c = cookies._parse_setcookie("sid=abc; HttpOnly; Secure; SameSite=Lax")
    assert c.name == "sid" and c.http_only and c.secure and c.samesite == "Lax"


def test_cookie_flags_missing():
    c = cookies._parse_setcookie("x=1")
    assert not c.http_only and not c.secure and c.samesite == ""


def test_tls_name_helper():
    assert tls._name(((("commonName", "github.com"),),)) == "github.com"
    assert tls._name(()) == ""
