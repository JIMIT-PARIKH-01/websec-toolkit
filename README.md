# Web Security Toolkit

A **dependency-free** web-application security toolkit — four tools in one, with a
**GUI and a CLI**. Complements the network-level `recon-suite` by focusing on the
**application layer**.

1. **JWT analyzer + cracker** — decode a token, flag weaknesses (`alg=none`, no expiry, weak
   HMAC), and **dictionary-crack** HS256/384/512 signing secrets — *offline*
2. **TLS / certificate analyzer** — protocol, cipher, issuer, SANs, expiry; flags weak
   protocols, expiring/self-signed/failed-verification certs
3. **CORS misconfiguration checker** — detects reflected-origin, `null`-origin, and
   wildcard-with-credentials mistakes
4. **Cookie analyzer** — checks each `Set-Cookie` for HttpOnly / Secure / SameSite

Built on the Python standard library only (`hmac`, `hashlib`, `ssl`, `urllib`).

---

## ⚠️ Authorized use only

Analyze **your own** tokens and sites, or targets you have explicit permission to test.

---

## Install & run

Just **Python 3.8+** — nothing to install.

```powershell
# GUI (tabs: JWT / TLS / CORS / Cookies)
python websec/gui.py             # or double-click run.bat

# CLI
python -m websec jwt     --text "eyJhbGciOiJIUzI1NiJ9..."   # decode + crack weak secret
python -m websec jwt     --text "<token>" --wordlist rockyou.txt
python -m websec tls     github.com
python -m websec cors    https://api.example.com
python -m websec cookies https://example.com
```

### Commands

| Command | Purpose |
|---|---|
| `jwt --text TOKEN [--wordlist FILE]` | decode header/payload, flag weaknesses, crack HMAC secret |
| `tls HOST [--port N]` | TLS protocol/cipher + certificate audit |
| `cors URL` | detect CORS misconfigurations |
| `cookies URL` | audit cookie security flags |

---

## Highlight: the JWT tool

The JWT analyzer is fully **offline** and a CTF/web-pentest staple:

```
$ python -m websec jwt --text eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.<sig>
=== JWT analysis ===
Header : { "alg": "HS256", "typ": "JWT" }
Payload: { "user": "admin" }
Weaknesses:
  - HS256 (HMAC) - forgeable if the secret is weak; try cracking it
CRACKED secret: 'secret'
```

## Project layout

```
websec-toolkit/
└── websec/
    ├── jwt_tool.py   # decode + analyze + HMAC secret cracker
    ├── tls.py        # TLS + certificate analysis
    ├── cors.py       # CORS misconfiguration checks
    ├── cookies.py    # cookie security-flag analysis
    ├── cli.py  gui.py  run.bat  requirements.txt
```

## License
MIT — see [LICENSE](./LICENSE).
