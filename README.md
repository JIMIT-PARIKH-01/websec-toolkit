# Web Security Toolkit

[![CI](https://github.com/JIMIT-PARIKH-01/websec-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/JIMIT-PARIKH-01/websec-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

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

## ⬇️ Download & Install

**This is a public tool — download and use it on your device for free.**

```bash
# 1) Clone it
git clone https://github.com/JIMIT-PARIKH-01/websec-toolkit.git
cd websec-toolkit

# 2) ...or download a ZIP (no git needed)
#    https://github.com/JIMIT-PARIKH-01/websec-toolkit/archive/refs/heads/main.zip

# 3) ...or install the command straight from GitHub
pip install git+https://github.com/JIMIT-PARIKH-01/websec-toolkit.git
```

Then run it as shown in the usage section above (CLI `python -m ...`, or launch
the GUI via `run.bat`).

<details>
<summary><b>🔒 Requesting access to a private tool</b></summary>

Public tools install with the commands above. If a tool is **private**, access
is granted by the owner through GitHub — a static link cannot unlock private
code, only GitHub can:

1. **Request access** — open an [access request](https://github.com/JIMIT-PARIKH-01/JIMIT-PARIKH-01/issues/new?template=tool-access-request.md&title=Access+request:+websec-toolkit) or message on
   [LinkedIn](https://www.linkedin.com/in/jimit-devangkumar-parikh/).
2. The owner reviews it and, if approved, **adds you as a collaborator** on the
   private repository.
3. GitHub then lets you clone / download it with your own account. Access is
   revoked the moment the owner removes you as a collaborator.

</details>

## License
MIT — see [LICENSE](./LICENSE).
