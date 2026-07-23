"""
Web Security Toolkit command line.

    python -m websec jwt     --text "eyJhbGciOi..."   [--wordlist words.txt]
    python -m websec tls     github.com    [--port 443]
    python -m websec cors    https://api.example.com
    python -m websec cookies https://example.com

Authorized use only: assess sites/tokens you own or are permitted to test.
"""

from __future__ import annotations

import argparse
import sys

from . import jwt_tool, tls, cors, cookies


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="websec",
        description="Web-app security: JWT analysis, TLS/cert, CORS, cookie flags.")
    sub = p.add_subparsers(dest="command", required=True)

    jw = sub.add_parser("jwt", help="Decode + analyze (+ crack) a JWT.")
    jw.add_argument("--text", required=True, help="The JWT string.")
    jw.add_argument("--wordlist", help="Extra secrets file for HMAC cracking.")

    tl = sub.add_parser("tls", help="TLS + certificate analysis.")
    tl.add_argument("host")
    tl.add_argument("--port", type=int, default=443)

    co = sub.add_parser("cors", help="CORS misconfiguration check.")
    co.add_argument("url")

    ck = sub.add_parser("cookies", help="Cookie security-flag analysis.")
    ck.add_argument("url")
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "jwt":
            words = None
            if args.wordlist:
                with open(args.wordlist, encoding="utf-8", errors="replace") as fh:
                    words = fh.read().splitlines()
            print(jwt_tool.analyze(args.text, wordlist=words).as_text())

        elif args.command == "tls":
            print(tls.analyze(args.host, port=args.port).as_text())

        elif args.command == "cors":
            print(cors.analyze(args.url).as_text())

        elif args.command == "cookies":
            print(cookies.analyze(args.url).as_text())
    except (ValueError, ConnectionError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
