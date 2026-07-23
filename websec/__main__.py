"""Entry point:  python -m websec <jwt|tls|cors|cookies> ..."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
