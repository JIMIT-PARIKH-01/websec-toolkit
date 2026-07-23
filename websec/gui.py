"""
Tkinter GUI for the Web Security Toolkit (standard library only).

Tabs: JWT · TLS · CORS · Cookies. Network operations run on background threads;
only the main thread touches widgets (via a queue).

Authorized use only. Launch with run.bat, or:  python websec/gui.py
"""

from __future__ import annotations

import queue
import threading

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

try:
    from websec import jwt_tool, tls, cors, cookies
except ImportError:  # pragma: no cover
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from websec import jwt_tool, tls, cors, cookies


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Web Security Toolkit")
        self.geometry("860x680")
        self.minsize(720, 560)
        self.ui_queue: "queue.Queue" = queue.Queue()
        self.after(60, self._drain)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        for tab, title in ((JWTTab, "  JWT  "), (TLSTab, "  TLS / Cert  "),
                           (CORSTab, "  CORS  "), (CookieTab, "  Cookies  ")):
            nb.add(tab(nb, self), text=title)

        self.status = ttk.Label(self, relief="sunken", anchor="w",
                                text="Ready - authorized testing only.")
        self.status.pack(fill="x", side="bottom")

    def set_status(self, msg: str) -> None:
        self.status.configure(text=msg)

    def _drain(self) -> None:
        try:
            while True:
                cb = self.ui_queue.get_nowait()
                try:
                    cb()
                except Exception:  # noqa: BLE001
                    self.set_status("A UI update failed.")
        except queue.Empty:
            pass
        self.after(60, self._drain)


class _Tab(ttk.Frame):
    def __init__(self, master, app: App) -> None:
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        self.btn: ttk.Button | None = None

    def _output(self, row: int) -> scrolledtext.ScrolledText:
        box = scrolledtext.ScrolledText(self, wrap="word", font=("Consolas", 10),
                                        state="disabled")
        box.grid(row=row, column=0, sticky="nsew", pady=(8, 0))
        return box

    def _show(self, widget, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _run_async(self, work, on_done, busy: str) -> None:
        if self.btn:
            self.btn.configure(state="disabled")
        self.app.set_status(busy)

        def runner() -> None:
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001
                result = f"Error: {exc}"

            def finish() -> None:
                on_done(result)
                if self.btn:
                    self.btn.configure(state="normal")
                self.app.set_status("Done.")
            self.app.ui_queue.put(finish)

        threading.Thread(target=runner, daemon=True).start()


class JWTTab(_Tab):
    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="Paste a JWT").grid(row=0, column=0, sticky="w")
        self.inp = scrolledtext.ScrolledText(self, height=5, wrap="char",
                                             font=("Consolas", 10))
        self.inp.grid(row=1, column=0, sticky="ew")
        ctl = ttk.Frame(self); ctl.grid(row=2, column=0, sticky="ew", pady=6)
        self.btn = ttk.Button(ctl, text="Analyze + crack", command=self.run)
        self.btn.pack(side="right")
        self.out = self._output(3)

    def run(self):
        tok = self.inp.get("1.0", "end").strip()
        if not tok:
            messagebox.showinfo("No token", "Paste a JWT first."); return
        # analysis is offline/instant, but keep it uniform
        self._run_async(lambda: jwt_tool.analyze(tok).as_text(),
                        lambda r: self._show(self.out, r), "Analyzing token…")


class _HostTab(_Tab):
    label = "Host"
    busy = "Working…"

    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text=self.label).grid(row=0, column=0, sticky="w")
        self.value = tk.StringVar()
        ttk.Entry(self, textvariable=self.value).grid(row=1, column=0, sticky="ew")
        ctl = ttk.Frame(self); ctl.grid(row=2, column=0, sticky="ew", pady=6)
        self.btn = ttk.Button(ctl, text="Run", command=self.run); self.btn.pack(side="right")
        self.out = self._output(3)

    def work(self, value: str) -> str:
        raise NotImplementedError

    def run(self):
        v = self.value.get().strip()
        if not v:
            messagebox.showinfo("No input", f"Enter a {self.label.lower()}."); return
        self._run_async(lambda: self.work(v),
                        lambda r: self._show(self.out, r), self.busy)


class TLSTab(_HostTab):
    label, busy = "Host (e.g. github.com)", "Handshaking…"

    def work(self, v):
        host, _, port = v.partition(":")
        return tls.analyze(host, port=int(port) if port else 443).as_text()


class CORSTab(_HostTab):
    label, busy = "URL", "Probing CORS…"

    def work(self, v):
        return cors.analyze(v).as_text()


class CookieTab(_HostTab):
    label, busy = "URL", "Fetching cookies…"

    def work(self, v):
        return cookies.analyze(v).as_text()


def main() -> int:
    App().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
