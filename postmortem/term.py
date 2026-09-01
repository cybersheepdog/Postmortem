"""Terminal color helpers with safe auto-detection.

Color is emitted only when enabled (a TTY, ``NO_COLOR`` unset, not ``--no-color``,
and — on Windows — VT processing could be turned on). When disabled, ``c()`` is
a transparent passthrough, so the same print statements work when piped to a
file. ANSI is never written to the HTML/JSON/CSV reports — only to the console.
"""

import os
import sys

_ENABLED = False
_CODES = {
    "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36", "grey": "90", "bold": "1", "dim": "2",
}


def _enable_windows_vt() -> bool:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def supports_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if sys.platform == "win32":
        return _enable_windows_vt()
    return True


def set_enabled(flag: bool) -> None:
    global _ENABLED
    _ENABLED = bool(flag)


def enabled() -> bool:
    return _ENABLED


def c(text, *styles) -> str:
    """Wrap `text` in the given ANSI styles when color is enabled."""
    if not _ENABLED or not styles:
        return str(text)
    codes = ";".join(_CODES[s] for s in styles if s in _CODES)
    return f"\x1b[{codes}m{text}\x1b[0m" if codes else str(text)


def tier_color(tier: int) -> tuple:
    """ANSI styles for a review tier (1=prime/red, 2=secondary/yellow, else dim)."""
    return {1: ("red", "bold"), 2: ("yellow",)}.get(int(tier), ("dim",))


def severity_color(severity: str) -> tuple:
    return {"high": ("red",), "medium": ("yellow",)}.get(
        str(severity).lower(), ("dim",))
