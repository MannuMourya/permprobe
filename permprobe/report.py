"""Human-readable matrix printer."""

from __future__ import annotations

import json
import os
import sys

from .models import ResourceReport, Verdict


def enable_windows_color() -> bool:
    """Turn on VT sequences on Windows so ANSI colors work in cmd/PowerShell."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    except Exception:
        return False


_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
COLORS = {
    Verdict.ALLOWED: "\033[32m",
    Verdict.INFERRED: "\033[36m",
    Verdict.EXISTS_DENIED: "\033[33m",
    Verdict.DENIED: "\033[31m",
    Verdict.AUTH_REQUIRED: "\033[35m",
    Verdict.NOT_FOUND: "\033[90m",
    Verdict.METHOD_BLOCKED: "\033[90m",
    Verdict.REDIRECT: "\033[34m",
    Verdict.ERROR: "\033[31m",
    Verdict.SKIPPED: "\033[90m",
}


def _c(use_color: bool, verdict: Verdict, text: str) -> str:
    if not use_color:
        return text
    return f"{COLORS.get(verdict, '')}{text}{_RESET}"


def render_text(reports: list[ResourceReport], verbose: bool = False, use_color: bool = True) -> str:
    lines: list[str] = []
    for r in reports:
        title = f"{r.kind.upper()}  {r.target}"
        lines.append("=" * 78)
        lines.append(title)
        lines.append(f"url       {r.resolved_url}")
        if r.region:
            lines.append(f"region    {r.region}")
        lines.append(f"identity  {r.identity}")
        lines.append("-" * 78)
        lines.append(f"{'ACTION':<36} {'METH':<7} {'ST':<4} {'CODE':<28} {'ORIG':<8} VERDICT")
        for p in r.probes:
            st = "-" if p.status is None else str(p.status)
            code = p.error_code or ""
            orig = getattr(p, "origin", None) or "unknown"
            row = f"{p.action:<36} {p.method:<7} {st:<4} {code:<28} {orig:<8} {p.verdict.value}"
            lines.append(_c(use_color, p.verdict, row))
            if verbose:
                extra = []
                if p.evidence:
                    extra.append(p.evidence)
                if p.interesting_headers:
                    hdrs = ", ".join(f"{k}={v}" for k, v in list(p.interesting_headers.items())[:6])
                    extra.append(hdrs)
                if p.mutated:
                    extra.append("[mutated canary]")
                if extra:
                    prefix = f"{_DIM}    " if use_color else "    "
                    suffix = _RESET if use_color else ""
                    lines.append(prefix + " | ".join(extra)[:160] + suffix)
        lines.append("-" * 78)
        lines.append("CAPABILITY ROLLUP")
        if r.capabilities:
            width = max(len(k) for k in r.capabilities)
            for cap, summary in r.capabilities.items():
                lines.append(f"  {cap:<{width}}  {summary}")
        else:
            lines.append("  (none)")
        if r.findings:
            lines.append("-" * 78)
            lines.append("FINDINGS")
            for f in r.findings:
                lines.append(f"  ! {f}")
        if r.warnings:
            lines.append("WARNINGS")
            for w in r.warnings:
                lines.append(f"  - {w}")
        lines.append("")
    return "\n".join(lines)


def render_json(reports: list[ResourceReport]) -> str:
    return json.dumps([r.to_dict() for r in reports], indent=2)


def print_report(reports: list[ResourceReport], as_json: bool = False, verbose: bool = False, use_color: bool = True) -> None:
    if as_json:
        sys.stdout.write(render_json(reports) + "\n")
        return
    color = bool(use_color and sys.stdout.isatty())
    if color:
        color = enable_windows_color()
    sys.stdout.write(render_text(reports, verbose=verbose, use_color=color) + "\n")
