"""Shared HTTP client: timeouts, identity headers, no redirects by default."""

from __future__ import annotations

import time
from typing import Optional

import requests
from requests import Response

from .interpret import extract_error_code, pick_headers
from .models import ProbeResult, Verdict
from .interpret import classify


DEFAULT_UA = "permprobe/1.0 (+non-destructive permission mapper; authorized testing only)"
TIMEOUT = 20


class Client:
    def __init__(
        self,
        extra_headers: Optional[dict] = None,
        timeout: float = TIMEOUT,
        follow_redirects: bool = False,
        verify_tls: bool = True,
    ):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_UA})
        if extra_headers:
            self.session.headers.update(extra_headers)
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_tls = verify_tls

    def request(
        self,
        method: str,
        url: str,
        *,
        action: str,
        capability: str,
        headers: Optional[dict] = None,
        data=None,
        params=None,
        signed: bool = False,
        mutated: bool = False,
        allow_redirects: Optional[bool] = None,
    ) -> ProbeResult:
        hdrs = dict(headers or {})
        t0 = time.time()
        status = None
        body = ""
        resp_headers: dict = {}
        err_note = ""
        try:
            resp: Response = self.session.request(
                method=method,
                url=url,
                headers=hdrs,
                data=data,
                params=params,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects if allow_redirects is None else allow_redirects,
                verify=self.verify_tls,
            )
            status = resp.status_code
            resp_headers = dict(resp.headers)
            # keep bodies small — we only need error XML/JSON
            raw = resp.content[:16384] if resp.content else b""
            try:
                body = raw.decode("utf-8", errors="replace")
            except Exception:
                body = ""
        except requests.exceptions.SSLError as e:
            err_note = f"tls: {e}"
        except requests.exceptions.Timeout:
            err_note = "timeout"
        except requests.exceptions.ConnectionError as e:
            err_note = f"connect: {e.__class__.__name__}"
        except requests.exceptions.RequestException as e:
            err_note = f"http: {e.__class__.__name__}"

        elapsed = (time.time() - t0) * 1000
        error_code, error_msg = extract_error_code(body, resp_headers)
        verdict = classify(status, error_code, method, action) if status is not None else Verdict.ERROR
        evidence = (error_msg or _snippet(body) or err_note or "").strip()
        if not evidence and status is not None:
            evidence = f"HTTP {status}"
        if err_note and status is None:
            verdict = Verdict.ERROR
            evidence = err_note

        return ProbeResult(
            action=action,
            capability=capability,
            method=method,
            url=str(resp.url) if status is not None else url,
            status=status,
            error_code=error_code,
            error_message=error_msg,
            verdict=verdict,
            evidence=evidence[:300],
            interesting_headers=pick_headers(resp_headers),
            signed=signed,
            mutated=mutated,
            elapsed_ms=round(elapsed, 1),
            note=err_note,
        )


def _snippet(body: str) -> str:
    if not body:
        return ""
    compact = " ".join(body.split())
    return compact[:240]
