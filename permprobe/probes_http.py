"""Generic HTTP resource probes.

Never sends PUT/PATCH/DELETE to the live URL. Mutating verbs only hit a
canary sibling path so an existing invoice/user/object cannot be overwritten.
"""

from __future__ import annotations

import uuid
from urllib.parse import urlparse, urlunparse

from .http import Client
from .models import ResourceReport, Verdict
from .interpret import summarize_capabilities, findings_from
from .detect import Target


SAFE_METHODS = [
    ("OPTIONS", "http:OPTIONS", "CORS"),
    ("HEAD", "http:HEAD", "EXISTS"),
    ("GET", "http:GET", "READ"),
]

# Sent only to the canary URL, never to the live resource.
CANARY_METHODS = [
    ("PUT", "http:PUT-canary", "WRITE"),
    ("POST", "http:POST-canary", "WRITE"),
    ("PATCH", "http:PATCH-canary", "WRITE"),
    ("DELETE", "http:DELETE-canary", "DELETE"),
]


def _canary_url(url: str) -> str:
    p = urlparse(url)
    path = p.path or "/"
    if path.endswith("/"):
        new_path = path + f".__permprobe_{uuid.uuid4().hex}"
    else:
        new_path = path + f".__permprobe_{uuid.uuid4().hex}"
    return urlunparse((p.scheme, p.netloc, new_path, "", "", ""))


class HTTPProber:
    def __init__(self, client: Client, mode: str = "readonly", identity: str = "anonymous"):
        self.client = client
        self.mode = mode
        self.identity = identity

    def run(self, target: Target) -> ResourceReport:
        url = target.url or target.raw
        report = ResourceReport(target=target.raw, kind="http", resolved_url=url, identity=self.identity)

        for method, action, cap in SAFE_METHODS:
            extra = {}
            if method == "OPTIONS":
                extra = {
                    "Origin": "https://permprobe.example",
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "authorization,content-type",
                }
            if method == "GET":
                extra = {"Range": "bytes=0-0"}
            p = self.client.request(method, url, action=action, capability=cap, headers=extra)
            report.probes.append(p)

        # TRACE is sometimes enabled and leaks headers. Safe-ish, but noisy —
        # include it as a metadata probe.
        report.probes.append(self.client.request("TRACE", url, action="http:TRACE", capability="METADATA"))

        canary = _canary_url(url)
        for method, action, cap in CANARY_METHODS:
            extra = {"Content-Type": "application/json"} if method in {"PUT", "POST", "PATCH"} else {}
            data = None
            mutated = False
            if method in {"PUT", "PATCH"} and self.mode != "write-probe":
                extra["If-Match"] = '"permprobe-never-matches"'
            if self.mode == "write-probe" and method in {"PUT", "POST", "PATCH"}:
                data = b'{"permprobe":"canary"}'
                mutated = True
            p = self.client.request(
                method, canary, action=action, capability=cap, headers=extra, data=data, mutated=mutated
            )
            # 404 on canary DELETE/PUT is expected and still useful
            if method == "DELETE" and p.status in (200, 202, 204):
                p.verdict = Verdict.ALLOWED
                p.evidence = p.evidence or "canary delete succeeded"
            report.probes.append(p)

        if self.mode == "write-probe":
            # best-effort cleanup if PUT created something
            report.probes.append(
                self.client.request("DELETE", canary, action="http:DELETE-canary", capability="DELETE", mutated=True)
            )

        # Surface Allow / CORS as a finding-friendly note
        for p in report.probes:
            allow = p.interesting_headers.get("Allow") or p.interesting_headers.get("Access-Control-Allow-Methods")
            if allow:
                report.warnings.append(f"{p.action} advertised methods: {allow}")

        report.capabilities = summarize_capabilities(report.probes)
        report.findings = findings_from(report.probes, "http")
        return report
