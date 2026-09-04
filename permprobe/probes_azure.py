"""Azure Blob Storage REST probes. Auth is via --header (SAS or Shared Key)."""

from __future__ import annotations

import uuid
from typing import Optional

from .http import Client
from .models import ResourceReport, Verdict
from .interpret import summarize_capabilities, findings_from, origin_warnings
from .detect import Target


class AzureProber:
    def __init__(self, client: Client, mode: str = "readonly", identity: str = "anonymous"):
        self.client = client
        self.mode = mode
        self.identity = identity

    def _call(self, method, url, action, capability, extra=None, data=None, mutated=False):
        hdrs = {"x-ms-version": "2020-10-02"}
        if extra:
            hdrs.update(extra)
        return self.client.request(method, url, action=action, capability=capability, headers=hdrs, data=data, mutated=mutated)

    def run(self, target: Target) -> ResourceReport:
        account = target.account
        container = target.container
        key = target.key
        if not account or not container:
            raise ValueError("Azure target needs https://{account}.blob.core.windows.net/{container}")
        base = f"https://{account}.blob.core.windows.net/{container}"
        report = ResourceReport(target=target.raw, kind="azure", resolved_url=base, identity=self.identity)

        report.probes.append(self._call("HEAD", f"{base}?restype=container", "azure:HeadContainer", "EXISTS"))
        report.probes.append(self._call("GET", f"{base}?restype=container", "azure:GetContainerProperties", "METADATA"))
        report.probes.append(self._call("GET", f"{base}?restype=container&comp=list&maxresults=2", "azure:ListBlobs", "LIST"))
        report.probes.append(self._call("GET", f"{base}?restype=container&comp=acl", "azure:GetContainerAcl", "ACL_READ"))
        report.probes.append(self._call("GET", f"{base}?restype=container&comp=metadata", "azure:GetContainerMetadata", "METADATA"))
        report.probes.append(
            self._call(
                "OPTIONS",
                base,
                "azure:OPTIONS",
                "CORS",
                extra={"Origin": "https://permprobe.example", "Access-Control-Request-Method": "GET"},
            )
        )

        if key:
            blob = f"{base}/{key}"
            report.probes.append(self._call("HEAD", blob, "azure:HeadBlob", "EXISTS"))
            report.probes.append(self._call("GET", blob, "azure:GetBlob", "READ", extra={"Range": "bytes=0-0"}))
            report.probes.append(self._call("GET", f"{blob}?comp=metadata", "azure:GetBlobMetadata", "METADATA"))
            report.probes.append(self._call("GET", f"{blob}?comp=acl", "azure:GetBlobAcl", "ACL_READ"))

        canary = f".__permprobe_{uuid.uuid4().hex}"
        canary_url = f"{base}/{canary}"
        put_infer = self._call(
            "PUT",
            canary_url,
            "azure:PutBlob",
            "WRITE",
            extra={"x-ms-blob-type": "BlockBlob", "If-Match": '"permprobe-never-matches"'},
        )
        if put_infer.status == 412:
            put_infer.verdict = Verdict.INFERRED
            put_infer.evidence = "412 on If-Match — PutBlob authorized, blob not created"
        elif put_infer.status in (200, 201):
            put_infer.mutated = True
            self._call("DELETE", canary_url, "azure:DeleteBlob", "DELETE", mutated=True)
        report.probes.append(put_infer)
        d = self._call("DELETE", canary_url, "azure:DeleteBlob", "DELETE")
        if d.status in (202, 204, 200):
            d.verdict = Verdict.ALLOWED
        report.probes.append(d)

        if self.mode == "write-probe":
            put = self._call(
                "PUT",
                canary_url,
                "azure:PutBlob",
                "WRITE",
                extra={"x-ms-blob-type": "BlockBlob", "Content-Type": "text/plain"},
                data=b"permprobe-canary-ok",
                mutated=True,
            )
            report.probes.append(put)
            report.probes.append(self._call("DELETE", canary_url, "azure:DeleteBlob", "DELETE", mutated=True))

        report.capabilities = summarize_capabilities(report.probes)
        report.findings = findings_from(report.probes, "azure")
        report.warnings.extend(origin_warnings("azure", report.probes))
        return report
