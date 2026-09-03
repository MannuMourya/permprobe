"""Google Cloud Storage probes.

When a Bearer token is present we call testIamPermissions — the official
non-destructive way to ask GCS what the caller can do.
Anonymous probes use the XML and JSON APIs the same way hunters do.
"""

from __future__ import annotations

import json
import uuid
from typing import Optional
from urllib.parse import quote

from .http import Client
from .models import ProbeResult, ResourceReport, Verdict
from .interpret import summarize_capabilities, findings_from
from .detect import Target


IAM_PERMS = [
    "storage.buckets.get",
    "storage.buckets.list",
    "storage.buckets.delete",
    "storage.buckets.getIamPolicy",
    "storage.buckets.setIamPolicy",
    "storage.buckets.update",
    "storage.objects.list",
    "storage.objects.get",
    "storage.objects.create",
    "storage.objects.delete",
    "storage.objects.update",
    "storage.objects.getIamPolicy",
    "storage.objects.setIamPolicy",
]


class GCSProber:
    def __init__(self, client: Client, token: Optional[str] = None, mode: str = "readonly", identity: str = "anonymous"):
        self.client = client
        self.token = token
        self.mode = mode
        self.identity = identity

    def _auth_headers(self) -> dict:
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    def _call(self, method, url, action, capability, extra=None, data=None, mutated=False) -> ProbeResult:
        hdrs = self._auth_headers()
        if extra:
            hdrs.update(extra)
        return self.client.request(
            method, url, action=action, capability=capability, headers=hdrs, data=data, signed=bool(self.token), mutated=mutated
        )

    def _first_object_name(self, json_base: str, preferred: Optional[str] = None) -> Optional[str]:
        if preferred:
            return preferred
        try:
            resp = self.client.session.get(
                f"{json_base}/o?maxResults=5",
                headers=self._auth_headers(),
                timeout=self.client.timeout,
                allow_redirects=False,
                verify=self.client.verify_tls,
            )
            if resp.status_code != 200:
                return None
            items = (resp.json() or {}).get("items") or []
            for item in items:
                name = item.get("name")
                if name:
                    return name
        except Exception:
            return None
        return None

    def _precondition_delete(self, json_base: str, object_name: str) -> ProbeResult:
        """DELETE a live object with ifGenerationMatch=1.

        Real GCS generations are large timestamps, so 1 will not match.
        412 = delete IAM allowed, object kept.
        401/403 = delete denied.
        204 would mean generation was actually 1 (object removed) — we warn.
        """
        encoded = quote(object_name, safe="")
        url = f"{json_base}/o/{encoded}?ifGenerationMatch=1"
        p = self._call("DELETE", url, "gcs:objects.delete.precondition", "DELETE")
        if p.status == 412:
            p.verdict = Verdict.INFERRED
            p.evidence = f"412 conditionNotMet on {object_name} — delete allowed, object not removed"
        elif p.status == 401:
            p.verdict = Verdict.AUTH_REQUIRED
            p.evidence = p.evidence or f"anonymous has no storage.objects.delete on {object_name}"
        elif p.status == 403:
            p.verdict = Verdict.EXISTS_DENIED
            p.evidence = p.evidence or f"storage.objects.delete denied on {object_name}"
        elif p.status in (200, 204):
            p.verdict = Verdict.ALLOWED
            p.mutated = True
            p.evidence = f"WARNING: {object_name} may have been deleted (generation was 1)"
        elif p.status == 404:
            p.verdict = Verdict.NOT_FOUND
            p.evidence = f"{object_name} not found for precondition delete"
        p.note = f"ifGenerationMatch=1 on live object {object_name}"
        return p

    def run(self, target: Target) -> ResourceReport:
        bucket = target.bucket
        key = target.key
        xml_base = f"https://storage.googleapis.com/{bucket}"
        json_base = f"https://storage.googleapis.com/storage/v1/b/{bucket}"
        report = ResourceReport(
            target=target.raw,
            kind="gcs",
            resolved_url=xml_base,
            identity=self.identity,
        )

        report.probes.append(self._call("HEAD", xml_base, "gcs:HeadBucket", "EXISTS"))
        report.probes.append(self._call("GET", json_base, "gcs:buckets.get", "METADATA"))
        report.probes.append(self._call("GET", f"{json_base}/iam", "gcs:buckets.getIamPolicy", "POLICY_READ"))
        report.probes.append(self._call("GET", f"{xml_base}?max-keys=2", "gcs:objects.list", "LIST"))
        report.probes.append(self._call("GET", f"{json_base}/o?maxResults=2", "gcs:objects.list.json", "LIST"))
        report.probes.append(
            self._call(
                "OPTIONS",
                xml_base,
                "gcs:OPTIONS",
                "CORS",
                extra={
                    "Origin": "https://permprobe.example",
                    "Access-Control-Request-Method": "GET",
                },
            )
        )

        if key:
            obj_xml = f"{xml_base}/{key}"
            obj_json = f"{json_base}/o/{key}"
            report.probes.append(self._call("HEAD", obj_xml, "gcs:HeadObject", "EXISTS"))
            report.probes.append(self._call("GET", obj_xml, "gcs:objects.get", "READ", extra={"Range": "bytes=0-0"}))
            report.probes.append(self._call("GET", f"{obj_json}?alt=json", "gcs:objects.get.meta", "METADATA"))

        listed = self._first_object_name(json_base, preferred=key)
        if listed:
            report.probes.append(self._precondition_delete(json_base, listed))
        else:
            report.probes.append(
                ProbeResult(
                    action="gcs:objects.delete.precondition",
                    capability="DELETE",
                    method="DELETE",
                    url=f"{json_base}/o",
                    verdict=Verdict.SKIPPED,
                    evidence="no live object name available to run ifGenerationMatch DELETE",
                )
            )

        canary = f".__permprobe_{uuid.uuid4().hex}"
        canary_url = f"{xml_base}/{canary}"
        put = self._call(
            "PUT",
            canary_url,
            "gcs:objects.create",
            "WRITE",
            extra={"If-Match": "permprobe-never-matches", "Content-Type": "application/octet-stream"},
        )
        if put.status == 412:
            put.verdict = Verdict.INFERRED
            put.evidence = "412 on If-Match — create authorized, object not written"
        elif put.status in (200, 201):
            put.mutated = True
            self._call("DELETE", canary_url, "gcs:objects.delete", "DELETE", mutated=True)
        report.probes.append(put)
        delete = self._call("DELETE", canary_url, "gcs:objects.delete", "DELETE")
        if delete.status in (204, 200):
            delete.verdict = Verdict.ALLOWED
            delete.evidence = "delete of missing canary succeeded"
        elif delete.status == 404:
            delete.verdict = Verdict.NOT_FOUND
            delete.evidence = "NoSuchKey — object missing; delete permission not proven"
        report.probes.append(delete)

        if self.mode == "write-probe":
            put2 = self._call(
                "PUT",
                canary_url,
                "gcs:objects.create",
                "WRITE",
                extra={"Content-Type": "text/plain"},
                data=b"permprobe-canary-ok",
                mutated=True,
            )
            report.probes.append(put2)
            report.probes.append(self._call("DELETE", canary_url, "gcs:objects.delete", "DELETE", mutated=True))

        if self.token:
            url = f"{json_base}/iam:testIamPermissions"
            hdrs = self._auth_headers()
            hdrs["Content-Type"] = "application/json"
            try:
                resp = self.client.session.post(
                    url,
                    headers=hdrs,
                    data=json.dumps({"permissions": IAM_PERMS}),
                    timeout=self.client.timeout,
                    allow_redirects=False,
                    verify=self.client.verify_tls,
                )
                granted = []
                if resp.status_code == 200:
                    try:
                        granted = list(resp.json().get("permissions") or [])
                    except Exception:
                        granted = []
                iam = ProbeResult(
                    action="gcs:testIamPermissions",
                    capability="METADATA",
                    method="POST",
                    url=url,
                    status=resp.status_code,
                    verdict=Verdict.ALLOWED if resp.status_code == 200 else Verdict.DENIED,
                    evidence=("granted: " + ", ".join(granted)) if granted else (resp.text or "")[:240],
                    signed=True,
                )
                if resp.status_code == 401:
                    iam.verdict = Verdict.AUTH_REQUIRED
                elif resp.status_code == 403:
                    iam.verdict = Verdict.EXISTS_DENIED
                report.probes.append(iam)
                cap_map = {
                    "storage.objects.list": "LIST",
                    "storage.buckets.list": "LIST",
                    "storage.objects.get": "READ",
                    "storage.buckets.get": "READ",
                    "storage.objects.create": "WRITE",
                    "storage.objects.update": "WRITE",
                    "storage.buckets.update": "WRITE",
                    "storage.objects.delete": "DELETE",
                    "storage.buckets.delete": "DELETE",
                    "storage.buckets.getIamPolicy": "POLICY_READ",
                    "storage.objects.getIamPolicy": "POLICY_READ",
                    "storage.buckets.setIamPolicy": "POLICY_READ",
                    "storage.objects.setIamPolicy": "POLICY_READ",
                }
                for perm in granted:
                    report.probes.append(
                        ProbeResult(
                            action=f"gcs:{perm}",
                            capability=cap_map.get(perm, "METADATA"),
                            method="POST",
                            url=url,
                            status=200,
                            verdict=Verdict.ALLOWED,
                            evidence="testIamPermissions granted",
                            signed=True,
                        )
                    )
            except Exception as e:
                report.warnings.append(f"testIamPermissions failed: {e}")

        report.capabilities = summarize_capabilities(report.probes)
        report.findings = findings_from(report.probes, "gcs")
        return report
